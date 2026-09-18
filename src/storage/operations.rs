use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::{File, Permissions},
    io::{self, Cursor, Read},
    num::NonZeroUsize,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use crate::narinfo::{BoundNarInfo, CompressedNarExpectation, ValidatedNarInfo};
use crate::object::{EncodedIdentity, NarFileName, NarHash, WireEncoding};

use super::{
    EGRESS_RECEIPT_DIRECTORY, INGESTION_RECEIPT_DIRECTORY, NAR_DIRECTORY, REALISATIONS_DIRECTORY,
    TEMPORARY_DIRECTORY, VALIDATION_DIRECTORY,
    chunk_store::{ChunkStoreError, ChunkedNarReader, ChunkingWriter, MAX_CHUNK_MANIFEST_BYTES},
    chunked::{ChunkManifest, ChunkProfile},
    compression::{
        IngestionReceipt, encoded_file_matches, ingestion_receipt_file_name, nar_file_size_matches,
        receive_uploaded_nar,
    },
    directory::Directory,
    egress::CanonicalRawStatus,
    fs::{
        BoundedRegularFile, StorageCapacity, directory_is_empty, ensure_directory_at,
        entry_is_regular_at, files_equal_at, filesystem_space, hard_link_at, open_at,
        open_directory_at, open_optional_at, open_regular_at, read_bounded_regular_file,
        read_dir_names, remove_temp, rename_at, reserve_staging_bytes, rollback_link_at, unlink_at,
    },
    ids::StoreHash,
    publication::{
        DestinationPublication, NEXT_TEMP, NarUploadPolicy, ProcessLock, PublicationDestination,
        PublicationDirectory, PublishBoundary, PublishOutcome, PublishTarget, PublishedPair,
        StagedPublication, StagingReservation, StorageError, Streaming, TemporaryDirectory,
        TemporaryFile,
    },
    reconcile::{self, ReconcileEntry, ReconcileReport},
    recovery::{PublicationState, PublicationTransaction, RecoveryState},
    state::{Storage, StorageBackend},
};

#[cfg(test)]
use super::publication::{Layout, injected_fault};

const MAX_CACHE_INFO_BYTES: u64 = 1024;
pub(super) const MAX_INGESTION_RECEIPT_BYTES: u64 = 256;

#[allow(dead_code)]
fn storage_error_for_chunk_store(error: ChunkStoreError) -> StorageError {
    match error {
        ChunkStoreError::InvalidRange { .. } => StorageError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunked NAR range is outside the object",
        )),
        ChunkStoreError::Io(error) => StorageError::Io(error),
        ChunkStoreError::Manifest(error) => {
            StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, error))
        }
        ChunkStoreError::NarHashMismatch { .. } | ChunkStoreError::NarSizeMismatch { .. } => {
            StorageError::NarMismatch
        }
    }
}

#[derive(Clone, Copy)]
enum TemporaryLocation {
    Staging,
    Destination,
}

impl TemporaryLocation {
    fn synchronize_source_directory_after_destination_creation(
        self,
        temp: &TemporaryFile,
    ) -> Result<(), StorageError> {
        match self {
            Self::Staging => Ok(()),
            Self::Destination => Ok(temp.directory.sync_all()?),
        }
    }

    fn rollback_destination_before_durability(
        self,
        destination_directory: &File,
        destination_name: &OsStr,
    ) -> Result<(), StorageError> {
        match self {
            Self::Staging => Ok(rollback_link_at(destination_directory, destination_name)?),
            Self::Destination => Ok(()),
        }
    }

    fn remove_temporary(self, storage: &Storage, temp: &TemporaryFile) -> Result<(), StorageError> {
        match self {
            Self::Staging => storage.remove_temp(temp),
            Self::Destination => {
                storage.temporary_objects.fetch_sub(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }
}

enum DestinationPublicationAttempt {
    Existing,
    Created(TemporaryLocation),
}

struct CreatedDestination<'a> {
    temporary_location: TemporaryLocation,
    directory: &'a File,
    name: &'a OsStr,
}

impl<'a> CreatedDestination<'a> {
    fn new(temporary_location: TemporaryLocation, directory: &'a File, name: &'a OsStr) -> Self {
        Self {
            temporary_location,
            directory,
            name,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CleanupAction {
    Keep,
    Remove,
}

impl CleanupAction {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Remove, _) | (_, Self::Remove) => Self::Remove,
            (Self::Keep, Self::Keep) => Self::Keep,
        }
    }
}

struct CompressedValidationName(NarFileName);

impl CompressedValidationName {
    fn parse(name: &OsStr) -> Option<Self> {
        let stem = name.to_str()?.strip_suffix(".validation")?;
        let nar_name = NarFileName::parse(stem).ok()?;
        (nar_name.encoding() != WireEncoding::Raw).then_some(Self(nar_name))
    }

    fn nar_name(&self) -> OsString {
        self.0.os_string()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NarMatch {
    Missing,
    Mismatch,
    Match,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageReadiness {
    Ready,
    Insufficient,
}

impl StorageReadiness {
    pub(crate) const fn is_ready(self) -> bool {
        match self {
            Self::Ready => true,
            Self::Insufficient => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NarInfoDeletion {
    Deleted,
    Absent,
}

pub(crate) enum NarReadBody<'storage> {
    File(File),
    Chunked(Box<ChunkedNarReader<'storage>>),
}

pub(crate) struct OpenedNar<'storage> {
    pub(crate) body: NarReadBody<'storage>,
}

impl Read for NarReadBody<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            Self::Chunked(reader) => reader.read(buffer),
        }
    }
}

pub(super) struct OwnedTemporary<'storage> {
    storage: &'storage Storage,
    file: Option<TemporaryFile>,
}

impl<'storage> OwnedTemporary<'storage> {
    pub(super) fn new(storage: &'storage Storage, file: TemporaryFile) -> Self {
        Self {
            storage,
            file: Some(file),
        }
    }

    pub(super) fn file(&self) -> &TemporaryFile {
        self.file.as_ref().expect("owned temporary file is present")
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self
            .file
            .as_mut()
            .expect("owned temporary file is present")
            .file
    }

    pub(super) fn into_file(mut self) -> TemporaryFile {
        self.file.take().expect("owned temporary file is present")
    }

    pub(super) fn cleanup(&mut self) -> Result<(), StorageError> {
        let Some(file) = self.file.as_ref() else {
            return Ok(());
        };
        self.storage.remove_temp(file)?;
        self.file = None;
        Ok(())
    }
}

impl Drop for OwnedTemporary<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Clone, Copy)]
enum PublicationProgress {
    Pending(TemporaryLocation),
    Durable(TemporaryLocation),
}

impl PublicationProgress {
    fn created(location: TemporaryLocation) -> Self {
        Self::Pending(location)
    }

    fn mark_durable(&mut self) {
        *self = match *self {
            Self::Pending(location) => Self::Durable(location),
            Self::Durable(location) => Self::Durable(location),
        };
    }

    fn finish(
        self,
        result: Result<PublishOutcome, StorageError>,
        storage: &Storage,
        temp: &TemporaryFile,
        transaction: PublicationTransaction,
    ) -> Result<PublishOutcome, StorageError> {
        match (result, self) {
            (Ok(outcome), Self::Pending(location) | Self::Durable(location)) => {
                location.remove_temporary(storage, temp)?;
                transaction.complete()?;
                Ok(outcome)
            }
            (Err(error), Self::Durable(location)) => {
                location.remove_temporary(storage, temp)?;
                transaction.complete()?;
                Err(error)
            }
            (Err(error), Self::Pending(location)) => {
                let _ = location.remove_temporary(storage, temp);
                Err(error)
            }
        }
    }
}

impl BoundNarInfo<'_> {
    pub(crate) fn publish(self) -> Result<PublishOutcome, StorageError> {
        self.stored().storage().publish(
            PublishTarget::NarInfo(self.store()),
            Cursor::new(self.output_bytes()?),
        )
    }
}

fn validate_cache_info(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() as u64 > MAX_CACHE_INFO_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nix-cache-info exceeds configured size limit",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "nix-cache-info is not UTF-8"))?;
    let mut fields = CacheInfoFields::default();
    for line in text.lines() {
        let (name, value) = line.split_once(": ").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed nix-cache-info")
        })?;
        fields.record(name, value)?;
    }
    fields.finish()
}

#[derive(Default)]
struct CacheInfoFields {
    store_dir: Option<()>,
    mass_query: Option<()>,
    priority: Option<u32>,
}

impl CacheInfoFields {
    fn record(&mut self, name: &str, value: &str) -> io::Result<()> {
        match name {
            "StoreDir" if self.store_dir.is_none() && value == "/nix/store" => {
                self.store_dir = Some(());
            }
            "WantMassQuery" if self.mass_query.is_none() && value == "0" => {
                self.mass_query = Some(());
            }
            "Priority" if self.priority.is_none() => {
                self.priority = Some(value.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid nix-cache-info priority",
                    )
                })?);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported or duplicate nix-cache-info field",
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> io::Result<()> {
        if self.store_dir.is_some() && self.mass_query.is_some() && self.priority.is_some() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nix-cache-info is missing a required field",
            ))
        }
    }
}

impl Storage {
    pub fn initialize(root: &Directory) -> Result<Self, StorageError> {
        Self::initialize_with_backend(root, StorageBackend::Flat)
    }

    pub fn initialize_with_backend(
        root: &Directory,
        backend: StorageBackend,
    ) -> Result<Self, StorageError> {
        #[cfg(test)]
        let layout = Layout::new(root.path.clone());
        let root_directory = root.file.try_clone()?;
        let root_is_empty = directory_is_empty(&root_directory)?;
        let lock = ProcessLock::acquire(open_at(
            &root_directory,
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?)?;
        ProcessLock::validate_lock_file(&root_directory)?;
        let nar_directory =
            ensure_directory_at(&root_directory, OsStr::new(NAR_DIRECTORY), "nar directory")?;
        ensure_directory_at(
            &nar_directory,
            OsStr::new(TEMPORARY_DIRECTORY),
            "NAR temporary directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(TEMPORARY_DIRECTORY),
            "temporary directory",
        )?;
        let transactions = ensure_directory_at(
            &root_directory,
            OsStr::new(".narjar-transactions"),
            "publication transaction directory",
        )?;
        transactions.set_permissions(Permissions::from_mode(0o700))?;
        let realisations_directory = ensure_directory_at(
            &root_directory,
            OsStr::new(REALISATIONS_DIRECTORY),
            "realisations directory",
        )?;
        ensure_directory_at(
            &realisations_directory,
            OsStr::new(".tmp"),
            "realisation temporary directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(VALIDATION_DIRECTORY),
            "validation evidence directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(INGESTION_RECEIPT_DIRECTORY),
            "compressed ingestion receipt directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(EGRESS_RECEIPT_DIRECTORY),
            "compressed egress receipt directory",
        )?;
        let chunk_store = super::chunk_store::ChunkStore::initialize(&root_directory)?;

        root_directory.sync_all()?;

        let recovery = RecoveryState::new(&root_directory)?;
        let storage = Self {
            #[cfg(test)]
            layout,
            root: root_directory,
            chunk_store,
            backend,
            recovery,
            publication_locks: Mutex::new(HashMap::new()),
            staging_budget: Arc::new(Mutex::new(Default::default())),
            temporary_objects: AtomicU64::new(0),
            #[cfg(test)]
            egress_generations: AtomicU64::new(0),
            _lock: lock,
        };
        if root_is_empty {
            storage.recovery.initialize_clean()?;
        }
        Ok(storage)
    }

    #[cfg(test)]
    pub(super) fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn recovery_required(&self) -> Result<bool, StorageError> {
        self.recovery.required()
    }

    pub fn recovery_required_for(&self) -> Result<bool, StorageError> {
        self.recovery.required_for()
    }

    /// Records that a full inventory scan has completed successfully.
    pub fn finish_recovery(&self) -> Result<(), StorageError> {
        self.remove_orphan_validation_evidence()?;
        self.remove_orphan_ingestion_receipts()?;
        self.remove_orphan_egress_receipts()?;
        self.recovery.finish()
    }

    pub fn reserve_staging(
        &self,
        bytes: u64,
        min_free_bytes: u64,
    ) -> Result<StagingReservation, StorageError> {
        if bytes == 0 {
            return Ok(StagingReservation::empty(Arc::clone(&self.staging_budget)));
        }
        let directory = self.nar_temp_directory()?;
        reserve_staging_bytes(&self.staging_budget, &directory, min_free_bytes, bytes)
    }

    pub(super) fn empty_staging_reservation(
        &self,
        min_free_bytes: u64,
    ) -> Result<StagingReservation, StorageError> {
        let directory = self.nar_temp_directory()?;
        reserve_staging_bytes(&self.staging_budget, &directory, min_free_bytes, 0)
    }

    pub fn publish_cache_info(&self, source: impl Read) -> Result<PublishOutcome, StorageError> {
        self.publish(PublishTarget::CacheInfo, source)
    }

    pub fn cache_info(&self) -> Result<Vec<u8>, StorageError> {
        let root = self.root_directory()?;
        let file = open_regular_at(&root, OsStr::new("nix-cache-info"))?;
        let mut bytes = Vec::new();
        file.take(MAX_CACHE_INFO_BYTES + 1)
            .read_to_end(&mut bytes)?;
        validate_cache_info(&bytes)?;
        Ok(bytes)
    }

    pub fn publish_nar(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
    ) -> Result<PublishOutcome, StorageError> {
        if expected_length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }

        let staging = self.reserve_staging(expected_length, policy.min_free_bytes)?;
        self.publish_nar_with_staging(name, source, expected_length, policy, staging)
    }

    #[allow(dead_code)]
    pub(crate) fn publish_chunked_nar(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
    ) -> Result<ChunkManifest, StorageError> {
        if expected_length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }
        let reservation = self.empty_staging_reservation(policy.min_free_bytes)?;
        let mut destination: ChunkingWriter<'_> = self
            .chunk_store
            .begin_ingest_with_reservation(
                ChunkProfile::MinCdcHash4V1,
                reservation,
                policy.min_free_bytes,
            )
            .map_err(storage_error_for_chunk_store)?;
        let received = receive_uploaded_nar(
            source,
            name,
            expected_length,
            policy.max_bytes,
            &mut destination,
        )?;
        let completed = destination
            .finish(received.identity())
            .map_err(storage_error_for_chunk_store)?;
        if let Some(receipt) = received.ingestion_receipt() {
            self.publish_ingestion_receipt(receipt)?;
        }
        let manifest = completed.manifest();
        completed.release_reservation();
        Ok(manifest)
    }

    pub fn publish_nar_with_staging(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
        staging: StagingReservation,
    ) -> Result<PublishOutcome, StorageError> {
        match self.backend {
            StorageBackend::Flat => {
                let receiving = self.begin_upload(name, expected_length, policy, staging)?;
                let complete = receiving.receive(source)?;
                complete.commit()
            }
            StorageBackend::Chunked => self.publish_chunked_nar_with_staging(
                name,
                source,
                expected_length,
                policy,
                staging,
            ),
        }
    }

    fn publish_chunked_nar_with_staging(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
    ) -> Result<PublishOutcome, StorageError> {
        let mut destination = self
            .chunk_store
            .begin_ingest_with_reservation(
                ChunkProfile::MinCdcHash4V1,
                reservation,
                policy.min_free_bytes,
            )
            .map_err(storage_error_for_chunk_store)?;
        let received = receive_uploaded_nar(
            source,
            name,
            expected_length,
            policy.max_bytes,
            &mut destination,
        )?;
        let completed = destination
            .finish(received.identity())
            .map_err(storage_error_for_chunk_store)?;
        if let Some(receipt) = received.ingestion_receipt() {
            self.publish_ingestion_receipt(receipt)?;
        }
        let outcome = completed.outcome();
        completed.release_reservation();
        Ok(outcome)
    }

    #[cfg(test)]
    pub(super) fn publish_nar_unchecked(
        &self,
        hash: &NarHash,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish(PublishTarget::Nar(NarFileName::raw(*hash)), source)
    }

    #[cfg(test)]
    pub(super) fn publish_nar_fault(
        &self,
        hash: &NarHash,
        source: impl Read,
        fault: PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(
            PublishTarget::Nar(NarFileName::raw(*hash)),
            source,
            |boundary| injected_fault(boundary, fault),
        )
    }

    pub(crate) fn bind_narinfo(
        &self,
        narinfo: ValidatedNarInfo,
        output_encoding: WireEncoding,
        policy: NarUploadPolicy,
    ) -> Result<BoundNarInfo<'_>, StorageError> {
        let stored = self.open_verified_canonical_nar(narinfo.payload())?;
        let output = self.select_egress(&stored, output_encoding, policy)?;
        narinfo
            .bind_raw(stored, output.file_name(), output.size())
            .map_err(|_| StorageError::NarMismatch)
    }

    pub(crate) fn nar_matches(&self, narinfo: &ValidatedNarInfo) -> Result<NarMatch, StorageError> {
        let nar_directory = self.nar_directory()?;
        let payload_name = narinfo.payload_name();
        open_optional_at(&nar_directory, &payload_name.os_string())?.map_or(
            Ok(NarMatch::Missing),
            |file| {
                nar_file_size_matches(&file, narinfo.file_size().get())
                    .map(|matches| match matches {
                        true => NarMatch::Match,
                        false => NarMatch::Mismatch,
                    })
                    .map_err(Into::into)
            },
        )
    }

    #[cfg(test)]
    pub(super) fn publish_narinfo_unchecked(
        &self,
        store: &StoreHash,
        nar: NarHash,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.ensure_nar(&nar)?;
        self.publish(PublishTarget::NarInfo(store), source)
    }

    #[cfg(test)]
    pub(super) fn publish_narinfo_fault(
        &self,
        store: &StoreHash,
        nar: NarHash,
        source: impl Read,
        fault: PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.ensure_nar(&nar)?;
        self.publish_with(PublishTarget::NarInfo(store), source, |boundary| {
            injected_fault(boundary, fault)
        })
    }

    #[cfg(test)]
    pub(super) fn ensure_nar(&self, nar: &NarHash) -> Result<(), StorageError> {
        let nar_directory = self.nar_directory()?;
        let nar_name = NarFileName::raw(*nar);
        match open_regular_at(&nar_directory, &nar_name.os_string()) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(StorageError::MissingNar),
            Err(error) => Err(error.into()),
        }
    }

    pub fn open_nar(&self, nar: NarHash) -> Result<Option<File>, StorageError> {
        self.open_nar_encoded(NarFileName::raw(nar))
    }

    pub fn open_nar_encoded(&self, name: NarFileName) -> Result<Option<File>, StorageError> {
        let directory = self.nar_directory()?;
        open_optional_at(&directory, &name.os_string())
    }

    pub(crate) fn nar_size(&self, name: NarFileName) -> Result<Option<u64>, StorageError> {
        if let (StorageBackend::Chunked, Some(hash)) = (self.backend, name.raw_hash()) {
            return Ok(self
                .chunk_store
                .manifest_identity(hash)
                .map_err(storage_error_for_chunk_store)?
                .map(|manifest| manifest.identity().size().get()));
        }
        let Some(file) = self.open_nar_encoded(name)? else {
            return Ok(None);
        };
        Ok(Some(file.metadata()?.len()))
    }

    pub(crate) fn open_nar_range(
        &self,
        name: NarFileName,
        range: std::ops::Range<u64>,
    ) -> Result<Option<OpenedNar<'_>>, StorageError> {
        if let (StorageBackend::Chunked, Some(hash)) = (self.backend, name.raw_hash()) {
            if self
                .chunk_store
                .manifest_identity(hash)
                .map_err(storage_error_for_chunk_store)?
                .is_none()
            {
                return Ok(None);
            }
            let reader = self
                .chunk_store
                .open_reader(hash, range, MAX_CHUNK_MANIFEST_BYTES)
                .map_err(storage_error_for_chunk_store)?;
            return Ok(Some(OpenedNar {
                body: NarReadBody::Chunked(Box::new(reader)),
            }));
        }
        let Some(file) = self.open_nar_encoded(name)? else {
            return Ok(None);
        };
        Ok(Some(OpenedNar {
            body: NarReadBody::File(file),
        }))
    }

    pub fn open_narinfo(&self, store: &StoreHash) -> Result<Option<File>, StorageError> {
        let directory = self.root_directory()?;
        let name = format!("{}.narinfo", store.as_str());
        open_optional_at(&directory, OsStr::new(&name))
    }

    pub fn open_pair(
        &self,
        store: &StoreHash,
        nar: NarHash,
    ) -> Result<Option<PublishedPair>, StorageError> {
        Ok(self
            .open_narinfo(store)?
            .zip(self.open_nar(nar)?)
            .map(|(narinfo, nar)| PublishedPair { nar, narinfo }))
    }

    pub fn is_ready(&self, min_free_bytes: u64) -> Result<StorageReadiness, StorageError> {
        let directory = self.nar_temp_directory()?;
        Ok(
            match filesystem_space(&directory)?.required_capacity(min_free_bytes) {
                Ok(()) => StorageReadiness::Ready,
                Err(_) => StorageReadiness::Insufficient,
            },
        )
    }

    pub(crate) fn capacity(&self) -> Result<StorageCapacity, StorageError> {
        let directory = self.nar_directory()?;
        let space = filesystem_space(&directory)?;
        Ok(StorageCapacity {
            total_bytes: space.total_bytes,
            available_bytes: space.available_bytes,
            total_inodes: space.total_inodes,
            available_inodes: space.available_inodes,
            read_only: space.read_only,
        })
    }

    pub(crate) fn temporary_objects(&self) -> u64 {
        self.temporary_objects.load(Ordering::Relaxed)
    }

    pub fn reconcile(
        &self,
        limit: NonZeroUsize,
        stale_before: SystemTime,
    ) -> Result<ReconcileReport, StorageError> {
        reconcile::scan(self, limit, stale_before)
    }

    pub fn cleanup_stale_temp(
        &self,
        entry: &ReconcileEntry,
    ) -> Result<reconcile::CleanupOutcome, StorageError> {
        reconcile::cleanup_stale_temp(self, entry)
    }

    pub fn delete_narinfo(&self, store: &StoreHash) -> Result<NarInfoDeletion, StorageError> {
        let root = self.root_directory()?;
        let name = OsString::from(format!("{}.narinfo", store.as_str()));
        match entry_is_regular_at(&root, &name) {
            Ok(true) => {
                unlink_at(&root, &name)?;
                root.sync_all()?;
                Ok(NarInfoDeletion::Deleted)
            }
            Ok(false) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "narinfo is not a regular file",
            )
            .into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(NarInfoDeletion::Absent),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn publish(
        &self,
        target: PublishTarget<'_>,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(target, source, |_| Ok(()))
    }

    pub(super) fn begin_publication<'storage, 'target, Checkpoint>(
        &'storage self,
        target: PublishTarget<'target>,
        mut checkpoint: Checkpoint,
    ) -> Result<StagedPublication<'storage, Checkpoint, Streaming>, StorageError>
    where
        Checkpoint: FnMut(PublishBoundary) -> Result<(), StorageError>,
    {
        let destination = target.destination();
        let temp_name = self.next_temp_name(&target);
        let temporary_path = self.temporary_path(&target, &temp_name);
        let mut transaction = self.recovery.begin(&temporary_path)?;
        checkpoint(PublishBoundary::BeforeTempCreate)?;
        let temporary = OwnedTemporary::new(self, self.create_temp_named(&target, temp_name)?);
        transaction.transition(PublicationState::Streaming)?;

        Ok(StagedPublication::from_parts(
            self,
            destination,
            temporary,
            transaction,
            checkpoint,
        ))
    }

    pub(super) fn publish_with(
        &self,
        target: PublishTarget<'_>,
        source: impl Read,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        self.begin_publication(target, &mut checkpoint)?
            .finish_and_sync(source)?
            .commit()
    }

    pub(super) fn commit_temporary(
        &self,
        destination: PublicationDestination,
        temp: &TemporaryFile,
        mut transaction: PublicationTransaction,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        let mut progress = PublicationProgress::Pending(TemporaryLocation::Staging);
        let result = (|| {
            let destination_directory = self.destination_directory(destination.directory)?;
            checkpoint(PublishBoundary::BeforeFinalLink)?;
            self.publish_temporary_at_destination_or_resolve_existing(
                &destination,
                &destination_directory,
                temp,
                &mut transaction,
                &mut checkpoint,
                &mut progress,
            )
        })();
        progress.finish(result, self, temp, transaction)
    }

    fn publish_temporary_at_destination_or_resolve_existing(
        &self,
        destination: &PublicationDestination,
        destination_directory: &File,
        temp: &TemporaryFile,
        transaction: &mut PublicationTransaction,
        checkpoint: &mut impl FnMut(PublishBoundary) -> Result<(), StorageError>,
        progress: &mut PublicationProgress,
    ) -> Result<PublishOutcome, StorageError> {
        match destination.publication {
            DestinationPublication::Link | DestinationPublication::Repair(_) => self
                .with_destination_lock(destination, || {
                    self.publish_temporary_and_finalize_destination(
                        destination,
                        destination_directory,
                        temp,
                        transaction,
                        checkpoint,
                        progress,
                    )
                }),
            DestinationPublication::Replace => self.publish_temporary_and_finalize_destination(
                destination,
                destination_directory,
                temp,
                transaction,
                checkpoint,
                progress,
            ),
        }
    }

    fn with_destination_lock<T>(
        &self,
        destination: &PublicationDestination,
        action: impl FnOnce() -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let destination_lock = self.destination_lock(self.destination_key(destination));
        let _destination_guard = destination_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        action()
    }

    fn publish_temporary_and_finalize_destination(
        &self,
        destination: &PublicationDestination,
        destination_directory: &File,
        temp: &TemporaryFile,
        transaction: &mut PublicationTransaction,
        checkpoint: &mut impl FnMut(PublishBoundary) -> Result<(), StorageError>,
        progress: &mut PublicationProgress,
    ) -> Result<PublishOutcome, StorageError> {
        match self.place_temporary_at_destination_or_resolve_existing(
            destination,
            destination_directory,
            temp,
        )? {
            DestinationPublicationAttempt::Existing => {
                transaction.transition(PublicationState::Published)?;
                Ok(PublishOutcome::Identical)
            }
            DestinationPublicationAttempt::Created(location) => {
                *progress = PublicationProgress::created(location);
                self.durably_finalize_created_destination(
                    CreatedDestination::new(location, destination_directory, &destination.name),
                    temp,
                    transaction,
                    checkpoint,
                    progress,
                )?;
                Ok(PublishOutcome::Created)
            }
        }
    }

    fn place_temporary_at_destination_or_resolve_existing(
        &self,
        destination: &PublicationDestination,
        destination_directory: &File,
        temp: &TemporaryFile,
    ) -> Result<DestinationPublicationAttempt, StorageError> {
        match destination.publication {
            DestinationPublication::Replace => {
                rename_at(
                    &temp.directory,
                    &temp.name,
                    destination_directory,
                    &destination.name,
                )?;
                Ok(DestinationPublicationAttempt::Created(
                    TemporaryLocation::Destination,
                ))
            }
            DestinationPublication::Link => self.link_temporary_while_destination_is_locked(
                destination,
                destination_directory,
                temp,
            ),
            DestinationPublication::Repair(output) => self
                .repair_egress_derivative_while_destination_is_locked(
                    destination,
                    destination_directory,
                    temp,
                    output,
                ),
        }
    }

    fn link_temporary_while_destination_is_locked(
        &self,
        destination: &PublicationDestination,
        destination_directory: &File,
        temp: &TemporaryFile,
    ) -> Result<DestinationPublicationAttempt, StorageError> {
        match hard_link_at(
            &temp.directory,
            &temp.name,
            destination_directory,
            &destination.name,
        ) {
            Ok(()) => Ok(DestinationPublicationAttempt::Created(
                TemporaryLocation::Staging,
            )),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => self
                .compare_temporary_with_existing_destination(
                    destination,
                    destination_directory,
                    temp,
                ),
            Err(error) => Err(error.into()),
        }
    }

    fn compare_temporary_with_existing_destination(
        &self,
        destination: &PublicationDestination,
        destination_directory: &File,
        temp: &TemporaryFile,
    ) -> Result<DestinationPublicationAttempt, StorageError> {
        if files_equal_at(
            &temp.directory,
            &temp.name,
            destination_directory,
            &destination.name,
        )? {
            Ok(DestinationPublicationAttempt::Existing)
        } else {
            Err(StorageError::Conflict)
        }
    }

    fn repair_egress_derivative_while_destination_is_locked(
        &self,
        destination: &PublicationDestination,
        destination_directory: &File,
        temp: &TemporaryFile,
        output: EncodedIdentity,
    ) -> Result<DestinationPublicationAttempt, StorageError> {
        match self.replace_corrupt_egress_derivative(
            temp,
            destination_directory,
            &destination.name,
            output,
        ) {
            Ok(()) => Ok(DestinationPublicationAttempt::Created(
                TemporaryLocation::Destination,
            )),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Ok(DestinationPublicationAttempt::Existing)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn durably_finalize_created_destination(
        &self,
        destination: CreatedDestination<'_>,
        temp: &TemporaryFile,
        transaction: &mut PublicationTransaction,
        checkpoint: &mut impl FnMut(PublishBoundary) -> Result<(), StorageError>,
        progress: &mut PublicationProgress,
    ) -> Result<(), StorageError> {
        destination
            .temporary_location
            .synchronize_source_directory_after_destination_creation(temp)?;
        transaction.transition(PublicationState::Linked)?;
        if let Err(error) = checkpoint(PublishBoundary::BeforeParentSync) {
            destination
                .temporary_location
                .rollback_destination_before_durability(destination.directory, destination.name)?;
            return Err(error);
        }
        if let Err(error) = destination.directory.sync_all() {
            destination
                .temporary_location
                .rollback_destination_before_durability(destination.directory, destination.name)?;
            return Err(error.into());
        }
        transaction.transition(PublicationState::Published)?;
        progress.mark_durable();
        checkpoint(PublishBoundary::AfterParentSync)
    }

    fn replace_corrupt_egress_derivative(
        &self,
        temp: &TemporaryFile,
        destination_directory: &File,
        destination_name: &OsStr,
        output: EncodedIdentity,
    ) -> io::Result<()> {
        match open_regular_at(destination_directory, destination_name) {
            Ok(file) if encoded_file_matches(&file, output)? => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "egress derivative was published concurrently",
            )),
            Ok(_) => rename_at(
                &temp.directory,
                &temp.name,
                destination_directory,
                destination_name,
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => rename_at(
                &temp.directory,
                &temp.name,
                destination_directory,
                destination_name,
            ),
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    pub(super) fn create_temp(
        &self,
        target: &PublishTarget<'_>,
    ) -> Result<TemporaryFile, StorageError> {
        let name = self.next_temp_name(target);
        self.create_temp_named(target, name)
    }

    pub(super) fn next_temp_name(&self, target: &PublishTarget<'_>) -> OsString {
        self.next_temp_name_with_prefix(target.destination().temp_prefix)
    }

    pub(super) fn next_temp_name_with_prefix(&self, prefix: &str) -> OsString {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        OsString::from(format!("{prefix}-{}-{sequence:016x}.part", process::id()))
    }

    pub(super) fn temporary_path(&self, target: &PublishTarget<'_>, name: &OsStr) -> PathBuf {
        let destination = target.destination();
        Self::temporary_path_for(destination.temporary_directory, name)
    }

    pub(super) fn create_temp_named(
        &self,
        target: &PublishTarget<'_>,
        name: OsString,
    ) -> Result<TemporaryFile, StorageError> {
        let directory = self.temporary_directory(target.destination().temporary_directory)?;
        self.create_temp_in_directory(directory, name)
    }

    pub(super) fn create_nar_temp_named(
        &self,
        name: OsString,
    ) -> Result<TemporaryFile, StorageError> {
        self.create_temp_in_directory(self.nar_temp_directory()?, name)
    }

    fn create_temp_in_directory(
        &self,
        directory: File,
        name: OsString,
    ) -> Result<TemporaryFile, StorageError> {
        let file = open_at(
            &directory,
            &name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        self.temporary_objects.fetch_add(1, Ordering::Relaxed);
        Ok(TemporaryFile {
            name,
            directory,
            file,
        })
    }

    pub(super) fn remove_temp(&self, temp: &TemporaryFile) -> Result<(), StorageError> {
        remove_temp(temp).map_err(StorageError::from).inspect(|_| {
            self.temporary_objects.fetch_sub(1, Ordering::Relaxed);
        })
    }

    pub(super) fn root_directory(&self) -> Result<File, StorageError> {
        Ok(self.root.try_clone()?)
    }

    pub(super) fn nar_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new("nar"))?)
    }

    pub(super) fn temp_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new(".tmp"))?)
    }

    pub(super) fn nar_temp_directory(&self) -> Result<File, StorageError> {
        let nar = self.nar_directory()?;
        Ok(open_directory_at(&nar, OsStr::new(".tmp"))?)
    }

    pub(super) fn realisations_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new("realisations"))?)
    }

    pub(super) fn realisations_temp_directory(&self) -> Result<File, StorageError> {
        let realisations = self.realisations_directory()?;
        Ok(open_directory_at(&realisations, OsStr::new(".tmp"))?)
    }

    pub(super) fn destination_directory(
        &self,
        directory: PublicationDirectory,
    ) -> Result<File, StorageError> {
        match directory {
            PublicationDirectory::Root => self.root_directory(),
            PublicationDirectory::Nar => self.nar_directory(),
            PublicationDirectory::IngestionReceipts => self.ingestion_receipt_directory(),
            PublicationDirectory::EgressReceipts => self.egress_receipt_directory(),
        }
    }

    pub(super) fn destination_key(&self, destination: &PublicationDestination) -> PathBuf {
        match destination.directory {
            PublicationDirectory::Root => PathBuf::from(&destination.name),
            PublicationDirectory::Nar => PathBuf::from("nar").join(&destination.name),
            PublicationDirectory::IngestionReceipts => {
                PathBuf::from(INGESTION_RECEIPT_DIRECTORY).join(&destination.name)
            }
            PublicationDirectory::EgressReceipts => {
                PathBuf::from(EGRESS_RECEIPT_DIRECTORY).join(&destination.name)
            }
        }
    }

    fn temporary_directory(&self, directory: TemporaryDirectory) -> Result<File, StorageError> {
        match directory {
            TemporaryDirectory::Root => self.temp_directory(),
            TemporaryDirectory::Nar => self.nar_temp_directory(),
        }
    }

    fn temporary_path_for(directory: TemporaryDirectory, name: &OsStr) -> PathBuf {
        match directory {
            TemporaryDirectory::Root => PathBuf::from(".tmp").join(name),
            TemporaryDirectory::Nar => PathBuf::from("nar/.tmp").join(name),
        }
    }

    pub(super) fn validation_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new(VALIDATION_DIRECTORY))?)
    }

    pub(super) fn ingestion_receipt_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(
            &root,
            OsStr::new(INGESTION_RECEIPT_DIRECTORY),
        )?)
    }

    pub(super) fn publish_ingestion_receipt(
        &self,
        receipt: IngestionReceipt,
    ) -> Result<PublishOutcome, StorageError> {
        let bytes = receipt.bytes();
        self.publish(
            PublishTarget::IngestionReceipt(&receipt),
            Cursor::new(bytes),
        )
    }

    pub(super) fn read_ingestion_receipt(
        &self,
        expectation: CompressedNarExpectation,
    ) -> Result<Option<IngestionReceipt>, StorageError> {
        let directory = self.ingestion_receipt_directory()?;
        let name = ingestion_receipt_file_name(expectation);
        match Self::read_ingestion_receipt_file(&directory, &name)? {
            BoundedRegularFile::Valid(receipt) if receipt.matches(expectation) => Ok(Some(receipt)),
            BoundedRegularFile::Missing
            | BoundedRegularFile::Invalid
            | BoundedRegularFile::Valid(_) => Ok(None),
        }
    }

    pub(super) fn remove_orphan_ingestion_receipts(&self) -> Result<(), StorageError> {
        let receipts = self.ingestion_receipt_directory()?;
        let action = read_dir_names(&receipts)?.into_iter().try_fold(
            CleanupAction::Keep,
            |action, name| {
                self.cleanup_ingestion_receipt(&receipts, &name)
                    .map(|entry_action| action.combine(entry_action))
            },
        )?;
        if action == CleanupAction::Remove {
            receipts.sync_all()?;
        }
        Ok(())
    }

    fn cleanup_ingestion_receipt(
        &self,
        receipts: &File,
        name: &OsStr,
    ) -> Result<CleanupAction, StorageError> {
        match Self::read_ingestion_receipt_file(receipts, name)? {
            BoundedRegularFile::Missing => Ok(CleanupAction::Keep),
            BoundedRegularFile::Invalid => {
                CompressedValidationName::parse(name).map_or(Ok(CleanupAction::Keep), |_| {
                    unlink_at(receipts, name)?;
                    Ok(CleanupAction::Remove)
                })
            }
            BoundedRegularFile::Valid(receipt) => {
                match self.canonical_raw_status(receipt.decoded_identity())? {
                    CanonicalRawStatus::Present => Ok(CleanupAction::Keep),
                    CanonicalRawStatus::Missing | CanonicalRawStatus::WrongSize => {
                        unlink_at(receipts, name)?;
                        Ok(CleanupAction::Remove)
                    }
                }
            }
        }
    }

    fn read_ingestion_receipt_file(
        directory: &File,
        name: &OsStr,
    ) -> Result<BoundedRegularFile<IngestionReceipt>, StorageError> {
        Ok(
            read_bounded_regular_file(directory, name, MAX_INGESTION_RECEIPT_BYTES)?
                .parse(IngestionReceipt::parse),
        )
    }

    pub(super) fn remove_orphan_validation_evidence(&self) -> Result<(), StorageError> {
        let validation = self.validation_directory()?;
        let nar = self.nar_directory()?;
        let action = read_dir_names(&validation)?.into_iter().try_fold(
            CleanupAction::Keep,
            |action, name| {
                self.cleanup_validation_evidence(&validation, &nar, &name)
                    .map(|entry_action| action.combine(entry_action))
            },
        )?;
        if action == CleanupAction::Remove {
            validation.sync_all()?;
        }
        Ok(())
    }

    fn cleanup_validation_evidence(
        &self,
        validation: &File,
        nar: &File,
        name: &OsStr,
    ) -> Result<CleanupAction, StorageError> {
        let Some(evidence_name) = CompressedValidationName::parse(name) else {
            return Ok(CleanupAction::Keep);
        };
        match entry_is_regular_at(nar, &evidence_name.nar_name()) {
            Ok(true) => Ok(CleanupAction::Keep),
            Ok(false) => self.remove_validation_evidence(validation, name),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.remove_validation_evidence(validation, name)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn remove_validation_evidence(
        &self,
        validation: &File,
        name: &OsStr,
    ) -> Result<CleanupAction, StorageError> {
        unlink_at(validation, name)?;
        Ok(CleanupAction::Remove)
    }

    pub(super) fn destination_lock(&self, key: PathBuf) -> Arc<Mutex<()>> {
        let mut locks = self
            .publication_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }
}
