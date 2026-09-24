use std::{
    ffi::{OsStr, OsString},
    fs::{File, Permissions},
    io::{self, Cursor, Read},
    num::NonZeroUsize,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process,
    sync::{Arc, Mutex, Weak, atomic::Ordering},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::narinfo::{BoundNarInfo, ValidatedNarInfo};
#[cfg(test)]
use crate::object::NarHash;
use crate::object::{
    CompressedNarIdentity, EncodedIdentity, NarFileName, NarIdentity, NarRepresentation,
    WireEncoding,
};

use super::{
    CleanupAction, INGESTION_RECEIPT_DIRECTORY, VALIDATION_DIRECTORY,
    cache_info::{MAX_CACHE_INFO_BYTES, validate as validate_cache_info},
    chunk_store::{ChunkStoreError, MAX_CHUNK_MANIFEST_BYTES},
    chunked::ChunkProfile,
    compression::{
        IngestionReceipt, ReceivedNar, compressed_file_identity, encoded_file_matches,
        nar_file_matches, receive_uploaded_nar,
    },
    egress::{CanonicalRawStatus, NarReadBody},
    fs::{
        BoundedRegularFile, StorageCapacity, entry_is_regular_at, files_equal_at, filesystem_space,
        hard_link_at, open_at, open_directory_at, open_optional_at, open_regular_at,
        read_bounded_regular_file, read_dir_names, remove_temp, rename_at, reserve_staging_bytes,
        rollback_link_at, unlink_at,
    },
    ids::StoreHash,
    location::TemporaryPath,
    publication::{
        DestinationPublication, NEXT_TEMP, NarUploadPolicy, PublicationDestination,
        PublishBoundary, PublishOutcome, PublishTarget, StagedPublication, StagingReservation,
        StorageError, TemporaryDirectory, TemporaryFile,
    },
    reconcile::{self, ReconcileEntry, ReconcileReport},
    recovery::{PublicationState, PublicationTransaction},
    state::{PayloadStorage, Storage},
    typestate::Streaming,
};

#[cfg(test)]
use super::publication::injected_fault;

pub(super) const MAX_INGESTION_RECEIPT_BYTES: u64 = 256;

#[allow(dead_code)]
pub(super) fn storage_error_for_chunk_store(error: ChunkStoreError) -> StorageError {
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
    Repaired(TemporaryLocation),
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

struct CompressedValidationName(NarFileName);

impl CompressedValidationName {
    fn parse(name: &OsStr) -> Option<Self> {
        let stem = name.to_str()?.strip_suffix(".validation")?;
        let nar_name = NarFileName::parse(stem).ok()?;
        match nar_name.encoding() {
            WireEncoding::Raw => None,
            WireEncoding::Compressed(_) => Some(Self(nar_name)),
        }
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

impl NarMatch {
    const fn from_content_match(matches: bool) -> Self {
        match matches {
            true => Self::Match,
            false => Self::Mismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageReadiness {
    Ready,
    LowSpace,
    NoInodes,
    ReadOnly,
    ProbeFailed,
}

impl StorageReadiness {
    pub(crate) const fn is_ready(self) -> bool {
        match self {
            Self::Ready => true,
            Self::LowSpace | Self::NoInodes | Self::ReadOnly | Self::ProbeFailed => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NarInfoDeletion {
    Deleted,
    Absent,
}

pub(crate) struct OpenedNar<'storage> {
    pub(crate) body: NarReadBody<'storage>,
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

    pub(super) const fn storage(&self) -> &'storage Storage {
        self.storage
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

impl Storage {
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
        let directory = self.nar_temp_directory()?;
        reserve_staging_bytes(&self.staging_budget, &directory, min_free_bytes, bytes)
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

    pub fn publish_nar_with_staging(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
        staging: StagingReservation,
    ) -> Result<PublishOutcome, StorageError> {
        match &self.payloads {
            PayloadStorage::Flat => {
                let receiving = self.begin_upload(name, expected_length, policy, staging)?;
                let complete = receiving.receive(source)?;
                complete.commit()
            }
            PayloadStorage::Chunked(store) => self.publish_chunked_nar_with_staging(
                store,
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
        store: &super::chunk_store::ChunkStore,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
    ) -> Result<PublishOutcome, StorageError> {
        let mut destination = store
            .begin_ingest_with_reservation(
                ChunkProfile::MinCdcHash4V2,
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
        self.publish_ingestion_receipt_for_received_nar(received)?;
        let outcome = completed.outcome();
        completed.release_reservation();
        Ok(outcome)
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
            .bind_to_stored_nar(stored, output)
            .map_err(|_| StorageError::NarMismatch)
    }

    pub(crate) fn nar_matches(&self, narinfo: &ValidatedNarInfo) -> Result<NarMatch, StorageError> {
        if let NarRepresentation::Raw(identity) = narinfo.payload() {
            return self.canonical_nar_matches(identity);
        }
        let representation = narinfo.payload();
        let nar_directory = self.nar_directory()?;
        let payload_name = representation.file_name();
        open_optional_at(&nar_directory, &payload_name.os_string())?.map_or(
            Ok(NarMatch::Missing),
            |file| {
                if file.metadata()?.len() != representation.encoded_size().get() {
                    return Ok(NarMatch::Mismatch);
                }
                self.validated_delivery_identity(payload_name, &file)
                    .map(|identity| match identity == representation.identity() {
                        true => NarMatch::Match,
                        false => NarMatch::Mismatch,
                    })
            },
        )
    }

    fn canonical_nar_matches(&self, identity: NarIdentity) -> Result<NarMatch, StorageError> {
        match &self.payloads {
            PayloadStorage::Chunked(store) => Ok(
                match store
                    .validate_manifest(identity.hash())
                    .map_err(storage_error_for_chunk_store)?
                {
                    None => NarMatch::Missing,
                    Some(manifest) if manifest.identity() == identity => NarMatch::Match,
                    Some(_) => NarMatch::Mismatch,
                },
            ),
            PayloadStorage::Flat => {
                let nar_directory = self.nar_directory()?;
                let name = NarFileName::raw(identity.hash());
                open_optional_at(&nar_directory, &name.os_string())?.map_or(
                    Ok(NarMatch::Missing),
                    |file| {
                        self.validated_delivery_identity(name, &file)
                            .map(|actual| NarMatch::from_content_match(actual == identity))
                    },
                )
            }
        }
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
        match &self.payloads {
            PayloadStorage::Chunked(store) => match store
                .validate_manifest(*nar)
                .map_err(storage_error_for_chunk_store)?
            {
                Some(manifest) if manifest.identity().hash() == *nar => Ok(()),
                Some(_) => Err(StorageError::NarMismatch),
                None => Err(StorageError::MissingNar),
            },
            PayloadStorage::Flat => {
                let nar_directory = self.nar_directory()?;
                let nar_name = NarFileName::raw(*nar);
                match open_regular_at(&nar_directory, &nar_name.os_string()) {
                    Ok(_) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        Err(StorageError::MissingNar)
                    }
                    Err(error) => Err(error.into()),
                }
            }
        }
    }

    pub fn open_nar(&self, name: NarFileName) -> Result<Option<File>, StorageError> {
        let directory = self.nar_directory()?;
        open_optional_at(&directory, &name.os_string())
    }

    pub(crate) fn nar_size(&self, name: NarFileName) -> Result<Option<u64>, StorageError> {
        match (&self.payloads, name.raw_hash()) {
            (PayloadStorage::Chunked(store), Some(hash)) => Ok(store
                .manifest_identity(hash)
                .map_err(storage_error_for_chunk_store)?
                .map(|manifest| manifest.identity().size().get())),
            (PayloadStorage::Flat | PayloadStorage::Chunked(_), None)
            | (PayloadStorage::Flat, Some(_)) => self
                .open_nar(name)?
                .map_or(Ok(None), |file| Ok(Some(file.metadata()?.len()))),
        }
    }

    pub(crate) fn open_nar_range(
        &self,
        name: NarFileName,
        range: std::ops::Range<u64>,
    ) -> Result<Option<OpenedNar<'_>>, StorageError> {
        match (&self.payloads, name.raw_hash()) {
            (PayloadStorage::Chunked(store), Some(hash)) => {
                if store
                    .validate_manifest(hash)
                    .map_err(storage_error_for_chunk_store)?
                    .is_none()
                {
                    return Ok(None);
                }
                let reader = store
                    .open_verified_reader(hash, range, MAX_CHUNK_MANIFEST_BYTES)
                    .map_err(storage_error_for_chunk_store)?;
                Ok(Some(OpenedNar {
                    body: NarReadBody::Chunked(Box::new(reader)),
                }))
            }
            (PayloadStorage::Flat | PayloadStorage::Chunked(_), None)
            | (PayloadStorage::Flat, Some(_)) => self.open_nar(name)?.map_or(Ok(None), |file| {
                self.validated_delivery_identity(name, &file)?;
                Ok(Some(OpenedNar {
                    body: NarReadBody::File(file),
                }))
            }),
        }
    }

    pub(super) fn validated_delivery_identity(
        &self,
        name: NarFileName,
        file: &File,
    ) -> Result<NarIdentity, StorageError> {
        if let Some(identity) = self.delivery_validation.get(name, file)? {
            return Ok(identity);
        }
        let identity = match name.raw_hash() {
            Some(hash) => {
                let identity = NarIdentity::new(hash, file.metadata()?.len().into());
                if !nar_file_matches(file, NarRepresentation::Raw(identity))? {
                    return Err(StorageError::NarMismatch);
                }
                identity
            }
            None => {
                let encoded = EncodedIdentity::new(
                    match name.encoding() {
                        WireEncoding::Compressed(codec) => codec,
                        WireEncoding::Raw => unreachable!("raw names have a raw hash"),
                    },
                    name.file_hash(),
                    file.metadata()?.len().into(),
                );
                compressed_file_identity(file, encoded)?.ok_or(StorageError::NarMismatch)?
            }
        };
        self.delivery_validation.insert(name, file, identity)?;
        Ok(identity)
    }

    pub fn open_narinfo(&self, store: &StoreHash) -> Result<Option<File>, StorageError> {
        let directory = self.root_directory()?;
        let name = format!("{}.narinfo", store.as_str());
        open_optional_at(&directory, OsStr::new(&name))
    }

    pub fn is_ready(&self, min_free_bytes: u64) -> Result<StorageReadiness, StorageError> {
        let directory = self.nar_temp_directory()?;
        let space = filesystem_space(&directory)?;
        Ok(match space.required_capacity(min_free_bytes) {
            Ok(()) => StorageReadiness::Ready,
            Err(StorageError::InsufficientSpace) => StorageReadiness::LowSpace,
            Err(StorageError::InsufficientInodes) => StorageReadiness::NoInodes,
            Err(StorageError::Io(error)) if error.raw_os_error() == Some(libc::EROFS) => {
                StorageReadiness::ReadOnly
            }
            Err(_) => StorageReadiness::ProbeFailed,
        })
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

    pub(crate) fn capacity_and_staging(&self) -> Result<(StorageCapacity, u64), StorageError> {
        let staging = self
            .staging_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let capacity = self.capacity()?;
        Ok((capacity, staging.outstanding_bytes()))
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
        let temporary_path = self.temporary_path(&target, temp_name.clone());
        let mut transaction = self.recovery.begin(
            &temporary_path.relative_path(),
            &destination.relative_path(),
        )?;
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
            let root = self.root_directory()?;
            let destination_directory = destination.path.open_parent(&root)?;
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
                    CreatedDestination::new(
                        location,
                        destination_directory,
                        destination.path.name(),
                    ),
                    temp,
                    transaction,
                    checkpoint,
                    progress,
                )?;
                Ok(PublishOutcome::Created)
            }
            DestinationPublicationAttempt::Repaired(location) => {
                *progress = PublicationProgress::created(location);
                self.durably_finalize_created_destination(
                    CreatedDestination::new(
                        location,
                        destination_directory,
                        destination.path.name(),
                    ),
                    temp,
                    transaction,
                    checkpoint,
                    progress,
                )?;
                self.activity.record_egress_repair();
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
                    destination.path.name(),
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
            destination.path.name(),
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
            destination.path.name(),
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
            destination.path.name(),
            output,
        ) {
            Ok(true) => Ok(DestinationPublicationAttempt::Repaired(
                TemporaryLocation::Destination,
            )),
            Ok(false) => Ok(DestinationPublicationAttempt::Created(
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
    ) -> io::Result<bool> {
        match open_regular_at(destination_directory, destination_name) {
            Ok(file) if encoded_file_matches(&file, output)? => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "egress derivative was published concurrently",
            )),
            Ok(_) => {
                rename_at(
                    &temp.directory,
                    &temp.name,
                    destination_directory,
                    destination_name,
                )?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                rename_at(
                    &temp.directory,
                    &temp.name,
                    destination_directory,
                    destination_name,
                )?;
                Ok(false)
            }
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

    pub(super) fn temporary_path(
        &self,
        target: &PublishTarget<'_>,
        name: OsString,
    ) -> TemporaryPath {
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

    pub(super) fn create_temp_in_directory(
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

    pub(crate) fn root_directory(&self) -> Result<File, StorageError> {
        Ok(self.root.try_clone()?)
    }

    pub(crate) fn nar_directory(&self) -> Result<File, StorageError> {
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

    pub(super) fn destination_key(&self, destination: &PublicationDestination) -> PathBuf {
        destination.path.relative_path()
    }

    fn temporary_directory(&self, directory: TemporaryDirectory) -> Result<File, StorageError> {
        match directory {
            TemporaryDirectory::Root => self.temp_directory(),
            TemporaryDirectory::Nar => self.nar_temp_directory(),
        }
    }

    fn temporary_path_for(directory: TemporaryDirectory, name: OsString) -> TemporaryPath {
        match directory {
            TemporaryDirectory::Root => TemporaryPath::root(name),
            TemporaryDirectory::Nar => TemporaryPath::nar(name),
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

    fn publish_ingestion_receipt_for_received_nar(
        &self,
        received: ReceivedNar,
    ) -> Result<(), StorageError> {
        match received {
            ReceivedNar::Raw(_) => Ok(()),
            ReceivedNar::Compressed(receipt) => self.publish_ingestion_receipt(receipt).map(|_| ()),
        }
    }

    pub(super) fn read_ingestion_receipt(
        &self,
        expectation: CompressedNarIdentity,
    ) -> Result<Option<IngestionReceipt>, StorageError> {
        let directory = self.ingestion_receipt_directory()?;
        let name = IngestionReceipt::file_name_for(expectation);
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
