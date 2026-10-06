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

use rustix::fs::OFlags;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::object::NarHash;
use crate::object::{
    CompressedNarIdentity, EncodedIdentity, NarFileName, NarIdentity, NarRepresentation,
    WireEncoding,
};
use crate::{
    inventory::{Inventory, RecoveryOutcome},
    narinfo::{
        BoundNarInfo, NarInfoClaims, TrustedPublicKeys, ValidatedNarInfo, read_narinfo_file,
    },
    records::{BoundedRegularFile, read_bounded_regular_file},
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
    egress::NarReadBody,
    fs::{
        ImmutableLinkOutcome, StorageCapacity, entry_is_regular_at, filesystem_space,
        link_or_compare_immutable, open_at, open_directory_at, open_optional_at, open_regular_at,
        read_dir_names, remove_temp, rename_at, reserve_staging_bytes, rollback_link_at, unlink_at,
    },
    ids::StoreHash,
    location::{StorePath, TemporaryPath},
    publication::{
        DestinationPublication, NEXT_TEMP, NarUploadPolicy, PublicationDestination,
        PublishBoundary, PublishOutcome, PublishTarget, StagedPublication, StagingReservation,
        StorageError, TemporaryDirectory, TemporaryFile,
    },
    reconcile::{self, ReconcileEntry, ReconcileReport},
    recovery::{PublicationState, PublicationTransaction, RecoveryStatus},
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

#[derive(Clone, Copy)]
enum DestinationPublicationAttempt {
    Existing,
    Created(TemporaryLocation),
    Repaired(TemporaryLocation),
}

impl DestinationPublicationAttempt {
    fn temporary_location(self) -> TemporaryLocation {
        match self {
            Self::Existing => TemporaryLocation::Staging,
            Self::Created(location) | Self::Repaired(location) => location,
        }
    }

    fn record_linked_destination(
        self,
        path: &StorePath,
        transaction: &mut PublicationTransaction,
    ) -> Result<(), StorageError> {
        match self {
            Self::Existing => Ok(()),
            Self::Created(_) | Self::Repaired(_) => {
                transaction.transition(PublicationState::Linked(path.clone()))
            }
        }
    }

    fn rollback_new_link(self, directory: &File, name: &OsStr) -> Result<(), StorageError> {
        match self {
            Self::Existing => Ok(()),
            Self::Created(location) | Self::Repaired(location) => {
                location.rollback_destination_before_durability(directory, name)
            }
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
    pub(super) const fn from_content_match(matches: bool) -> Self {
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
    fn pending(location: TemporaryLocation) -> Self {
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
        let claims = self.claims();
        let bytes = self.output_bytes()?;
        self.stored()
            .storage()
            .publish_narinfo_with_claims(claims, bytes)
    }
}

impl Storage {
    pub(crate) fn publish_narinfo_with_claims(
        &self,
        claims: &NarInfoClaims,
        bytes: Vec<u8>,
    ) -> Result<PublishOutcome, StorageError> {
        match self.publish(PublishTarget::NarInfo(claims.store()), Cursor::new(bytes)) {
            Err(StorageError::Conflict) if self.existing_narinfo_matches(claims)? => {
                Ok(PublishOutcome::Identical)
            }
            result => result,
        }
    }

    fn existing_narinfo_matches(&self, expected: &NarInfoClaims) -> Result<bool, StorageError> {
        let destination = PublishTarget::NarInfo(expected.store()).destination();
        let Some(file) = self.open_durable_destination(&destination)? else {
            return Ok(false);
        };
        let bytes = read_narinfo_file(file)?;
        Ok(expected.matches_external_narinfo(bytes))
    }

    pub fn recovery_required(&self) -> Result<bool, StorageError> {
        self.recovery.required()
    }

    pub fn recovery_required_for(&self) -> Result<bool, StorageError> {
        self.recovery.required_for()
    }

    /// Validates published references and completes pending recovery while this storage lease is held.
    pub fn recover_if_required(
        &self,
        trusted_keys: &TrustedPublicKeys,
        mut report_progress: impl FnMut(crate::inventory::NarInfoCount),
    ) -> Result<RecoveryStatus, StorageError> {
        let status = match self.recovery_required_for()? {
            false => RecoveryStatus::NotRequired,
            true => match Inventory::can_recover(self, trusted_keys, &mut report_progress)? {
                RecoveryOutcome::Ready { checked } => RecoveryStatus::Completed(checked),
                RecoveryOutcome::Invalid { checked, entry } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "published inventory contains an invalid narinfo/NAR pair after checking {checked} entries: {} ({})",
                            entry.identifier(),
                            entry.class().as_str()
                        ),
                    )
                    .into());
                }
            },
        };
        self.finish_recovery()?;
        Ok(status)
    }

    /// Complete recovery and return the capability required for cache mutation.
    pub fn recover_for_mutation(
        &self,
        trusted_keys: &TrustedPublicKeys,
    ) -> Result<RecoveredStorage<'_>, StorageError> {
        let status = self.recover_if_required(trusted_keys, |_| {})?;
        Ok(RecoveredStorage {
            storage: self,
            status,
        })
    }

    /// Cleans abandoned publication state after published references were checked.
    pub fn finish_recovery(&self) -> Result<(), StorageError> {
        self.remove_orphan_validation_evidence()?;
        self.remove_orphan_ingestion_receipts()?;
        self.remove_orphan_egress_receipts()?;
        self.recovery.finish()?;
        if let PayloadStorage::Chunked(chunk_store) = &self.payloads {
            chunk_store.remove_abandoned_temporary_files()?;
        }
        Ok(())
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
        policy.ensure_encoded_size_within_limit(expected_length)?;

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
        policy.ensure_encoded_size_within_limit(expected_length)?;
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
            policy.max_decoded_bytes,
            policy.decoder_memory_limit,
            &mut destination,
        )?;
        let completed = destination
            .finish(received.identity())
            .map_err(storage_error_for_chunk_store)?;
        let identity = received.identity();
        let outcome = completed.outcome();
        self.activity
            .record_upload_validated_logical_bytes(identity.size().get());
        self.activity
            .record_upload_publication(outcome, identity.size().get());
        self.publish_ingestion_receipt_for_received_nar(received)?;
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
                match open_regular_at(&nar_directory, nar_name.os_string()) {
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

    pub(super) fn open_durable_nar(&self, name: NarFileName) -> Result<File, StorageError> {
        let destination = PublishTarget::Nar(name).destination();
        self.open_durable_destination(&destination)?
            .ok_or(StorageError::MissingNar)
    }

    fn open_durable_destination(
        &self,
        destination: &PublicationDestination,
    ) -> Result<Option<File>, StorageError> {
        self.open_destination_with_directory_sync(destination, File::sync_all)
    }

    fn open_destination_with_directory_sync(
        &self,
        destination: &PublicationDestination,
        sync_directory: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<Option<File>, StorageError> {
        self.with_destination_lock(destination, || {
            let root = self.root_directory()?;
            let directory = destination.path.open_parent(&root)?;
            let file = open_optional_at(&directory, destination.path.name())?;
            // A visible entry may be left by an interrupted publication. Wait
            // for its publisher and complete the barrier before binding it.
            if file.is_some() {
                sync_directory(&directory)?;
            }
            Ok(file)
        })
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

    pub(crate) fn ensure_canonical_nar_available(
        &self,
        identity: NarIdentity,
    ) -> Result<(), StorageError> {
        match &self.payloads {
            PayloadStorage::Chunked(store) => store
                .check_nar_availability(identity)
                .map_err(storage_error_for_chunk_store),
            PayloadStorage::Flat => {
                let name = NarFileName::raw(identity.hash());
                let file = self.open_nar(name)?.ok_or(StorageError::MissingNar)?;
                if file.metadata()?.len() != identity.size().get() {
                    return Err(StorageError::NarMismatch);
                }
                Ok(())
            }
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
            Err(StorageError::Io(error))
                if error.raw_os_error() == Some(rustix::io::Errno::ROFS.raw_os_error()) =>
            {
                StorageReadiness::ReadOnly
            }
            Err(_) => StorageReadiness::ProbeFailed,
        })
    }

    pub(crate) fn capacity(&self) -> Result<StorageCapacity, StorageError> {
        let directory = self.nar_directory()?;
        Ok(filesystem_space(&directory)?)
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
        destination.validate_path()?;
        let temp_name = self.next_temp_name(&target);
        let temporary_path = self.temporary_path(&target, temp_name.clone());
        let mut transaction = self.recovery.begin(&temporary_path.relative_path())?;
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
        let attempt = self.place_temporary_at_destination_or_resolve_existing(
            destination,
            destination_directory,
            temp,
        )?;
        *progress = PublicationProgress::pending(attempt.temporary_location());
        let barrier = (|| {
            attempt
                .temporary_location()
                .synchronize_source_directory_after_destination_creation(temp)?;
            attempt.record_linked_destination(&destination.path, transaction)?;
            checkpoint(PublishBoundary::BeforeParentSync)?;
            destination_directory.sync_all()?;
            Ok::<_, StorageError>(())
        })();
        if let Err(error) = barrier {
            attempt.rollback_new_link(destination_directory, destination.path.name())?;
            return Err(error);
        }
        // The destination is durable even if recording that fact fails. Never
        // roll it back because of a later journal or response failure.
        progress.mark_durable();
        transaction.transition(PublicationState::Published(destination.path.clone()))?;
        checkpoint(PublishBoundary::AfterParentSync)?;
        match attempt {
            DestinationPublicationAttempt::Existing => Ok(PublishOutcome::Identical),
            DestinationPublicationAttempt::Created(_) => Ok(PublishOutcome::Created),
            DestinationPublicationAttempt::Repaired(_) => {
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
        match link_or_compare_immutable(
            &temp.directory,
            &temp.name,
            destination_directory,
            destination.path.name(),
        )? {
            ImmutableLinkOutcome::Created => Ok(DestinationPublicationAttempt::Created(
                TemporaryLocation::Staging,
            )),
            ImmutableLinkOutcome::Identical => Ok(DestinationPublicationAttempt::Existing),
            ImmutableLinkOutcome::Collision => Err(StorageError::Conflict),
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
        let temporary = self.create_temp_named_owned(target, name)?;
        temporary
            .file()
            .file
            .set_permissions(Permissions::from_mode(0o600))?;
        Ok(temporary.into_file())
    }

    pub(super) fn create_temp_named_owned(
        &self,
        target: &PublishTarget<'_>,
        name: OsString,
    ) -> Result<OwnedTemporary<'_>, StorageError> {
        let directory = self.temporary_directory(target.destination().temporary_directory)?;
        self.create_temp_in_directory_owned(directory, name)
    }

    pub(super) fn create_temp_in_directory(
        &self,
        directory: File,
        name: OsString,
    ) -> Result<TemporaryFile, StorageError> {
        let temporary = self.create_temp_in_directory_owned(directory, name)?;
        temporary
            .file()
            .file
            .set_permissions(Permissions::from_mode(0o600))?;
        Ok(temporary.into_file())
    }

    fn create_temp_in_directory_owned(
        &self,
        directory: File,
        name: OsString,
    ) -> Result<OwnedTemporary<'_>, StorageError> {
        let file = open_at(
            &directory,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            0o600,
        )?;
        self.temporary_objects.fetch_add(1, Ordering::Relaxed);
        Ok(OwnedTemporary::new(
            self,
            TemporaryFile {
                name,
                directory,
                file,
            },
        ))
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
                    NarMatch::Match => Ok(CleanupAction::Keep),
                    NarMatch::Missing | NarMatch::Mismatch => {
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

/// A storage lease whose pending recovery has been validated and completed.
pub struct RecoveredStorage<'storage> {
    storage: &'storage Storage,
    status: RecoveryStatus,
}

impl RecoveredStorage<'_> {
    pub const fn storage(&self) -> &Storage {
        self.storage
    }

    pub const fn recovery_status(&self) -> RecoveryStatus {
        self.status
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    use crate::storage::{CacheCreation, Directory, SupportedStorageBackend};

    #[test]
    fn existing_object_acquisition_requires_directory_sync_under_its_publication_lock() {
        let directory = tempfile::tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .unwrap()
            .create_or_complete()
            .unwrap();
        let store = StoreHash::parse("00000000000000000000000000000000").unwrap();
        let nar = NarHash::from_digest([0; 32]);
        for target in [
            PublishTarget::Nar(NarFileName::raw(nar)),
            PublishTarget::NarInfo(&store),
        ] {
            let destination = target.destination();
            storage
                .publish(target, Cursor::new(b"stored bytes"))
                .unwrap();
            let lock = storage.destination_lock(storage.destination_key(&destination));
            let result = storage.open_destination_with_directory_sync(&destination, |_| {
                assert!(matches!(
                    lock.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                Err(io::Error::other(
                    "injected acquisition directory sync failure",
                ))
            });
            assert!(matches!(result, Err(StorageError::Io(error))
                if error.to_string() == "injected acquisition directory sync failure"));
            assert!(
                storage
                    .open_durable_destination(&destination)
                    .unwrap()
                    .is_some()
            );
        }
    }
}
