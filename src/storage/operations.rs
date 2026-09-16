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

use crate::narinfo::{CompressedNarExpectation, NarEncoding, ValidatedNarInfo, ValidatedPayload};
use crate::object::{FileHash, NarFileName, NarHash, NarIdentity};

use super::{
    compression::{
        CheckedUploadReader, EncodedUploadExpectation, IngestionReceipt, RawStagingWriter,
        finish_checked_upload, ingestion_receipt_file_name, nar_file_size_matches,
        write_uploaded_representation_as_raw_nar,
    },
    directory::Directory,
    fs::{
        StorageCapacity, directory_is_empty, ensure_directory_at, entry_is_regular_at,
        files_equal_at, filesystem_space, hard_link_at, open_at, open_directory_at,
        open_optional_at, open_regular_at, read_dir_names, remove_temp, rename_at,
        reserve_staging_bytes, rollback_link_at, unlink_at,
    },
    ids::StoreHash,
    publication::{
        NEXT_TEMP, NarUploadPolicy, ProcessLock, PublishBoundary, PublishOutcome, PublishTarget,
        PublishedPair, StagingReservation, StorageError, TemporaryFile,
    },
    reconcile::{self, ReconcileEntry, ReconcileReport},
    recovery::{PublicationState, PublicationTransaction, RecoveryState},
    state::Storage,
};

#[cfg(test)]
use super::publication::{Layout, injected_fault};

const MAX_CACHE_INFO_BYTES: u64 = 1024;
pub(super) const VALIDATION_DIRECTORY: &str = ".narjar-validation";
pub(super) const INGESTION_RECEIPT_DIRECTORY: &str = ".narjar-ingress";
pub(super) const MAX_INGESTION_RECEIPT_BYTES: u64 = 256;

struct CompletedRawNarStaging {
    temporary: TemporaryFile,
    transaction: PublicationTransaction,
    receipt: IngestionReceipt,
}

impl CompletedRawNarStaging {
    fn raw_nar_identity(&self) -> NarIdentity {
        self.receipt.decoded_identity()
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
    let mut store_dir = false;
    let mut mass_query = false;
    let mut priority = false;
    for line in text.lines() {
        let (name, value) = line.split_once(": ").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed nix-cache-info")
        })?;
        match name {
            "StoreDir" if !store_dir && value == "/nix/store" => store_dir = true,
            "WantMassQuery" if !mass_query && value == "0" => mass_query = true,
            "Priority" if !priority && value.parse::<u32>().is_ok() => priority = true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported or duplicate nix-cache-info field",
                ));
            }
        }
    }
    if store_dir && mass_query && priority {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nix-cache-info is missing a required field",
        ))
    }
}

impl Storage {
    pub fn initialize(root: &Directory) -> Result<Self, StorageError> {
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
            ensure_directory_at(&root_directory, OsStr::new("nar"), "nar directory")?;
        ensure_directory_at(
            &nar_directory,
            OsStr::new(".tmp"),
            "NAR temporary directory",
        )?;
        ensure_directory_at(&root_directory, OsStr::new(".tmp"), "temporary directory")?;
        let transactions = ensure_directory_at(
            &root_directory,
            OsStr::new(".narjar-transactions"),
            "publication transaction directory",
        )?;
        transactions.set_permissions(Permissions::from_mode(0o700))?;
        let realisations_directory = ensure_directory_at(
            &root_directory,
            OsStr::new("realisations"),
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

        root_directory.sync_all()?;

        let recovery = RecoveryState::new(&root_directory)?;
        let storage = Self {
            #[cfg(test)]
            layout,
            root: root_directory,
            recovery,
            publication_locks: Mutex::new(HashMap::new()),
            staging_reservations: Arc::new(AtomicU64::new(0)),
            temporary_objects: AtomicU64::new(0),
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
        self.recovery.finish()
    }

    pub fn reserve_staging(
        &self,
        bytes: u64,
        min_free_bytes: u64,
    ) -> Result<StagingReservation, StorageError> {
        if bytes == 0 {
            return Ok(StagingReservation::empty(Arc::clone(
                &self.staging_reservations,
            )));
        }
        let directory = self.nar_temp_directory()?;
        let space = filesystem_space(&directory)?;
        let required_bytes = bytes
            .checked_add(min_free_bytes)
            .ok_or(StorageError::InsufficientSpace)?;
        space.required_capacity(required_bytes)?;
        reserve_staging_bytes(
            &self.staging_reservations,
            space.available_bytes,
            min_free_bytes,
            bytes,
        )
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
        mut staging: StagingReservation,
    ) -> Result<PublishOutcome, StorageError> {
        if expected_length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }

        match name.encoding() {
            NarEncoding::Raw => self.publish_raw_nar_upload(name, source, expected_length),
            NarEncoding::Xz | NarEncoding::Zstd => self.publish_compressed_nar_upload_as_raw(
                name,
                source,
                expected_length,
                policy,
                &mut staging,
            ),
        }
    }

    fn publish_raw_nar_upload(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
    ) -> Result<PublishOutcome, StorageError> {
        let file_hash = name.file_hash();
        self.publish_with_admission(
            PublishTarget::Nar(name),
            CheckedUploadReader::new(source, &file_hash, expected_length),
            || Ok(()),
            |_| Ok(()),
            |input| finish_checked_upload(input).map_err(StorageError::from),
        )
    }

    fn publish_compressed_nar_upload_as_raw(
        &self,
        encoded_name: NarFileName,
        source: impl Read,
        encoded_size: u64,
        policy: NarUploadPolicy,
        staging: &mut StagingReservation,
    ) -> Result<PublishOutcome, StorageError> {
        let staging = self.stage_compressed_upload_as_raw_nar(
            encoded_name,
            source,
            encoded_size,
            policy,
            staging,
        )?;
        let raw_identity = staging.raw_nar_identity();
        let CompletedRawNarStaging {
            temporary,
            transaction,
            receipt,
        } = staging;

        let outcome = self.commit_temporary(
            PublishTarget::Nar(NarFileName::raw(raw_identity.hash())),
            temporary,
            transaction,
            |_| Ok(()),
        )?;
        self.publish_ingestion_receipt(receipt)?;
        Ok(outcome)
    }

    fn stage_compressed_upload_as_raw_nar(
        &self,
        encoded_name: NarFileName,
        source: impl Read,
        encoded_size: u64,
        policy: NarUploadPolicy,
        staging: &mut StagingReservation,
    ) -> Result<CompletedRawNarStaging, StorageError> {
        let staging_target = PublishTarget::Nar(encoded_name);
        let temp_name = self.next_temp_name(&staging_target);
        let temporary_path = self.temporary_path(&staging_target, &temp_name);
        let mut transaction = self.recovery.begin(&temporary_path)?;
        let mut temp = self.create_temp_named(&staging_target, temp_name)?;

        let expectation = EncodedUploadExpectation {
            expected_file_hash: &encoded_name.file_hash(),
            expected_file_size: encoded_size.into(),
            max_nar_size: policy.max_bytes,
        };
        let receipt = match Self::write_and_validate_compressed_upload(
            source,
            encoded_name.encoding(),
            expectation,
            policy.min_free_bytes,
            staging,
            &mut temp,
            &mut transaction,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = self.remove_temp(&temp);
                return Err(error);
            }
        };

        Ok(CompletedRawNarStaging {
            temporary: temp,
            transaction,
            receipt,
        })
    }

    fn write_and_validate_compressed_upload(
        source: impl Read,
        encoding: NarEncoding,
        expectation: EncodedUploadExpectation<'_>,
        min_free_bytes: u64,
        staging: &mut StagingReservation,
        temporary: &mut TemporaryFile,
        transaction: &mut PublicationTransaction,
    ) -> Result<IngestionReceipt, StorageError> {
        transaction.transition(PublicationState::Streaming)?;
        let decoded = {
            let mut destination =
                RawStagingWriter::new(&mut temporary.file, staging, min_free_bytes);
            write_uploaded_representation_as_raw_nar(
                source,
                encoding,
                expectation,
                &mut destination,
            )?
        };
        temporary.file.sync_all()?;
        transaction.transition(PublicationState::Validated)?;
        Ok(IngestionReceipt::from_decoded(
            encoding,
            *expectation.expected_file_hash,
            expectation.expected_file_size,
            decoded,
        ))
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

    pub fn publish_narinfo(
        &self,
        store: &StoreHash,
        narinfo: ValidatedNarInfo,
    ) -> Result<PublishOutcome, StorageError> {
        let expected = narinfo.payload();
        let raw_narinfo = narinfo.into_raw_narinfo();
        let raw_identity = self.resolve_raw_identity_for_narinfo(expected)?;
        if raw_identity != raw_narinfo.identity() {
            return Err(StorageError::NarMismatch);
        }
        let Some(file) = self.open_nar(raw_identity.hash())? else {
            return Err(StorageError::MissingNar);
        };
        if !nar_file_size_matches(&file, raw_identity.size().get())? {
            return Err(StorageError::NarMismatch);
        }
        self.publish(
            PublishTarget::NarInfo(store),
            Cursor::new(raw_narinfo.into_bytes()),
        )
    }

    fn resolve_raw_identity_for_narinfo(
        &self,
        expectation: ValidatedPayload,
    ) -> Result<NarIdentity, StorageError> {
        match expectation {
            ValidatedPayload::Raw(identity) => Ok(identity),
            ValidatedPayload::Compressed(expectation) => {
                self.resolve_raw_identity_from_ingestion_receipt(expectation)
            }
        }
    }

    fn resolve_raw_identity_from_ingestion_receipt(
        &self,
        expectation: CompressedNarExpectation,
    ) -> Result<NarIdentity, StorageError> {
        let Some(receipt) = self.read_ingestion_receipt(expectation)? else {
            return Err(StorageError::NarMismatch);
        };
        Ok(receipt.decoded_identity())
    }

    pub(crate) fn nar_matches(&self, narinfo: &ValidatedNarInfo) -> Result<bool, StorageError> {
        let nar_directory = self.nar_directory()?;
        let payload_name = narinfo.payload_name();
        let Some(file) = open_optional_at(&nar_directory, &payload_name.os_string())? else {
            return Ok(false);
        };
        nar_file_size_matches(&file, narinfo.file_size().get()).map_err(Into::into)
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
        let Some(narinfo) = self.open_narinfo(store)? else {
            return Ok(None);
        };
        let Some(nar) = self.open_nar(nar)? else {
            return Ok(None);
        };

        Ok(Some(PublishedPair { nar, narinfo }))
    }

    pub fn is_ready(&self, min_free_bytes: u64) -> Result<bool, StorageError> {
        let directory = self.nar_temp_directory()?;
        Ok(filesystem_space(&directory)?
            .required_capacity(min_free_bytes)
            .is_ok())
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

    pub fn cleanup_stale_temp(&self, entry: &ReconcileEntry) -> Result<bool, StorageError> {
        reconcile::cleanup_stale_temp(self, entry)
    }

    pub fn delete_narinfo(&self, store: &StoreHash) -> Result<bool, StorageError> {
        let root = self.root_directory()?;
        let name = OsString::from(format!("{}.narinfo", store.as_str()));
        match entry_is_regular_at(&root, &name) {
            Ok(true) => {
                unlink_at(&root, &name)?;
                root.sync_all()?;
                Ok(true)
            }
            Ok(false) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "narinfo is not a regular file",
            )
            .into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
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

    pub(super) fn publish_with(
        &self,
        target: PublishTarget<'_>,
        source: impl Read,
        checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with_admission(target, source, || Ok(()), checkpoint, |_| Ok(()))
    }

    pub(super) fn publish_with_admission<R: Read>(
        &self,
        target: PublishTarget<'_>,
        mut source: R,
        admit: impl FnOnce() -> Result<(), StorageError>,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
        finish_source: impl FnOnce(R) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        admit()?;
        let temp_name = self.next_temp_name(&target);
        let temporary_path = self.temporary_path(&target, &temp_name);
        let mut transaction = Some(self.recovery.begin(&temporary_path)?);
        checkpoint(PublishBoundary::BeforeTempCreate)?;
        let mut temp = Some(self.create_temp_named(&target, temp_name)?);
        transaction
            .as_mut()
            .expect("publication transaction exists")
            .transition(PublicationState::Streaming)?;
        let staging = (|| {
            checkpoint(PublishBoundary::AfterTempCreate)?;
            io::copy(
                &mut source,
                &mut temp.as_mut().expect("temporary file exists").file,
            )?;
            finish_source(source)?;
            checkpoint(PublishBoundary::AfterStream)?;
            temp.as_ref()
                .expect("temporary file exists")
                .file
                .sync_all()?;
            checkpoint(PublishBoundary::AfterTempSync)?;
            transaction
                .as_mut()
                .expect("publication transaction exists")
                .transition(PublicationState::Validated)
        })();

        if let Err(error) = staging {
            if let Some(temp) = temp {
                let _ = self.remove_temp(&temp);
            }
            return Err(error);
        }

        self.commit_temporary(
            target,
            temp.take().expect("temporary file exists"),
            transaction.take().expect("publication transaction exists"),
            checkpoint,
        )
    }

    fn commit_temporary(
        &self,
        target: PublishTarget<'_>,
        temp: TemporaryFile,
        mut transaction: PublicationTransaction,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        let destination_directory = self.destination_directory(&target)?;
        let destination_name = target.destination_name();
        let destination_key = self.destination_key(&target, &destination_name);
        let replace_destination = target.replaces_destination();
        let mut durable = false;
        let mut temp_moved = false;
        let result = (|| {
            checkpoint(PublishBoundary::BeforeFinalLink)?;
            let mut finalize_publication = |publish_result: io::Result<()>| match publish_result {
                Ok(()) => {
                    if replace_destination {
                        temp_moved = true;
                        temp.directory.sync_all()?;
                    }
                    transaction.transition(PublicationState::Linked)?;
                    if let Err(error) = checkpoint(PublishBoundary::BeforeParentSync) {
                        if !replace_destination {
                            rollback_link_at(&destination_directory, &destination_name)?;
                        }
                        return Err(error);
                    }
                    if let Err(error) = destination_directory.sync_all() {
                        if !replace_destination {
                            rollback_link_at(&destination_directory, &destination_name)?;
                        }
                        return Err(error.into());
                    }
                    durable = true;
                    transaction.transition(PublicationState::Published)?;
                    checkpoint(PublishBoundary::AfterParentSync)?;
                    Ok(PublishOutcome::Created)
                }
                Err(error)
                    if !replace_destination && error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    if files_equal_at(
                        &temp.directory,
                        &temp.name,
                        &destination_directory,
                        &destination_name,
                    )? {
                        transaction.transition(PublicationState::Published)?;
                        Ok(PublishOutcome::Identical)
                    } else {
                        Err(StorageError::Conflict)
                    }
                }
                Err(error) => Err(error.into()),
            };
            if replace_destination {
                finalize_publication(rename_at(
                    &temp.directory,
                    &temp.name,
                    &destination_directory,
                    &destination_name,
                ))
            } else {
                let destination_lock = self.destination_lock(destination_key);
                let _destination_guard = destination_lock
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                finalize_publication(hard_link_at(
                    &temp.directory,
                    &temp.name,
                    &destination_directory,
                    &destination_name,
                ))
            }
        })();

        let cleanup = if temp_moved {
            self.temporary_objects.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.remove_temp(&temp)
        };

        match result {
            Ok(outcome) => {
                cleanup?;
                transaction.complete()?;
                Ok(outcome)
            }
            Err(error) => {
                if durable {
                    cleanup?;
                    transaction.complete()?;
                } else {
                    let _ = cleanup;
                }
                Err(error)
            }
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
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        OsString::from(format!(
            "{}-{}-{sequence:016x}.part",
            target.temp_prefix(),
            process::id()
        ))
    }

    pub(super) fn temporary_path(&self, target: &PublishTarget<'_>, name: &OsStr) -> PathBuf {
        match target {
            PublishTarget::Nar(_) => PathBuf::from("nar/.tmp").join(name),
            PublishTarget::CacheInfo
            | PublishTarget::NarInfo(_)
            | PublishTarget::IngestionReceipt(_) => PathBuf::from(".tmp").join(name),
        }
    }

    pub(super) fn create_temp_named(
        &self,
        target: &PublishTarget<'_>,
        name: OsString,
    ) -> Result<TemporaryFile, StorageError> {
        let directory = match target {
            PublishTarget::Nar(_) => self.nar_temp_directory()?,
            PublishTarget::CacheInfo
            | PublishTarget::NarInfo(_)
            | PublishTarget::IngestionReceipt(_) => self.temp_directory()?,
        };
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
        target: &PublishTarget<'_>,
    ) -> Result<File, StorageError> {
        match target {
            PublishTarget::Nar(_) => self.nar_directory(),
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) => self.root_directory(),
            PublishTarget::IngestionReceipt(_) => self.ingestion_receipt_directory(),
        }
    }

    pub(super) fn destination_key(&self, target: &PublishTarget<'_>, name: &OsStr) -> PathBuf {
        match target {
            PublishTarget::Nar(_) => PathBuf::from("nar").join(name),
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) => PathBuf::from(name),
            PublishTarget::IngestionReceipt(_) => {
                PathBuf::from(INGESTION_RECEIPT_DIRECTORY).join(name)
            }
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
        let file = match open_regular_at(&directory, &name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_INGESTION_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_INGESTION_RECEIPT_BYTES {
            return Ok(None);
        }
        Ok(IngestionReceipt::parse(&bytes).filter(|receipt| receipt.matches(expectation)))
    }

    pub(super) fn remove_orphan_validation_evidence(&self) -> Result<(), StorageError> {
        let validation = self.validation_directory()?;
        let nar = self.nar_directory()?;
        let mut removed = false;
        for name in read_dir_names(&validation)? {
            let Some(evidence_name) = name.to_str() else {
                continue;
            };
            let Some(nar_name) = evidence_name.strip_suffix(".validation") else {
                continue;
            };
            if !nar_name.ends_with(".nar.xz") && !nar_name.ends_with(".nar.zst") {
                continue;
            }
            if FileHash::parse(
                nar_name
                    .strip_suffix(".nar.xz")
                    .or_else(|| nar_name.strip_suffix(".nar.zst"))
                    .unwrap_or_default(),
            )
            .is_err()
            {
                continue;
            }
            match entry_is_regular_at(&nar, OsStr::new(nar_name)) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            unlink_at(&validation, &name)?;
            removed = true;
        }
        if removed {
            validation.sync_all()?;
        }
        Ok(())
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
