use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read},
    sync::{Arc, Mutex, atomic::AtomicU64},
};

use super::{
    capacity::{StorageCapacity, filesystem_space},
    collection::{ActivityLease, CollectionLease},
    operations::OwnedTemporary,
    recovery::{PublicationState, PublicationTransaction},
    state::Storage,
    typestate::{Streaming, Validated},
};

mod target;
#[cfg(test)]
pub(super) use target::Layout;
pub(super) use target::{
    DestinationPublication, PublicationDestination, PublishTarget, TemporaryDirectory,
};

#[derive(Debug)]
pub(super) struct TemporaryFile {
    pub(super) name: OsString,
    pub(super) directory: File,
    pub(super) file: File,
}

pub(super) struct OwnedPublication<'storage> {
    temporary: Option<OwnedTemporary<'storage>>,
    transaction: Option<PublicationTransaction>,
}

impl<'storage> OwnedPublication<'storage> {
    pub(super) fn new(
        temporary: OwnedTemporary<'storage>,
        transaction: PublicationTransaction,
    ) -> Self {
        Self {
            temporary: Some(temporary),
            transaction: Some(transaction),
        }
    }

    pub(super) fn temporary(&self) -> &OwnedTemporary<'storage> {
        self.temporary
            .as_ref()
            .expect("owned publication temporary is present")
    }

    pub(super) fn temporary_mut(&mut self) -> &mut OwnedTemporary<'storage> {
        self.temporary
            .as_mut()
            .expect("owned publication temporary is present")
    }

    pub(super) fn transaction_mut(&mut self) -> &mut PublicationTransaction {
        self.transaction
            .as_mut()
            .expect("owned publication transaction is present")
    }

    pub(super) fn into_parts(mut self) -> (OwnedTemporary<'storage>, PublicationTransaction) {
        (
            self.temporary
                .take()
                .expect("owned publication temporary is present"),
            self.transaction
                .take()
                .expect("owned publication transaction is present"),
        )
    }
}

impl Drop for OwnedPublication<'_> {
    fn drop(&mut self) {
        let Some(transaction) = self.transaction.take() else {
            return;
        };
        let temporary_cleaned = match self.temporary.as_mut() {
            Some(temporary) => temporary.cleanup().is_ok(),
            None => true,
        };
        if temporary_cleaned {
            transaction.cancel();
        } else {
            drop(transaction);
        }
    }
}

pub(super) enum PublicationActivity<'storage> {
    Operation {
        _lease: ActivityLease<'storage>,
    },
    Collection {
        _lease: &'storage CollectionLease<'storage>,
    },
}

pub(super) struct StagedPublication<'storage, Checkpoint, State> {
    pub(super) storage: &'storage Storage,
    pub(super) destination: PublicationDestination,
    publication: OwnedPublication<'storage>,
    checkpoint: Checkpoint,
    _state: State,
    _activity: PublicationActivity<'storage>,
}

impl<'storage, Checkpoint> StagedPublication<'storage, Checkpoint, Streaming> {
    pub(super) fn from_parts(
        storage: &'storage Storage,
        destination: PublicationDestination,
        publication: OwnedPublication<'storage>,
        checkpoint: Checkpoint,
        activity: PublicationActivity<'storage>,
    ) -> Self {
        Self {
            storage,
            destination,
            publication,
            checkpoint,
            _state: Streaming::new(()),
            _activity: activity,
        }
    }
}

impl<'storage, Checkpoint> StagedPublication<'storage, Checkpoint, Streaming>
where
    Checkpoint: FnMut(PublishBoundary) -> Result<(), StorageError>,
{
    pub(super) fn finish_and_sync(
        mut self,
        mut source: impl Read,
    ) -> Result<StagedPublication<'storage, Checkpoint, Validated>, StorageError> {
        (self.checkpoint)(PublishBoundary::AfterTempCreate)?;
        io::copy(&mut source, self.publication.temporary_mut().file_mut())?;
        (self.checkpoint)(PublishBoundary::AfterStream)?;
        self.publication.temporary().file().file.sync_all()?;
        (self.checkpoint)(PublishBoundary::AfterTempSync)?;
        self.publication
            .transaction_mut()
            .transition(PublicationState::Validated)?;

        let Self {
            storage,
            destination,
            publication,
            checkpoint,
            _state: _,
            _activity,
        } = self;
        Ok(StagedPublication {
            storage,
            destination,
            publication,
            checkpoint,
            _state: Validated::new(()),
            _activity,
        })
    }
}

impl<'storage, Checkpoint> StagedPublication<'storage, Checkpoint, Validated>
where
    Checkpoint: FnMut(PublishBoundary) -> Result<(), StorageError>,
{
    pub(super) fn commit(self) -> Result<PublishOutcome, StorageError> {
        let Self {
            storage,
            destination,
            publication,
            checkpoint,
            _state: _,
            _activity,
        } = self;
        let (temporary, transaction) = publication.into_parts();
        let temporary = temporary.into_file();
        storage.commit_temporary_with_activity(
            destination,
            &temporary,
            transaction,
            checkpoint,
            _activity,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublishBoundary {
    BeforeTempCreate,
    AfterTempCreate,
    AfterStream,
    AfterTempSync,
    BeforeFinalLink,
    BeforeParentSync,
    AfterParentSync,
    AfterNarPublication,
}

#[cfg(test)]
pub(super) fn injected_fault(
    boundary: PublishBoundary,
    fault: PublishBoundary,
) -> Result<(), StorageError> {
    if boundary == fault {
        Err(io::Error::other(format!("injected fault at {boundary:?}")).into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderMemoryLimit(u64);

impl DecoderMemoryLimit {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NarUploadPolicy {
    pub(super) max_encoded_bytes: u64,
    pub(super) max_decoded_bytes: u64,
    pub(super) decoder_memory_limit: DecoderMemoryLimit,
    pub(super) min_free_bytes: u64,
}

impl NarUploadPolicy {
    #[cfg(test)]
    pub const DEFAULT_MAX_DECODER_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

    #[cfg(test)]
    pub const fn new(max_bytes: u64, min_free_bytes: u64) -> Self {
        Self {
            max_encoded_bytes: max_bytes,
            max_decoded_bytes: max_bytes,
            decoder_memory_limit: DecoderMemoryLimit::new(Self::DEFAULT_MAX_DECODER_MEMORY_BYTES),
            min_free_bytes,
        }
    }

    /// Construct upload policy with separate encoded, decoded, and decoder-memory limits.
    pub const fn with_limits(
        max_encoded_bytes: u64,
        max_decoded_bytes: u64,
        max_decoder_memory_bytes: u64,
        min_free_bytes: u64,
    ) -> Self {
        Self {
            max_encoded_bytes,
            max_decoded_bytes,
            decoder_memory_limit: DecoderMemoryLimit::new(max_decoder_memory_bytes),
            min_free_bytes,
        }
    }

    pub(crate) fn ensure_encoded_size_within_limit(
        self,
        encoded_bytes: u64,
    ) -> Result<(), StorageError> {
        if encoded_bytes > self.max_encoded_bytes {
            return Err(StorageError::UploadTooLarge);
        }
        Ok(())
    }

    pub const fn min_free_bytes(self) -> u64 {
        self.min_free_bytes
    }

    pub(crate) fn ensure_decoded_size_within_limit(
        self,
        size: crate::cache::object::NarSize,
    ) -> Result<(), StorageError> {
        if size.get() > self.max_decoded_bytes {
            return Err(StorageError::UploadTooLarge);
        }
        Ok(())
    }

    pub(crate) const fn bounded_by_nar_size(
        self,
        identity: crate::cache::object::NarIdentity,
    ) -> Self {
        Self {
            max_decoded_bytes: if self.max_decoded_bytes < identity.size().get() {
                self.max_decoded_bytes
            } else {
                identity.size().get()
            },
            ..self
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct StagingBudget {
    outstanding_bytes: u64,
    outstanding_inodes: u64,
}

impl StagingBudget {
    pub(super) fn reserve(
        &mut self,
        space: StorageCapacity,
        min_free_bytes: u64,
        bytes: u64,
    ) -> Result<(), StorageError> {
        let total = self
            .outstanding_bytes
            .checked_add(bytes)
            .ok_or(StorageError::InsufficientSpace)?;
        let required = total
            .checked_add(min_free_bytes)
            .ok_or(StorageError::InsufficientSpace)?;
        space.required_capacity(required)?;
        self.outstanding_bytes = total;
        Ok(())
    }

    fn release(&mut self, bytes: u64) {
        self.outstanding_bytes = self.outstanding_bytes.saturating_sub(bytes);
    }

    pub(super) const fn outstanding_bytes(&self) -> u64 {
        self.outstanding_bytes
    }

    pub(super) fn reserve_inodes(
        &mut self,
        capacity: super::capacity::StorageCapacity,
        requested: u64,
    ) -> Result<u64, StorageError> {
        match capacity.inodes {
            super::capacity::InodeCapacity::Measured { available, .. } => {
                let total = self
                    .outstanding_inodes
                    .checked_add(requested)
                    .ok_or(StorageError::InsufficientInodes)?;
                if total > available {
                    return Err(StorageError::InsufficientInodes);
                }
                self.outstanding_inodes = total;
                Ok(requested)
            }
            super::capacity::InodeCapacity::NotReported => Ok(0),
        }
    }

    fn release_inodes(&mut self, slots: u64) {
        self.outstanding_inodes = self.outstanding_inodes.saturating_sub(slots);
    }
}

pub(crate) struct StagingInodeReservation {
    budget: Arc<Mutex<StagingBudget>>,
    slots: u64,
}

impl StagingInodeReservation {
    pub(super) fn reserve(
        budget: &Arc<Mutex<StagingBudget>>,
        directory: &File,
        slots: u64,
    ) -> Result<Self, StorageError> {
        Self::reserve_with_measurement(budget, slots, || {
            super::capacity::filesystem_space(directory)
        })
    }

    fn reserve_with_measurement(
        budget: &Arc<Mutex<StagingBudget>>,
        slots: u64,
        measure: impl FnOnce() -> io::Result<super::capacity::StorageCapacity>,
    ) -> Result<Self, StorageError> {
        let mut budget_guard = budget
            .lock()
            .map_err(|_| StorageError::Io(io::Error::other("staging budget lock poisoned")))?;
        let capacity = measure()?;
        let slots = budget_guard.reserve_inodes(capacity, slots)?;
        Ok(Self {
            budget: Arc::clone(budget),
            slots,
        })
    }

    #[cfg(test)]
    pub(super) fn reserve_for_test(
        budget: &Arc<Mutex<StagingBudget>>,
        slots: u64,
        measure: impl FnOnce() -> io::Result<super::capacity::StorageCapacity>,
    ) -> Result<Self, StorageError> {
        Self::reserve_with_measurement(budget, slots, measure)
    }

    pub(super) fn record_created_staging_entries(&mut self, count: u64) {
        let released = count.min(self.slots);
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        budget.release_inodes(released);
        self.slots -= released;
    }
}

impl Drop for StagingInodeReservation {
    fn drop(&mut self) {
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        budget.release_inodes(self.slots);
    }
}

#[derive(Debug)]
pub struct StagingReservation {
    pub(super) budget: Arc<Mutex<StagingBudget>>,
    pub(super) bytes: u64,
}

impl StagingReservation {
    #[cfg(test)]
    pub(super) fn empty(budget: Arc<Mutex<StagingBudget>>) -> Self {
        Self { budget, bytes: 0 }
    }

    pub(super) fn grow_to(
        &mut self,
        directory: &File,
        min_free_bytes: u64,
        required_bytes: u64,
    ) -> Result<(), StorageError> {
        let additional = required_bytes.saturating_sub(self.bytes);
        if additional == 0 {
            return Ok(());
        }
        let new_bytes = self
            .bytes
            .checked_add(additional)
            .ok_or_else(|| io::Error::other("staging reservation size overflow"))?;
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| StorageError::Io(io::Error::other("staging budget lock poisoned")))?;
        budget.reserve(filesystem_space(directory)?, min_free_bytes, additional)?;
        self.bytes = new_bytes;
        Ok(())
    }

    pub(super) fn record_materialized_bytes(&mut self, bytes: u64) {
        let released = bytes.min(self.bytes);
        if released == 0 {
            return;
        }
        if let Ok(mut budget) = self.budget.lock() {
            budget.release(released);
        }
        self.bytes -= released;
    }

    pub(super) const fn reserved_bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        if let Ok(mut budget) = self.budget.lock() {
            debug_assert!(budget.outstanding_bytes >= self.bytes);
            budget.release(self.bytes);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    Created,
    Identical,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("collection deferred while cache operations are active")]
    CollectionBusy,
    #[error("collection inventory changed during scanning")]
    CollectionChanged,
    #[error("immutable destination has different contents")]
    Conflict,
    #[error("decoded NAR exceeds configured size limit")]
    DecodedSizeLimitExceeded,
    #[error("compressed decoder memory requirement exceeds configured limit")]
    DecoderMemoryLimitExceeded,
    #[error("configured free space reserve would be violated")]
    InsufficientSpace,
    #[error("filesystem has no free inodes")]
    InsufficientInodes,
    #[error("data directory is locked by another process")]
    Locked,
    #[error("referenced NAR is not published")]
    MissingNar,
    #[error("referenced NAR size does not match narinfo")]
    NarMismatch,
    #[error("NAR upload exceeds configured size limit")]
    UploadTooLarge,
    #[error("{0}")]
    Io(#[source] io::Error),
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        match error.get_ref() {
            Some(source) if source.is::<DecoderMemoryLimitExceeded>() => {
                Self::DecoderMemoryLimitExceeded
            }
            Some(source) if source.is::<DecodedSizeLimitExceeded>() => {
                Self::DecodedSizeLimitExceeded
            }
            _ => Self::Io(error),
        }
    }
}

impl From<StorageError> for io::Error {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::InsufficientSpace | StorageError::InsufficientInodes => {
                io::ErrorKind::StorageFull.into()
            }
            StorageError::Io(error) => error,
            error => io::Error::other(error),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("decoded NAR exceeds configured size limit")]
pub(super) struct DecodedSizeLimitExceeded;

#[derive(Debug, thiserror::Error)]
#[error("compressed decoder memory requirement exceeds configured limit")]
pub(super) struct DecoderMemoryLimitExceeded;

pub(super) static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &StorageError::Conflict,
                "immutable destination has different contents",
            ),
            (
                &StorageError::DecodedSizeLimitExceeded,
                "decoded NAR exceeds configured size limit",
            ),
            (
                &StorageError::DecoderMemoryLimitExceeded,
                "compressed decoder memory requirement exceeds configured limit",
            ),
            (
                &StorageError::InsufficientSpace,
                "configured free space reserve would be violated",
            ),
            (
                &StorageError::InsufficientInodes,
                "filesystem has no free inodes",
            ),
            (
                &StorageError::Locked,
                "data directory is locked by another process",
            ),
            (&StorageError::MissingNar, "referenced NAR is not published"),
            (
                &StorageError::NarMismatch,
                "referenced NAR size does not match narinfo",
            ),
            (
                &StorageError::UploadTooLarge,
                "NAR upload exceeds configured size limit",
            ),
            (
                &DecodedSizeLimitExceeded,
                "decoded NAR exceeds configured size limit",
            ),
            (
                &DecoderMemoryLimitExceeded,
                "compressed decoder memory requirement exceeds configured limit",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_storage_io_conversion_preserves_sources_and_limit_classification() {
        use std::error::Error as _;
        let error = StorageError::from(io::Error::other("read failure"));
        assert_eq!(error.to_string(), "read failure");
        let source = error.source().unwrap();
        assert!(source.is::<io::Error>());
        assert_eq!(source.to_string(), "read failure");
        assert!(source.source().is_none());
        assert!(matches!(
            StorageError::from(io::Error::other(DecodedSizeLimitExceeded)),
            StorageError::DecodedSizeLimitExceeded
        ));
        assert!(matches!(
            StorageError::from(io::Error::other(DecoderMemoryLimitExceeded)),
            StorageError::DecoderMemoryLimitExceeded
        ));
    }
}
