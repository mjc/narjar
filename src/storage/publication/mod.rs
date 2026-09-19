use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, atomic::AtomicU64},
};

use super::{
    fs::{FilesystemSpace, filesystem_space, lock_exclusive, open_at},
    operations::OwnedTemporary,
    recovery::{PublicationState, PublicationTransaction},
    state::Storage,
    typestate::{Streaming, Validated},
};

mod target;
#[cfg(test)]
pub(super) use target::Layout;
pub(super) use target::{
    DestinationPublication, PublicationDestination, PublicationDirectory, PublishTarget,
    TemporaryDirectory,
};

#[derive(Debug)]
pub(super) struct TemporaryFile {
    pub(super) name: OsString,
    pub(super) directory: File,
    pub(super) file: File,
}

struct OwnedPublication<'storage> {
    temporary: Option<OwnedTemporary<'storage>>,
    transaction: Option<PublicationTransaction>,
}

impl<'storage> OwnedPublication<'storage> {
    fn new(temporary: OwnedTemporary<'storage>, transaction: PublicationTransaction) -> Self {
        Self {
            temporary: Some(temporary),
            transaction: Some(transaction),
        }
    }

    fn temporary(&self) -> &OwnedTemporary<'storage> {
        self.temporary
            .as_ref()
            .expect("owned publication temporary is present")
    }

    fn temporary_mut(&mut self) -> &mut OwnedTemporary<'storage> {
        self.temporary
            .as_mut()
            .expect("owned publication temporary is present")
    }

    fn transaction_mut(&mut self) -> &mut PublicationTransaction {
        self.transaction
            .as_mut()
            .expect("owned publication transaction is present")
    }

    fn preserve_recovery_record(&mut self) {
        let _ = self.transaction.take();
    }

    fn into_parts(mut self) -> (OwnedTemporary<'storage>, PublicationTransaction) {
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

pub(super) struct StagedPublication<'storage, Checkpoint, State> {
    pub(super) storage: &'storage Storage,
    pub(super) destination: PublicationDestination,
    publication: OwnedPublication<'storage>,
    checkpoint: Checkpoint,
    _state: State,
}

impl<'storage, Checkpoint> StagedPublication<'storage, Checkpoint, Streaming> {
    pub(super) fn from_parts(
        storage: &'storage Storage,
        destination: PublicationDestination,
        temporary: OwnedTemporary<'storage>,
        transaction: PublicationTransaction,
        checkpoint: Checkpoint,
    ) -> Self {
        Self {
            storage,
            destination,
            publication: OwnedPublication::new(temporary, transaction),
            checkpoint,
            _state: Streaming::new(()),
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
        let result = (|| {
            (self.checkpoint)(PublishBoundary::AfterTempCreate)?;
            io::copy(&mut source, self.publication.temporary_mut().file_mut())?;
            (self.checkpoint)(PublishBoundary::AfterStream)?;
            self.publication.temporary().file().file.sync_all()?;
            (self.checkpoint)(PublishBoundary::AfterTempSync)?;
            self.publication
                .transaction_mut()
                .transition(PublicationState::Validated)?;
            Ok::<_, StorageError>(())
        })();
        if let Err(error) = result {
            self.publication.preserve_recovery_record();
            return Err(error);
        }

        let Self {
            storage,
            destination,
            publication,
            checkpoint,
            _state: _,
        } = self;
        Ok(StagedPublication {
            storage,
            destination,
            publication,
            checkpoint,
            _state: Validated::new(()),
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
        } = self;
        let (temporary, transaction) = publication.into_parts();
        let temporary = temporary.into_file();
        storage.commit_temporary(destination, &temporary, transaction, checkpoint)
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

/// The lease is held on the opened DATA directory, not `DATA/lock`.
///
/// This keeps replacing the lock pathname from creating a second lease. It
/// relies on local-filesystem `flock` semantics for directory file
/// descriptions; distributed filesystems are outside the supported guarantee.
#[derive(Debug)]
pub(super) struct ProcessLock {
    _file: File,
}

impl ProcessLock {
    pub(super) fn acquire(parent: File) -> Result<Self, StorageError> {
        lock_exclusive(&parent)?;
        Ok(Self { _file: parent })
    }

    pub(super) fn validate_lock_file(root: &File) -> Result<(), StorageError> {
        let file = open_at(
            root,
            OsStr::new("lock"),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|error| io::Error::new(error.kind(), format!("lock: {error}")))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "lock is not a regular file").into(),
            );
        }
        if metadata.permissions().mode() & 0o133 != 0 {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "lock has unsafe permissions").into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NarUploadPolicy {
    pub(super) max_bytes: u64,
    pub(super) min_free_bytes: u64,
}

impl NarUploadPolicy {
    pub const fn new(max_bytes: u64, min_free_bytes: u64) -> Self {
        Self {
            max_bytes,
            min_free_bytes,
        }
    }

    pub const fn min_free_bytes(self) -> u64 {
        self.min_free_bytes
    }
}

#[derive(Debug, Default)]
pub(super) struct StagingBudget {
    outstanding_bytes: u64,
}

impl StagingBudget {
    pub(super) fn reserve(
        &mut self,
        space: FilesystemSpace,
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

    #[cfg(test)]
    pub(super) const fn outstanding_bytes(&self) -> u64 {
        self.outstanding_bytes
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

#[derive(Debug)]
pub enum StorageError {
    Conflict,
    InsufficientSpace,
    InsufficientInodes,
    Locked,
    MissingNar,
    NarMismatch,
    UploadTooLarge,
    Io(io::Error),
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("immutable destination has different contents"),
            Self::InsufficientSpace => {
                formatter.write_str("configured free space reserve would be violated")
            }
            Self::InsufficientInodes => formatter.write_str("filesystem has no free inodes"),
            Self::Locked => formatter.write_str("data directory is locked by another process"),
            Self::MissingNar => formatter.write_str("referenced NAR is not published"),
            Self::NarMismatch => formatter.write_str("referenced NAR size does not match narinfo"),
            Self::UploadTooLarge => formatter.write_str("NAR upload exceeds configured size limit"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Conflict
            | Self::InsufficientSpace
            | Self::InsufficientInodes
            | Self::Locked
            | Self::MissingNar
            | Self::NarMismatch
            | Self::UploadTooLarge => None,
        }
    }
}

pub(super) static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
