use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fs::{FileType, OFlags};

use sha2::{Digest, Sha256};

use super::fs::{entry_mode_at, hard_link_at, open_at, rename_at, unlink_at};
use super::{
    StorageError, entry_is_regular_at,
    location::{StorePath, TemporaryPath},
    open_directory_at, open_regular_at, read_dir_names,
};

const TRANSACTION_DIRECTORY: &str = ".narjar-transactions";
const MAX_TRANSACTION_BYTES: u64 = 256;

static NEXT_TRANSACTION: AtomicU64 = AtomicU64::new(0);

/// Recovery work performed while opening storage for serving or maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStatus {
    /// The storage did not require recovery.
    NotRequired,
    /// Recovery completed after validating this many published narinfos.
    Completed(crate::inventory::NarInfoCount),
}

#[derive(Debug)]
pub(super) struct PublicationTransaction {
    directory: File,
    name: OsString,
    path: TemporaryPath,
    state: PublicationState,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) enum PublicationState {
    Staging,
    Streaming,
    Validated,
    Linked(StorePath),
    Published(StorePath),
}

impl PublicationState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Streaming => "streaming",
            Self::Validated => "validated",
            Self::Linked(_) => "linked",
            Self::Published(_) => "published",
        }
    }

    fn can_transition_to(&self, next: &Self) -> bool {
        match self {
            Self::Staging => *next == Self::Streaming,
            Self::Streaming => *next == Self::Validated,
            Self::Validated => match next {
                Self::Linked(_) | Self::Published(_) => true,
                Self::Staging | Self::Streaming | Self::Validated => false,
            },
            Self::Linked(destination) => match next {
                Self::Published(next_destination) => destination == next_destination,
                Self::Staging | Self::Streaming | Self::Validated | Self::Linked(_) => false,
            },
            Self::Published(_) => false,
        }
    }
}

#[derive(Debug)]
enum TransactionEntry {
    Record(OsString),
    Draft(OsString),
}

impl TransactionEntry {
    fn parse(name: OsString) -> io::Result<Self> {
        let name_text = name
            .to_str()
            .ok_or_else(|| invalid_transaction_filename("transaction filename is not UTF-8"))?;
        match name_text.rsplit_once(".next-") {
            Some((record, sequence)) if is_generated_draft_name(record, sequence) => {
                Ok(Self::Draft(name))
            }
            Some(_) => Err(invalid_transaction_filename(
                "transaction draft filename is malformed",
            )),
            None if name_text.ends_with(".txn") => Ok(Self::Record(name)),
            None => Err(invalid_transaction_filename(
                "transaction filename is malformed",
            )),
        }
    }

    fn name(&self) -> &OsStr {
        match self {
            Self::Record(name) | Self::Draft(name) => name,
        }
    }
}

fn is_generated_draft_name(record: &str, draft_sequence: &str) -> bool {
    let Some(record_sequence) = record
        .strip_prefix("publish-")
        .and_then(|record| record.strip_suffix(".txn"))
        .and_then(|record| record.rsplit_once('-'))
        .and_then(|(process_id, sequence)| {
            let generated_process_id =
                !process_id.is_empty() && process_id.bytes().all(|byte| byte.is_ascii_digit());
            generated_process_id.then_some(sequence)
        })
    else {
        return false;
    };
    let has_hex_sequence = |sequence: &str| {
        sequence.len() == 16 && sequence.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    has_hex_sequence(record_sequence) && has_hex_sequence(draft_sequence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionInstall {
    Create,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionRecordBoundary {
    DraftCreated,
    DraftWritten,
    DraftSynchronized,
    RecordInstalled,
    DirectorySynchronized,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionRecordOperation {
    SyncDraft,
    InstallRecord(TransactionInstall),
    SyncDirectory,
}

trait TransactionRecordOperations {
    fn sync_draft(&mut self, draft: &File) -> io::Result<()>;
    fn install_record(
        &mut self,
        directory: &File,
        draft_name: &OsStr,
        record_name: &OsStr,
        installation: TransactionInstall,
    ) -> io::Result<()>;
    fn sync_directory(&mut self, directory: &File) -> io::Result<()>;
}

struct FilesystemTransactionRecordOperations;

impl TransactionRecordOperations for FilesystemTransactionRecordOperations {
    fn sync_draft(&mut self, draft: &File) -> io::Result<()> {
        draft.sync_all()
    }

    fn install_record(
        &mut self,
        directory: &File,
        draft_name: &OsStr,
        record_name: &OsStr,
        installation: TransactionInstall,
    ) -> io::Result<()> {
        match installation {
            TransactionInstall::Create => {
                hard_link_at(directory, draft_name, directory, record_name)?;
                unlink_at(directory, draft_name)
            }
            TransactionInstall::Replace => rename_at(directory, draft_name, directory, record_name),
        }
    }

    fn sync_directory(&mut self, directory: &File) -> io::Result<()> {
        directory.sync_all()
    }
}

impl PublicationTransaction {
    pub(super) fn transition(&mut self, state: PublicationState) -> Result<(), StorageError> {
        if !self.state.can_transition_to(&state) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid publication transition: {} -> {}",
                    self.state.as_str(),
                    state.as_str()
                ),
            )
            .into());
        }
        let contents = serialize_transaction(self.path.clone(), state.clone())?;
        publish_transaction_record(
            &self.directory,
            &self.name,
            &contents,
            TransactionInstall::Replace,
            no_transaction_fault,
        )?;
        self.state = state;
        Ok(())
    }

    pub(super) fn complete(self) -> Result<(), StorageError> {
        unlink_at(&self.directory, &self.name)?;
        self.directory.sync_all()?;
        Ok(())
    }

    pub(super) fn cancel(self) {
        let _ = unlink_at(&self.directory, &self.name).and_then(|()| self.directory.sync_all());
    }
}

#[derive(Debug)]
pub(super) struct RecoveryState {
    root: File,
    transactions: File,
}

impl RecoveryState {
    pub(super) fn new(root: &File) -> io::Result<Self> {
        Ok(Self {
            root: root.try_clone()?,
            transactions: open_directory_at(root, OsStr::new(TRANSACTION_DIRECTORY))?,
        })
    }

    pub(super) fn initialize_clean(&self) -> Result<(), StorageError> {
        self.create_marker(OsStr::new(".narjar-clean"))
    }

    pub(super) fn required(&self) -> Result<bool, StorageError> {
        Ok(!self.marker_exists(OsStr::new(".narjar-clean"))?
            || self.marker_exists(OsStr::new(".narjar-recovery"))?
            || !self.transaction_entries()?.is_empty())
    }

    pub(super) fn required_for(&self) -> Result<bool, StorageError> {
        if self.required()? {
            return Ok(true);
        }

        let digest = trusted_keys_digest(&self.root)?;
        Ok(self.clean_marker()? != digest.as_slice())
    }

    pub(super) fn finish(&self) -> Result<(), StorageError> {
        self.clear_transactions()?;
        self.write_clean_marker(trusted_keys_digest(&self.root)?.as_slice())?;
        self.clear_recovery_marker()
    }

    pub(super) fn begin(
        &self,
        temporary_path: &Path,
    ) -> Result<PublicationTransaction, StorageError> {
        let temporary_path = TemporaryPath::parse(temporary_path)?;
        let contents = serialize_transaction(temporary_path.clone(), PublicationState::Staging)?;
        for _ in 0..128 {
            let sequence = NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!("publish-{}-{sequence:016x}.txn", process::id()));
            match publish_transaction_record(
                &self.transactions,
                &name,
                &contents,
                TransactionInstall::Create,
                no_transaction_fault,
            ) {
                Ok(()) => {
                    return Ok(PublicationTransaction {
                        directory: self.transactions.try_clone()?,
                        name,
                        path: temporary_path,
                        state: PublicationState::Staging,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate unique publication transaction",
        )
        .into())
    }

    pub(super) fn require(&self) -> Result<(), StorageError> {
        self.create_marker(OsStr::new(".narjar-recovery"))
    }

    fn transaction_entries(&self) -> Result<Vec<TransactionEntry>, StorageError> {
        let entries = read_dir_names(&self.transactions)?
            .into_iter()
            .map(TransactionEntry::parse)
            .collect::<io::Result<Vec<_>>>()?;
        for entry in &entries {
            let mode = entry_mode_at(&self.transactions, entry.name())?;
            if FileType::from_raw_mode(mode) != FileType::RegularFile || mode & 0o133 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "publication transaction entry has unsafe type or permissions",
                )
                .into());
            }
            if let TransactionEntry::Record(name) = entry {
                open_regular_at(&self.transactions, name)?;
            }
        }
        Ok(entries)
    }

    fn clear_transactions(&self) -> Result<(), StorageError> {
        for entry in self.transaction_entries()? {
            match entry {
                TransactionEntry::Draft(name) => unlink_at(&self.transactions, &name)?,
                TransactionEntry::Record(name) => self.recover_named_transaction(&name)?,
            }
        }
        self.transactions.sync_all()?;
        Ok(())
    }

    fn recover_named_transaction(&self, name: &OsStr) -> Result<(), StorageError> {
        let record = open_regular_at(&self.transactions, name)?;
        let contents = crate::records::read_bounded_bytes(record, MAX_TRANSACTION_BYTES)
            .map_err(io::Error::from)?;
        self.recover_transaction(parse_transaction(&contents)?)?;
        unlink_at(&self.transactions, name)?;
        Ok(())
    }

    fn recover_transaction(&self, transaction: TransactionRecord) -> Result<(), StorageError> {
        let TransactionRecord::V1 { temporary, state } = transaction;
        match state {
            PublicationState::Staging
            | PublicationState::Streaming
            | PublicationState::Validated => {}
            PublicationState::Linked(destination) => {
                match self.verify_destination(&destination) {
                    Ok(()) => {}
                    // A pre-durable rollback deliberately removes the linked
                    // destination. The transaction still records enough
                    // information to safely remove its temporary file.
                    Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            PublicationState::Published(destination) => {
                self.verify_destination(&destination)?;
            }
        }
        self.remove_temporary_path(temporary)
    }

    fn verify_destination(&self, destination: &StorePath) -> Result<(), StorageError> {
        let directory = destination.open_parent(&self.root)?;
        open_regular_at(&directory, destination.name())
            .map(|_| ())
            .map_err(Into::into)
    }

    fn remove_temporary_path(&self, temporary: TemporaryPath) -> Result<(), StorageError> {
        let directory = temporary.open_parent(&self.root)?;
        match unlink_at(&directory, temporary.name()) {
            Ok(()) => directory.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn clear_recovery_marker(&self) -> Result<(), StorageError> {
        match unlink_at(&self.root, OsStr::new(".narjar-recovery")) {
            Ok(()) => self.root.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn create_marker(&self, name: &OsStr) -> Result<(), StorageError> {
        match open_at(
            &self.root,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            0o600,
        ) {
            Ok(file) => {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                file.sync_all()?;
                self.root.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.marker_exists(name)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn write_clean_marker(&self, contents: &[u8]) -> Result<(), StorageError> {
        let name = OsStr::new(".narjar-clean");
        self.create_marker(name)?;
        let mut marker = open_at(
            &self.root,
            name,
            OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            0,
        )?;
        if !marker.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "clean recovery marker is not a regular file",
            )
            .into());
        }
        marker.write_all(contents)?;
        marker.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }

    fn clean_marker(&self) -> Result<Vec<u8>, StorageError> {
        let mut marker = open_regular_at(&self.root, OsStr::new(".narjar-clean"))?;
        let mut contents = Vec::new();
        marker.read_to_end(&mut contents)?;
        Ok(contents)
    }

    fn marker_exists(&self, name: &OsStr) -> Result<bool, StorageError> {
        match entry_is_regular_at(&self.root, name) {
            Ok(true) => {
                let marker = open_regular_at(&self.root, name)?;
                if marker.metadata()?.permissions().mode() & 0o133 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "recovery marker has unsafe permissions",
                    )
                    .into());
                }
                Ok(true)
            }
            Ok(false) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not a regular file", name.to_string_lossy()),
            )
            .into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

fn publish_transaction_record(
    directory: &File,
    name: &OsStr,
    contents: &[u8],
    installation: TransactionInstall,
    fault: impl FnMut(TransactionRecordBoundary) -> io::Result<()>,
) -> io::Result<()> {
    publish_transaction_record_with_operations(
        directory,
        name,
        contents,
        installation,
        &mut FilesystemTransactionRecordOperations,
        fault,
    )
}

fn publish_transaction_record_with_operations(
    directory: &File,
    name: &OsStr,
    contents: &[u8],
    installation: TransactionInstall,
    operations: &mut impl TransactionRecordOperations,
    mut fault: impl FnMut(TransactionRecordBoundary) -> io::Result<()>,
) -> io::Result<()> {
    let mut draft_name = name.to_os_string();
    draft_name.push(format!(
        ".next-{:016x}",
        NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        write_transaction_draft(directory, &draft_name, contents, operations, &mut fault)?;
        operations.install_record(directory, &draft_name, name, installation)?;
        fault(TransactionRecordBoundary::RecordInstalled)?;
        operations.sync_directory(directory)?;
        fault(TransactionRecordBoundary::DirectorySynchronized)
    })();
    if result.is_err() {
        let _ = unlink_at(directory, &draft_name);
    }
    result
}

fn write_transaction_draft(
    directory: &File,
    name: &OsStr,
    contents: &[u8],
    operations: &mut impl TransactionRecordOperations,
    fault: &mut impl FnMut(TransactionRecordBoundary) -> io::Result<()>,
) -> io::Result<()> {
    let mut draft = open_at(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        0o600,
    )?;
    fault(TransactionRecordBoundary::DraftCreated)?;
    draft.set_permissions(fs::Permissions::from_mode(0o600))?;
    draft.write_all(contents)?;
    fault(TransactionRecordBoundary::DraftWritten)?;
    operations.sync_draft(&draft)?;
    fault(TransactionRecordBoundary::DraftSynchronized)
}

fn no_transaction_fault(_: TransactionRecordBoundary) -> io::Result<()> {
    Ok(())
}

fn invalid_transaction_filename(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) enum TransactionRecord {
    V1 {
        temporary: TemporaryPath,
        state: PublicationState,
    },
}

fn serialize_transaction(temporary: TemporaryPath, state: PublicationState) -> io::Result<Vec<u8>> {
    let bytes = postcard::to_allocvec(&TransactionRecord::V1 { temporary, state })
        .map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

pub(super) fn parse_transaction(contents: &[u8]) -> Result<TransactionRecord, StorageError> {
    if contents.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData).into());
    }
    crate::records::decode_complete(contents)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error).into())
}

fn trusted_keys_digest(root: &File) -> Result<[u8; 32], StorageError> {
    let mut contents = Vec::new();
    match open_regular_at(root, OsStr::new("trusted-public-keys")) {
        Ok(mut file) => {
            file.read_to_end(&mut contents)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    };
    Ok(Sha256::digest(contents).into())
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, io, path::PathBuf};

    use tempfile::TempDir;

    use super::{
        FilesystemTransactionRecordOperations, TransactionInstall, TransactionRecordBoundary,
        TransactionRecordOperation, TransactionRecordOperations, no_transaction_fault,
        parse_transaction, publish_transaction_record, publish_transaction_record_with_operations,
    };

    const TRANSACTION_NAME: &str = "publish-123-0000000000000001.txn";
    // V1 discriminant, temporary path, pre-link state discriminant.
    const OLD_RECORD: &[u8] = b"\0\x0e.tmp/item.part\0";
    const NEW_RECORD: &[u8] = b"\0\x0e.tmp/item.part\x01";

    #[test]
    fn versioned_records_require_valid_terminal_paths_and_complete_consumption() {
        let destination = super::StorePath::parse(std::path::Path::new("nar/item.nar")).unwrap();
        for (state, expected_bytes) in [
            (super::PublicationState::Staging, OLD_RECORD),
            (super::PublicationState::Streaming, NEW_RECORD),
            (
                super::PublicationState::Validated,
                b"\0\x0e.tmp/item.part\x02".as_slice(),
            ),
            (
                super::PublicationState::Linked(destination.clone()),
                b"\0\x0e.tmp/item.part\x03\x0cnar/item.nar".as_slice(),
            ),
            (
                super::PublicationState::Published(destination),
                b"\0\x0e.tmp/item.part\x04\x0cnar/item.nar".as_slice(),
            ),
        ] {
            let bytes = super::serialize_transaction(
                super::TemporaryPath::parse(std::path::Path::new(".tmp/item.part")).unwrap(),
                state.clone(),
            )
            .unwrap();
            assert_eq!(bytes, expected_bytes, "V1 binary encoding must stay stable");
            let super::TransactionRecord::V1 {
                state: recorded, ..
            } = parse_transaction(&bytes).unwrap();
            assert_eq!(recorded, state);
            assert!(parse_transaction(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(parse_transaction(&trailing).is_err());
            let mut unknown_version = bytes;
            unknown_version[0] = 1;
            assert!(parse_transaction(&unknown_version).is_err());
        }
        for state in [3_u8, 4_u8] {
            for bad_path in ["", "../outside", "unknown/object", "/outside"] {
                let bytes =
                    postcard::to_allocvec(&(0_u8, ".tmp/item.part", state, bad_path)).unwrap();
                assert!(
                    parse_transaction(&bytes).is_err(),
                    "invalid terminal destination: {bad_path}"
                );
            }
        }
    }

    #[test]
    fn rejected_transitions_preserve_the_live_state_and_record() {
        let (root, directory_path, directory) = transaction_directory();
        let recovery = super::RecoveryState {
            root: File::open(root.path()).unwrap(),
            transactions: directory,
        };
        let mut transaction = recovery
            .begin(std::path::Path::new(".tmp/item.part"))
            .unwrap();
        transaction
            .transition(super::PublicationState::Streaming)
            .unwrap();
        let record_path = directory_path.join(&transaction.name);
        let before = fs::read(&record_path).unwrap();
        assert_eq!(before, NEW_RECORD);
        let destination = super::StorePath::parse(std::path::Path::new("nar/item.nar")).unwrap();
        assert!(matches!(
            transaction.transition(super::PublicationState::Linked(destination.clone())),
            Err(super::StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert_eq!(transaction.state, super::PublicationState::Streaming);
        assert_eq!(fs::read(&record_path).unwrap(), before);

        transaction
            .transition(super::PublicationState::Validated)
            .unwrap();
        transaction
            .transition(super::PublicationState::Linked(destination.clone()))
            .unwrap();
        let before = fs::read(&record_path).unwrap();
        let different_destination =
            super::StorePath::parse(std::path::Path::new("nar/different.nar")).unwrap();
        assert!(matches!(
            transaction.transition(super::PublicationState::Published(different_destination)),
            Err(super::StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert_eq!(
            transaction.state,
            super::PublicationState::Linked(destination.clone())
        );
        assert_eq!(fs::read(&record_path).unwrap(), before);

        transaction
            .transition(super::PublicationState::Published(destination.clone()))
            .unwrap();
        let super::TransactionRecord::V1 { state, .. } =
            parse_transaction(&fs::read(record_path).unwrap()).unwrap();
        assert_eq!(state, super::PublicationState::Published(destination));
        assert_eq!(transaction.state, state);
    }

    #[test]
    fn record_publication_failures_leave_only_complete_authoritative_records() {
        for installation in [TransactionInstall::Create, TransactionInstall::Replace] {
            for boundary in [
                TransactionRecordBoundary::DraftCreated,
                TransactionRecordBoundary::DraftWritten,
                TransactionRecordBoundary::DraftSynchronized,
                TransactionRecordBoundary::RecordInstalled,
                TransactionRecordBoundary::DirectorySynchronized,
            ] {
                assert_failure_preserves_a_complete_record(installation, boundary);
            }
        }
    }

    #[test]
    fn initial_record_collision_preserves_the_existing_record_and_removes_its_draft() {
        let (_temporary_root, directory_path, directory) = transaction_directory();
        let name = std::ffi::OsStr::new(TRANSACTION_NAME);
        publish_transaction_record(
            &directory,
            name,
            OLD_RECORD,
            TransactionInstall::Create,
            no_transaction_fault,
        )
        .expect("install initial record");

        let error = publish_transaction_record(
            &directory,
            name,
            NEW_RECORD,
            TransactionInstall::Create,
            no_transaction_fault,
        )
        .expect_err("initial install must not replace an existing record");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(directory_path.join(TRANSACTION_NAME)).expect("read original record"),
            OLD_RECORD,
            "the collision leaves the existing authoritative record intact"
        );
        assert!(
            fs::read_dir(&directory_path)
                .expect("read transaction directory")
                .all(|entry| entry
                    .expect("read transaction entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".txn")),
            "the failed install removes its temporary draft"
        );
    }

    #[test]
    fn initial_record_syncs_complete_draft_before_install_and_directory_afterward() {
        let (_temporary_root, _directory_path, directory) = transaction_directory();
        let mut operations = RecordingTransactionRecordOperations::default();
        publish_transaction_record_with_operations(
            &directory,
            std::ffi::OsStr::new(TRANSACTION_NAME),
            OLD_RECORD,
            TransactionInstall::Create,
            &mut operations,
            no_transaction_fault,
        )
        .expect("publish initial transaction");

        assert_eq!(
            operations.observed,
            [
                TransactionRecordOperation::SyncDraft,
                TransactionRecordOperation::InstallRecord(TransactionInstall::Create),
                TransactionRecordOperation::SyncDirectory,
            ]
        );
    }

    #[derive(Default)]
    struct RecordingTransactionRecordOperations {
        observed: Vec<TransactionRecordOperation>,
    }

    impl TransactionRecordOperations for RecordingTransactionRecordOperations {
        fn sync_draft(&mut self, draft: &File) -> io::Result<()> {
            self.observed.push(TransactionRecordOperation::SyncDraft);
            FilesystemTransactionRecordOperations.sync_draft(draft)
        }

        fn install_record(
            &mut self,
            directory: &File,
            draft_name: &std::ffi::OsStr,
            record_name: &std::ffi::OsStr,
            installation: TransactionInstall,
        ) -> io::Result<()> {
            self.observed
                .push(TransactionRecordOperation::InstallRecord(installation));
            FilesystemTransactionRecordOperations.install_record(
                directory,
                draft_name,
                record_name,
                installation,
            )
        }

        fn sync_directory(&mut self, directory: &File) -> io::Result<()> {
            self.observed
                .push(TransactionRecordOperation::SyncDirectory);
            FilesystemTransactionRecordOperations.sync_directory(directory)
        }
    }

    fn assert_failure_preserves_a_complete_record(
        installation: TransactionInstall,
        failing_boundary: TransactionRecordBoundary,
    ) {
        let (_temporary_root, directory_path, directory) = transaction_directory();
        let record_name = std::ffi::OsStr::new(TRANSACTION_NAME);
        if installation == TransactionInstall::Replace {
            publish_transaction_record(
                &directory,
                record_name,
                OLD_RECORD,
                TransactionInstall::Create,
                no_transaction_fault,
            )
            .expect("install initial record");
        }

        let result = publish_transaction_record(
            &directory,
            record_name,
            NEW_RECORD,
            installation,
            |boundary| {
                if boundary == failing_boundary {
                    Err(io::Error::other("injected transaction-record failure"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err(), "{failing_boundary:?} must fail");

        let expected_record = match (installation, failing_boundary) {
            (TransactionInstall::Create, TransactionRecordBoundary::RecordInstalled)
            | (TransactionInstall::Create, TransactionRecordBoundary::DirectorySynchronized)
            | (TransactionInstall::Replace, TransactionRecordBoundary::RecordInstalled)
            | (TransactionInstall::Replace, TransactionRecordBoundary::DirectorySynchronized) => {
                Some(NEW_RECORD)
            }
            (TransactionInstall::Create, _) => None,
            (TransactionInstall::Replace, _) => Some(OLD_RECORD),
        };
        match expected_record {
            Some(expected) => {
                let contents = fs::read(directory_path.join(TRANSACTION_NAME))
                    .expect("complete authoritative record remains");
                assert_eq!(contents, expected);
                assert!(parse_transaction(&contents).is_ok());
            }
            None => assert!(
                !directory_path.join(TRANSACTION_NAME).exists(),
                "failed initial creation leaves no authoritative record"
            ),
        }
        assert!(
            fs::read_dir(&directory_path)
                .expect("read transaction directory")
                .all(|entry| entry
                    .expect("read transaction entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".txn")),
            "returned errors clean temporary draft files"
        );
    }

    fn transaction_directory() -> (TempDir, PathBuf, File) {
        let root = tempfile::tempdir().expect("create temporary root");
        let path = root.path().join("transactions");
        fs::create_dir(&path).expect("create transaction directory");
        let directory = File::open(&path).expect("open transaction directory");
        (root, path, directory)
    }
}
