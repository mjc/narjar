use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fs::OFlags;

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
    name: Option<OsString>,
    path: PathBuf,
    destination: PathBuf,
    state: PublicationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationState {
    Staging,
    Streaming,
    Validated,
    Linked,
    Published,
}

impl PublicationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Streaming => "streaming",
            Self::Validated => "validated",
            Self::Linked => "linked",
            Self::Published => "published",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "staging" => Ok(Self::Staging),
            "streaming" => Ok(Self::Streaming),
            "validated" => Ok(Self::Validated),
            "linked" => Ok(Self::Linked),
            "published" => Ok(Self::Published),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication transaction record has an unknown state",
            )
            .into()),
        }
    }

    fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Staging, Self::Streaming)
                | (Self::Streaming, Self::Validated)
                | (Self::Validated, Self::Linked | Self::Published)
                | (Self::Linked, Self::Published)
        )
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
    pub(super) fn set_destination(&mut self, destination: &Path) {
        self.destination = destination.to_owned();
    }

    pub(super) fn transition(&mut self, state: PublicationState) -> Result<(), StorageError> {
        if !self.state.can_transition_to(state) {
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
        let name = self
            .name
            .as_ref()
            .expect("active publication transaction has a record name");
        let contents = self.record_contents(state)?;
        publish_transaction_record(
            &self.directory,
            name,
            &contents,
            TransactionInstall::Replace,
            no_transaction_fault,
        )?;
        self.state = state;
        Ok(())
    }

    fn record_contents(&self, state: PublicationState) -> io::Result<String> {
        let path = self.path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication transaction path is not UTF-8",
            )
        })?;
        let destination = self.destination.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication destination path is not UTF-8",
            )
        })?;
        Ok(format!(
            "state={}\npath={path}\ndestination={destination}\n",
            state.as_str()
        ))
    }

    pub(super) fn complete(mut self) -> Result<(), StorageError> {
        let name = self
            .name
            .take()
            .expect("active publication transaction has a record name");
        unlink_at(&self.directory, &name)?;
        self.directory.sync_all()?;
        Ok(())
    }

    pub(super) fn cancel(self) {
        let Some(name) = self.name else {
            return;
        };
        let _ = unlink_at(&self.directory, &name).and_then(|()| self.directory.sync_all());
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
        destination: &Path,
    ) -> Result<PublicationTransaction, StorageError> {
        let temporary_path = temporary_path.to_owned();
        let destination = destination.to_owned();
        let temporary_path_text = temporary_path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication temporary path is not UTF-8",
            )
        })?;
        let destination_text = destination.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication destination path is not UTF-8",
            )
        })?;
        let contents =
            format!("state=staging\npath={temporary_path_text}\ndestination={destination_text}\n");
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
                        name: Some(name),
                        path: temporary_path,
                        destination,
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
            if mode & libc::S_IFMT != libc::S_IFREG || mode & 0o133 != 0 {
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
        let mut contents = Vec::new();
        record
            .take(MAX_TRANSACTION_BYTES + 1)
            .read_to_end(&mut contents)?;
        self.recover_transaction(parse_transaction(&contents)?)?;
        unlink_at(&self.transactions, name)?;
        Ok(())
    }

    fn recover_transaction(&self, transaction: TransactionRecord) -> Result<(), StorageError> {
        let temporary = match transaction {
            TransactionRecord::Legacy { temporary } => temporary,
            TransactionRecord::Current { temporary, phase } => {
                match phase {
                    CurrentTransactionPhase::PreLink => {}
                    CurrentTransactionPhase::Linked(destination) => {
                        match self.verify_destination(&destination) {
                            Ok(()) => {}
                            // A pre-durable rollback deliberately removes the linked
                            // destination. The transaction still records enough
                            // information to safely remove its temporary file.
                            Err(StorageError::Io(error))
                                if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error),
                        }
                    }
                    CurrentTransactionPhase::Published(destination) => {
                        self.verify_destination(&destination)?;
                    }
                }
                temporary
            }
        };
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
    contents: &str,
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
    contents: &str,
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
    contents: &str,
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
    draft.write_all(contents.as_bytes())?;
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

enum TransactionRecord {
    Legacy {
        temporary: TemporaryPath,
    },
    Current {
        temporary: TemporaryPath,
        phase: CurrentTransactionPhase,
    },
}

enum CurrentTransactionPhase {
    PreLink,
    Linked(StorePath),
    Published(StorePath),
}

fn parse_transaction(contents: &[u8]) -> Result<TransactionRecord, StorageError> {
    let contents = contents.strip_suffix(b"\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "publication transaction record is not newline terminated",
        )
    })?;
    let contents = std::str::from_utf8(contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "publication transaction record is not UTF-8",
        )
    })?;
    let mut lines = contents.lines();
    let first = lines.next().unwrap_or_default();
    if let Some(state) = first.strip_prefix("state=") {
        let state = PublicationState::parse(state)?;
        let path = lines
            .next()
            .and_then(|line| line.strip_prefix("path="))
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "publication transaction record has no path",
                )
            })?;
        let temporary = TemporaryPath::parse(Path::new(path))?;
        let record = match lines.next() {
            None => TransactionRecord::Legacy { temporary },
            Some(line) => {
                let path = line.strip_prefix("destination=").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "publication transaction record has an invalid destination",
                    )
                })?;
                let destination = (!path.is_empty())
                    .then(|| StorePath::parse(Path::new(path)))
                    .transpose()?;
                let phase = match state {
                    PublicationState::Staging
                    | PublicationState::Streaming
                    | PublicationState::Validated => CurrentTransactionPhase::PreLink,
                    PublicationState::Linked => {
                        CurrentTransactionPhase::Linked(destination.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "linked transaction has no destination",
                            )
                        })?)
                    }
                    PublicationState::Published => {
                        CurrentTransactionPhase::Published(destination.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "published transaction has no destination",
                            )
                        })?)
                    }
                };
                TransactionRecord::Current { temporary, phase }
            }
        };
        if lines.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication transaction record has extra fields",
            )
            .into());
        }
        return Ok(record);
    }

    if first.is_empty() || lines.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "publication transaction record has an invalid legacy path",
        )
        .into());
    }
    Ok(TransactionRecord::Legacy {
        temporary: TemporaryPath::parse(Path::new(first))?,
    })
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
    const OLD_RECORD: &str = "state=staging\npath=.tmp/item.part\ndestination=item\n";
    const NEW_RECORD: &str = "state=streaming\npath=.tmp/item.part\ndestination=item\n";

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
            OLD_RECORD.as_bytes(),
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
                assert_eq!(contents, expected.as_bytes());
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
