use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::ffi::OsStrExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};

use super::{
    StorageError, entry_is_regular_at, open_at, open_directory_at, open_regular_at, read_dir_names,
    unlink_at,
};

const TRANSACTION_DIRECTORY: &str = ".narjar-transactions";
const MAX_TRANSACTION_BYTES: u64 = 256;

static NEXT_TRANSACTION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(super) struct PublicationTransaction {
    directory: File,
    name: OsString,
    path: PathBuf,
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
}

impl PublicationTransaction {
    pub(super) fn transition(&mut self, state: PublicationState) -> Result<(), StorageError> {
        let temporary_name = OsString::from(format!(
            "{}.next-{sequence:016x}",
            self.name.to_string_lossy(),
            sequence = NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut replacement = open_at(
                &self.directory,
                &temporary_name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )?;
            replacement.set_permissions(fs::Permissions::from_mode(0o600))?;
            let path = self.path.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "publication transaction path is not UTF-8",
                )
            })?;
            write!(replacement, "state={}\npath={path}\n", state.as_str())?;
            replacement.sync_all()?;
            rename_at(
                &self.directory,
                &temporary_name,
                &self.directory,
                &self.name,
            )?;
            self.directory.sync_all()?;
            Ok::<_, io::Error>(())
        })();
        if let Err(error) = result {
            let _ = unlink_at(&self.directory, &temporary_name);
            return Err(error.into());
        }
        Ok(())
    }

    pub(super) fn complete(&self) -> Result<(), StorageError> {
        unlink_at(&self.directory, &self.name)?;
        self.directory.sync_all()?;
        Ok(())
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
            || !self.transaction_names()?.is_empty())
    }

    pub(super) fn required_for(&self, trusted_keys: &Path) -> Result<bool, StorageError> {
        if self.required()? {
            return Ok(true);
        }

        let digest = trusted_keys_digest(trusted_keys)?;
        Ok(self.clean_marker()? != digest.as_slice())
    }

    pub(super) fn finish(&self, trusted_keys: &Path) -> Result<(), StorageError> {
        self.clear_transactions()?;
        self.write_clean_marker(trusted_keys_digest(trusted_keys)?.as_slice())?;
        self.clear_recovery_marker()
    }

    pub(super) fn begin(
        &self,
        temporary_path: &Path,
    ) -> Result<PublicationTransaction, StorageError> {
        let temporary_path = temporary_path.to_owned();
        let temporary_path_text = temporary_path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication temporary path is not UTF-8",
            )
        })?;
        for _ in 0..128 {
            let sequence = NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!("publish-{}-{sequence:016x}.txn", process::id()));
            match open_at(
                &self.transactions,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            ) {
                Ok(mut record) => {
                    record.set_permissions(fs::Permissions::from_mode(0o600))?;
                    write!(record, "state=staging\npath={temporary_path_text}\n")?;
                    record.sync_all()?;
                    self.transactions.sync_all()?;
                    return Ok(PublicationTransaction {
                        directory: self.transactions.try_clone()?,
                        name,
                        path: temporary_path,
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

    fn transaction_names(&self) -> Result<Vec<OsString>, StorageError> {
        let names = read_dir_names(&self.transactions)?;
        for name in &names {
            let record = open_regular_at(&self.transactions, name)?;
            if record.metadata()?.permissions().mode() & 0o133 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "publication transaction has unsafe permissions",
                )
                .into());
            }
        }
        Ok(names)
    }

    fn clear_transactions(&self) -> Result<(), StorageError> {
        for name in self.transaction_names()? {
            let record = open_regular_at(&self.transactions, &name)?;
            let mut contents = Vec::new();
            record
                .take(MAX_TRANSACTION_BYTES + 1)
                .read_to_end(&mut contents)?;
            let transaction = parse_transaction(&contents)?;
            self.remove_temporary_path(transaction.path)?;
            unlink_at(&self.transactions, &name)?;
        }
        self.transactions.sync_all()?;
        Ok(())
    }

    fn remove_temporary_path(&self, path: PathBuf) -> Result<(), StorageError> {
        let components: Vec<_> = path
            .components()
            .map(|component| component.as_os_str().to_owned())
            .collect();
        let (directory, name) = match components.as_slice() {
            [first, name] if first == OsStr::new(".tmp") => {
                (open_directory_at(&self.root, OsStr::new(".tmp"))?, name)
            }
            [first, second, name] if first == OsStr::new("nar") && second == OsStr::new(".tmp") => {
                let nar = open_directory_at(&self.root, OsStr::new("nar"))?;
                (open_directory_at(&nar, OsStr::new(".tmp"))?, name)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "publication transaction path is outside temporary storage",
                )
                .into());
            }
        };
        if !name.to_str().is_some_and(|name| name.ends_with(".part")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication transaction path has an invalid temporary name",
            )
            .into());
        }
        match unlink_at(&directory, name) {
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
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
            libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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

fn rename_at(
    from_directory: &File,
    from_name: &OsStr,
    to_directory: &File,
    to_name: &OsStr,
) -> io::Result<()> {
    let from_name = std::ffi::CString::new(from_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "publication transaction name contains a NUL byte",
        )
    })?;
    let to_name = std::ffi::CString::new(to_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "publication transaction name contains a NUL byte",
        )
    })?;
    // SAFETY: all descriptors and NUL-terminated names are live for the call;
    // renameat does not retain either pointer.
    let result = unsafe {
        libc::renameat(
            from_directory.as_raw_fd(),
            from_name.as_ptr(),
            to_directory.as_raw_fd(),
            to_name.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct TransactionRecord {
    _state: PublicationState,
    path: PathBuf,
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
        if lines.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication transaction record has extra fields",
            )
            .into());
        }
        return Ok(TransactionRecord {
            _state: PublicationState::parse(state)?,
            path: PathBuf::from(path),
        });
    }

    if first.is_empty() || lines.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "publication transaction record has an invalid legacy path",
        )
        .into());
    }
    Ok(TransactionRecord {
        _state: PublicationState::Staging,
        path: PathBuf::from(first),
    })
}

fn trusted_keys_digest(path: &Path) -> Result<[u8; 32], StorageError> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    Ok(Sha256::digest(contents).into())
}
