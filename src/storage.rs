use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read},
    mem::MaybeUninit,
    num::NonZeroUsize,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

#[cfg(test)]
use std::path::PathBuf;

use data_encoding::{BitOrder, Encoding, Specification};
use sha2::{Digest, Sha256};

use crate::narinfo::ValidatedNarInfo;

pub mod gc;
mod reconcile;
mod recovery;

pub use reconcile::{ReconcileClass, ReconcileEntry, ReconcileReport};
use recovery::RecoveryState;

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const TEMP_ATTEMPTS: u64 = 128;
const COMPARE_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidObjectId;

impl fmt::Display for InvalidObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Nix base-32 object identifier")
    }
}

impl std::error::Error for InvalidObjectId {}

#[derive(Debug, Eq, PartialEq)]
pub struct NarObjectId(String);

impl NarObjectId {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        parse_nix32(value, 52).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StoreHash(String);

impl StoreHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        parse_nix32(value, 32).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_nix32(value: &str, expected_len: usize) -> Result<String, InvalidObjectId> {
    (value.len() == expected_len && value.bytes().all(|byte| NIX32.as_bytes().contains(&byte)))
        .then(|| value.to_owned())
        .ok_or(InvalidObjectId)
}

pub(crate) fn nix32_sha256(digest: &[u8]) -> String {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    let encoding = ENCODING.get_or_init(|| {
        let mut specification = Specification::new();
        specification.symbols.push_str(NIX32);
        specification.bit_order = BitOrder::LeastSignificantFirst;
        specification
            .encoding()
            .expect("Nix base32 specification is valid")
    });
    encoding.encode(digest).chars().rev().collect()
}

struct CheckedNarReader<'a, R> {
    inner: R,
    expected_id: &'a str,
    expected_length: u64,
    bytes_read: u64,
    hasher: Sha256,
    done: bool,
}

impl<'a, R> CheckedNarReader<'a, R> {
    fn new(inner: R, expected_id: &'a str, expected_length: u64) -> Self {
        Self {
            inner,
            expected_id,
            expected_length,
            bytes_read: 0,
            hasher: Sha256::new(),
            done: false,
        }
    }
}

impl<R: Read> Read for CheckedNarReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }

        let read = self.inner.read(buffer)?;
        if read == 0 {
            let digest = self.hasher.clone().finalize();
            if self.bytes_read != self.expected_length || nix32_sha256(&digest) != self.expected_id
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NAR hash or size mismatch",
                ));
            }
            self.done = true;
            return Ok(0);
        }

        self.bytes_read = self
            .bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        if self.bytes_read > self.expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR exceeds declared length",
            ));
        }
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
struct Layout {
    root: PathBuf,
}

#[cfg(test)]
impl Layout {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[cfg(test)]
    fn nar_dir(&self) -> PathBuf {
        self.root.join("nar")
    }

    #[cfg(test)]
    fn nar_path(&self, id: &NarObjectId) -> PathBuf {
        self.nar_dir().join(format!("{}.nar", id.0))
    }

    #[cfg(test)]
    fn nar_temp_dir(&self) -> PathBuf {
        self.nar_dir().join(".tmp")
    }

    #[cfg(test)]
    fn narinfo_path(&self, hash: &StoreHash) -> PathBuf {
        self.root.join(format!("{}.narinfo", hash.0))
    }

    #[cfg(test)]
    fn temp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }
}

enum PublishTarget<'a> {
    CacheInfo,
    Nar(&'a NarObjectId),
    NarInfo(&'a StoreHash),
}

impl PublishTarget<'_> {
    fn destination_name(&self) -> OsString {
        match self {
            Self::CacheInfo => OsString::from("nix-cache-info"),
            Self::Nar(id) => OsString::from(format!("{}.nar", id.as_str())),
            Self::NarInfo(store) => OsString::from(format!("{}.narinfo", store.as_str())),
        }
    }

    fn temp_prefix(&self) -> &'static str {
        match self {
            Self::CacheInfo => "cache-info",
            Self::Nar(_) => "nar",
            Self::NarInfo(_) => "narinfo",
        }
    }
}

#[derive(Debug)]
struct TemporaryFile {
    name: OsString,
    directory: File,
    file: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishBoundary {
    BeforeTempCreate,
    AfterTempCreate,
    AfterStream,
    AfterTempSync,
    BeforeFinalLink,
    BeforeParentSync,
    AfterParentSync,
}

#[cfg(test)]
fn injected_fault(boundary: PublishBoundary, fault: PublishBoundary) -> Result<(), StorageError> {
    if boundary == fault {
        Err(io::Error::other(format!("injected fault at {boundary:?}")).into())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct ProcessLock {
    _file: File,
}

impl ProcessLock {
    fn acquire(root: &File) -> Result<Self, StorageError> {
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
        lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NarUploadPolicy {
    max_bytes: u64,
    min_free_bytes: u64,
}

impl NarUploadPolicy {
    pub const fn new(max_bytes: u64, min_free_bytes: u64) -> Self {
        Self {
            max_bytes,
            min_free_bytes,
        }
    }
}

#[derive(Debug)]
pub struct Storage {
    #[cfg(test)]
    layout: Layout,
    root: File,
    recovery: RecoveryState,
    publication_lock: Mutex<()>,
    _lock: ProcessLock,
}

impl Storage {
    pub fn initialize(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root_path = root.as_ref().to_owned();
        #[cfg(test)]
        let layout = Layout::new(root_path.clone());
        ensure_directory(&root_path, "data directory")?;
        let root_directory = open_directory(&root_path)?;
        let root_is_empty = read_dir_names(&root_directory)?.is_empty();
        let nar_directory =
            ensure_directory_at(&root_directory, OsStr::new("nar"), "nar directory")?;
        ensure_directory_at(
            &nar_directory,
            OsStr::new(".tmp"),
            "NAR temporary directory",
        )?;
        ensure_directory_at(&root_directory, OsStr::new(".tmp"), "temporary directory")?;
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

        let lock = ProcessLock::acquire(&root_directory)?;
        root_directory.sync_all()?;

        let recovery = RecoveryState::new(&root_directory)?;
        let storage = Self {
            #[cfg(test)]
            layout,
            root: root_directory,
            recovery,
            publication_lock: Mutex::new(()),
            _lock: lock,
        };
        if root_is_empty {
            storage.recovery.initialize_clean()?;
        }
        Ok(storage)
    }

    #[cfg(test)]
    fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn recovery_required(&self) -> Result<bool, StorageError> {
        self.recovery.required()
    }

    pub fn recovery_required_for(&self, trusted_keys: &Path) -> Result<bool, StorageError> {
        self.recovery.required_for(trusted_keys)
    }

    /// Records that a full inventory scan has completed successfully.
    pub fn finish_recovery(&self, trusted_keys: &Path) -> Result<(), StorageError> {
        self.recovery.finish(trusted_keys)
    }

    pub fn publish_cache_info(&self, source: impl Read) -> Result<PublishOutcome, StorageError> {
        self.publish(PublishTarget::CacheInfo, source)
    }

    pub fn publish_nar(
        &self,
        id: &NarObjectId,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
    ) -> Result<PublishOutcome, StorageError> {
        if expected_length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }

        let required_bytes = expected_length.saturating_add(policy.min_free_bytes);
        self.publish_with_admission(
            PublishTarget::Nar(id),
            CheckedNarReader::new(source, &id.0, expected_length),
            || {
                let directory = self.nar_temp_directory()?;
                filesystem_space(&directory)?.required_capacity(required_bytes)
            },
            |_| Ok(()),
        )
    }

    #[cfg(test)]
    fn publish_nar_unchecked(
        &self,
        id: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish(PublishTarget::Nar(id), source)
    }

    #[cfg(test)]
    fn publish_nar_fault(
        &self,
        id: &NarObjectId,
        source: impl Read,
        fault: PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(PublishTarget::Nar(id), source, |boundary| {
            injected_fault(boundary, fault)
        })
    }

    pub fn publish_narinfo(
        &self,
        store: &StoreHash,
        narinfo: ValidatedNarInfo,
    ) -> Result<PublishOutcome, StorageError> {
        let (nar, nar_size, bytes) = narinfo.into_parts();
        let nar_directory = self.nar_directory()?;
        let nar_name = format!("{}.nar", nar.as_str());
        match open_regular_at(&nar_directory, OsStr::new(&nar_name)) {
            Ok(file) if file.metadata()?.len() == nar_size => {}
            Ok(_) => return Err(StorageError::NarMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::MissingNar);
            }
            Err(error) => return Err(error.into()),
        }
        self.publish(PublishTarget::NarInfo(store), Cursor::new(bytes))
    }

    #[cfg(test)]
    fn publish_narinfo_unchecked(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.ensure_nar(nar)?;
        self.publish(PublishTarget::NarInfo(store), source)
    }

    #[cfg(test)]
    fn publish_narinfo_fault(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
        source: impl Read,
        fault: PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.ensure_nar(nar)?;
        self.publish_with(PublishTarget::NarInfo(store), source, |boundary| {
            injected_fault(boundary, fault)
        })
    }

    #[cfg(test)]
    fn ensure_nar(&self, nar: &NarObjectId) -> Result<(), StorageError> {
        let nar_directory = self.nar_directory()?;
        let nar_name = format!("{}.nar", nar.as_str());
        match open_regular_at(&nar_directory, OsStr::new(&nar_name)) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(StorageError::MissingNar),
            Err(error) => Err(error.into()),
        }
    }

    pub fn open_nar(&self, nar: &NarObjectId) -> Result<Option<File>, StorageError> {
        let directory = self.nar_directory()?;
        let name = format!("{}.nar", nar.as_str());
        open_optional_at(&directory, OsStr::new(&name))
    }

    pub fn open_narinfo(&self, store: &StoreHash) -> Result<Option<File>, StorageError> {
        let directory = self.root_directory()?;
        let name = format!("{}.narinfo", store.as_str());
        open_optional_at(&directory, OsStr::new(&name))
    }

    pub fn open_pair(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
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

    fn publish(
        &self,
        target: PublishTarget<'_>,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(target, source, |_| Ok(()))
    }

    fn publish_with(
        &self,
        target: PublishTarget<'_>,
        source: impl Read,
        checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with_admission(target, source, || Ok(()), checkpoint)
    }

    fn publish_with_admission(
        &self,
        target: PublishTarget<'_>,
        mut source: impl Read,
        admit: impl FnOnce() -> Result<(), StorageError>,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        let _publication = self
            .publication_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        admit()?;
        self.recovery.require()?;
        let destination_directory = self.destination_directory(&target)?;
        let destination_name = target.destination_name();
        checkpoint(PublishBoundary::BeforeTempCreate)?;
        let mut temp = self.create_temp(&target)?;
        let result = (|| {
            checkpoint(PublishBoundary::AfterTempCreate)?;
            io::copy(&mut source, &mut temp.file)?;
            checkpoint(PublishBoundary::AfterStream)?;
            temp.file.sync_all()?;
            checkpoint(PublishBoundary::AfterTempSync)?;
            checkpoint(PublishBoundary::BeforeFinalLink)?;

            match hard_link_at(
                &temp.directory,
                &temp.name,
                &destination_directory,
                &destination_name,
            ) {
                Ok(()) => {
                    if let Err(error) = checkpoint(PublishBoundary::BeforeParentSync) {
                        rollback_link_at(&destination_directory, &destination_name)?;
                        return Err(error);
                    }
                    if let Err(error) = destination_directory.sync_all() {
                        rollback_link_at(&destination_directory, &destination_name)?;
                        return Err(error.into());
                    }
                    checkpoint(PublishBoundary::AfterParentSync)?;
                    Ok(PublishOutcome::Created)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if files_equal_at(
                        &temp.directory,
                        &temp.name,
                        &destination_directory,
                        &destination_name,
                    )? {
                        Ok(PublishOutcome::Identical)
                    } else {
                        Err(StorageError::Conflict)
                    }
                }
                Err(error) => Err(error.into()),
            }
        })();

        let cleanup = remove_temp(&temp).map_err(StorageError::from);

        match result {
            Ok(outcome) => {
                cleanup?;
                self.recovery.finish_publication()?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = cleanup;
                Err(error)
            }
        }
    }

    fn create_temp(&self, target: &PublishTarget<'_>) -> Result<TemporaryFile, StorageError> {
        let directory = match target {
            PublishTarget::Nar(_) => self.nar_temp_directory()?,
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) => self.temp_directory()?,
        };
        let prefix = target.temp_prefix();
        for _ in 0..TEMP_ATTEMPTS {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!("{prefix}-{}-{sequence:016x}.part", process::id()));
            match open_at(
                &directory,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            ) {
                Ok(file) => {
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                    return Ok(TemporaryFile {
                        name,
                        directory,
                        file,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate unique temporary file",
        )
        .into())
    }

    fn root_directory(&self) -> Result<File, StorageError> {
        Ok(self.root.try_clone()?)
    }

    fn nar_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new("nar"))?)
    }

    fn temp_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new(".tmp"))?)
    }

    fn nar_temp_directory(&self) -> Result<File, StorageError> {
        let nar = self.nar_directory()?;
        Ok(open_directory_at(&nar, OsStr::new(".tmp"))?)
    }

    fn realisations_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new("realisations"))?)
    }

    fn realisations_temp_directory(&self) -> Result<File, StorageError> {
        let realisations = self.realisations_directory()?;
        Ok(open_directory_at(&realisations, OsStr::new(".tmp"))?)
    }

    fn destination_directory(&self, target: &PublishTarget<'_>) -> Result<File, StorageError> {
        match target {
            PublishTarget::Nar(_) => self.nar_directory(),
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) => self.root_directory(),
        }
    }
}

#[derive(Debug)]
pub struct PublishedPair {
    pub nar: File,
    pub narinfo: File,
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

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapacityErrorKind {
    NoSpace,
    Quota,
    Inodes,
    ReadOnly,
    Other,
}

pub(crate) fn capacity_error_kind(raw_error: i32) -> CapacityErrorKind {
    match raw_error {
        libc::ENOSPC => CapacityErrorKind::NoSpace,
        libc::EDQUOT => CapacityErrorKind::Quota,
        libc::EROFS => CapacityErrorKind::ReadOnly,
        _ => CapacityErrorKind::Other,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilesystemSpace {
    available_bytes: u64,
    available_inodes: u64,
}

impl FilesystemSpace {
    fn required_capacity(self, required_bytes: u64) -> Result<(), StorageError> {
        if self.available_bytes < required_bytes {
            return Err(StorageError::InsufficientSpace);
        }
        if self.available_inodes == 0 {
            return Err(StorageError::InsufficientInodes);
        }
        Ok(())
    }
}

fn filesystem_space(directory: &File) -> io::Result<FilesystemSpace> {
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();

    // SAFETY: directory owns a valid descriptor for the duration of the call,
    // and statistics points to writable storage for one statvfs value.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fstatvfs returned success, so it initialized statistics.
    let statistics = unsafe { statistics.assume_init() };
    let available = (statistics.f_bavail as u128).saturating_mul(statistics.f_frsize as u128);
    let inodes = statistics.f_favail as u128;
    Ok(FilesystemSpace {
        available_bytes: available.min(u128::from(u64::MAX)) as u64,
        available_inodes: inodes.min(u128::from(u64::MAX)) as u64,
    })
}

fn ensure_directory(path: &Path, name: &str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && metadata.permissions().mode() & 0o022 == 0 => Ok(()),
        Ok(metadata) if metadata.is_dir() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} has unsafe permissions: {}", path.display()),
        )),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} is not a directory: {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path),
        Err(error) => Err(error),
    }
}

fn ensure_directory_at(parent: &File, name: &OsStr, label: &str) -> io::Result<File> {
    match open_directory_at(parent, name) {
        Ok(directory) => validate_directory(&directory, label),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = CString::new(name.as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "storage entry name contains a NUL byte",
                )
            })?;
            // SAFETY: parent owns a live directory descriptor, name is
            // NUL-terminated, and mkdirat does not retain the pointer.
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            let directory = open_directory_at(parent, OsStr::from_bytes(name.as_bytes()))?;
            validate_directory(&directory, label)
        }
        Err(error) => Err(error),
    }
}

fn validate_directory(directory: &File, name: &str) -> io::Result<File> {
    if directory.metadata()?.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} has unsafe permissions"),
        ));
    }
    directory.try_clone()
}

pub(crate) fn open_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a directory", path.display()),
        ));
    }
    Ok(directory)
}

pub(crate) fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let directory = open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a directory", name.to_string_lossy()),
        ));
    }
    Ok(directory)
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

pub(crate) fn open_regular_at(directory: &File, name: &OsStr) -> io::Result<File> {
    let file = open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", name.to_string_lossy()),
        ));
    }
    Ok(file)
}

pub(crate) fn entry_is_regular_at(directory: &File, name: &OsStr) -> io::Result<bool> {
    Ok(entry_mode_at(directory, name)? & libc::S_IFMT == libc::S_IFREG)
}

pub(crate) fn entry_is_directory_at(directory: &File, name: &OsStr) -> io::Result<bool> {
    Ok(entry_mode_at(directory, name)? & libc::S_IFMT == libc::S_IFDIR)
}

pub(crate) fn entry_identity_at(directory: &File, name: &OsStr) -> io::Result<(u64, u64)> {
    let metadata = entry_stat_at(directory, name)?;
    Ok((metadata.st_dev as u64, metadata.st_ino as u64))
}

fn entry_mode_at(directory: &File, name: &OsStr) -> io::Result<libc::mode_t> {
    Ok(entry_stat_at(directory, name)?.st_mode as libc::mode_t)
}

fn entry_stat_at(directory: &File, name: &OsStr) -> io::Result<libc::stat> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory owns a live descriptor, name is NUL-terminated, and
    // metadata points to writable storage for one stat value.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned success, so it initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    Ok(metadata)
}

fn open_optional_at(directory: &File, name: &OsStr) -> Result<Option<File>, StorageError> {
    match open_regular_at(directory, name) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn open_at(parent: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: parent owns a live directory descriptor, name is NUL-terminated,
    // and the returned descriptor is transferred to File exactly once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn read_dir_names(directory: &File) -> io::Result<Vec<OsString>> {
    let directory = open_at(
        directory,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    let fd = directory.into_raw_fd();
    // SAFETY: fd is a newly opened directory descriptor. On success,
    // fdopendir transfers ownership to the DIR handle.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and did not transfer ownership.
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    let mut names = Vec::new();
    loop {
        // SAFETY: stream is a live DIR handle and remains valid until the
        // matching closedir below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is a NUL-terminated entry name owned by stream and is
        // copied before the next readdir call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(OsStr::from_bytes(name.to_bytes()).to_owned());
        }
    }

    // SAFETY: stream is the sole owner of the duplicated descriptor now.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(names)
}

fn rollback_link_at(directory: &File, name: &OsStr) -> Result<(), StorageError> {
    unlink_at(directory, name)?;
    directory.sync_all()?;
    Ok(())
}

fn lock_exclusive(file: &File) -> Result<(), StorageError> {
    // SAFETY: file owns this live descriptor for the entire call. flock neither
    // dereferences Rust memory nor retains the descriptor after returning.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    let code = error.raw_os_error();
    if error.kind() == io::ErrorKind::WouldBlock
        || code == Some(libc::EAGAIN)
        || code == Some(libc::EWOULDBLOCK)
    {
        Err(StorageError::Locked)
    } else {
        Err(error.into())
    }
}

#[cfg(test)]
fn sync_dir(path: &Path) -> io::Result<()> {
    open_directory(path)?.sync_all()
}

fn files_equal_at(
    left_directory: &File,
    left_name: &OsStr,
    right_directory: &File,
    right_name: &OsStr,
) -> io::Result<bool> {
    let mut left = open_regular_at(left_directory, left_name)?;
    let mut right = open_regular_at(right_directory, right_name)?;
    if left.metadata()?.len() != right.metadata()?.len() {
        return Ok(false);
    }

    let mut left_buffer = [0; COMPARE_BUFFER_BYTES];
    let mut right_buffer = [0; COMPARE_BUFFER_BYTES];

    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn hard_link_at(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source_name = CString::new(source_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    let destination_name = CString::new(destination_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: both directory descriptors are live, both names are
    // NUL-terminated, and linkat does not retain either pointer.
    let result = unsafe {
        libc::linkat(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            destination_directory.as_raw_fd(),
            destination_name.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_at(directory: &File, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: directory owns a live descriptor, name is NUL-terminated, and
    // unlinkat does not retain the pointer.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove_temp(temp: &TemporaryFile) -> io::Result<()> {
    unlink_at(&temp.directory, &temp.name).and_then(|()| temp.directory.sync_all())
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::{self, Cursor, Read},
        num::NonZeroUsize,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        process,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        time::{Duration, SystemTime},
    };

    use super::{
        CapacityErrorKind, FilesystemSpace, Layout, NarObjectId, PublishBoundary, PublishOutcome,
        PublishTarget, ReconcileClass, Storage, StorageError, StoreHash, capacity_error_kind,
        remove_temp, sync_dir,
    };

    const NAR_ID: &str = "0000000000000000000000000000000000000000000000000000";
    const STORE_HASH: &str = "00000000000000000000000000000000";

    #[test]
    fn validated_ids_map_to_exact_layout_paths() {
        let layout = Layout::new(PathBuf::from("/cache"));
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

        assert_eq!(
            layout.nar_path(&nar),
            PathBuf::from(format!("/cache/nar/{NAR_ID}.nar"))
        );
        assert_eq!(
            layout.narinfo_path(&store),
            PathBuf::from(format!("/cache/{STORE_HASH}.narinfo"))
        );
        assert_eq!(layout.temp_dir(), PathBuf::from("/cache/.tmp"));
    }

    #[test]
    fn ids_reject_wrong_length_and_non_nix32_bytes() {
        for value in [
            "",
            "0",
            "0000000000000000000000000000000",
            "000000000000000000000000000000000",
            "0000000000000000000000000000000/",
            "0000000000000000000000000000000e",
            "0000000000000000000000000000000A",
        ] {
            assert!(
                StoreHash::parse(value).is_err(),
                "accepted invalid store hash: {value:?}"
            );
        }

        for value in [
            &NAR_ID[..51],
            "00000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000e",
            "../0000000000000000000000000000000000000000000000000",
        ] {
            assert!(
                NarObjectId::parse(value).is_err(),
                "accepted invalid NAR object id: {value:?}"
            );
        }
    }

    #[test]
    fn initialization_creates_only_the_fixed_layout() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");

        assert!(directory.path().join("nar").is_dir());
        assert!(directory.path().join("nar/.tmp").is_dir());
        assert!(directory.path().join(".tmp").is_dir());
        assert!(directory.path().join("realisations").is_dir());
        assert!(directory.path().join("realisations/.tmp").is_dir());
        assert_eq!(storage.layout(), &Layout::new(directory.path().to_owned()));
    }

    #[test]
    fn initialization_rejects_a_symlinked_data_directory() {
        let directory = TestDir::new();
        let target = directory.path().join("target");
        let link = directory.path().join("data");
        fs::create_dir(&target).expect("create symlink target");
        symlink(&target, &link).expect("create data directory symlink");

        let error = Storage::initialize(&link).expect_err("symlinked data must be rejected");
        assert!(error.to_string().contains("data directory"));
        assert!(!target.join("nar").exists());
        assert!(!target.join(".tmp").exists());
        assert!(!target.join("realisations").exists());
    }

    #[test]
    fn initialization_rejects_a_symlinked_lock() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        drop(storage);

        let target = directory.path().join("lock-target");
        let lock = directory.path().join("lock");
        fs::write(&target, b"external lock").expect("create lock target");
        fs::remove_file(&lock).expect("remove original lock");
        symlink(&target, &lock).expect("create lock symlink");

        let error = Storage::initialize(directory.path()).expect_err("symlinked lock must fail");
        assert!(error.to_string().contains("lock"));
    }

    #[test]
    fn initialization_rejects_writable_storage_directories() {
        let directory = TestDir::new();
        let nar = directory.path().join("nar");
        fs::create_dir(&nar).expect("create NAR directory");
        fs::set_permissions(&nar, fs::Permissions::from_mode(0o777))
            .expect("make NAR directory writable");

        let error = Storage::initialize(directory.path())
            .expect_err("writable storage directory must be rejected");
        assert!(error.to_string().contains("nar directory"));
    }

    #[test]
    fn temporary_publication_files_are_private() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let temporary = storage
            .create_temp(&PublishTarget::CacheInfo)
            .expect("create temporary publication file");

        assert_eq!(
            temporary
                .file
                .metadata()
                .expect("read temp metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        remove_temp(&temporary).expect("remove temporary publication file");
    }

    #[test]
    fn nar_publication_uses_a_destination_local_temporary_directory() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");

        let temporary = storage
            .create_temp(&PublishTarget::Nar(&nar))
            .expect("create NAR temporary publication file");
        assert_eq!(
            fs::read_dir(storage.layout().temp_dir())
                .expect("read metadata temporary directory")
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(storage.layout().nar_temp_dir())
                .expect("read NAR temporary directory")
                .count(),
            1
        );
        remove_temp(&temporary).expect("remove NAR temporary publication file");
    }

    #[test]
    fn directory_sync_rejects_a_symlinked_directory() {
        let directory = TestDir::new();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::create_dir(&target).expect("create sync target");
        symlink(&target, &link).expect("create sync directory symlink");

        assert!(sync_dir(&link).is_err());
    }

    #[test]
    fn publication_rejects_a_symlinked_temporary_directory() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let temporary = storage.layout.nar_temp_dir();
        let real_temporary = directory.path().join("nar-tmp-real");
        let target = directory.path().join("external");
        fs::rename(&temporary, &real_temporary).expect("move real temporary directory");
        fs::create_dir(&target).expect("create external directory");
        symlink(&target, &temporary).expect("create temporary directory symlink");

        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        assert!(
            storage
                .publish_nar_unchecked(&nar, Cursor::new(b"must not escape"))
                .is_err()
        );
        assert!(!storage.layout.nar_path(&nar).exists());
        assert!(
            fs::read_dir(&target)
                .expect("read external directory")
                .next()
                .is_none()
        );
    }

    #[test]
    fn publication_rejects_a_symlinked_destination_directory() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        let nar_dir = storage.layout.nar_dir();
        let real_nar_dir = directory.path().join("nar-real");
        let external = directory.path().join("external");
        let external_nar = external.join(format!("{NAR_ID}.nar"));
        fs::rename(&nar_dir, &real_nar_dir).expect("move real NAR directory");
        fs::create_dir(&external).expect("create external directory");
        fs::write(&external_nar, b"must not be compared").expect("write external NAR");
        symlink(&external, &nar_dir).expect("create NAR directory symlink");

        assert!(
            storage
                .publish_nar_unchecked(&nar, Cursor::new(b"must not be compared"))
                .is_err()
        );
        assert_eq!(
            fs::read(&external_nar).expect("read external NAR"),
            b"must not be compared"
        );
    }

    #[test]
    fn reconciliation_rejects_a_symlinked_nar_directory() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("storage should initialize");
        let nar_dir = storage.layout.nar_dir();
        let real_nar_dir = directory.path().join("nar-real");
        let external = directory.path().join("external");
        fs::rename(&nar_dir, &real_nar_dir).expect("move real NAR directory");
        fs::create_dir(&external).expect("create external directory");
        fs::write(
            external.join("0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar"),
            b"external",
        )
        .expect("write external NAR");
        symlink(&external, &nar_dir).expect("create NAR directory symlink");

        assert!(
            storage
                .reconcile(
                    NonZeroUsize::new(32).expect("non-zero limit"),
                    SystemTime::now()
                )
                .is_err()
        );
    }

    #[test]
    fn delete_rejects_a_symlinked_narinfo() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("storage should initialize");
        let store = StoreHash::parse(STORE_HASH).expect("valid store hash");
        let target = directory.path().join("external-narinfo");
        let link = directory.path().join(format!("{STORE_HASH}.narinfo"));
        fs::write(&target, b"external narinfo").expect("write external narinfo");
        symlink(&target, &link).expect("create narinfo symlink");

        assert!(storage.delete_narinfo(&store).is_err());
        assert!(link.exists());
        assert_eq!(
            fs::read(&target).expect("read external narinfo"),
            b"external narinfo"
        );
    }

    #[test]
    fn recovery_marker_distinguishes_clean_and_interrupted_publication() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");

        assert!(
            !storage
                .recovery_required()
                .expect("inspect clean recovery marker")
        );
        assert!(
            storage
                .publish_nar_fault(
                    &nar,
                    Cursor::new(b"nar bytes"),
                    PublishBoundary::AfterTempCreate
                )
                .is_err()
        );
        assert!(
            storage
                .recovery_required()
                .expect("inspect interrupted recovery marker")
        );
    }

    #[test]
    fn publication_is_immutable_idempotent_and_pair_gated() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

        assert_eq!(
            storage
                .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
                .expect("publish NAR"),
            PublishOutcome::Created
        );
        assert_eq!(
            storage
                .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
                .expect("retry identical NAR"),
            PublishOutcome::Identical
        );
        assert!(matches!(
            storage.publish_nar_unchecked(&nar, Cursor::new(b"different")),
            Err(StorageError::Conflict)
        ));
        assert!(
            storage
                .open_pair(&store, &nar)
                .expect("check incomplete pair")
                .is_none(),
            "an orphan NAR must not make a store path visible"
        );

        assert_eq!(
            storage
                .publish_narinfo_unchecked(&store, &nar, Cursor::new(b"narinfo bytes"))
                .expect("publish narinfo"),
            PublishOutcome::Created
        );
        assert_eq!(
            storage
                .publish_narinfo_unchecked(&store, &nar, Cursor::new(b"narinfo bytes"))
                .expect("retry identical narinfo"),
            PublishOutcome::Identical
        );
        assert!(matches!(
            storage.publish_narinfo_unchecked(&store, &nar, Cursor::new(b"different")),
            Err(StorageError::Conflict)
        ));

        let mut pair = storage
            .open_pair(&store, &nar)
            .expect("open durable pair")
            .expect("pair should be visible");
        let mut nar_bytes = Vec::new();
        let mut narinfo_bytes = Vec::new();
        pair.nar.read_to_end(&mut nar_bytes).expect("read NAR");
        pair.narinfo
            .read_to_end(&mut narinfo_bytes)
            .expect("read narinfo");
        assert_eq!(nar_bytes, b"nar bytes");
        assert_eq!(narinfo_bytes, b"narinfo bytes");
        assert!(
            fs::read_dir(storage.layout().temp_dir())
                .expect("read temp directory")
                .next()
                .is_none(),
            "completed attempts must not leave temporary files"
        );
    }

    #[test]
    fn failed_publisher_cannot_invalidate_concurrent_identical_success() {
        let directory = TestDir::new();
        let storage = Arc::new(Storage::initialize(directory.path()).expect("initialize storage"));
        let (linked_tx, linked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let winner = {
            let storage = Arc::clone(&storage);
            std::thread::spawn(move || {
                let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
                storage.publish_with(
                    PublishTarget::Nar(&nar),
                    Cursor::new(b"nar bytes"),
                    |boundary| {
                        if boundary == PublishBoundary::BeforeParentSync {
                            linked_tx.send(()).expect("signal linked destination");
                            release_rx.recv().expect("release failing publisher");
                            return Err(io::Error::other("injected parent sync failure").into());
                        }
                        Ok(())
                    },
                )
            })
        };

        linked_rx.recv().expect("wait for linked destination");
        let (started_tx, started_rx) = mpsc::channel();
        let (outcome_tx, outcome_rx) = mpsc::channel();
        let contender = {
            let storage = Arc::clone(&storage);
            std::thread::spawn(move || {
                let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
                started_tx.send(()).expect("signal contender start");
                let outcome = storage.publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"));
                outcome_tx.send(outcome).expect("send contender outcome");
            })
        };

        started_rx.recv().expect("wait for contender");
        let early_outcome = outcome_rx.recv_timeout(Duration::from_millis(500)).ok();
        release_tx.send(()).expect("release failing publisher");

        assert!(winner.join().expect("join failing publisher").is_err());
        let outcome = match early_outcome {
            Some(outcome) => outcome,
            None => outcome_rx.recv().expect("wait for contender outcome"),
        };
        contender.join().expect("join contender");
        assert_eq!(
            outcome.expect("concurrent identical publication"),
            PublishOutcome::Created
        );

        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        assert!(storage.layout().nar_path(&nar).exists());
    }

    #[test]
    fn each_failed_pre_durable_boundary_leaves_no_final_or_temp() {
        for boundary in [
            PublishBoundary::BeforeTempCreate,
            PublishBoundary::AfterTempCreate,
            PublishBoundary::AfterStream,
            PublishBoundary::AfterTempSync,
            PublishBoundary::BeforeFinalLink,
            PublishBoundary::BeforeParentSync,
        ] {
            let directory = TestDir::new();
            let storage = Storage::initialize(directory.path()).expect("initialize storage");
            let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");

            assert!(
                storage
                    .publish_nar_fault(&nar, Cursor::new(b"nar bytes"), boundary)
                    .is_err(),
                "{boundary:?} unexpectedly succeeded"
            );
            assert!(
                !storage.layout().nar_path(&nar).exists(),
                "{boundary:?} left a final NAR"
            );
            assert!(
                fs::read_dir(storage.layout().temp_dir())
                    .expect("read temp directory")
                    .next()
                    .is_none(),
                "{boundary:?} left a temporary file"
            );
        }
    }

    #[test]
    fn response_loss_after_parent_sync_is_visible_and_idempotent() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

        assert!(
            storage
                .publish_nar_fault(
                    &nar,
                    Cursor::new(b"nar bytes"),
                    PublishBoundary::AfterParentSync,
                )
                .is_err()
        );
        assert_eq!(
            storage
                .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
                .expect("retry durable NAR"),
            PublishOutcome::Identical
        );

        assert!(
            storage
                .publish_narinfo_fault(
                    &store,
                    &nar,
                    Cursor::new(b"narinfo bytes"),
                    PublishBoundary::AfterParentSync,
                )
                .is_err()
        );
        assert!(
            storage
                .open_pair(&store, &nar)
                .expect("open durable pair")
                .is_some(),
            "a parent-synced pair must remain visible after response loss"
        );
        assert_eq!(
            storage
                .publish_narinfo_unchecked(&store, &nar, Cursor::new(b"narinfo bytes"))
                .expect("retry durable narinfo"),
            PublishOutcome::Identical
        );
    }

    #[test]
    fn stream_resource_failures_leave_no_false_publication_state() {
        for raw_error in [libc::EIO, libc::ENOSPC] {
            let directory = TestDir::new();
            let storage = Storage::initialize(directory.path()).expect("initialize storage");
            let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");

            let error = storage
                .publish_nar_unchecked(&nar, BrokenReader::new(raw_error))
                .expect_err("stream failure must reject publication");
            let StorageError::Io(error) = error else {
                panic!("stream failure returned a non-I/O error");
            };
            assert_eq!(error.raw_os_error(), Some(raw_error));
            assert!(!storage.layout().nar_path(&nar).exists());
            assert!(
                fs::read_dir(storage.layout().temp_dir())
                    .expect("read temp directory")
                    .next()
                    .is_none()
            );
        }
    }

    #[test]
    fn destination_capacity_rejects_inode_exhaustion() {
        let space = FilesystemSpace {
            available_bytes: u64::MAX,
            available_inodes: 0,
        };

        assert!(matches!(
            space.required_capacity(1),
            Err(StorageError::InsufficientInodes)
        ));
    }

    #[test]
    fn capacity_errors_have_stable_categories() {
        assert_eq!(
            capacity_error_kind(libc::ENOSPC),
            CapacityErrorKind::NoSpace
        );
        assert_eq!(capacity_error_kind(libc::EDQUOT), CapacityErrorKind::Quota);
        assert_eq!(
            capacity_error_kind(libc::EROFS),
            CapacityErrorKind::ReadOnly
        );
    }

    struct BrokenReader {
        raw_error: i32,
        returned_prefix: bool,
    }

    impl BrokenReader {
        fn new(raw_error: i32) -> Self {
            Self {
                raw_error,
                returned_prefix: false,
            }
        }
    }

    impl Read for BrokenReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.returned_prefix {
                return Err(io::Error::from_raw_os_error(self.raw_error));
            }

            self.returned_prefix = true;
            buffer[..3].copy_from_slice(b"nar");
            Ok(3)
        }
    }

    #[test]
    fn process_lock_is_exclusive_and_released_on_drop() {
        let directory = TestDir::new();
        let first = Storage::initialize(directory.path()).expect("acquire first process lock");

        assert!(directory.path().join("lock").is_file());
        assert!(matches!(
            Storage::initialize(directory.path()),
            Err(StorageError::Locked)
        ));

        drop(first);
        Storage::initialize(directory.path()).expect("reacquire released process lock");
    }

    #[test]
    fn reconciliation_is_deterministic_bounded_and_reports_manual_changes() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        fs::write(directory.path().join("manual"), b"manual").expect("write manual file");
        fs::write(directory.path().join("nar/not-valid.nar"), b"bad").expect("write malformed NAR");
        fs::write(directory.path().join(".tmp/nar-manual.part"), b"temp")
            .expect("write temporary file");

        let stale_before = SystemTime::now() + Duration::from_secs(1);
        let full = storage
            .reconcile(NonZeroUsize::new(16).expect("nonzero limit"), stale_before)
            .expect("reconcile storage");
        let paths: Vec<_> = full
            .entries()
            .iter()
            .map(|entry| entry.relative_path().to_owned())
            .collect();
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(full.entries().iter().any(|entry| {
            entry.relative_path() == Path::new("manual")
                && entry.class() == ReconcileClass::UnknownFile
        }));
        assert!(full.entries().iter().any(|entry| {
            entry.relative_path() == Path::new("nar/not-valid.nar")
                && entry.class() == ReconcileClass::InvalidFilename
        }));
        assert!(full.entries().iter().any(|entry| {
            entry.relative_path() == Path::new(".tmp/nar-manual.part")
                && entry.class() == ReconcileClass::TempStale
        }));

        let bounded = storage
            .reconcile(NonZeroUsize::new(1).expect("nonzero limit"), stale_before)
            .expect("bounded reconcile");
        assert_eq!(bounded.entries().len(), 1);
        assert!(bounded.truncated());
        assert_eq!(bounded.entries()[0].relative_path(), paths[0]);
    }

    #[test]
    fn cleanup_removes_only_reported_stale_temps() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let stale_path = directory.path().join(".tmp/nar-stale.part");
        fs::write(&stale_path, b"temp").expect("write stale temp");

        let stale_report = storage
            .reconcile(
                NonZeroUsize::new(16).expect("nonzero limit"),
                SystemTime::now() + Duration::from_secs(1),
            )
            .expect("classify stale temp");
        let stale = stale_report
            .entries()
            .iter()
            .find(|entry| entry.relative_path() == Path::new(".tmp/nar-stale.part"))
            .expect("stale temp entry");
        assert_eq!(stale.class(), ReconcileClass::TempStale);
        assert!(
            storage
                .cleanup_stale_temp(stale)
                .expect("cleanup stale temp")
        );
        assert!(!stale_path.exists());

        let young_path = directory.path().join(".tmp/nar-young.part");
        fs::write(&young_path, b"temp").expect("write young temp");
        let young_report = storage
            .reconcile(
                NonZeroUsize::new(16).expect("nonzero limit"),
                SystemTime::now()
                    .checked_sub(Duration::from_secs(1))
                    .expect("past time"),
            )
            .expect("classify young temp");
        let young = young_report
            .entries()
            .iter()
            .find(|entry| entry.relative_path() == Path::new(".tmp/nar-young.part"))
            .expect("young temp entry");
        assert_eq!(young.class(), ReconcileClass::TempYoung);
        assert!(!storage.cleanup_stale_temp(young).expect("keep young temp"));
        assert!(young_path.exists());
    }

    #[test]
    fn safe_delete_removes_only_narinfo_and_syncs_visibility() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        let store = StoreHash::parse(STORE_HASH).expect("valid store hash");
        storage
            .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
            .expect("publish NAR");
        storage
            .publish_narinfo_unchecked(&store, &nar, Cursor::new(b"narinfo bytes"))
            .expect("publish narinfo");

        assert!(storage.delete_narinfo(&store).expect("delete narinfo"));
        assert!(
            storage
                .open_pair(&store, &nar)
                .expect("open deleted pair")
                .is_none()
        );
        assert!(storage.layout().nar_path(&nar).is_file());
        assert!(!storage.delete_narinfo(&store).expect("repeat delete"));
    }

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "narjar-storage-test-{}-{}",
                process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }
}
