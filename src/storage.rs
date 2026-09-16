use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fmt,
    fs::{File, Permissions},
    io::{self, Cursor, Read},
    num::NonZeroUsize,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use data_encoding::{BitOrder, Encoding, Specification};
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::narinfo::CompressedEncoding;
use crate::narinfo::{CompressedNarExpectation, NarEncoding, NarExpectation, ValidatedNarInfo};

mod compression;
mod fs;
pub mod gc;
pub(crate) mod inspection;
mod operations;
mod reconcile;
mod recovery;

use compression::{
    CheckedUploadReader, ValidationEvidence, nar_encoding, nar_file_matches, nar_file_size_matches,
    validate_compressed_nar, validate_xz, validate_zstd, validation_file_name,
};
#[cfg(test)]
use compression::{
    DecodedValidation, verify_decoded_compressed_file, verify_encoded_compressed_file,
};
pub(crate) use fs::{
    CapacityErrorKind, StorageCapacity, capacity_error_kind, entry_identity_at,
    entry_is_directory_at, entry_is_regular_at, for_each_dir_name, open_directory_at,
    open_regular_at, read_dir_names,
};
#[cfg(test)]
use fs::{FilesystemSpace, sync_dir};
use fs::{
    directory_is_empty, ensure_directory_at, files_equal_at, filesystem_space, hard_link_at,
    lock_exclusive, open_at, open_directory, open_optional_at, remove_temp, rename_at,
    require_directory_at, require_private_file_at, reserve_staging_bytes, rollback_link_at,
    unlink_at,
};

pub use reconcile::{ReconcileClass, ReconcileEntry, ReconcileReport};
use recovery::{PublicationState, RecoveryState};

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const NIX32_SHA256_LEN: usize = 52;
const COMPARE_BUFFER_BYTES: usize = 16 * 1024;
const MAX_CACHE_INFO_BYTES: u64 = 1024;
const VALIDATION_DIRECTORY: &str = ".narjar-validation";
const VALIDATION_EVIDENCE_VERSION: u8 = 1;
const MAX_VALIDATION_EVIDENCE_BYTES: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidObjectId;

impl fmt::Display for InvalidObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Nix base-32 object identifier")
    }
}

impl std::error::Error for InvalidObjectId {}

#[derive(Debug)]
pub struct Directory {
    file: File,
    #[cfg(test)]
    path: PathBuf,
}

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = open_directory(path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidData => {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("data directory is not a directory: {}", path.display()),
                )
            }
            _ if error.raw_os_error() == Some(libc::ELOOP) => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("data directory is not a directory: {}", path.display()),
            ),
            _ => error,
        })?;
        if file.metadata()?.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("data directory has unsafe permissions: {}", path.display()),
            ));
        }
        Ok(Self {
            file,
            #[cfg(test)]
            path: path.to_owned(),
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub fn validate_initialized(&self) -> io::Result<()> {
        let nar = require_directory_at(&self.file, "nar")?;
        require_directory_at(&nar, ".tmp")?;
        require_directory_at(&self.file, ".tmp")?;
        let realisations = require_directory_at(&self.file, "realisations")?;
        require_directory_at(&realisations, ".tmp")?;
        let auth = require_directory_at(&self.file, "auth")?;
        for name in ["nix-cache-info", "trusted-public-keys"] {
            require_private_file_at(&self.file, name, true)?;
        }
        require_private_file_at(&auth, "write.tokens", true)?;
        let clean = require_private_file_at(&self.file, ".narjar-clean", false)?;
        let recovery = require_private_file_at(&self.file, ".narjar-recovery", false)?;
        if clean || recovery {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "data directory is not initialized",
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NarObjectId(String);

impl NarObjectId {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        parse_nix32(value, 52).map(Self)
    }

    pub(crate) fn validate(value: &str) -> Result<(), InvalidObjectId> {
        valid_nix32(value, 52).then_some(()).ok_or(InvalidObjectId)
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

    pub(crate) fn validate(value: &str) -> Result<(), InvalidObjectId> {
        valid_nix32(value, 32).then_some(()).ok_or(InvalidObjectId)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_nix32(value: &str, expected_len: usize) -> Result<String, InvalidObjectId> {
    valid_nix32(value, expected_len)
        .then(|| value.to_owned())
        .ok_or(InvalidObjectId)
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

fn valid_nix32(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|byte| NIX32.as_bytes().contains(&byte))
}

fn nix32_encoding() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut specification = Specification::new();
        specification.symbols.push_str(NIX32);
        specification.bit_order = BitOrder::LeastSignificantFirst;
        specification
            .encoding()
            .expect("Nix base32 specification is valid")
    })
}

fn nix32_sha256(digest: &[u8]) -> String {
    let encoding = nix32_encoding();
    let mut encoded = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(digest, &mut encoded);
    encoded.reverse();
    String::from_utf8(encoded).expect("Nix base32 encoding is ASCII")
}

fn nix32_sha256_matches(digest: &[u8], expected: &str) -> bool {
    if digest.len() != Sha256::output_size() || expected.len() != NIX32_SHA256_LEN {
        return false;
    }

    let mut encoded = [0; NIX32_SHA256_LEN];
    nix32_encoding().encode_mut(digest, &mut encoded);
    encoded.reverse();
    expected.as_bytes() == encoded
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

    fn nar_dir(&self) -> PathBuf {
        self.root.join("nar")
    }

    fn nar_path(&self, id: &NarObjectId) -> PathBuf {
        self.nar_dir().join(format!("{}.nar", id.0))
    }

    fn nar_path_encoded(&self, id: &NarObjectId, encoding: NarEncoding) -> PathBuf {
        self.nar_dir()
            .join(format!("{}{}", id.0, encoding.suffix()))
    }

    fn nar_temp_dir(&self) -> PathBuf {
        self.nar_dir().join(".tmp")
    }

    fn narinfo_path(&self, hash: &StoreHash) -> PathBuf {
        self.root.join(format!("{}.narinfo", hash.0))
    }

    fn temp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }
}

enum PublishTarget<'a> {
    CacheInfo,
    Nar(&'a NarObjectId, NarEncoding),
    NarInfo(&'a StoreHash),
    Validation(&'a ValidationEvidence),
}

impl PublishTarget<'_> {
    fn destination_name(&self) -> OsString {
        match self {
            Self::CacheInfo => OsString::from("nix-cache-info"),
            Self::Nar(id, encoding) => {
                OsString::from(format!("{}{}", id.as_str(), encoding.suffix()))
            }
            Self::NarInfo(store) => OsString::from(format!("{}.narinfo", store.as_str())),
            Self::Validation(evidence) => evidence.file_name(),
        }
    }

    fn temp_prefix(&self) -> &'static str {
        match self {
            Self::CacheInfo => "cache-info",
            Self::Nar(_, _) => "nar",
            Self::NarInfo(_) => "narinfo",
            Self::Validation(_) => "validation",
        }
    }

    fn replaces_destination(&self) -> bool {
        match self {
            Self::Validation(_) => true,
            Self::CacheInfo | Self::Nar(_, _) | Self::NarInfo(_) => false,
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

/// The lease is held on the opened DATA directory, not `DATA/lock`.
///
/// This keeps replacing the lock pathname from creating a second lease. It
/// relies on local-filesystem `flock` semantics for directory file
/// descriptions; distributed filesystems are outside the supported guarantee.
#[derive(Debug)]
struct ProcessLock {
    _file: File,
}

impl ProcessLock {
    fn acquire(parent: File) -> Result<Self, StorageError> {
        lock_exclusive(&parent)?;
        Ok(Self { _file: parent })
    }

    fn validate_lock_file(root: &File) -> Result<(), StorageError> {
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
    publication_locks: Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>,
    staging_reservations: Arc<AtomicU64>,
    temporary_objects: AtomicU64,
    _lock: ProcessLock,
}

#[derive(Debug)]
pub struct StagingReservation {
    reservations: Arc<AtomicU64>,
    bytes: u64,
}

impl StagingReservation {
    fn empty(reservations: Arc<AtomicU64>) -> Self {
        Self {
            reservations,
            bytes: 0,
        }
    }
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let previous = self.reservations.fetch_sub(self.bytes, Ordering::Release);
        debug_assert!(previous >= self.bytes);
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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests;
