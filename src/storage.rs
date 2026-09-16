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
    fn layout(&self) -> &Layout {
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
        id: &NarObjectId,
        encoding: NarEncoding,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
    ) -> Result<PublishOutcome, StorageError> {
        if expected_length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }

        let required_bytes = expected_length.saturating_add(policy.min_free_bytes);
        let admit = || {
            let directory = self.nar_temp_directory()?;
            filesystem_space(&directory)?.required_capacity(required_bytes)
        };
        let validate = |file: &File| -> Result<Option<ValidationEvidence>, StorageError> {
            match encoding {
                NarEncoding::None => Ok(None),
                NarEncoding::Zstd => validate_zstd(file, None, None, policy.max_bytes)
                    .map(|decoded| {
                        Some(ValidationEvidence::from_decoded(
                            encoding,
                            id.clone(),
                            expected_length,
                            decoded,
                        ))
                    })
                    .map_err(Into::into),
                NarEncoding::Xz => validate_xz(file, None, None, policy.max_bytes)
                    .map(|decoded| {
                        Some(ValidationEvidence::from_decoded(
                            encoding,
                            id.clone(),
                            expected_length,
                            decoded,
                        ))
                    })
                    .map_err(Into::into),
            }
        };

        match encoding {
            NarEncoding::None => self.publish_with_admission(
                PublishTarget::Nar(id, encoding),
                CheckedUploadReader::new(source, &id.0, expected_length),
                admit,
                validate,
                |_| Ok(()),
            ),
            NarEncoding::Zstd | NarEncoding::Xz => self.publish_with_admission(
                PublishTarget::Nar(id, encoding),
                CheckedUploadReader::new(source, &id.0, expected_length),
                admit,
                validate,
                |_| Ok(()),
            ),
        }
    }

    #[cfg(test)]
    fn publish_nar_unchecked(
        &self,
        id: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish(PublishTarget::Nar(id, NarEncoding::None), source)
    }

    #[cfg(test)]
    fn publish_nar_fault(
        &self,
        id: &NarObjectId,
        source: impl Read,
        fault: PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(
            PublishTarget::Nar(id, NarEncoding::None),
            source,
            |boundary| injected_fault(boundary, fault),
        )
    }

    pub fn publish_narinfo(
        &self,
        store: &StoreHash,
        narinfo: ValidatedNarInfo,
    ) -> Result<PublishOutcome, StorageError> {
        let nar_directory = self.nar_directory()?;
        let expectation = narinfo.payload_expectation();
        let nar_name = narinfo.payload_name().to_string();
        match open_regular_at(&nar_directory, OsStr::new(&nar_name)) {
            Ok(file) => {
                let matches = match expectation {
                    NarExpectation::Raw { nar_size, .. } => nar_file_size_matches(&file, nar_size)?,
                    NarExpectation::Compressed(expectation) => {
                        self.compressed_nar_matches_with_evidence(&file, expectation)?
                    }
                };
                if !matches {
                    return Err(StorageError::NarMismatch);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::MissingNar);
            }
            Err(error) => return Err(error.into()),
        }
        self.publish(
            PublishTarget::NarInfo(store),
            Cursor::new(narinfo.into_bytes()),
        )
    }

    fn compressed_nar_matches_with_evidence(
        &self,
        file: &File,
        expectation: CompressedNarExpectation<'_>,
    ) -> Result<bool, StorageError> {
        if let Some(evidence) = self.read_validation_evidence(expectation)? {
            return Ok(evidence.matches(expectation));
        }

        let Some(decoded) = validate_compressed_nar(file, expectation)? else {
            return Ok(false);
        };
        self.publish_validation_evidence(ValidationEvidence::from_decoded(
            nar_encoding(expectation.encoding),
            expectation.encoded_hash.clone(),
            expectation.encoded_size,
            decoded,
        ))?;
        Ok(true)
    }

    fn read_validation_evidence(
        &self,
        expectation: CompressedNarExpectation<'_>,
    ) -> Result<Option<ValidationEvidence>, StorageError> {
        let directory = self.validation_directory()?;
        let name = validation_file_name(expectation);
        let file = match open_regular_at(&directory, &name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_VALIDATION_EVIDENCE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_VALIDATION_EVIDENCE_BYTES {
            return Ok(None);
        }
        if let Some(evidence) =
            ValidationEvidence::parse(&bytes).filter(|evidence| evidence.matches(expectation))
        {
            return Ok(Some(evidence));
        }
        Ok(None)
    }

    pub(crate) fn nar_matches(&self, narinfo: &ValidatedNarInfo) -> Result<bool, StorageError> {
        let Some(file) = self.open_nar_encoded(narinfo.nar(), narinfo.encoding())? else {
            return Ok(false);
        };
        nar_file_size_matches(&file, narinfo.file_size()).map_err(Into::into)
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
        self.open_nar_encoded(nar, NarEncoding::None)
    }

    pub fn open_nar_encoded(
        &self,
        nar: &NarObjectId,
        encoding: NarEncoding,
    ) -> Result<Option<File>, StorageError> {
        let directory = self.nar_directory()?;
        let name = format!("{}{}", nar.as_str(), encoding.suffix());
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
        self.publish_with_admission(target, source, || Ok(()), |_| Ok(None), checkpoint)
    }

    fn publish_with_admission(
        &self,
        target: PublishTarget<'_>,
        mut source: impl Read,
        admit: impl FnOnce() -> Result<(), StorageError>,
        validate: impl FnOnce(&File) -> Result<Option<ValidationEvidence>, StorageError>,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        admit()?;
        let destination_directory = self.destination_directory(&target)?;
        let destination_name = target.destination_name();
        let destination_key = self.destination_key(&target, &destination_name);
        let replace_destination = target.replaces_destination();
        let temp_name = self.next_temp_name(&target);
        let temporary_path = self.temporary_path(&target, &temp_name);
        let mut transaction = self.recovery.begin(&temporary_path)?;
        checkpoint(PublishBoundary::BeforeTempCreate)?;
        let mut temp = self.create_temp_named(&target, temp_name)?;
        transaction.transition(PublicationState::Streaming)?;
        let mut durable = false;
        let mut temp_moved = false;
        let result = (|| {
            checkpoint(PublishBoundary::AfterTempCreate)?;
            io::copy(&mut source, &mut temp.file)?;
            checkpoint(PublishBoundary::AfterStream)?;
            temp.file.sync_all()?;
            checkpoint(PublishBoundary::AfterTempSync)?;
            if let Some(evidence) = validate(&temp.file)? {
                self.publish_validation_evidence(evidence)?;
            }
            transaction.transition(PublicationState::Validated)?;
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
    fn create_temp(&self, target: &PublishTarget<'_>) -> Result<TemporaryFile, StorageError> {
        let name = self.next_temp_name(target);
        self.create_temp_named(target, name)
    }

    fn next_temp_name(&self, target: &PublishTarget<'_>) -> OsString {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        OsString::from(format!(
            "{}-{}-{sequence:016x}.part",
            target.temp_prefix(),
            process::id()
        ))
    }

    fn temporary_path(&self, target: &PublishTarget<'_>, name: &OsStr) -> PathBuf {
        match target {
            PublishTarget::Nar(_, _) => PathBuf::from("nar/.tmp").join(name),
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) | PublishTarget::Validation(_) => {
                PathBuf::from(".tmp").join(name)
            }
        }
    }

    fn create_temp_named(
        &self,
        target: &PublishTarget<'_>,
        name: OsString,
    ) -> Result<TemporaryFile, StorageError> {
        let directory = match target {
            PublishTarget::Nar(_, _) => self.nar_temp_directory()?,
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) | PublishTarget::Validation(_) => {
                self.temp_directory()?
            }
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

    fn remove_temp(&self, temp: &TemporaryFile) -> Result<(), StorageError> {
        remove_temp(temp).map_err(StorageError::from).inspect(|_| {
            self.temporary_objects.fetch_sub(1, Ordering::Relaxed);
        })
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
            PublishTarget::Nar(_, _) => self.nar_directory(),
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) => self.root_directory(),
            PublishTarget::Validation(_) => self.validation_directory(),
        }
    }

    fn destination_key(&self, target: &PublishTarget<'_>, name: &OsStr) -> PathBuf {
        match target {
            PublishTarget::Nar(_, _) => PathBuf::from("nar").join(name),
            PublishTarget::CacheInfo | PublishTarget::NarInfo(_) => PathBuf::from(name),
            PublishTarget::Validation(_) => PathBuf::from(VALIDATION_DIRECTORY).join(name),
        }
    }

    fn validation_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(open_directory_at(&root, OsStr::new(VALIDATION_DIRECTORY))?)
    }

    fn remove_orphan_validation_evidence(&self) -> Result<(), StorageError> {
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
            if NarObjectId::parse(
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

    fn publish_validation_evidence(
        &self,
        evidence: ValidationEvidence,
    ) -> Result<PublishOutcome, StorageError> {
        let bytes = evidence.bytes();
        self.publish(PublishTarget::Validation(&evidence), Cursor::new(bytes))
    }

    fn destination_lock(&self, key: PathBuf) -> Arc<Mutex<()>> {
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
