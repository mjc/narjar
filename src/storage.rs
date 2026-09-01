use std::{
    collections::BinaryHeap,
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    num::NonZeroUsize,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
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
}

#[derive(Debug, Eq, PartialEq)]
pub struct StoreHash(String);

impl StoreHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        parse_nix32(value, 32).map(Self)
    }
}

fn parse_nix32(value: &str, expected_len: usize) -> Result<String, InvalidObjectId> {
    (value.len() == expected_len && value.bytes().all(|byte| NIX32.contains(&byte)))
        .then(|| value.to_owned())
        .ok_or(InvalidObjectId)
}

#[derive(Debug, Eq, PartialEq)]
struct Layout {
    root: PathBuf,
}

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

    fn narinfo_path(&self, hash: &StoreHash) -> PathBuf {
        self.root.join(format!("{}.narinfo", hash.0))
    }

    fn temp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }

    fn realisations_dir(&self) -> PathBuf {
        self.root.join("realisations")
    }
    fn lock_path(&self) -> PathBuf {
        self.root.join("lock")
    }
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
    fn acquire(path: &Path) -> Result<Self, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug)]
pub struct Storage {
    layout: Layout,
    _lock: ProcessLock,
}

impl Storage {
    pub fn initialize(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let layout = Layout::new(root.as_ref().to_owned());
        fs::create_dir_all(&layout.root)?;
        fs::create_dir_all(layout.nar_dir())?;
        fs::create_dir_all(layout.temp_dir())?;
        fs::create_dir_all(layout.realisations_dir())?;

        let lock = ProcessLock::acquire(&layout.lock_path())?;
        sync_dir(&layout.root)?;

        Ok(Self {
            layout,
            _lock: lock,
        })
    }

    #[cfg(test)]
    fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn publish_nar(
        &self,
        id: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish("nar", self.layout.nar_path(id), source)
    }

    #[cfg(test)]
    fn publish_nar_fault(
        &self,
        id: &NarObjectId,
        source: impl Read,
        fault: PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with("nar", self.layout.nar_path(id), source, |boundary| {
            injected_fault(boundary, fault)
        })
    }

    pub fn publish_narinfo(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.ensure_nar(nar)?;
        self.publish("narinfo", self.layout.narinfo_path(store), source)
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
        self.publish_with(
            "narinfo",
            self.layout.narinfo_path(store),
            source,
            |boundary| injected_fault(boundary, fault),
        )
    }

    fn ensure_nar(&self, nar: &NarObjectId) -> Result<(), StorageError> {
        match fs::metadata(self.layout.nar_path(nar)) {
            Ok(metadata) if metadata.is_file() => Ok(()),
            Ok(_) => Err(StorageError::MissingNar),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(StorageError::MissingNar),
            Err(error) => Err(error.into()),
        }
    }

    pub fn open_pair(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
    ) -> Result<Option<PublishedPair>, StorageError> {
        let Some(narinfo) = open_optional(self.layout.narinfo_path(store))? else {
            return Ok(None);
        };
        let Some(nar) = open_optional(self.layout.nar_path(nar))? else {
            return Ok(None);
        };

        Ok(Some(PublishedPair { nar, narinfo }))
    }

    pub fn reconcile(
        &self,
        limit: NonZeroUsize,
        stale_before: SystemTime,
    ) -> Result<ReconcileReport, StorageError> {
        let mut found = BoundedEntries::new(limit);

        for entry in fs::read_dir(&self.layout.root)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let file_type = entry.file_type()?;
            let class = classify_root_entry(&name, &file_type);
            if let Some(class) = class {
                found.record(PathBuf::from(name), class, &path)?;
            }
        }

        for entry in fs::read_dir(self.layout.nar_dir())? {
            let entry = entry?;
            let path = entry.path();
            let relative = PathBuf::from("nar").join(entry.file_name());
            let file_type = entry.file_type()?;
            let class = if !file_type.is_file() {
                ReconcileClass::UnexpectedType
            } else if valid_nar_filename(&entry.file_name()) {
                ReconcileClass::NarObject
            } else {
                ReconcileClass::InvalidFilename
            };
            found.record(relative, class, &path)?;
        }

        for entry in fs::read_dir(self.layout.temp_dir())? {
            let entry = entry?;
            let path = entry.path();
            let relative = PathBuf::from(".tmp").join(entry.file_name());
            let file_type = entry.file_type()?;
            let metadata = fs::symlink_metadata(&path)?;
            let class = if !file_type.is_file() {
                ReconcileClass::UnexpectedType
            } else if !valid_temp_filename(&entry.file_name()) {
                ReconcileClass::InvalidFilename
            } else if metadata.modified()? <= stale_before {
                ReconcileClass::TempStale
            } else {
                ReconcileClass::TempYoung
            };
            found.record_with_metadata(relative, class, metadata);
        }

        for entry in fs::read_dir(self.layout.realisations_dir())? {
            let entry = entry?;
            let path = entry.path();
            let relative = PathBuf::from("realisations").join(entry.file_name());
            let file_type = entry.file_type()?;
            let class = if !file_type.is_file() {
                ReconcileClass::UnexpectedType
            } else if valid_realisation_filename(&entry.file_name()) {
                ReconcileClass::Realisation
            } else {
                ReconcileClass::InvalidFilename
            };
            found.record(relative, class, &path)?;
        }

        Ok(found.finish())
    }

    pub fn cleanup_stale_temp(&self, entry: &ReconcileEntry) -> Result<bool, StorageError> {
        if entry.class != ReconcileClass::TempStale
            || entry.relative_path.parent() != Some(Path::new(".tmp"))
        {
            return Ok(false);
        }

        let path = self.layout.root.join(&entry.relative_path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if FileIdentity::from(&metadata) != entry.identity {
            return Ok(false);
        }

        fs::remove_file(path)?;
        sync_dir(&self.layout.temp_dir())?;
        Ok(true)
    }

    pub fn delete_narinfo(&self, store: &StoreHash) -> Result<bool, StorageError> {
        match fs::remove_file(self.layout.narinfo_path(store)) {
            Ok(()) => {
                sync_dir(&self.layout.root)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn publish(
        &self,
        prefix: &str,
        destination: PathBuf,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(prefix, destination, source, |_| Ok(()))
    }

    fn publish_with(
        &self,
        prefix: &str,
        destination: PathBuf,
        mut source: impl Read,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        checkpoint(PublishBoundary::BeforeTempCreate)?;
        let (temp_path, mut temp) = self.create_temp(prefix)?;
        let result = (|| {
            checkpoint(PublishBoundary::AfterTempCreate)?;
            io::copy(&mut source, &mut temp)?;
            checkpoint(PublishBoundary::AfterStream)?;
            temp.sync_all()?;
            checkpoint(PublishBoundary::AfterTempSync)?;
            checkpoint(PublishBoundary::BeforeFinalLink)?;

            match fs::hard_link(&temp_path, &destination) {
                Ok(()) => {
                    let parent = destination
                        .parent()
                        .expect("validated storage destination has a parent");
                    if let Err(error) = checkpoint(PublishBoundary::BeforeParentSync) {
                        rollback_link(&destination, parent)?;
                        return Err(error);
                    }
                    if let Err(error) = sync_dir(parent) {
                        rollback_link(&destination, parent)?;
                        return Err(error.into());
                    }
                    checkpoint(PublishBoundary::AfterParentSync)?;
                    Ok(PublishOutcome::Created)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if files_equal(&temp_path, &destination)? {
                        Ok(PublishOutcome::Identical)
                    } else {
                        Err(StorageError::Conflict)
                    }
                }
                Err(error) => Err(error.into()),
            }
        })();

        drop(temp);
        let cleanup = fs::remove_file(&temp_path)
            .and_then(|()| sync_dir(&self.layout.temp_dir()))
            .map_err(StorageError::from);

        match result {
            Ok(outcome) => {
                cleanup?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = cleanup;
                Err(error)
            }
        }
    }

    fn create_temp(&self, prefix: &str) -> Result<(PathBuf, File), StorageError> {
        for _ in 0..TEMP_ATTEMPTS {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = self
                .layout
                .temp_dir()
                .join(format!("{prefix}-{}-{sequence:016x}.part", process::id()));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReconcileClass {
    NarObject,
    NarInfo,
    Realisation,
    TempYoung,
    TempStale,
    InvalidFilename,
    UnexpectedType,
    UnknownFile,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReconcileEntry {
    relative_path: PathBuf,
    class: ReconcileClass,
    identity: FileIdentity,
}

impl ReconcileEntry {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn class(&self) -> ReconcileClass {
        self.class
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReconcileReport {
    entries: Vec<ReconcileEntry>,
    truncated: bool,
}

impl ReconcileReport {
    pub fn entries(&self) -> &[ReconcileEntry] {
        &self.entries
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl From<&fs::Metadata> for FileIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug)]
pub enum StorageError {
    Conflict,
    Locked,
    MissingNar,
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
            Self::MissingNar => formatter.write_str("referenced NAR is not published"),
            Self::Locked => formatter.write_str("data directory is locked by another process"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Conflict | Self::MissingNar | Self::Locked => None,
        }
    }
}

#[derive(Debug)]
struct BoundedEntries {
    limit: usize,
    seen: usize,
    entries: BinaryHeap<ReconcileEntry>,
}

impl BoundedEntries {
    fn new(limit: NonZeroUsize) -> Self {
        Self {
            limit: limit.get(),
            seen: 0,
            entries: BinaryHeap::with_capacity(limit.get()),
        }
    }

    fn record(
        &mut self,
        relative_path: PathBuf,
        class: ReconcileClass,
        path: &Path,
    ) -> Result<(), StorageError> {
        let metadata = fs::symlink_metadata(path)?;
        self.record_with_metadata(relative_path, class, metadata);
        Ok(())
    }

    fn record_with_metadata(
        &mut self,
        relative_path: PathBuf,
        class: ReconcileClass,
        metadata: fs::Metadata,
    ) {
        self.seen += 1;
        self.entries.push(ReconcileEntry {
            relative_path,
            class,
            identity: FileIdentity::from(&metadata),
        });
        if self.entries.len() > self.limit {
            self.entries.pop();
        }
    }

    fn finish(self) -> ReconcileReport {
        let mut entries = self.entries.into_vec();
        entries.sort_unstable();
        ReconcileReport {
            truncated: self.seen > entries.len(),
            entries,
        }
    }
}

fn classify_root_entry(name: &OsStr, file_type: &fs::FileType) -> Option<ReconcileClass> {
    match name.to_str() {
        Some("nar" | ".tmp" | "realisations" | "auth") => {
            (!file_type.is_dir()).then_some(ReconcileClass::UnexpectedType)
        }
        Some("lock" | "nix-cache-info" | "trusted-public-keys") => {
            (!file_type.is_file()).then_some(ReconcileClass::UnexpectedType)
        }
        Some(name) if valid_store_hash_filename(name) => Some(if file_type.is_file() {
            ReconcileClass::NarInfo
        } else {
            ReconcileClass::UnexpectedType
        }),
        Some(_) => Some(ReconcileClass::UnknownFile),
        None => Some(ReconcileClass::InvalidFilename),
    }
}

fn valid_store_hash_filename(name: &str) -> bool {
    name.strip_suffix(".narinfo")
        .is_some_and(|hash| parse_nix32(hash, 32).is_ok())
}

fn valid_nar_filename(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".nar"))
        .is_some_and(|hash| parse_nix32(hash, 52).is_ok())
}

fn valid_temp_filename(name: &OsStr) -> bool {
    let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".part")) else {
        return false;
    };
    let Some(body) = ["nar-", "narinfo-", "realisation-"]
        .into_iter()
        .find_map(|prefix| stem.strip_prefix(prefix))
    else {
        return false;
    };
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_realisation_filename(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".doi"))
        .is_some_and(|stem| {
            !stem.is_empty()
                && stem.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_')
                })
        })
}

fn open_optional(path: PathBuf) -> Result<Option<File>, StorageError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn rollback_link(destination: &Path, parent: &Path) -> Result<(), StorageError> {
    fs::remove_file(destination)?;
    sync_dir(parent)?;
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

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn files_equal(left: &Path, right: &Path) -> io::Result<bool> {
    if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
        return Ok(false);
    }

    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::{self, Cursor, Read},
        num::NonZeroUsize,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime},
    };

    use super::{
        Layout, NarObjectId, PublishBoundary, PublishOutcome, ReconcileClass, Storage,
        StorageError, StoreHash,
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
        assert!(directory.path().join(".tmp").is_dir());
        assert!(directory.path().join("realisations").is_dir());
        assert_eq!(storage.layout(), &Layout::new(directory.path().to_owned()));
    }

    #[test]
    fn publication_is_immutable_idempotent_and_pair_gated() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");
        let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

        assert_eq!(
            storage
                .publish_nar(&nar, Cursor::new(b"nar bytes"))
                .expect("publish NAR"),
            PublishOutcome::Created
        );
        assert_eq!(
            storage
                .publish_nar(&nar, Cursor::new(b"nar bytes"))
                .expect("retry identical NAR"),
            PublishOutcome::Identical
        );
        assert!(matches!(
            storage.publish_nar(&nar, Cursor::new(b"different")),
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
                .publish_narinfo(&store, &nar, Cursor::new(b"narinfo bytes"))
                .expect("publish narinfo"),
            PublishOutcome::Created
        );
        assert_eq!(
            storage
                .publish_narinfo(&store, &nar, Cursor::new(b"narinfo bytes"))
                .expect("retry identical narinfo"),
            PublishOutcome::Identical
        );
        assert!(matches!(
            storage.publish_narinfo(&store, &nar, Cursor::new(b"different")),
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
                .publish_nar(&nar, Cursor::new(b"nar bytes"))
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
                .publish_narinfo(&store, &nar, Cursor::new(b"narinfo bytes"))
                .expect("retry durable narinfo"),
            PublishOutcome::Identical
        );
    }

    #[test]
    fn stream_io_failure_leaves_no_final_or_temp() {
        let directory = TestDir::new();
        let storage = Storage::initialize(directory.path()).expect("initialize storage");
        let nar = NarObjectId::parse(NAR_ID).expect("valid NAR object id");

        assert!(storage.publish_nar(&nar, BrokenReader::default()).is_err());
        assert!(!storage.layout().nar_path(&nar).exists());
        assert!(
            fs::read_dir(storage.layout().temp_dir())
                .expect("read temp directory")
                .next()
                .is_none()
        );
    }

    #[derive(Default)]
    struct BrokenReader {
        returned_prefix: bool,
    }

    impl Read for BrokenReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.returned_prefix {
                return Err(io::Error::other("injected stream failure"));
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
            .publish_nar(&nar, Cursor::new(b"nar bytes"))
            .expect("publish NAR");
        storage
            .publish_narinfo(&store, &nar, Cursor::new(b"narinfo bytes"))
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
