use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    mem::MaybeUninit,
    num::NonZeroUsize,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use data_encoding::{BitOrder, Encoding, Specification};
use sha2::{Digest, Sha256};

mod reconcile;

pub use reconcile::{ReconcileClass, ReconcileEntry, ReconcileReport};

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
}

#[derive(Debug, Eq, PartialEq)]
pub struct StoreHash(String);

impl StoreHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        parse_nix32(value, 32).map(Self)
    }
}

fn parse_nix32(value: &str, expected_len: usize) -> Result<String, InvalidObjectId> {
    (value.len() == expected_len && value.bytes().all(|byte| NIX32.as_bytes().contains(&byte)))
        .then(|| value.to_owned())
        .ok_or(InvalidObjectId)
}

fn nix32_sha256(digest: &[u8]) -> String {
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

enum PublishTarget<'a> {
    Nar(&'a NarObjectId),
    NarInfo(&'a StoreHash),
}

impl PublishTarget<'_> {
    fn destination(&self, layout: &Layout) -> PathBuf {
        match self {
            Self::Nar(id) => layout.nar_path(id),
            Self::NarInfo(store) => layout.narinfo_path(store),
        }
    }

    fn temp_prefix(&self) -> &'static str {
        match self {
            Self::Nar(_) => "nar",
            Self::NarInfo(_) => "narinfo",
        }
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
    publication_lock: Mutex<()>,
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
            publication_lock: Mutex::new(()),
            _lock: lock,
        })
    }

    pub(crate) fn has_capacity_for(
        &self,
        object_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<bool, StorageError> {
        let required = object_bytes.saturating_add(min_free_bytes);
        Ok(available_bytes(&self.layout.root)? >= required)
    }

    #[cfg(test)]
    fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn publish_nar(
        &self,
        id: &NarObjectId,
        source: impl Read,
        expected_length: u64,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish(
            PublishTarget::Nar(id),
            CheckedNarReader::new(source, &id.0, expected_length),
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

    fn ensure_nar(&self, nar: &NarObjectId) -> Result<(), StorageError> {
        match fs::metadata(self.layout.nar_path(nar)) {
            Ok(metadata) if metadata.is_file() => Ok(()),
            Ok(_) => Err(StorageError::MissingNar),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(StorageError::MissingNar),
            Err(error) => Err(error.into()),
        }
    }

    pub fn open_nar(&self, nar: &NarObjectId) -> Result<Option<File>, StorageError> {
        open_optional(self.layout.nar_path(nar))
    }

    pub fn open_narinfo(&self, store: &StoreHash) -> Result<Option<File>, StorageError> {
        open_optional(self.layout.narinfo_path(store))
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

    pub fn reconcile(
        &self,
        limit: NonZeroUsize,
        stale_before: SystemTime,
    ) -> Result<ReconcileReport, StorageError> {
        reconcile::scan(&self.layout, limit, stale_before)
    }

    pub fn cleanup_stale_temp(&self, entry: &ReconcileEntry) -> Result<bool, StorageError> {
        reconcile::cleanup_stale_temp(&self.layout, entry)
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
        target: PublishTarget<'_>,
        source: impl Read,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish_with(target, source, |_| Ok(()))
    }

    fn publish_with(
        &self,
        target: PublishTarget<'_>,
        mut source: impl Read,
        mut checkpoint: impl FnMut(PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        let _publication = self
            .publication_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let destination = target.destination(&self.layout);
        checkpoint(PublishBoundary::BeforeTempCreate)?;
        let (temp_path, mut temp) = self.create_temp(&target)?;
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

    fn create_temp(&self, target: &PublishTarget<'_>) -> Result<(PathBuf, File), StorageError> {
        let prefix = target.temp_prefix();
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

fn available_bytes(path: &Path) -> io::Result<u64> {
    let directory = File::open(path)?;
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();

    // SAFETY: directory owns a valid descriptor for the duration of the call,
    // and statistics points to writable storage for one statvfs value.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fstatvfs returned success, so it initialized statistics.
    let statistics = unsafe { statistics.assume_init() };
    let available = (statistics.f_bavail as u128).saturating_mul(statistics.f_frsize as u128);
    Ok(available.min(u128::from(u64::MAX)) as u64)
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
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        time::{Duration, SystemTime},
    };

    use super::{
        Layout, NarObjectId, PublishBoundary, PublishOutcome, PublishTarget, ReconcileClass,
        Storage, StorageError, StoreHash,
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
                .publish_narinfo(&store, &nar, Cursor::new(b"narinfo bytes"))
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
