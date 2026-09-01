use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
const TEMP_ATTEMPTS: u64 = 128;
const COMPARE_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct NarObjectId(String);

impl NarObjectId {
    fn parse(value: &str) -> Result<Self, ()> {
        parse_nix32(value, 52).map(Self)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StoreHash(String);

impl StoreHash {
    fn parse(value: &str) -> Result<Self, ()> {
        parse_nix32(value, 32).map(Self)
    }
}

fn parse_nix32(value: &str, expected_len: usize) -> Result<String, ()> {
    (value.len() == expected_len && value.bytes().all(|byte| NIX32.contains(&byte)))
        .then(|| value.to_owned())
        .ok_or(())
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
}

#[derive(Debug)]
struct Storage {
    layout: Layout,
}

impl Storage {
    fn initialize(root: impl AsRef<Path>) -> Result<Self, PublishError> {
        let layout = Layout::new(root.as_ref().to_owned());
        fs::create_dir_all(&layout.root)?;
        fs::create_dir_all(layout.nar_dir())?;
        fs::create_dir_all(layout.temp_dir())?;
        fs::create_dir_all(layout.realisations_dir())?;
        sync_dir(&layout.root)?;

        Ok(Self { layout })
    }

    fn layout(&self) -> &Layout {
        &self.layout
    }

    fn publish_nar(
        &self,
        id: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, PublishError> {
        self.publish("nar", self.layout.nar_path(id), source)
    }

    fn publish_narinfo(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
        source: impl Read,
    ) -> Result<PublishOutcome, PublishError> {
        match fs::metadata(self.layout.nar_path(nar)) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(PublishError::MissingNar),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PublishError::MissingNar);
            }
            Err(error) => return Err(error.into()),
        }

        self.publish("narinfo", self.layout.narinfo_path(store), source)
    }

    fn open_pair(
        &self,
        store: &StoreHash,
        nar: &NarObjectId,
    ) -> Result<Option<PublishedPair>, PublishError> {
        let Some(narinfo) = open_optional(self.layout.narinfo_path(store))? else {
            return Ok(None);
        };
        let Some(nar) = open_optional(self.layout.nar_path(nar))? else {
            return Ok(None);
        };

        Ok(Some(PublishedPair { nar, narinfo }))
    }

    fn publish(
        &self,
        prefix: &str,
        destination: PathBuf,
        mut source: impl Read,
    ) -> Result<PublishOutcome, PublishError> {
        let (temp_path, mut temp) = self.create_temp(prefix)?;
        let result = (|| {
            io::copy(&mut source, &mut temp)?;
            temp.sync_all()?;

            match fs::hard_link(&temp_path, &destination) {
                Ok(()) => {
                    let parent = destination
                        .parent()
                        .expect("validated storage destination has a parent");
                    sync_dir(parent)?;
                    Ok(PublishOutcome::Created)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if files_equal(&temp_path, &destination)? {
                        Ok(PublishOutcome::Identical)
                    } else {
                        Err(PublishError::Conflict)
                    }
                }
                Err(error) => Err(error.into()),
            }
        })();

        drop(temp);
        let cleanup = fs::remove_file(&temp_path)
            .and_then(|()| sync_dir(&self.layout.temp_dir()))
            .map_err(PublishError::from);

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

    fn create_temp(&self, prefix: &str) -> Result<(PathBuf, File), PublishError> {
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
struct PublishedPair {
    nar: File,
    narinfo: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishOutcome {
    Created,
    Identical,
}

#[derive(Debug)]
enum PublishError {
    Conflict,
    MissingNar,
    Io(io::Error),
}

impl From<io::Error> for PublishError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("immutable destination has different contents"),
            Self::MissingNar => formatter.write_str("referenced NAR is not published"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Conflict | Self::MissingNar => None,
        }
    }
}

fn open_optional(path: PathBuf) -> Result<Option<File>, PublishError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
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
        io::{Cursor, Read},
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{Layout, NarObjectId, PublishError, PublishOutcome, Storage, StoreHash};

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
            Err(PublishError::Conflict)
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
            Err(PublishError::Conflict)
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
