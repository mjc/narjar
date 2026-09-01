use std::path::PathBuf;

const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

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

    fn nar_path(&self, id: &NarObjectId) -> PathBuf {
        self.root.join("nar").join(format!("{}.nar", id.0))
    }

    fn narinfo_path(&self, hash: &StoreHash) -> PathBuf {
        self.root.join(format!("{}.narinfo", hash.0))
    }

    fn temp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }
}

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
