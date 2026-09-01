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
    use std::path::PathBuf;

    use super::{Layout, NarObjectId, StoreHash};

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
}
