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
