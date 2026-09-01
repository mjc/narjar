use std::path::Path;

#[test]
fn repository_has_authoritative_nix_boundary() {
    for path in [
        "flake.nix",
        "flake.lock",
        "Cargo.lock",
        ".envrc",
        "README.md",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(path).is_file(),
            "missing required repository artifact: {path}"
        );
    }
}
