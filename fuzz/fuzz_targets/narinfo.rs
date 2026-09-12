#![no_main]

use libfuzzer_sys::fuzz_target;
use narjar::narinfo::TrustedPublicKeys;
use tempfile::tempdir;

fuzz_target!(|input: &[u8]| {
    let directory = tempdir().expect("temporary narinfo directory");
    let name = "0123456789abcdfghijklmnpqrsvwxyz.narinfo";
    std::fs::write(directory.path().join(name), input).expect("narinfo bytes");
    let trusted = TrustedPublicKeys::default();
    let _ = trusted.validate_published(directory.path());
});
