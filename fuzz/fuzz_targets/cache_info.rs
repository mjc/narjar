#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use narjar::storage::Storage;
use tempfile::tempdir;

fuzz_target!(|input: &[u8]| {
    let directory = tempdir().expect("temporary storage directory");
    let storage = Storage::initialize(directory.path()).expect("initialize storage");
    let _ = storage.publish_cache_info(Cursor::new(input));
    std::fs::write(directory.path().join("nix-cache-info"), input)
        .expect("write cache-info fixture");
    let _ = storage.cache_info();
});
