#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use narjar::narinfo::NarEncoding;
use narjar::storage::{NarObjectId, NarUploadPolicy, Storage};
use tempfile::tempdir;

fuzz_target!(|input: &[u8]| {
    let directory = tempdir().expect("temporary storage directory");
    let storage = Storage::initialize(directory.path()).expect("initialize storage");
    let id = NarObjectId::parse("0123456789abcdfghijklmnpqrsvwxyz0123456789abcdfghijk").unwrap();
    let policy = NarUploadPolicy::new(4 * 1024 * 1024, 0);
    let _ = storage.publish_nar(
        &id,
        NarEncoding::Zstd,
        Cursor::new(input),
        input.len() as u64,
        policy,
    );
});
