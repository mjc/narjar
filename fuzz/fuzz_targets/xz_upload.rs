#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use narjar::narinfo::NarEncoding;
use narjar::storage::{Directory, NarObjectId, NarUploadPolicy, Storage};
use tempfile::tempdir;

fuzz_target!(|input: &[u8]| {
    let directory = tempdir().expect("temporary storage directory");
    let root = Directory::open(directory.path()).expect("open storage directory");
    let storage = Storage::initialize(&root).expect("initialize storage");
    let id = NarObjectId::parse("0123456789abcdfghijklmnpqrsvwxyz0123456789abcdfghijk").unwrap();
    let policy = NarUploadPolicy::new(4 * 1024 * 1024, 0);
    let _ = storage.publish_nar(
        &id,
        NarEncoding::Xz,
        Cursor::new(input),
        input.len() as u64,
        policy,
    );
});
