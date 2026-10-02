#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use narjar::__private::storage::{
    Directory, FileHash, NarFileName, NarUploadPolicy, Storage, SupportedStorageBackend,
};
use narjar::object::{CompressionCodec, WireEncoding};
use tempfile::tempdir;

fuzz_target!(|input: &[u8]| {
    let directory = tempdir().expect("temporary storage directory");
    let root = Directory::open(directory.path()).expect("open storage directory");
    let storage =
        Storage::initialize(&root, SupportedStorageBackend::FLAT).expect("initialize storage");
    let hash = FileHash::from_digest([0; 32]);
    let policy = NarUploadPolicy::new(4 * 1024 * 1024, 0);
    let _ = storage.publish_nar(
        NarFileName::new(hash, WireEncoding::Compressed(CompressionCodec::Zstd)),
        Cursor::new(input),
        input.len() as u64,
        policy,
    );
});
