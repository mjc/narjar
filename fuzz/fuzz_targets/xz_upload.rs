#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use narjar::__private::storage::{
    CacheCreation, Directory, FileHash, NarFileName, NarUploadPolicy, SupportedStorageBackend,
};
use narjar::object::{CompressionCodec, WireEncoding};
use tempfile::tempdir;

fuzz_target!(|input: &[u8]| {
    let directory = tempdir().expect("temporary storage directory");
    let root = Directory::open(directory.path()).expect("open storage directory");
    let storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
        .and_then(|creation| creation.create_or_complete())
        .expect("initialize storage");
    let hash = FileHash::from_digest([0; 32]);
    let policy = NarUploadPolicy::new(4 * 1024 * 1024, 0);
    let _ = storage.publish_nar(
        NarFileName::new(hash, WireEncoding::Compressed(CompressionCodec::Xz)),
        Cursor::new(input),
        input.len() as u64,
        policy,
    );
});
