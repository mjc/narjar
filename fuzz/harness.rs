// Compile private cache source once for the application fuzz targets. This crate
// is unpublished; the installed narjar library exposes none of these modules.
#[allow(dead_code, unused_imports)]
#[path = "../src/cache.rs"]
mod cache;

use std::{
    io::{Cursor, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use cache::{
    auth::{Authorizer, Permission},
    http_server::Request,
    narinfo::TrustedPublicKeys,
    storage::{
        CacheCreation, Directory, NarUploadPolicy, Storage, StoreHash, SupportedStorageBackend,
    },
};
use narjar::object::{CompressionCodec, FileHash, NarFileName, WireEncoding};

fn with_request(input: &[u8], inspect: impl FnOnce(Request)) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fuzz listener");
    let address = listener.local_addr().expect("listener address");
    let input = input.to_vec();
    let writer = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect fuzz listener");
        let _ = stream.write_all(&input);
    });
    if let Ok((stream, _)) = listener.accept()
        && let Ok(request) = Request::read(stream)
    {
        inspect(request);
    }
    writer.join().expect("fuzz writer");
}

pub fn http_request(input: &[u8]) {
    with_request(input, drop);
}

pub fn auth_request(input: &[u8]) {
    let directory = tempfile::tempdir().expect("temporary auth directory");
    let auth = directory.path().join("auth");
    std::fs::create_dir(&auth).expect("auth directory");
    std::fs::write(auth.join("write.tokens"), input).expect("write fuzz token file");
    let root = Directory::open(directory.path()).expect("open auth directory");
    if let Ok(authorizer) = Authorizer::load(&root) {
        with_request(input, |request| {
            let _ = authorizer.allows(&request, Permission::Read);
            let _ = authorizer.allows(&request, Permission::Write);
        });
    }
}

fn initialize_cache(root: &Directory) -> Storage {
    CacheCreation::prepare(root, SupportedStorageBackend::FLAT)
        .and_then(|creation| creation.create_or_complete())
        .expect("initialize storage")
}

pub fn cache_info(input: &[u8]) {
    let directory = tempfile::tempdir().expect("temporary storage directory");
    let root = Directory::open(directory.path()).expect("open storage directory");
    let storage = initialize_cache(&root);
    let _ = storage.publish_cache_info(Cursor::new(input));
    std::fs::write(directory.path().join("nix-cache-info"), input)
        .expect("write cache-info fixture");
    let _ = storage.cache_info();
}

pub fn narinfo(input: &[u8]) {
    let store = StoreHash::parse("0123456789abcdfghijklmnpqrsvwxyz").unwrap();
    let trusted = TrustedPublicKeys::default();
    let _ = trusted.validate(&store, input.to_vec());
}

pub fn compressed_upload(input: &[u8], codec: CompressionCodec) {
    let directory = tempfile::tempdir().expect("temporary storage directory");
    let root = Directory::open(directory.path()).expect("open storage directory");
    let storage = initialize_cache(&root);
    let policy =
        NarUploadPolicy::with_limits(4 * 1024 * 1024, 4 * 1024 * 1024, 128 * 1024 * 1024, 0);
    let hash = FileHash::from_digest([0; 32]);
    if input.len() <= 4 * 1024 * 1024 {
        let _ = storage
            .reserve_staging(input.len() as u64, 0)
            .and_then(|staging| {
                storage.publish_nar_with_staging(
                    NarFileName::new(hash, WireEncoding::Compressed(codec)),
                    Cursor::new(input),
                    input.len() as u64,
                    policy,
                    staging,
                )
            });
    }
}
