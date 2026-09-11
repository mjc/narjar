use std::{
    io::{Cursor, Read},
    sync::atomic::AtomicBool,
    time::Duration,
};

use gix_object::Write;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    let store = gix_odb::loose::Store::at(directory.path(), gix_hash::Kind::Sha1);
    let object_id = store.write_stream(
        gix_object::Kind::Blob,
        5,
        &mut Cursor::new(b"hello"),
    )?;
    let mut output = Vec::new();
    let object = store
        .try_find(&object_id, &mut output)?
        .expect("loose object");
    assert_eq!(object.data, b"hello");

    let mut pack = Cursor::new(b"PACK\0\0\0\x02\0\0\0\x01".to_vec());
    let mut progress = gix_features::progress::Discard;
    let result = gix_pack::Bundle::write_to_directory(
        &mut pack,
        Some(directory.path()),
        &mut progress,
        &AtomicBool::new(false),
        None::<gix_object::find::Never>,
        gix_hash::Kind::Sha1,
        gix_pack::bundle::write::Options {
            thread_limit: Some(1),
            alloc_limit_bytes: Some(1024),
            ..Default::default()
        },
    );
    assert!(result.is_err(), "truncated pack must be rejected");

    let mut reader = Cursor::new(b"hello");
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    println!("variant=pack-write object_bytes={}", bytes.len());
    if let Ok(milliseconds) = std::env::var("GIX_PROBE_HOLD_MS") {
        std::thread::sleep(Duration::from_millis(milliseconds.parse()?));
    }
    Ok(())
}
