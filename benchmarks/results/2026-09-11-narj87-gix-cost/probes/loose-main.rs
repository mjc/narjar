use std::{
    io::{Cursor, Read},
    sync::Arc,
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

    let store = Arc::new(store);
    let readers = (0..std::env::var("GIX_PROBE_READERS")
        .ok()
        .map_or(1, |value| value.parse::<usize>().unwrap_or(1)))
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let mut output = Vec::new();
                let object = store
                    .try_find(&object_id, &mut output)
                    .expect("loose lookup")
                    .expect("loose object");
                assert_eq!(object.data, b"hello");
            })
        })
        .collect::<Vec<_>>();
    for reader in readers {
        reader.join().expect("reader thread");
    }

    let mut reader = Cursor::new(b"hello");
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    println!("variant=loose object_bytes={}", bytes.len());
    if let Ok(milliseconds) = std::env::var("GIX_PROBE_HOLD_MS") {
        std::thread::sleep(Duration::from_millis(milliseconds.parse()?));
    }
    Ok(())
}
