#![no_main]

use libfuzzer_sys::fuzz_target;
use narjar::nar::Limits;
use narjar::nar_encode::{Encoder, Event};

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(64 * 1024)];
    let limits = Limits {
        max_depth: 32,
        max_name_bytes: 1024,
        max_symlink_target_bytes: 1024,
        max_entries: 512,
        max_file_bytes: 1024 * 1024,
        max_total_bytes: 2 * 1024 * 1024,
        max_work: 4_096,
    };
    let mut output = Vec::new();
    let Ok(mut encoder) = Encoder::with_limits(&mut output, limits) else {
        return;
    };

    for chunk in input.chunks(8) {
        let body = &chunk[1..];
        let event = match chunk[0] % 7 {
            0 => Event::BeginDirectory,
            1 => Event::Entry(body),
            2 => Event::BeginFile {
                executable: chunk[0] & 8 != 0,
                size: body.len() as u64,
            },
            3 => Event::FileChunk(body),
            4 => Event::EndFile,
            5 => Event::Symlink(body),
            _ => Event::EndDirectory,
        };
        let _ = encoder.push(event);
    }
    let _ = encoder.finish();
});
