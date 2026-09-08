use std::{fmt::Write as _, io};

use narjar::nar_encode::{Encoder, Event};

const CHUNK_SIZE: usize = 64 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let size: u64 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| (20_u64 << 30).to_string())
        .parse()?;
    let mut encoder = Encoder::new(io::sink())?;
    encoder.push(Event::BeginFile {
        executable: false,
        size,
    })?;

    let chunk = [0_u8; CHUNK_SIZE];
    let mut remaining = size;
    while remaining != 0 {
        let length = remaining.min(chunk.len() as u64) as usize;
        encoder.push(Event::FileChunk(&chunk[..length]))?;
        remaining -= length as u64;
    }
    encoder.push(Event::EndFile)?;
    let (_, summary) = encoder.finish()?;
    let mut digest = String::with_capacity(64);
    for byte in summary.raw_sha256 {
        write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
    }
    println!("raw_size={} sha256={digest}", summary.raw_size);
    Ok(())
}
