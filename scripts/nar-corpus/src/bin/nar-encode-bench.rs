use std::{
    fmt::Write as _,
    io::{self, Write},
};

use narjar_corpus::HashingWriter;
use nix_archive::nar::Encoder;

const CHUNK_SIZE: usize = 64 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let size: u64 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| (20_u64 << 30).to_string())
        .parse()?;
    let mut output = HashingWriter::new(io::sink());
    {
        let mut encoder = Encoder::new(&mut output)?;
        let mut file = encoder.start_regular(None, false, size)?;
        let chunk = [0_u8; CHUNK_SIZE];
        let mut remaining = size;
        while remaining != 0 {
            let length = remaining.min(chunk.len() as u64) as usize;
            file.write_all(&chunk[..length])?;
            remaining -= length as u64;
        }
        file.finish()?;
        encoder.finish()?;
    }
    let (_, raw_size, raw_sha256) = output.finish();
    let mut digest = String::with_capacity(64);
    for byte in raw_sha256 {
        write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
    }
    println!("raw_size={raw_size} sha256={digest}");
    Ok(())
}
