use std::io::{self, Write};

use narjar_corpus::HashingWriter;
use nix_archive::nar::{Encoder, Error};

const CHUNK_SIZE: usize = 64 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let size: u64 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| (20_u64 << 30).to_string())
        .parse()?;
    let mut output = HashingWriter::new(io::sink());
    encode_zero_file(size, &mut output)?;
    let (_, summary) = output.finish();
    println!(
        "raw_size={} sha256={}",
        summary.bytes,
        narjar_corpus::hex(&summary.sha256)
    );
    Ok(())
}

fn encode_zero_file(size: u64, output: &mut impl Write) -> Result<(), Error> {
    let mut encoder = Encoder::new(&mut *output)?;
    let mut file = encoder.start_regular(None, false, size)?;
    let chunk = [0_u8; CHUNK_SIZE];
    (0..size.div_ceil(CHUNK_SIZE as u64))
        .map(|chunk_index| {
            let offset = chunk_index * CHUNK_SIZE as u64;
            let length = (size - offset).min(CHUNK_SIZE as u64) as usize;
            &chunk[..length]
        })
        .try_for_each(|chunk| file.write_all(chunk))?;
    file.finish()?;
    encoder.finish().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_archive::nar::{Event, decode_events};

    #[test]
    fn zero_file_benchmark_emits_one_canonical_file_of_the_requested_size() {
        // The benchmark is meant to exercise streaming encoder state, not a
        // fake counter. Decode the result so this test explains the contract:
        // one root regular file, exactly the declared bytes, and no retained
        // payload requirement.
        let mut nar = Vec::new();
        encode_zero_file(65_537, &mut nar).expect("zero-file encoding succeeds");
        let mut files = 0;
        decode_events(&nar, |event| {
            if let Event::Regular {
                name,
                executable,
                contents,
            } = event
            {
                assert!(name.is_none());
                assert!(!executable);
                assert_eq!(contents.len(), 65_537);
                assert!(contents.iter().all(|byte| *byte == 0));
                files += 1;
            }
            Ok(())
        })
        .expect("the encoder output is a valid NAR");
        assert_eq!(files, 1);
    }
}
