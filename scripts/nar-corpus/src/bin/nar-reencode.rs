use std::io::{self, BufReader, BufWriter, Write};

use narjar_corpus::{HashingReader, HashingWriter};
use nix_archive::nar::{Encoder, Error, Event, decode_events_reader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let (mut input, _) = HashingReader::new(BufReader::new(stdin.lock()));
    let stdout = io::stdout();
    let mut output = HashingWriter::new(BufWriter::new(stdout.lock()));
    reencode_nar(&mut input, &mut output)?;
    output.flush()?;
    let (mut stdout, output) = output.finish();
    stdout.flush()?;
    let (_, input) = input.finish();
    if input != output {
        return Err("decoder and encoder summaries differ".into());
    }
    eprintln!("round-trip raw_size={}", input.bytes);
    Ok(())
}

fn reencode_nar(input: &mut impl io::Read, output: &mut impl Write) -> Result<(), Error> {
    let mut encoder = Encoder::new(&mut *output)?;
    decode_events_reader(input, |event| -> Result<(), Error> {
        match event {
            Event::DirectoryStart { name } => encoder.start_directory(name),
            Event::DirectoryEnd { .. } => encoder.end_directory(),
            Event::Symlink { name, target } => encoder.symlink(name, target),
            Event::Regular {
                name,
                executable,
                mut contents,
            } => {
                let mut file = encoder.start_regular(name, executable, contents.size())?;
                contents.copy_to(&mut file)?;
                file.finish()
            }
        }
    })?;
    encoder.finish().map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use nix_archive::nar::encode_regular;

    use super::*;

    #[test]
    fn reencoder_preserves_the_exact_bytes_of_a_canonical_nar() {
        // This is the invariant used by the corpus roundtrip command. A
        // semantic decode followed by a canonical encode must not change the
        // bytes Nix would hash for the same tree.
        let mut source = Vec::new();
        encode_regular(&mut source, b"hello", false).expect("fixture encoding succeeds");
        let mut output = Vec::new();

        reencode_nar(&mut Cursor::new(&source), &mut output)
            .expect("canonical input can be reencoded");

        assert_eq!(output, source);
    }

    #[test]
    fn reencoder_rejects_truncated_nar_instead_of_emitting_a_partial_success() {
        let mut source = Vec::new();
        encode_regular(&mut source, b"hello", false).expect("fixture encoding succeeds");
        source.pop();

        let error = reencode_nar(&mut Cursor::new(source), &mut Vec::new())
            .expect_err("truncated input is not a NAR");
        assert!(error.to_string().contains("unexpected end"));
    }
}
