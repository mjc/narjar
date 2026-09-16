use std::io::{self, BufReader, BufWriter, Write};

use narjar_corpus::{HashingReader, HashingWriter};
use nix_archive::nar::{Encoder, Event, decode_events_reader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let (mut input, _) = HashingReader::new(BufReader::new(stdin.lock()));
    let stdout = io::stdout();
    let mut output = HashingWriter::new(BufWriter::new(stdout.lock()));
    {
        let mut encoder = Encoder::new(&mut output)?;
        decode_events_reader(&mut input, |event| -> Result<(), nix_archive::nar::Error> {
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
        encoder.finish()?;
    }
    output.flush()?;
    let (mut stdout, output_size, output_sha256) = output.finish();
    stdout.flush()?;
    let (_, input_size, input_sha256) = input.finish();
    if input_size != output_size || input_sha256 != output_sha256 {
        return Err("decoder and encoder summaries differ".into());
    }
    eprintln!("round-trip raw_size={input_size}");
    Ok(())
}
