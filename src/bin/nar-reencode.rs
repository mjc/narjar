use std::io::{self, Write};

use narjar::nar::{Decoder, Event as DecodeEvent, EventSink};
use narjar::nar_encode::{Encoder, Event as EncodeEvent};

struct Reencoder<W> {
    encoder: Encoder<W>,
}

impl<W: Write> EventSink for Reencoder<W> {
    fn event(&mut self, event: DecodeEvent<'_>) -> io::Result<()> {
        let result = match event {
            DecodeEvent::BeginDirectory { .. } => self.encoder.push(EncodeEvent::BeginDirectory),
            DecodeEvent::Entry { name } => self.encoder.push(EncodeEvent::Entry(&name)),
            DecodeEvent::BeginFile {
                executable, size, ..
            } => self
                .encoder
                .push(EncodeEvent::BeginFile { executable, size }),
            DecodeEvent::FileChunk(chunk) => self.encoder.push(EncodeEvent::FileChunk(chunk)),
            DecodeEvent::EndFile => self.encoder.push(EncodeEvent::EndFile),
            DecodeEvent::Symlink { target } => self.encoder.push(EncodeEvent::Symlink(&target)),
            DecodeEvent::EndDirectory => self.encoder.push(EncodeEvent::EndDirectory),
        };
        result.map_err(|error| io::Error::other(error.to_string()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let encoder = Encoder::new(stdout.lock())?;
    let mut reencoder = Reencoder { encoder };
    let mut decoder = Decoder::new(&mut input);
    let decoded = decoder.decode(&mut reencoder)?;
    let (_, encoded) = reencoder.encoder.finish()?;
    if decoded.raw_size != encoded.raw_size || decoded.raw_sha256 != encoded.raw_sha256 {
        return Err("decoder and encoder summaries differ".into());
    }
    eprintln!(
        "round-trip raw_size={} entries={} files={} symlinks={}",
        encoded.raw_size, encoded.entries, encoded.files, encoded.symlinks
    );
    Ok(())
}
