use std::io::{self, Write};

use narjar::nar::{Decoder, Event as DecodeEvent, EventSink};
use narjar::nar_encode::{EncodeError, Encoder, Event as EncodeEvent};

struct Reencoder<W> {
    encoder: Encoder<W>,
}

impl<W: Write> EventSink for Reencoder<W> {
    type Error = EncodeError;

    fn event(&mut self, event: DecodeEvent<'_>) -> Result<(), Self::Error> {
        match event {
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
        }
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

#[cfg(test)]
mod tests {
    use narjar::nar::DecodeError;

    use super::*;

    struct FailingWriter {
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "test writer"));
            }
            self.remaining -= bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reencoder_returns_concrete_encode_error() {
        let encoder = Encoder::new(Vec::new()).expect("create encoder");
        let mut reencoder = Reencoder { encoder };

        let error = reencoder
            .event(DecodeEvent::EndFile)
            .expect_err("an end event without a file should fail");
        assert!(matches!(
            error,
            EncodeError::Invalid("file end outside a regular node")
        ));
    }

    #[test]
    fn decoder_reencoder_preserves_output_writer_error() {
        let mut input_encoder = Encoder::new(Vec::new()).expect("create input encoder");
        input_encoder
            .push(EncodeEvent::BeginFile {
                executable: false,
                size: 5,
            })
            .expect("begin input file");
        input_encoder
            .push(EncodeEvent::FileChunk(b"hello"))
            .expect("write input file");
        input_encoder
            .push(EncodeEvent::EndFile)
            .expect("finish input file");
        let (input, _) = input_encoder.finish().expect("finish input encoder");

        let encoder = Encoder::new(FailingWriter { remaining: 24 }).expect("write NAR header");
        let mut reencoder = Reencoder { encoder };
        let mut decoder = Decoder::new(std::io::Cursor::new(input));
        let error: DecodeError<EncodeError> = decoder
            .decode(&mut reencoder)
            .expect_err("the output writer should fail");

        let DecodeError::Sink(EncodeError::Io(writer_error)) = &error else {
            panic!("expected the writer error to remain an EncodeError::Io");
        };
        assert_eq!(writer_error.kind(), io::ErrorKind::BrokenPipe);
        let encode_error = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<EncodeError>())
            .expect("decoder should expose the encoder error as its source");
        let source = std::error::Error::source(encode_error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("encoder should expose the writer error as its source");
        assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
    }
}
