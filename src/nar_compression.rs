//! Shared wire encoding for uploaded NARs and stored derivatives.

use std::io::{self, Write};

use lzma_rust2::{XzOptions, XzWriter};
use sha2::Sha256;
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};

use crate::object::{CompressionCodec, EncodedIdentity, EncodedSize, FileHash};

/// Invoke the raw-byte producer once and finish the selected encoding before returning.
/// The producer remains responsible for validating the raw NAR it supplies.
pub fn encode_nar(
    codec: CompressionCodec,
    destination: &mut impl Write,
    write_raw: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    match codec {
        CompressionCodec::Zstd => encode_zstd_nar(destination, write_raw),
        CompressionCodec::Xz => encode_xz_nar(destination, write_raw),
    }
}

/// Measure the bytes accepted by the destination, including the codec trailer.
/// No encoded identity is returned if production or encoder completion fails.
pub fn encode_and_measure_nar(
    codec: CompressionCodec,
    destination: &mut impl Write,
    write_raw: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> io::Result<EncodedIdentity> {
    let mut output = EncodedOutputHasher::new(destination);
    encode_nar(codec, &mut output, write_raw)?;
    Ok(output.finish(codec))
}

fn encode_zstd_nar(
    destination: &mut impl Write,
    write_raw: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    let mut encoder = StreamingEncoder::new(destination, CompressionLevel::Fastest);
    write_raw(&mut encoder)?;
    encoder.finish().map(|_| ())
}

fn encode_xz_nar(
    destination: &mut impl Write,
    write_raw: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    let mut encoder = XzWriter::new(destination, XzOptions::with_preset(1))?;
    write_raw(&mut encoder)?;
    encoder.finish().map(|_| ())
}

struct EncodedOutputHasher<W: Write> {
    inner: digest_io::HashWriter<Sha256, W>,
    bytes_written: u64,
}

impl<W: Write> EncodedOutputHasher<W> {
    fn new(inner: W) -> Self {
        Self {
            inner: digest_io::HashWriter::new(inner),
            bytes_written: 0,
        }
    }

    fn finish(self, codec: CompressionCodec) -> EncodedIdentity {
        EncodedIdentity::new(
            codec,
            FileHash::from_digest(self.inner.finalize().into()),
            EncodedSize::new(self.bytes_written),
        )
    }
}

impl<W: Write> Write for EncodedOutputHasher<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(written as u64)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "encoded NAR is too large")
            })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lzma_rust2::XzReader;
    use sha2::Digest;
    use std::{
        cell::Cell,
        io::{Cursor, Read},
        rc::Rc,
    };
    use structured_zstd::decoding::StreamingDecoder;

    #[test]
    fn encoded_measurement_ignores_zero_writes_and_propagates_flush_errors() {
        struct ZeroWriter;
        impl Write for ZeroWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush failed"))
            }
        }
        let mut measured = EncodedOutputHasher::new(ZeroWriter);
        assert_eq!(measured.write(b"not accepted").unwrap(), 0);
        assert_eq!(
            measured.flush().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let measured = measured.finish(CompressionCodec::Zstd);
        assert_eq!(measured.size().get(), 0);
        assert_eq!(
            measured.hash(),
            FileHash::from_digest(Sha256::digest([]).into())
        );
    }

    #[test]
    fn encoded_measurement_reports_counter_overflow_instead_of_wrapping() {
        let mut measured = EncodedOutputHasher::new(io::sink());
        measured.bytes_written = u64::MAX;
        assert_eq!(
            measured.write(b"x").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn multiblock_bytes() -> Vec<u8> {
        (0_usize..(384 * 1024 + 17))
            .map(|index| (index.wrapping_mul(31) ^ (index >> 7)).to_le_bytes()[0])
            .collect()
    }

    fn previous_encoder_output(codec: CompressionCodec, raw: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        match codec {
            CompressionCodec::Xz => {
                let mut encoder = XzWriter::new(&mut output, XzOptions::with_preset(1)).unwrap();
                io::copy(&mut Cursor::new(raw), &mut encoder).unwrap();
                encoder.finish().unwrap();
            }
            CompressionCodec::Zstd => {
                let mut encoder = StreamingEncoder::new(&mut output, CompressionLevel::Fastest);
                io::copy(&mut Cursor::new(raw), &mut encoder).unwrap();
                encoder.finish().unwrap();
            }
        }
        output
    }

    fn decode(codec: CompressionCodec, encoded: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        match codec {
            CompressionCodec::Xz => XzReader::new(encoded, false)
                .read_to_end(&mut decoded)
                .unwrap(),
            CompressionCodec::Zstd => StreamingDecoder::new(encoded)
                .unwrap()
                .read_to_end(&mut decoded)
                .unwrap(),
        };
        decoded
    }

    #[test]
    fn shared_encoding_preserves_existing_bytes_and_multiblock_decoding() {
        let raw = multiblock_bytes();
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let mut encoded = Vec::new();
            let mut calls = 0;
            encode_nar(codec, &mut encoded, |output| {
                calls += 1;
                io::copy(&mut Cursor::new(&raw), output).map(|_| ())
            })
            .unwrap();
            assert_eq!(calls, 1, "encoding must not reread or replay the producer");
            assert_eq!(encoded, previous_encoder_output(codec, &raw));
            assert_eq!(decode(codec, &encoded), raw);
        }
    }

    #[derive(Default)]
    struct ShortWriter(Vec<u8>);

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let accepted = bytes.len().min(3);
            self.0.extend_from_slice(&bytes[..accepted]);
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn measured_encoding_hashes_only_accepted_bytes_including_the_trailer() {
        let raw = multiblock_bytes();
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let mut output = ShortWriter::default();
            let mut calls = 0;
            let identity = encode_and_measure_nar(codec, &mut output, |writer| {
                calls += 1;
                raw.chunks(4093)
                    .try_for_each(|chunk| writer.write_all(chunk))
            })
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(identity.codec(), codec);
            assert_eq!(identity.size().get(), output.0.len() as u64);
            assert_eq!(
                identity.hash(),
                FileHash::from_digest(Sha256::digest(&output.0).into())
            );
            assert_eq!(decode(codec, &output.0), raw);
            let mut unmeasured = Vec::new();
            encode_nar(codec, &mut unmeasured, |writer| {
                raw.chunks(4093)
                    .try_for_each(|chunk| writer.write_all(chunk))
            })
            .unwrap();
            assert_eq!(
                output.0, unmeasured,
                "measurement must not change the encoding"
            );
        }
    }

    #[test]
    fn failed_raw_production_never_returns_an_encoded_identity() {
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let error = encode_and_measure_nar(codec, &mut io::sink(), |output| {
                output.write_all(b"incomplete raw NAR")?;
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::IO.raw_os_error(),
                ))
            })
            .unwrap_err();
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::IO.raw_os_error())
            );
        }
    }

    struct FailDuringFinish(Rc<Cell<bool>>);

    impl Write for FailDuringFinish {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.get() {
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::NOSPC.raw_os_error(),
                ))
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encoder_finalization_preserves_capacity_errors_and_returns_no_identity() {
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let fail = Rc::new(Cell::new(false));
            let mut output = FailDuringFinish(Rc::clone(&fail));
            let error = encode_and_measure_nar(codec, &mut output, |writer| {
                writer.write_all(b"complete producer, unfinished compressed stream")?;
                fail.set(true);
                Ok(())
            })
            .unwrap_err();
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::NOSPC.raw_os_error())
            );
        }
    }
}
