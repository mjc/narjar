use std::io::{self, Write};

use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};

use super::nar_stream::{local_store_path, verify_nar_summary, write_nar};
use super::{NarInfoMetadata, PushError};
use narjar::object::{CompressionCodec, EncodedIdentity, EncodedSize, FileHash};

pub(super) fn measure_encoded_nar(
    info: &NarInfoMetadata,
    codec: CompressionCodec,
) -> Result<EncodedIdentity, PushError> {
    let mut measured = MeasuredWriter::new(io::sink());
    let path = local_store_path(info.claims().store_path())?;
    write_encoded_nar(&path, info, codec, &mut measured)?;
    let (_, file_hash, file_size) = measured.finish();
    Ok(EncodedIdentity::new(codec, file_hash, file_size))
}

pub(super) fn write_encoded_nar<W: Write>(
    path: &std::path::Path,
    info: &NarInfoMetadata,
    codec: CompressionCodec,
    mut output: W,
) -> Result<(), PushError> {
    let summary = match codec {
        CompressionCodec::Zstd => {
            let mut encoder = StreamingEncoder::new(&mut output, CompressionLevel::Fastest);
            let summary = write_nar(path, &mut encoder)?;
            encoder
                .finish()
                .map_err(|error| format!("finishing zstd NAR: {error}"))?;
            summary
        }
        CompressionCodec::Xz => {
            let mut encoder = XzWriter::new(&mut output, XzOptions::with_preset(1))
                .map_err(|error| format!("creating XZ encoder: {error}"))?;
            let summary = write_nar(path, &mut encoder)?;
            encoder
                .finish()
                .map_err(|error| format!("finishing XZ NAR: {error}"))?;
            summary
        }
    };
    verify_nar_summary(info, &summary)
}

struct MeasuredWriter<W> {
    writer: W,
    digest: Sha256,
    bytes: u64,
}

impl<W> MeasuredWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (W, FileHash, EncodedSize) {
        (
            self.writer,
            FileHash::from_digest(self.digest.finalize().into()),
            EncodedSize::new(self.bytes),
        )
    }
}

impl<W: Write> Write for MeasuredWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(bytes)?;
        self.digest.update(&bytes[..written]);
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("encoded NAR size overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
