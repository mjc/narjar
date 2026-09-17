use std::io::{self, Write};

use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};

use super::nar_stream::{local_store_path, verify_nar_summary, write_nar};
use super::{Compression, PathInfo};
use crate::object::{CompressionCodec, EncodedIdentity, EncodedSize, FileHash};

pub(super) struct PreparedNar {
    pub(super) identity: EncodedIdentity,
}

pub(super) fn prepare_nar(
    info: &PathInfo,
    compression: Compression,
) -> Result<PreparedNar, String> {
    let mut measured = MeasuredWriter::new(io::sink());
    let path = local_store_path(&info.path)?;
    match compression {
        Compression::None => unreachable!(),
        Compression::Zstd => {
            let mut encoder = StreamingEncoder::new(&mut measured, CompressionLevel::Fastest);
            let summary = write_nar(&path, &mut encoder)?;
            encoder
                .finish()
                .map_err(|error| format!("finishing zstd NAR: {error}"))?;
            verify_nar_summary(info, &summary)?;
        }
        Compression::Xz => {
            let mut encoder = XzWriter::new(&mut measured, XzOptions::with_preset(1))
                .map_err(|error| format!("creating XZ encoder: {error}"))?;
            let summary = write_nar(&path, &mut encoder)?;
            encoder
                .finish()
                .map_err(|error| format!("finishing XZ NAR: {error}"))?;
            verify_nar_summary(info, &summary)?;
        }
    }
    let (_, file_hash, file_size) = measured.finish();
    let codec = match compression {
        Compression::Zstd => CompressionCodec::Zstd,
        Compression::Xz => CompressionCodec::Xz,
        Compression::None => unreachable!(),
    };
    Ok(PreparedNar {
        identity: EncodedIdentity::new(codec, file_hash, file_size),
    })
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
