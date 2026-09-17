use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    process::{Command, Stdio},
};

use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};
use tempfile::NamedTempFile;

use super::{Compression, PathInfo};

pub(super) struct PreparedNar {
    pub(super) file: NamedTempFile,
    pub(super) file_hash: String,
    pub(super) file_size: u64,
}

pub(super) fn prepare_nar(
    info: &PathInfo,
    compression: Compression,
) -> Result<PreparedNar, String> {
    let mut raw =
        NamedTempFile::new().map_err(|error| format!("creating NAR temporary: {error}"))?;
    let stdout = raw
        .as_file()
        .try_clone()
        .map_err(|error| format!("opening NAR temporary: {error}"))?;
    let output = Command::new("nix")
        .arg("store")
        .arg("dump-path")
        .arg("--")
        .arg(&info.path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run nix store dump-path: {error}"))?
        .wait_with_output()
        .map_err(|error| format!("failed to wait for nix store dump-path: {error}"))?;
    if !output.status.success() {
        return Err(super::format_command_failure(
            "nix store dump-path",
            &output.stderr,
        ));
    }
    raw.as_file_mut()
        .sync_all()
        .map_err(|error| format!("syncing NAR temporary: {error}"))?;
    let raw_size = raw
        .as_file()
        .metadata()
        .map_err(|error| format!("statting NAR temporary: {error}"))?
        .len();
    if raw_size != info.nar_size {
        return Err(format!(
            "NAR size mismatch for {}: expected {}, got {raw_size}",
            info.path, info.nar_size
        ));
    }
    let expected_hash = super::nix32_sha256_from_sri(&info.nar_hash)?;
    let actual_hash = sha256_file(raw.as_file())?;
    if actual_hash != expected_hash {
        return Err(format!(
            "NAR hash mismatch for {}: expected {expected_hash}, got {actual_hash}",
            info.path
        ));
    }

    if compression == Compression::None {
        return Ok(PreparedNar {
            file: raw,
            file_hash: actual_hash,
            file_size: raw_size,
        });
    }

    raw.as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewinding NAR temporary: {error}"))?;
    let mut encoded =
        NamedTempFile::new().map_err(|error| format!("creating encoded NAR temporary: {error}"))?;
    match compression {
        Compression::None => unreachable!(),
        Compression::Zstd => {
            let mut encoder =
                StreamingEncoder::new(encoded.as_file_mut(), CompressionLevel::Fastest);
            io::copy(raw.as_file_mut(), &mut encoder)
                .map_err(|error| format!("compressing NAR with zstd: {error}"))?;
            encoder
                .finish()
                .map_err(|error| format!("finishing zstd NAR: {error}"))?;
        }
        Compression::Xz => {
            let mut encoder = XzWriter::new(encoded.as_file_mut(), XzOptions::with_preset(1))
                .map_err(|error| format!("creating XZ encoder: {error}"))?;
            io::copy(raw.as_file_mut(), &mut encoder)
                .map_err(|error| format!("compressing NAR with XZ: {error}"))?;
            encoder
                .finish()
                .map_err(|error| format!("finishing XZ NAR: {error}"))?;
        }
    }
    encoded
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("syncing encoded NAR temporary: {error}"))?;
    let file_size = encoded
        .as_file()
        .metadata()
        .map_err(|error| format!("statting encoded NAR temporary: {error}"))?
        .len();
    let file_hash = sha256_file(encoded.as_file())?;
    Ok(PreparedNar {
        file: encoded,
        file_hash,
        file_size,
    })
}

fn sha256_file(file: &File) -> Result<String, String> {
    let mut file = file
        .try_clone()
        .map_err(|error| format!("cloning NAR file for hashing: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewinding NAR file for hashing: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("hashing NAR file: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let encoding = super::nix32_encoding();
    let mut output = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(&digest, &mut output);
    output.reverse();
    String::from_utf8(output).map_err(|error| format!("invalid Nix base32 output: {error}"))
}
