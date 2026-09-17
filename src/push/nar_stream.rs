use std::{
    fs::{self, File},
    io::{self, PipeReader, Read, Write},
    path::{Path, PathBuf},
    thread,
};

use sha2::{Digest, Sha256};

use super::{Compression, PathInfo};
use crate::nar_encode::{EncodeSummary, Encoder, Event};

const FILE_BUFFER_SIZE: usize = 64 * 1024;

pub(super) fn write_nar<W: Write>(path: &Path, output: W) -> Result<EncodeSummary, String> {
    let mut encoder =
        Encoder::new(output).map_err(|error| format!("creating NAR encoder: {error}"))?;
    emit_path(&mut encoder, path)
        .map_err(|error| format!("serializing {}: {error}", path.display()))?;
    encoder
        .finish()
        .map(|(_, summary)| summary)
        .map_err(|error| format!("finishing {}: {error}", path.display()))
}

pub(super) fn local_store_path(store_path: &str) -> Result<PathBuf, String> {
    let relative = store_path
        .strip_prefix("/nix/store/")
        .filter(|relative| !relative.is_empty() && !relative.contains('/'))
        .ok_or_else(|| format!("invalid store path: {store_path}"))?;
    let root =
        std::env::var_os("NIX_STORE_DIR").unwrap_or_else(|| std::ffi::OsString::from("/nix/store"));
    Ok(PathBuf::from(root).join(relative))
}

pub(super) fn verify_nar_summary(info: &PathInfo, summary: &EncodeSummary) -> Result<(), String> {
    let expected_hash = super::nix32_sha256_from_sri(&info.nar_hash)?;
    let actual_hash = nix32_digest(summary.raw_sha256);
    if summary.raw_size != info.nar_size || actual_hash != expected_hash {
        return Err(format!(
            "NAR identity mismatch for {}: expected {expected_hash}/{}; got {actual_hash}/{}",
            info.path, info.nar_size, summary.raw_size
        ));
    }
    Ok(())
}

pub(super) fn open_verified_nar_reader(info: &PathInfo) -> Result<Box<dyn Read + Send>, String> {
    open_verified_nar_reader_at(info, local_store_path(&info.path)?)
}

fn open_verified_nar_reader_at(
    info: &PathInfo,
    path: PathBuf,
) -> Result<Box<dyn Read + Send>, String> {
    let expected_hash = super::nix32_sha256_from_sri(&info.nar_hash)?;
    let reader = VerifiedNarReader {
        reader: spawn_nar_writer(path, Compression::None, None)?,
        expected_hash,
        expected_size: info.nar_size,
        digest: Sha256::new(),
        bytes_read: 0,
        complete: false,
    };
    Ok(Box::new(reader))
}

pub(super) fn open_verified_encoded_nar_reader(
    info: &PathInfo,
    compression: Compression,
    expected_hash: &str,
    expected_size: u64,
) -> Result<Box<dyn Read + Send>, String> {
    let reader = VerifiedNarReader {
        reader: spawn_nar_writer(
            local_store_path(&info.path)?,
            compression,
            Some(info.clone()),
        )?,
        expected_hash: expected_hash.to_owned(),
        expected_size,
        digest: Sha256::new(),
        bytes_read: 0,
        complete: false,
    };
    Ok(Box::new(reader))
}

fn spawn_nar_writer(
    path: PathBuf,
    compression: Compression,
    info: Option<PathInfo>,
) -> Result<PipeReader, String> {
    let (reader, mut writer) = io::pipe().map_err(|error| format!("creating NAR pipe: {error}"))?;
    thread::Builder::new()
        .name("narjar-nar-stream".into())
        .spawn(move || {
            let result = match compression {
                Compression::None => write_nar(&path, &mut writer).map(|_| ()),
                Compression::Zstd | Compression::Xz => write_encoded_nar(
                    &path,
                    info.as_ref().expect("encoded NAR metadata"),
                    compression,
                    &mut writer,
                ),
            };
            let _ = result;
        })
        .map_err(|error| format!("starting NAR serializer: {error}"))?;
    Ok(reader)
}

fn write_encoded_nar<W: Write>(
    path: &Path,
    info: &PathInfo,
    compression: Compression,
    output: W,
) -> Result<(), String> {
    let mut output = output;
    let summary = match compression {
        Compression::Zstd => {
            let mut encoder = structured_zstd::encoding::StreamingEncoder::new(
                &mut output,
                structured_zstd::encoding::CompressionLevel::Fastest,
            );
            let summary = write_nar(path, &mut encoder)?;
            encoder
                .finish()
                .map_err(|error| format!("finishing zstd NAR: {error}"))?;
            summary
        }
        Compression::Xz => {
            let mut encoder =
                lzma_rust2::XzWriter::new(&mut output, lzma_rust2::XzOptions::with_preset(1))
                    .map_err(|error| format!("creating XZ encoder: {error}"))?;
            let summary = write_nar(path, &mut encoder)?;
            encoder
                .finish()
                .map_err(|error| format!("finishing XZ NAR: {error}"))?;
            summary
        }
        Compression::None => unreachable!("raw NARs do not use an encoded writer"),
    };
    verify_nar_summary(info, &summary)
}

struct VerifiedNarReader {
    reader: PipeReader,
    expected_hash: String,
    expected_size: u64,
    digest: Sha256,
    bytes_read: u64,
    complete: bool,
}

impl Read for VerifiedNarReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.complete {
            return Ok(0);
        }
        let length = self.reader.read(buffer)?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NAR serializer ended before the declared size",
            ));
        }
        self.bytes_read = self
            .bytes_read
            .checked_add(length as u64)
            .ok_or_else(|| io::Error::other("NAR stream size overflow"))?;
        if self.bytes_read > self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR serializer exceeded the declared size",
            ));
        }
        self.digest.update(&buffer[..length]);
        if self.bytes_read == self.expected_size {
            let actual_hash =
                super::nar_stream::nix32_digest(self.digest.clone().finalize().into());
            if actual_hash != self.expected_hash {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "NAR identity mismatch: expected {}/{}; got {}/{}",
                        self.expected_hash, self.expected_size, actual_hash, self.bytes_read
                    ),
                ));
            }
            self.complete = true;
        }
        Ok(length)
    }
}

fn emit_path<W: Write>(encoder: &mut Encoder<W>, path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        emit_directory(encoder, path)
    } else if file_type.is_file() {
        emit_regular_file(encoder, path, metadata.len())
    } else if file_type.is_symlink() {
        emit_symlink(encoder, path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAR cannot represent this filesystem object",
        ))
    }
}

fn emit_directory<W: Write>(encoder: &mut Encoder<W>, path: &Path) -> io::Result<()> {
    encoder
        .push(Event::BeginDirectory)
        .map_err(encode_io_error)?;

    let mut entries = fs::read_dir(path)?
        .map(|entry| {
            let entry = entry?;
            let name = entry.file_name();
            #[cfg(unix)]
            let bytes = std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str()).to_vec();
            #[cfg(not(unix))]
            let bytes = name.to_string_lossy().into_owned().into_bytes();
            Ok((bytes, entry.path()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for (name, child) in entries {
        encoder.push(Event::Entry(&name)).map_err(encode_io_error)?;
        emit_path(encoder, &child)?;
    }
    encoder.push(Event::EndDirectory).map_err(encode_io_error)
}

fn emit_regular_file<W: Write>(encoder: &mut Encoder<W>, path: &Path, size: u64) -> io::Result<()> {
    #[cfg(unix)]
    let executable =
        std::os::unix::fs::MetadataExt::mode(&fs::symlink_metadata(path)?) & 0o111 != 0;
    #[cfg(not(unix))]
    let executable = false;

    encoder
        .push(Event::BeginFile { executable, size })
        .map_err(encode_io_error)?;
    let mut file = File::open(path)?;
    let mut buffer = [0; FILE_BUFFER_SIZE];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        encoder
            .push(Event::FileChunk(&buffer[..length]))
            .map_err(encode_io_error)?;
    }
    encoder.push(Event::EndFile).map_err(encode_io_error)
}

fn emit_symlink<W: Write>(encoder: &mut Encoder<W>, path: &Path) -> io::Result<()> {
    let target = fs::read_link(path)?;
    #[cfg(unix)]
    let target = std::os::unix::ffi::OsStrExt::as_bytes(target.as_os_str()).to_vec();
    #[cfg(not(unix))]
    let target = target.to_string_lossy().into_owned().into_bytes();
    encoder
        .push(Event::Symlink(&target))
        .map_err(encode_io_error)
}

fn encode_io_error(error: crate::nar_encode::EncodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(super) fn nix32_digest(digest: [u8; 32]) -> String {
    let encoding = super::nix32_encoding();
    let mut output = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(&digest, &mut output);
    output.reverse();
    String::from_utf8(output).expect("Nix base32 alphabet is ASCII")
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::{convert::Infallible, fs, io::Read};

    use data_encoding::BASE64;

    use super::{nix32_digest, open_verified_nar_reader_at, write_nar};
    use crate::nar::{Decoder, Event};
    use crate::push::PathInfo;

    #[test]
    fn emits_a_canonical_sorted_directory_stream() {
        let directory = tempfile::tempdir().expect("create NAR fixture directory");
        fs::write(directory.path().join("z"), b"last").expect("write z");
        fs::write(directory.path().join("a"), b"first").expect("write a");
        std::os::unix::fs::symlink("a", directory.path().join("link")).expect("write link");

        let mut archive = Vec::new();
        let summary = write_nar(directory.path(), &mut archive).expect("serialize fixture");
        assert_eq!(summary.entries, 3);
        assert_eq!(summary.files, 2);
        assert_eq!(summary.symlinks, 1);

        let mut names = Vec::<Vec<u8>>::new();
        let mut sink = |event: Event<'_>| -> Result<(), Infallible> {
            if let Event::Entry { name } = event {
                names.push(name);
            }
            Ok(())
        };
        Decoder::new(&archive[..])
            .decode(&mut sink)
            .expect("decode serialized fixture");
        assert_eq!(names, [b"a".to_vec(), b"link".to_vec(), b"z".to_vec()]);
    }

    #[test]
    fn verified_reader_reproduces_the_measured_nar_without_a_file() {
        let directory = tempfile::tempdir().expect("create NAR fixture directory");
        fs::write(directory.path().join("payload"), vec![b'x'; 128 * 1024])
            .expect("write NAR fixture");
        let mut expected = Vec::new();
        let summary = write_nar(directory.path(), &mut expected).expect("measure NAR fixture");
        let info = PathInfo {
            path: directory.path().display().to_string(),
            ca: None,
            deriver: None,
            nar_hash: format!("sha256-{}", BASE64.encode(&summary.raw_sha256)),
            nar_size: summary.raw_size,
            references: Vec::new(),
            signatures: Vec::new(),
        };

        let mut reader = open_verified_nar_reader_at(&info, directory.path().to_owned())
            .expect("open NAR stream");
        let mut actual = Vec::new();
        reader
            .read_to_end(&mut actual)
            .expect("read verified NAR stream");
        assert_eq!(actual, expected);
        assert_eq!(
            nix32_digest(summary.raw_sha256),
            super::super::nix32_sha256_from_sri(&info.nar_hash).expect("Nix hash")
        );
    }
}
