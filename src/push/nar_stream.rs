use std::{
    fs::{self, File},
    io::{self, PipeReader, Read, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    thread,
};

use sha2::{Digest, Sha256};

use super::{NarInfoMetadata, payload::write_encoded_nar};
use narjar::nar_encode::{EncodeSummary, Encoder, Event};
use narjar::object::{CompressionCodec, EncodedIdentity, FileHash, NarHash};

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

pub(super) fn verify_nar_summary(
    info: &NarInfoMetadata,
    summary: &EncodeSummary,
) -> Result<(), String> {
    let expected = info.claims().identity();
    let expected_hash = expected.hash();
    let actual_hash = NarHash::from_digest(summary.raw_sha256);
    if summary.raw_size != expected.size().get() || actual_hash != expected_hash {
        return Err(format!(
            "NAR identity mismatch for {}: expected {expected_hash}/{}; got {actual_hash}/{}",
            info.claims().store_path(),
            expected.size(),
            summary.raw_size
        ));
    }
    Ok(())
}

pub(super) fn open_verified_nar_reader(
    info: &NarInfoMetadata,
) -> Result<Box<dyn Read + Send>, String> {
    open_verified_nar_reader_at(info, local_store_path(info.claims().store_path())?)
}

fn open_verified_nar_reader_at(
    info: &NarInfoMetadata,
    path: PathBuf,
) -> Result<Box<dyn Read + Send>, String> {
    let (reader, producer) = spawn_nar_writer(move |writer| write_nar(&path, writer).map(|_| ()))?;
    let reader = VerifiedNarReader {
        reader,
        producer,
        expected_hash: FileHash::from_nar_hash(info.claims().identity().hash()),
        expected_size: info.claims().identity().size().get(),
        digest: Sha256::new(),
        bytes_read: 0,
        state: VerificationState::Streaming,
    };
    Ok(Box::new(reader))
}

pub(super) fn open_verified_encoded_nar_reader(
    info: &NarInfoMetadata,
    codec: CompressionCodec,
    expected: EncodedIdentity,
) -> Result<Box<dyn Read + Send>, String> {
    let path = local_store_path(info.claims().store_path())?;
    let info = info.clone();
    let (reader, producer) =
        spawn_nar_writer(move |writer| write_encoded_nar(&path, &info, codec, writer))?;
    let reader = VerifiedNarReader {
        reader,
        producer,
        expected_hash: expected.hash(),
        expected_size: expected.size().get(),
        digest: Sha256::new(),
        bytes_read: 0,
        state: VerificationState::Streaming,
    };
    Ok(Box::new(reader))
}

fn spawn_nar_writer(
    write: impl FnOnce(&mut std::io::PipeWriter) -> Result<(), String> + Send + 'static,
) -> Result<(PipeReader, Receiver<Result<(), String>>), String> {
    let (reader, mut writer) = io::pipe().map_err(|error| format!("creating NAR pipe: {error}"))?;
    let (result_sender, result_receiver) = mpsc::channel();
    thread::Builder::new()
        .name("narjar-nar-stream".into())
        .spawn(move || {
            let result = write(&mut writer);
            drop(writer);
            let _ = result_sender.send(result);
        })
        .map_err(|error| format!("starting NAR serializer: {error}"))?;
    Ok((reader, result_receiver))
}

enum VerificationState {
    Streaming,
    Complete,
    Failed,
}

struct VerifiedNarReader {
    reader: PipeReader,
    producer: Receiver<Result<(), String>>,
    expected_hash: FileHash,
    expected_size: u64,
    digest: Sha256,
    bytes_read: u64,
    state: VerificationState,
}

impl VerifiedNarReader {
    fn finish_stream(&mut self) -> io::Result<()> {
        let mut extra = [0; 1];
        let result = (|| {
            if self.reader.read(&mut extra)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NAR serializer exceeded the declared size",
                ));
            }
            match self.producer.recv() {
                Ok(Ok(())) => {
                    self.state = VerificationState::Complete;
                    Ok(())
                }
                Ok(Err(error)) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("NAR serializer failed: {error}"),
                )),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "NAR serializer result was dropped",
                )),
            }
        })();
        if result.is_err() {
            self.state = VerificationState::Failed;
        }
        result
    }
}

impl Read for VerifiedNarReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if matches!(self.state, VerificationState::Complete) {
            return Ok(0);
        }
        if matches!(self.state, VerificationState::Failed) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified NAR stream is in a failed state",
            ));
        }
        if self.bytes_read == self.expected_size {
            self.finish_stream()?;
            return Ok(0);
        }
        let length = match self.reader.read(buffer) {
            Ok(length) => length,
            Err(error) => {
                self.state = VerificationState::Failed;
                return Err(error);
            }
        };
        if length == 0 {
            self.state = VerificationState::Failed;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NAR serializer ended before the declared size",
            ));
        }
        self.bytes_read = match self.bytes_read.checked_add(length as u64) {
            Some(bytes_read) => bytes_read,
            None => {
                self.state = VerificationState::Failed;
                return Err(io::Error::other("NAR stream size overflow"));
            }
        };
        if self.bytes_read > self.expected_size {
            self.state = VerificationState::Failed;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR serializer exceeded the declared size",
            ));
        }
        self.digest.update(&buffer[..length]);
        if self.bytes_read == self.expected_size {
            let actual_hash = FileHash::from_digest(self.digest.clone().finalize().into());
            if actual_hash != self.expected_hash {
                self.state = VerificationState::Failed;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "NAR identity mismatch: expected {}/{}; got {}/{}",
                        self.expected_hash, self.expected_size, actual_hash, self.bytes_read
                    ),
                ));
            }
            self.finish_stream()?;
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

fn encode_io_error(error: narjar::nar_encode::EncodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::{
        convert::Infallible,
        fs,
        io::{self, Read, Write},
    };

    use super::{
        VerificationState, VerifiedNarReader, open_verified_nar_reader_at, spawn_nar_writer,
        write_nar,
    };
    use crate::push::NarInfoMetadata;
    use narjar::nar::{Decoder, Event};
    use narjar::object::{FileHash, NarHash, NarIdentity, NarSize};
    use sha2::{Digest, Sha256};

    fn test_reader(
        output: Vec<u8>,
        expected: Vec<u8>,
        result: Result<(), String>,
    ) -> VerifiedNarReader {
        let (reader, producer) = spawn_nar_writer(move |writer| {
            writer
                .write_all(&output)
                .map_err(|error| error.to_string())?;
            result
        })
        .expect("spawn test NAR producer");
        VerifiedNarReader {
            reader,
            producer,
            expected_hash: FileHash::from_digest(Sha256::digest(&expected).into()),
            expected_size: expected.len() as u64,
            digest: Sha256::new(),
            bytes_read: 0,
            state: VerificationState::Streaming,
        }
    }

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
        let info = NarInfoMetadata::from_store_metadata(
            "/nix/store/00000000000000000000000000000000-fixture".to_owned(),
            None,
            None,
            NarIdentity::new(
                NarHash::from_digest(summary.raw_sha256),
                NarSize::new(summary.raw_size),
            ),
            Vec::new(),
            Vec::new(),
        )
        .expect("valid fixture metadata");

        let mut reader = open_verified_nar_reader_at(&info, directory.path().to_owned())
            .expect("open NAR stream");
        let mut actual = Vec::new();
        reader
            .read_to_end(&mut actual)
            .expect("read verified NAR stream");
        assert_eq!(actual, expected);
        assert_eq!(
            info.claims().identity().hash(),
            NarHash::from_digest(summary.raw_sha256)
        );
    }

    #[test]
    fn verified_reader_requires_producer_success_after_the_expected_prefix() {
        let expected = b"verified prefix".to_vec();
        let mut reader = test_reader(
            expected.clone(),
            expected,
            Err("producer failed after writing the prefix".to_owned()),
        );

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("producer failure is hidden");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("producer failed"));
    }

    #[test]
    fn verified_reader_rejects_trailing_bytes_after_the_expected_prefix() {
        let mut output = b"expected".to_vec();
        output.push(b'!');
        let mut reader = test_reader(output, b"expected".to_vec(), Ok(()));

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("trailing bytes accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeded"));
    }

    #[test]
    fn verified_reader_rejects_short_output_even_when_the_producer_succeeds() {
        let mut reader = test_reader(b"short".to_vec(), b"shorter".to_vec(), Ok(()));

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("short output accepted");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn verified_reader_stays_failed_after_a_hash_mismatch() {
        let mut reader = test_reader(b"actual".to_vec(), b"expect".to_vec(), Ok(()));

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("hash mismatch accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("identity mismatch"));

        let error = reader
            .read(&mut [0; 1])
            .expect_err("failed reader returned a clean EOF");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failed state"));
    }

    #[test]
    fn verified_reader_finishes_only_after_a_successful_exact_stream() {
        let expected = b"complete".to_vec();
        let mut reader = test_reader(expected.clone(), expected.clone(), Ok(()));
        let mut actual = Vec::new();

        reader
            .read_to_end(&mut actual)
            .expect("complete stream should read successfully");
        assert_eq!(actual, expected);
        assert_eq!(
            reader
                .read(&mut [0; 1])
                .expect("completed reader is readable"),
            0
        );
    }
}
