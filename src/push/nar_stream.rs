use std::{
    fs::{self, File},
    io::{self, PipeReader, Read, Take, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    thread,
};

use sha2::{Digest, Sha256};

use super::{NarInfoMetadata, PushError, payload::write_encoded_nar};
use narjar::nar_encode::{EncodeSummary, Encoder, Event};
use narjar::object::{ContentIdentity, EncodedFile, FileHash, NarRepresentation};

const FILE_BUFFER_SIZE: usize = 64 * 1024;

pub(super) fn write_nar<W: Write>(path: &Path, output: W) -> Result<EncodeSummary, PushError> {
    let mut encoder =
        Encoder::new(output).map_err(|error| format!("creating NAR encoder: {error}"))?;
    emit_path(&mut encoder, path)
        .map_err(|error| format!("serializing {}: {error}", path.display()))?;
    encoder
        .finish()
        .map(|(_, summary)| summary)
        .map_err(|error| PushError::new(format!("finishing {}: {error}", path.display())))
}

pub(super) fn local_store_path(store_path: &str) -> Result<PathBuf, PushError> {
    let relative = store_path
        .strip_prefix("/nix/store/")
        .filter(|relative| !relative.is_empty() && !relative.contains('/'))
        .ok_or_else(|| format!("invalid store path: {store_path}"))?;
    let root =
        std::env::var_os("NIX_STORE_DIR").unwrap_or_else(|| std::ffi::OsString::from("/nix/store"));
    Ok(PathBuf::from(root).join(relative))
}

pub(super) fn open_upload_reader(
    representation: NarRepresentation,
    info: &NarInfoMetadata,
) -> Result<Box<dyn Read + Send>, PushError> {
    open_upload_reader_at(
        representation,
        local_store_path(info.claims().store_path())?,
    )
}

fn open_upload_reader_at(
    representation: NarRepresentation,
    path: PathBuf,
) -> Result<Box<dyn Read + Send>, PushError> {
    let expected = ContentIdentity::new(
        representation.file_name().file_hash(),
        representation.encoded_size(),
    );
    let reader = VerifiedNarReader::spawn(expected, move |writer| match representation {
        NarRepresentation::Raw(_) => write_nar(&path, writer).map(|_| ()),
        NarRepresentation::Compressed(identity) => write_encoded_nar(&path, identity, writer),
    })?;
    Ok(Box::new(reader))
}

enum VerifiedNarReader {
    Streaming(StreamingNar),
    Complete,
    Failed,
}

struct StreamingNar {
    reader: Take<PipeReader>,
    producer: Receiver<Result<(), PushError>>,
    expected: ContentIdentity<EncodedFile>,
    digest: Sha256,
}

impl VerifiedNarReader {
    fn spawn(
        expected: ContentIdentity<EncodedFile>,
        write: impl FnOnce(&mut std::io::PipeWriter) -> Result<(), PushError> + Send + 'static,
    ) -> Result<Self, PushError> {
        let (reader, mut writer) =
            io::pipe().map_err(|error| format!("creating NAR pipe: {error}"))?;
        let (sender, producer) = mpsc::channel();
        thread::Builder::new()
            .name("narjar-nar-stream".into())
            .spawn(move || {
                let result = write(&mut writer);
                drop(writer);
                let _ = sender.send(result);
            })
            .map_err(|error| format!("starting NAR serializer: {error}"))?;
        Ok(Self::Streaming(StreamingNar {
            reader: reader.take(expected.size().get()),
            producer,
            expected,
            digest: Sha256::new(),
        }))
    }

    fn read_next(self, buffer: &mut [u8]) -> io::Result<(Self, usize)> {
        match self {
            Self::Streaming(mut stream) => {
                let length = stream.read_chunk(buffer)?;
                let next = match stream.reader.limit() {
                    0 => {
                        stream.finish()?;
                        Self::Complete
                    }
                    _ => Self::Streaming(stream),
                };
                Ok((next, length))
            }
            Self::Complete => Ok((Self::Complete, 0)),
            Self::Failed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified NAR stream is in a failed state",
            )),
        }
    }
}

impl Read for VerifiedNarReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let current = std::mem::replace(self, Self::Failed);
        let (next, length) = current.read_next(buffer)?;
        *self = next;
        Ok(length)
    }
}

impl StreamingNar {
    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = self.reader.read(buffer)?;
        if length == 0 && self.reader.limit() != 0 {
            wait_for_nar_producer(&self.producer)?;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NAR serializer ended before the declared size",
            ));
        }
        self.digest.update(&buffer[..length]);
        Ok(length)
    }

    fn finish(self) -> io::Result<()> {
        let Self {
            reader: mut bounded_reader,
            producer,
            expected,
            digest,
        } = self;
        let actual_hash = FileHash::from_digest(digest.finalize().into());
        if actual_hash != expected.hash() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "NAR identity mismatch: expected {}/{}; got {}/{}",
                    expected.hash(),
                    expected.size(),
                    actual_hash,
                    expected.size(),
                ),
            ));
        }
        if bounded_reader.get_mut().read(&mut [0; 1])? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR serializer exceeded the declared size",
            ));
        }
        wait_for_nar_producer(&producer)
    }
}

fn wait_for_nar_producer(producer: &Receiver<Result<(), PushError>>) -> io::Result<()> {
    producer
        .recv()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "NAR serializer result was dropped",
            )
        })?
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("NAR serializer failed: {error}"),
            )
        })
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

    use super::{VerifiedNarReader, open_upload_reader_at, write_nar};
    use crate::push::NarInfoMetadata;
    use narjar::nar::{Decoder, Event};
    use narjar::object::{
        ContentIdentity, EncodedSize, FileHash, NarHash, NarIdentity, NarRepresentation, NarSize,
    };
    use sha2::{Digest, Sha256};

    fn test_reader(
        output: Vec<u8>,
        expected: Vec<u8>,
        result: Result<(), super::PushError>,
    ) -> VerifiedNarReader {
        let expected = ContentIdentity::new(
            FileHash::from_digest(Sha256::digest(&expected).into()),
            EncodedSize::new(expected.len() as u64),
        );
        VerifiedNarReader::spawn(expected, move |writer| {
            writer
                .write_all(&output)
                .map_err(|error| error.to_string())?;
            result
        })
        .expect("spawn test NAR producer")
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
                names.push(name.to_vec());
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

        let mut reader = open_upload_reader_at(
            NarRepresentation::Raw(info.claims().identity()),
            directory.path().to_owned(),
        )
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
            Err("producer failed after writing the prefix".into()),
        );

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("producer failure is hidden");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("producer failed"));
        assert_stays_failed(&mut reader);
    }

    #[test]
    fn verified_reader_rejects_trailing_bytes_after_the_expected_prefix() {
        let mut output = b"expected".to_vec();
        output.push(b'!');
        let mut reader = test_reader(output, b"expected".to_vec(), Ok(()));

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("trailing bytes accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeded"));
        assert_stays_failed(&mut reader);
    }

    #[test]
    fn verified_reader_rejects_short_output_even_when_the_producer_succeeds() {
        let mut reader = test_reader(b"short".to_vec(), b"shorter".to_vec(), Ok(()));

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("short output accepted");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_stays_failed(&mut reader);
    }

    #[test]
    fn verified_reader_reports_producer_failure_when_output_is_short() {
        let mut reader = test_reader(
            b"short".to_vec(),
            b"longer than short".to_vec(),
            Err("source file could not be read".into()),
        );

        let error = io::copy(&mut reader, &mut io::sink())
            .expect_err("producer failure should explain the short stream");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("source file could not be read"));
        assert_stays_failed(&mut reader);
    }

    #[test]
    fn verified_reader_stays_failed_after_a_hash_mismatch() {
        let mut reader = test_reader(b"actual".to_vec(), b"expect".to_vec(), Ok(()));

        let error = io::copy(&mut reader, &mut io::sink()).expect_err("hash mismatch accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("identity mismatch"));
        assert_stays_failed(&mut reader);
    }

    fn assert_stays_failed(reader: &mut VerifiedNarReader) {
        assert!(matches!(reader, VerifiedNarReader::Failed));
        assert_eq!(reader.read(&mut []).unwrap(), 0);
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
        assert!(matches!(reader, VerifiedNarReader::Complete));
        assert_eq!(
            reader
                .read(&mut [0; 1])
                .expect("completed reader is readable"),
            0
        );
    }

    #[test]
    fn verified_reader_does_not_return_the_final_byte_before_producer_verification() {
        for (output, result) in [
            (b"ab".to_vec(), Err("producer failed".into())),
            (b"ab!".to_vec(), Ok(())),
        ] {
            let mut reader = test_reader(output, b"ab".to_vec(), result);
            let mut byte = [0; 1];
            assert_eq!(reader.read(&mut byte).unwrap(), 1);
            assert_eq!(byte, *b"a");
            let error = reader
                .read(&mut byte)
                .expect_err("the last byte must not complete a failed upload");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_stays_failed(&mut reader);
        }
    }

    #[test]
    fn empty_reads_do_not_consume_or_complete_a_stream() {
        let mut reader = test_reader(b"a".to_vec(), b"a".to_vec(), Ok(()));
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert!(matches!(reader, VerifiedNarReader::Streaming(_)));
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 1);
        assert!(matches!(reader, VerifiedNarReader::Complete));
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn empty_streams_still_require_the_expected_hash_and_producer_success() {
        let empty_hash = FileHash::from_digest(Sha256::digest([]).into());
        let wrong_hash = FileHash::from_digest(Sha256::digest(b"not empty").into());
        for (hash, result, succeeds) in [
            (empty_hash, Ok(()), true),
            (wrong_hash, Ok(()), false),
            (empty_hash, Err("producer failed".into()), false),
        ] {
            let mut reader = VerifiedNarReader::spawn(
                ContentIdentity::new(hash, EncodedSize::new(0)),
                move |_| result,
            )
            .unwrap();
            let read = reader.read(&mut [0; 1]);
            if succeeds {
                assert_eq!(read.unwrap(), 0);
                assert!(matches!(reader, VerifiedNarReader::Complete));
            } else {
                assert_eq!(read.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert_stays_failed(&mut reader);
            }
        }
    }
}
