use std::{
    io::{self, PipeReader, PipeWriter, Read, Take},
    sync::mpsc::{self, Receiver},
    thread,
};

use narjar::object::{ContentIdentity, Sha256Digest};
use sha2::{Digest, Sha256};

/// Withholds successful completion until the stream and producer both agree.
pub(crate) struct VerifiedStream<Purpose, R = PipeReader> {
    state: StreamState<Purpose, R>,
}

enum StreamState<Purpose, R> {
    Streaming(ReceivingStream<Purpose, R>),
    Complete,
    Failed,
}

struct ReceivingStream<Purpose, R> {
    reader: Take<R>,
    producer: Receiver<io::Result<()>>,
    expected: ContentIdentity<Purpose>,
    digest: Sha256,
}

impl<Purpose: Copy + Eq> VerifiedStream<Purpose> {
    pub(crate) fn spawn(
        expected: ContentIdentity<Purpose>,
        thread_name: &str,
        produce: impl FnOnce(&mut PipeWriter) -> io::Result<()> + Send + 'static,
    ) -> io::Result<Self> {
        let (reader, mut writer) = io::pipe()?;
        let (sender, producer) = mpsc::channel();
        thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                let result = produce(&mut writer);
                drop(writer);
                let _ = sender.send(result);
            })?;
        Ok(Self::new(expected, reader, producer))
    }
}

impl<Purpose: Copy + Eq, R: Read> VerifiedStream<Purpose, R> {
    pub(crate) fn new(
        expected: ContentIdentity<Purpose>,
        reader: R,
        producer: Receiver<io::Result<()>>,
    ) -> Self {
        Self {
            state: StreamState::Streaming(ReceivingStream {
                reader: reader.take(expected.size().get()),
                producer,
                expected,
                digest: Sha256::new(),
            }),
        }
    }
}

impl<Purpose: Copy + Eq, R: Read> StreamState<Purpose, R> {
    fn read_and_verify_completion(self, buffer: &mut [u8]) -> io::Result<(Self, usize)> {
        match self {
            Self::Streaming(stream) => stream.read_and_verify_completion(buffer),
            Self::Complete => Ok((Self::Complete, 0)),
            Self::Failed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified NAR stream is in a failed state",
            )),
        }
    }
}

impl<Purpose: Copy + Eq, R: Read> Read for VerifiedStream<Purpose, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let current = std::mem::replace(&mut self.state, StreamState::Failed);
        let (next, length) = current.read_and_verify_completion(buffer)?;
        self.state = next;
        Ok(length)
    }
}

impl<Purpose: Copy + Eq, R: Read> ReceivingStream<Purpose, R> {
    fn read_and_verify_completion(
        mut self,
        buffer: &mut [u8],
    ) -> io::Result<(StreamState<Purpose, R>, usize)> {
        let length = self.read_chunk(buffer)?;
        let next = match self.reader.limit() {
            0 => {
                self.verify_identity_and_producer_completion()?;
                StreamState::Complete
            }
            _ => StreamState::Streaming(self),
        };
        Ok((next, length))
    }

    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = read_uninterrupted_chunk(&mut self.reader, buffer)?;
        if length == 0 && self.reader.limit() != 0 {
            wait_for_producer_completion(&self.producer)?;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NAR producer ended before the declared size",
            ));
        }
        self.digest.update(&buffer[..length]);
        Ok(length)
    }

    fn verify_identity_and_producer_completion(self) -> io::Result<()> {
        let Self {
            mut reader,
            producer,
            expected,
            digest,
        } = self;
        let actual_hash = Sha256Digest::<Purpose>::from_digest(digest.finalize().into());
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
        if read_uninterrupted_chunk(reader.get_mut(), &mut [0; 1])? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR producer exceeded the declared size",
            ));
        }
        wait_for_producer_completion(&producer)
    }
}

fn wait_for_producer_completion(producer: &Receiver<io::Result<()>>) -> io::Result<()> {
    producer
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "NAR producer result was dropped"))?
}

pub(crate) fn read_uninterrupted_chunk(
    source: &mut impl Read,
    buffer: &mut [u8],
) -> io::Result<usize> {
    std::iter::repeat_with(|| source.read(buffer))
        .find(|result| match result {
            Ok(_) => true,
            Err(error) => error.kind() != io::ErrorKind::Interrupted,
        })
        .expect("repeat_with yields until the read is not interrupted")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Read},
        sync::mpsc,
    };

    use narjar::object::{
        ByteCount, ContentIdentity, EncodedFile, EncodedSize, FileHash, LogicalNar, Sha256Digest,
    };
    use sha2::{Digest, Sha256};

    use super::VerifiedStream;

    fn identity<Purpose>(bytes: &[u8]) -> ContentIdentity<Purpose> {
        ContentIdentity::new(
            Sha256Digest::from_digest(Sha256::digest(bytes).into()),
            ByteCount::new(bytes.len() as u64),
        )
    }

    #[derive(Debug)]
    struct SourceFailure;

    impl std::fmt::Display for SourceFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("original source failure")
        }
    }

    impl std::error::Error for SourceFailure {}

    struct FailAtOffset {
        source: io::Cursor<Vec<u8>>,
        fail_at: u64,
    }

    impl Read for FailAtOffset {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.source.position() == self.fail_at {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    SourceFailure,
                ));
            }
            self.source.read(buffer)
        }
    }

    struct InterruptAtOffset {
        source: io::Cursor<Vec<u8>>,
        interrupt_at: Option<u64>,
    }

    impl Read for InterruptAtOffset {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt_at == Some(self.source.position()) {
                self.interrupt_at = None;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.source.read(buffer)
        }
    }

    #[test]
    fn retries_interruption_before_progress_after_progress_and_at_the_excess_byte_probe() {
        for offset in [0, 3, 6] {
            let bytes = b"narjar".to_vec();
            let expected: ContentIdentity<EncodedFile> = ContentIdentity::new(
                FileHash::from_digest(Sha256::digest(&bytes).into()),
                EncodedSize::new(bytes.len() as u64),
            );
            let (sender, producer) = mpsc::channel();
            sender.send(Ok(())).unwrap();
            let source = InterruptAtOffset {
                source: io::Cursor::new(bytes.clone()),
                interrupt_at: Some(offset),
            };
            let mut reader = VerifiedStream::new(expected, source, producer);
            let mut actual = Vec::new();
            let mut chunk = [0; 3];
            for _ in 0..2 {
                let length = reader
                    .read(&mut chunk)
                    .expect("retry interruption internally");
                actual.extend_from_slice(&chunk[..length]);
            }
            assert_eq!(actual, bytes);
            assert_eq!(reader.read(&mut chunk).expect("verified EOF"), 0);
        }
    }

    #[test]
    fn preserves_source_errors_before_progress_after_progress_and_during_the_excess_byte_probe() {
        for offset in [0, 3, 6] {
            let bytes = b"narjar";
            let (sender, producer) = mpsc::channel();
            sender.send(Ok(())).unwrap();
            let source = FailAtOffset {
                source: io::Cursor::new(bytes.to_vec()),
                fail_at: offset,
            };
            let mut reader = VerifiedStream::new(identity::<LogicalNar>(bytes), source, producer);
            let mut chunk = [0; 3];
            if offset != 0 {
                assert_eq!(reader.read(&mut chunk).unwrap(), 3);
                assert_eq!(chunk, *b"nar");
            }
            let error = reader
                .read(&mut chunk)
                .expect_err("source error must fail the read");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.get_ref().unwrap().is::<SourceFailure>());
            assert_eq!(reader.read(&mut []).unwrap(), 0);
            assert_eq!(
                reader.read(&mut chunk).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn native_producer_errors_retain_their_kind_and_cause_for_short_and_exact_output() {
        let expected = b"narjar";
        for output in [expected.as_slice(), b"nar".as_slice()] {
            let (sender, producer) = mpsc::channel();
            sender
                .send(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    SourceFailure,
                )))
                .unwrap();
            let mut reader = VerifiedStream::new(
                identity::<LogicalNar>(expected),
                io::Cursor::new(output),
                producer,
            );
            let error = io::copy(&mut reader, &mut io::sink())
                .expect_err("producer failure must not become clean EOF");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.get_ref().unwrap().is::<SourceFailure>());
        }
    }

    #[test]
    fn disconnected_producers_never_complete_empty_short_or_exact_streams() {
        for (expected, output) in [
            (b"".as_slice(), b"".as_slice()),
            (b"narjar".as_slice(), b"nar".as_slice()),
            (b"narjar".as_slice(), b"narjar".as_slice()),
        ] {
            let (sender, producer) = mpsc::channel::<io::Result<()>>();
            drop(sender);
            let mut reader = VerifiedStream::new(
                identity::<EncodedFile>(expected),
                io::Cursor::new(output),
                producer,
            );
            // Even an empty stream must observe producer completion on a nonempty read.
            assert_eq!(reader.read(&mut []).unwrap(), 0);
            let error = io::copy(&mut reader, &mut io::sink())
                .expect_err("missing result is not producer success");
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(reader.read(&mut []).unwrap(), 0);
            assert_eq!(
                reader.read(&mut [0; 1]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn logical_and_encoded_streams_both_verify_without_retagging_the_expected_identity() {
        fn verify<Purpose: Copy + Eq>() {
            let bytes = b"narjar";
            let (sender, producer) = mpsc::channel();
            sender.send(Ok(())).unwrap();
            let mut reader =
                VerifiedStream::new(identity::<Purpose>(bytes), io::Cursor::new(bytes), producer);
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, bytes);
            assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        }
        verify::<LogicalNar>();
        verify::<EncodedFile>();
    }
}
