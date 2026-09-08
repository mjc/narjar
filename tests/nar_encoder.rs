use std::io::{self, Write};

use narjar::nar::{Decoder, Event as DecodeEvent, EventSink, RootKind};
use narjar::nar_encode::{ENCODER_VERSION, EncodeError, Encoder, Event};
use sha2::{Digest, Sha256};

struct ShortWriter {
    output: Vec<u8>,
    max_write: usize,
}

struct FailingWriter {
    remaining: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "test sink"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len().min(self.max_write);
        self.output.extend_from_slice(&bytes[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Sink {
    chunks: Vec<Vec<u8>>,
    names: Vec<Vec<u8>>,
}

impl EventSink for Sink {
    fn event(&mut self, event: DecodeEvent<'_>) -> io::Result<()> {
        match event {
            DecodeEvent::Entry { name } => self.names.push(name),
            DecodeEvent::FileChunk(chunk) => self.chunks.push(chunk.to_vec()),
            _ => {}
        }
        Ok(())
    }
}

fn encode(
    events: impl IntoIterator<Item = Event<'static>>,
) -> (Vec<u8>, narjar::nar_encode::EncodeSummary) {
    let mut encoder = Encoder::new(ShortWriter {
        output: Vec::new(),
        max_write: 3,
    })
    .expect("header");
    for event in events {
        encoder.push(event).expect("valid event stream");
    }
    let (writer, summary) = encoder.finish().expect("complete event stream");
    (writer.output, summary)
}

#[test]
fn encodes_all_root_forms_and_round_trips() {
    let cases = [
        (
            vec![
                Event::BeginFile {
                    executable: true,
                    size: 5,
                },
                Event::FileChunk(b"he"),
                Event::FileChunk(b"llo"),
                Event::EndFile,
            ],
            RootKind::Regular,
        ),
        (vec![Event::Symlink(b"../target")], RootKind::Symlink),
        (
            vec![
                Event::BeginDirectory,
                Event::Entry(b"a"),
                Event::BeginFile {
                    executable: false,
                    size: 5,
                },
                Event::FileChunk(b"hello"),
                Event::EndFile,
                Event::Entry(b"link"),
                Event::Symlink(b"../target"),
                Event::EndDirectory,
            ],
            RootKind::Directory,
        ),
    ];

    for (events, root) in cases {
        let (bytes, summary) = encode(events);
        assert_eq!(summary.version, ENCODER_VERSION);
        assert_eq!(summary.root, root);
        assert_eq!(summary.raw_size, bytes.len() as u64);
        assert_eq!(
            summary.raw_sha256.as_slice(),
            Sha256::digest(&bytes).as_slice()
        );

        let mut decoder = Decoder::new(io::Cursor::new(bytes));
        let mut sink = Sink::default();
        let decoded = decoder
            .decode(&mut sink)
            .expect("encoder output is canonical");
        assert_eq!(decoded.root, root);
    }
}

#[test]
fn preserves_streamed_payload_and_directory_order() {
    let (bytes, summary) = encode([
        Event::BeginDirectory,
        Event::Entry(b"a"),
        Event::BeginFile {
            executable: false,
            size: 6,
        },
        Event::FileChunk(b"one"),
        Event::FileChunk(b"two"),
        Event::EndFile,
        Event::Entry(b"b"),
        Event::Symlink(b"target"),
        Event::EndDirectory,
    ]);

    let mut decoder = Decoder::new(io::Cursor::new(bytes));
    let mut sink = Sink::default();
    decoder.decode(&mut sink).expect("decode");
    assert_eq!(summary.entries, 2);
    assert_eq!(summary.files, 1);
    assert_eq!(summary.symlinks, 1);
    assert_eq!(sink.names, vec![b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(sink.chunks.concat(), b"onetwo");
}

#[test]
fn rejects_noncanonical_or_incomplete_events() {
    let mut encoder = Encoder::new(Vec::new()).expect("header");
    assert!(matches!(
        encoder.push(Event::Entry(b"orphan")),
        Err(EncodeError::Invalid(_))
    ));

    let mut encoder = Encoder::new(Vec::new()).expect("header");
    encoder.push(Event::BeginDirectory).expect("directory");
    encoder.push(Event::Entry(b"b")).expect("entry");
    encoder
        .push(Event::BeginFile {
            executable: false,
            size: 0,
        })
        .expect("file");
    encoder.push(Event::EndFile).expect("file end");
    assert!(matches!(
        encoder.push(Event::Entry(b"a")),
        Err(EncodeError::NonCanonical(_))
    ));

    let mut encoder = Encoder::new(Vec::new()).expect("header");
    encoder
        .push(Event::BeginFile {
            executable: false,
            size: 2,
        })
        .expect("file");
    encoder.push(Event::FileChunk(b"x")).expect("chunk");
    assert!(matches!(
        encoder.push(Event::EndFile),
        Err(EncodeError::Invalid(_))
    ));
}

#[test]
fn handles_faulting_writers_and_invariant_chunking() {
    let one_chunk = encode([
        Event::BeginFile {
            executable: false,
            size: 5,
        },
        Event::FileChunk(b"hello"),
        Event::EndFile,
    ]);
    let split_chunks = encode([
        Event::BeginFile {
            executable: false,
            size: 5,
        },
        Event::FileChunk(b"he"),
        Event::FileChunk(b"llo"),
        Event::EndFile,
    ]);
    assert_eq!(one_chunk.0, split_chunks.0);
    assert_eq!(one_chunk.1, split_chunks.1);

    let mut encoder = Encoder::new(FailingWriter { remaining: 64 }).expect("header");
    assert!(matches!(
        encoder.push(Event::BeginFile {
            executable: false,
            size: 0,
        }),
        Err(EncodeError::Io(_))
    ));
}
