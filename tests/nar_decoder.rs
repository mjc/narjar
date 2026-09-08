use std::io::{self, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};

use narjar::nar::{DecodeError, Decoder, Event, EventSink, Limits, RootKind};
use sha2::{Digest, Sha256};

fn string(value: &[u8]) -> Vec<u8> {
    let mut output = (value.len() as u64).to_le_bytes().to_vec();
    output.extend_from_slice(value);
    output.resize(output.len() + (8 - output.len() % 8) % 8, 0);
    output
}

fn node(kind: &[u8], body: Vec<u8>) -> Vec<u8> {
    let mut output = string(b"(");
    output.extend([string(b"type"), string(kind)].into_iter().flatten());
    output.extend(body);
    output.extend(string(b")"));
    output
}

fn regular(contents: &[u8], executable: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if executable {
        body.extend([string(b"executable"), string(b"")].into_iter().flatten());
    }
    body.extend(
        [string(b"contents"), string(contents)]
            .into_iter()
            .flatten(),
    );
    node(b"regular", body)
}

fn symlink(target: &[u8]) -> Vec<u8> {
    node(
        b"symlink",
        [string(b"target"), string(target)]
            .into_iter()
            .flatten()
            .collect(),
    )
}

fn directory(entries: impl IntoIterator<Item = (&'static [u8], Vec<u8>)>) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, child) in entries {
        body.extend(string(b"entry"));
        body.extend(string(b"("));
        body.extend(
            [string(b"name"), string(name), string(b"node")]
                .into_iter()
                .flatten(),
        );
        body.extend(child);
        body.extend(string(b")"));
    }
    node(b"directory", body)
}

fn archive(root: Vec<u8>) -> Vec<u8> {
    [string(b"nix-archive-1"), root]
        .into_iter()
        .flatten()
        .collect()
}

#[derive(Default)]
struct Events {
    names: Vec<Vec<u8>>,
    file_chunks: Vec<Vec<u8>>,
    symlinks: Vec<Vec<u8>>,
    root: Option<RootKind>,
}

impl EventSink for Events {
    fn event(&mut self, event: Event<'_>) -> io::Result<()> {
        match event {
            Event::BeginDirectory { depth: 0 } => self.root = Some(RootKind::Directory),
            Event::Entry { name } => self.names.push(name),
            Event::FileChunk(chunk) => self.file_chunks.push(chunk.to_vec()),
            Event::Symlink { target } => self.symlinks.push(target),
            _ => {}
        }
        Ok(())
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.data.len() {
            return Ok(0);
        }
        let length = (self.data.len() - self.offset)
            .min(buffer.len())
            .min(self.chunk);
        buffer[..length].copy_from_slice(&self.data[self.offset..self.offset + length]);
        self.offset += length;
        Ok(length)
    }
}

struct Chunked<'a> {
    data: &'a [u8],
    offset: usize,
    chunk: usize,
}

#[test]
fn decodes_chunked_directory_without_materializing_file_contents() {
    let data = archive(directory([
        (b"a".as_slice(), regular(b"hello", true)),
        (b"link".as_slice(), symlink(b"../target")),
    ]));
    let mut decoder = Decoder::new(Chunked {
        data: &data,
        offset: 0,
        chunk: 1,
    });
    let mut events = Events::default();
    let summary = decoder.decode(&mut events).expect("valid NAR");

    assert_eq!(summary.root, RootKind::Directory);
    assert_eq!(summary.files, 1);
    assert_eq!(summary.symlinks, 1);
    assert_eq!(events.names, vec![b"a".to_vec(), b"link".to_vec()]);
    assert_eq!(events.file_chunks.concat(), b"hello");
    assert_eq!(events.symlinks, vec![b"../target".to_vec()]);
}

#[test]
fn rejects_noncanonical_directory_order() {
    let data = archive(directory([
        (b"b".as_slice(), regular(b"b", false)),
        (b"a".as_slice(), regular(b"a", false)),
    ]));
    let mut decoder = Decoder::new(io::Cursor::new(data));
    let mut events = Events::default();
    assert!(matches!(
        decoder.decode(&mut events),
        Err(DecodeError::NonCanonical(_))
    ));
}

#[test]
fn rejects_file_before_reading_an_oversized_payload() {
    let data = archive(regular(b"hello", false));
    let limits = Limits {
        max_file_bytes: 4,
        ..Limits::default()
    };
    let mut decoder = Decoder::with_limits(io::Cursor::new(data), limits);
    let mut events = Events::default();
    assert!(matches!(
        decoder.decode(&mut events),
        Err(DecodeError::LimitExceeded { .. })
    ));
}

#[test]
fn hashes_the_complete_canonical_byte_stream() {
    let data = archive(regular(b"hello", false));
    let mut decoder = Decoder::new(io::Cursor::new(&data));
    let mut events = Events::default();
    let summary = decoder.decode(&mut events).expect("decode");
    let expected = Sha256::digest(&data);
    assert_eq!(summary.raw_size, data.len() as u64);
    assert_eq!(summary.raw_sha256.as_slice(), expected.as_slice());
}

#[test]
fn rejects_nonzero_string_padding() {
    let mut data = archive(regular(b"hello", false));
    let marker = string(b"hello");
    let start = data
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("content string");
    data[start + marker.len() - 1] = 1;
    let mut decoder = Decoder::new(io::Cursor::new(data));
    let mut events = Events::default();
    assert!(matches!(
        decoder.decode(&mut events),
        Err(DecodeError::NonCanonical("non-zero string padding"))
    ));
}

#[test]
fn enforces_total_bytes_and_depth_limits() {
    let data = archive(directory([(b"child".as_slice(), regular(b"x", false))]));
    let limits = Limits {
        max_total_bytes: (data.len() - 1) as u64,
        ..Limits::default()
    };
    let mut decoder = Decoder::with_limits(io::Cursor::new(data.clone()), limits);
    let mut events = Events::default();
    assert!(matches!(
        decoder.decode(&mut events),
        Err(DecodeError::LimitExceeded {
            what: "raw size",
            ..
        })
    ));

    let limits = Limits {
        max_depth: 0,
        ..Limits::default()
    };
    let mut decoder = Decoder::with_limits(io::Cursor::new(data), limits);
    assert!(matches!(
        decoder.decode(&mut events),
        Err(DecodeError::LimitExceeded {
            what: "directory depth",
            ..
        })
    ));
}

#[test]
fn mutated_inputs_never_panic() {
    let seed_data = archive(directory([
        (b"file".as_slice(), regular(b"payload", false)),
        (b"link".as_slice(), symlink(b"target")),
    ]));
    for seed in 0_u32..2_048 {
        let mut data = seed_data.clone();
        let index = (seed as usize * 17) % data.len();
        data[index] ^= (seed as u8).wrapping_mul(31).max(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut decoder = Decoder::new(io::Cursor::new(data));
            let mut events = Events::default();
            let _ = decoder.decode(&mut events);
        }));
        assert!(result.is_ok(), "decoder panicked for seed {seed}");
    }
}
