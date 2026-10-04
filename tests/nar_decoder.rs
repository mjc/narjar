use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{self, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};

use narjar::nar::{DecodeError, Decoder, Event, EventSink, Limits, RootKind};
use narjar::nar_encode::EncodeError;
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

#[test]
fn stack_tokens_preserve_the_grammar_limit_and_input_error_boundaries() {
    // Invalid tokens below the existing limit must still be consumed completely;
    // a shorter implementation-specific stack buffer must not change the policy.
    for length in [16, 17, 255, 256] {
        let token = vec![b'x'; length];
        let mut bytes = string(b"nix-archive-1");
        bytes.extend(string(&token));
        let result =
            Decoder::new(bytes.as_slice()).decode(&mut |_: Event<'_>| Ok::<(), Infallible>(()));
        assert!(
            matches!(result, Err(DecodeError::Invalid(_))),
            "length {length}: {result:?}"
        );

        // Truncation takes precedence over mismatched-token classification.
        bytes.truncate(bytes.len() - 1);
        let result =
            Decoder::new(bytes.as_slice()).decode(&mut |_: Event<'_>| Ok::<(), Infallible>(()));
        assert!(
            matches!(result, Err(DecodeError::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
    let bytes = (257_u64).to_le_bytes();
    let result =
        Decoder::new(bytes.as_slice()).decode(&mut |_: Event<'_>| Ok::<(), Infallible>(()));
    assert!(matches!(
        result,
        Err(DecodeError::LimitExceeded {
            what: "string length",
            limit: 256,
            actual: 257
        })
    ));
}

#[derive(Default)]
struct Events {
    names: Vec<Vec<u8>>,
    file_chunks: Vec<Vec<u8>>,
    symlinks: Vec<Vec<u8>>,
    root: Option<RootKind>,
}

impl EventSink for Events {
    type Error = io::Error;

    fn event(&mut self, event: Event<'_>) -> io::Result<()> {
        match event {
            Event::BeginDirectory { depth: 0 } => self.root = Some(RootKind::Directory),
            Event::Entry { name } => self.names.push(name.to_vec()),
            Event::FileChunk(chunk) => self.file_chunks.push(chunk.to_vec()),
            Event::Symlink { target } => self.symlinks.push(target.to_vec()),
            _ => {}
        }
        Ok(())
    }
}

struct EncodeFailure;

impl EventSink for EncodeFailure {
    type Error = EncodeError;

    fn event(&mut self, _event: Event<'_>) -> Result<(), Self::Error> {
        Err(EncodeError::Invalid("test encoder failure"))
    }
}

struct IoFailure;

impl EventSink for IoFailure {
    type Error = io::Error;

    fn event(&mut self, _event: Event<'_>) -> Result<(), Self::Error> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test sink failure",
        ))
    }
}

struct NeverFailure;

impl EventSink for NeverFailure {
    type Error = Infallible;

    fn event(&mut self, _event: Event<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct LateFailure {
    events: usize,
}

impl EventSink for LateFailure {
    type Error = EncodeError;

    fn event(&mut self, event: Event<'_>) -> Result<(), Self::Error> {
        self.events += 1;
        if matches!(event, Event::FileChunk(_)) {
            Err(EncodeError::Invalid("late sink failure"))
        } else {
            Ok(())
        }
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

enum ReadAction {
    Interruptions(usize),
    Failure(io::ErrorKind),
}

struct ScriptedReader {
    data: Vec<u8>,
    offset: usize,
    actions: BTreeMap<usize, ReadAction>,
}

impl ScriptedReader {
    fn with_actions(data: Vec<u8>, actions: impl IntoIterator<Item = (usize, ReadAction)>) -> Self {
        Self {
            data,
            offset: 0,
            actions: actions.into_iter().collect(),
        }
    }
}

impl ReadAction {
    fn interruptions(count: usize) -> Self {
        Self::Interruptions(count)
    }

    fn failure(kind: io::ErrorKind) -> Self {
        Self::Failure(kind)
    }
}

impl Read for ScriptedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(action) = self.actions.get_mut(&self.offset) {
            match action {
                ReadAction::Interruptions(remaining) if *remaining > 0 => {
                    *remaining -= 1;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                ReadAction::Failure(kind) => return Err(io::Error::from(*kind)),
                ReadAction::Interruptions(_) => {}
            }
        }
        if self.offset == self.data.len() {
            return Ok(0);
        }
        let next_action = self
            .actions
            .range((self.offset + 1)..)
            .next()
            .map_or(self.data.len(), |(&offset, _)| offset);
        let length = buffer
            .len()
            .min(self.data.len() - self.offset)
            .min(next_action - self.offset);
        buffer[..length].copy_from_slice(&self.data[self.offset..self.offset + length]);
        self.offset += length;
        Ok(length)
    }
}

#[test]
fn decodes_chunked_directory_without_materializing_file_contents() {
    let data = archive(directory([
        (b"a".as_slice(), regular(b"hello", true)),
        (b"link".as_slice(), symlink(b"../target")),
    ]));
    let decoder = Decoder::new(Chunked {
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
fn streams_multiple_files_in_bounded_chunks() {
    let first = vec![b'a'; 64 * 1024 + 3];
    let second = vec![b'b'; 65];
    let data = archive(directory([
        (b"first".as_slice(), regular(&first, false)),
        (b"second".as_slice(), regular(&second, false)),
    ]));
    let decoder = Decoder::new(io::Cursor::new(data));
    let mut chunks = Vec::new();
    let mut sink = |event: Event<'_>| {
        if let Event::FileChunk(chunk) = event {
            chunks.push(chunk.len());
        }
        Ok::<(), Infallible>(())
    };

    decoder
        .decode(&mut sink)
        .expect("mixed-size files are valid NAR input");

    assert_eq!(
        chunks,
        vec![64 * 1024, 3, 65],
        "each file is streamed through bounded decoder chunks"
    );
}

#[test]
fn decoder_preserves_each_event_sink_error_type() {
    let data = archive(regular(b"hello", false));

    let decoder = Decoder::new(io::Cursor::new(&data));
    let error = decoder
        .decode(&mut EncodeFailure)
        .expect_err("the encoder sink should fail");
    assert!(matches!(
        &error,
        DecodeError::Sink(EncodeError::Invalid("test encoder failure"))
    ));
    assert!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<EncodeError>())
            .is_some(),
        "the encoder error should remain the source"
    );

    let decoder = Decoder::new(io::Cursor::new(&data));
    let error = decoder
        .decode(&mut IoFailure)
        .expect_err("the I/O sink should fail");
    assert!(matches!(
        &error,
        DecodeError::Sink(error) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    assert!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some(),
        "the I/O error should remain the source"
    );

    let decoder = Decoder::new(io::Cursor::new(&data));
    let result: Result<_, DecodeError<Infallible>> = decoder.decode(&mut NeverFailure);
    assert!(result.is_ok(), "the never sink cannot fail");
}

#[test]
fn closure_sinks_use_their_declared_error_types() {
    let data = archive(regular(b"hello", false));

    let decoder = Decoder::new(io::Cursor::new(&data));
    let mut encode_sink = |_: Event<'_>| Err::<(), _>(EncodeError::Invalid("closure failure"));
    let error = decoder
        .decode(&mut encode_sink)
        .expect_err("the encoding closure should fail");
    assert!(matches!(
        error,
        DecodeError::Sink(EncodeError::Invalid("closure failure"))
    ));

    let decoder = Decoder::new(io::Cursor::new(&data));
    let mut infallible_sink = |_: Event<'_>| Ok::<(), Infallible>(());
    let result: Result<_, DecodeError<Infallible>> = decoder.decode(&mut infallible_sink);
    assert!(result.is_ok(), "the infallible closure cannot fail");
}

#[test]
fn infallible_sink_does_not_hide_decoder_errors() {
    let data = archive(regular(b"hello", false));

    let mut truncated = data.clone();
    truncated.pop();
    let decoder = Decoder::new(io::Cursor::new(truncated));
    let result: Result<_, DecodeError<Infallible>> = decoder.decode(&mut NeverFailure);
    assert!(matches!(result, Err(DecodeError::Io(_))));

    let invalid = archive(node(b"unknown", Vec::new()));
    let decoder = Decoder::new(io::Cursor::new(invalid));
    let result: Result<_, DecodeError<Infallible>> = decoder.decode(&mut NeverFailure);
    assert!(matches!(result, Err(DecodeError::Invalid(_))));

    let limits = Limits {
        max_total_bytes: (data.len() - 1) as u64,
        ..Limits::default()
    };
    let decoder = Decoder::with_limits(io::Cursor::new(data), limits);
    let result: Result<_, DecodeError<Infallible>> = decoder.decode(&mut NeverFailure);
    assert!(matches!(result, Err(DecodeError::LimitExceeded { .. })));
}

#[test]
fn sink_failure_after_progress_stops_event_delivery() {
    let data = archive(regular(b"hello", false));
    let decoder = Decoder::new(io::Cursor::new(data));
    let mut sink = LateFailure { events: 0 };
    let error = decoder
        .decode(&mut sink)
        .expect_err("the later sink event should fail");

    assert!(matches!(
        error,
        DecodeError::Sink(EncodeError::Invalid("late sink failure"))
    ));
    assert_eq!(sink.events, 2, "no event should follow the failed chunk");
}

#[test]
fn borrowed_names_remain_distinct_across_buffer_swaps_and_nested_siblings() {
    let data = archive(directory([
        (b"a".as_slice(), regular(b"first", false)),
        (
            b"b-longer-name".as_slice(),
            directory([
                (b"inside-a".as_slice(), regular(b"nested", false)),
                (b"inside-b-longer".as_slice(), regular(b"", false)),
            ]),
        ),
        (b"c".as_slice(), regular(b"last", false)),
        (
            b"d-longer-than-either-initial-buffer".as_slice(),
            regular(b"growth", false),
        ),
        (
            b"e-even-longer-than-the-other-reallocated-buffer".as_slice(),
            regular(b"growth again", false),
        ),
    ]));
    let mut events = Events::default();
    let summary = Decoder::new(Chunked {
        data: &data,
        offset: 0,
        chunk: 1,
    })
    .decode(&mut events)
    .expect("nested short-read stream");
    assert_eq!(
        events.names,
        [
            b"a".as_slice(),
            b"b-longer-name",
            b"inside-a",
            b"inside-b-longer",
            b"c",
            b"d-longer-than-either-initial-buffer",
            b"e-even-longer-than-the-other-reallocated-buffer"
        ]
    );
    assert_eq!(summary.entries, 7);
    assert_eq!(summary.raw_sha256, <[u8; 32]>::from(Sha256::digest(&data)));
}

#[test]
fn retained_symlink_targets_survive_reuse_shrinking_and_growth() {
    let long = vec![b'x'; 65_537];
    let longer = vec![b'y'; 131_075];
    let data = archive(directory([
        (b"a".as_slice(), symlink(b"short")),
        (b"b".as_slice(), symlink(&long)),
        (
            b"c".as_slice(),
            directory([(b"nested".as_slice(), symlink(b""))]),
        ),
        (b"d".as_slice(), symlink(&longer)),
    ]));
    let mut events = Events::default();
    let summary = Decoder::new(Chunked {
        data: &data,
        offset: 0,
        chunk: 3,
    })
    .decode(&mut events)
    .expect("short-read symlink stream");
    assert_eq!(events.symlinks, [b"short".to_vec(), long, vec![], longer]);
    assert_eq!(summary.symlinks, 4);
    assert_eq!(summary.raw_sha256, <[u8; 32]>::from(Sha256::digest(&data)));
}

#[test]
fn rejecting_later_borrowed_metadata_preserves_the_sink_error_and_stops_events() {
    let data = archive(directory([
        (b"a".as_slice(), symlink(b"first")),
        (b"b".as_slice(), symlink(b"second")),
        (b"c".as_slice(), symlink(b"never delivered")),
    ]));
    for fail_on_entry in [true, false] {
        let mut calls = 0;
        let mut sink = |event: Event<'_>| {
            calls += 1;
            let refused = match event {
                Event::Entry { name } => fail_on_entry && name == b"b",
                Event::Symlink { target } => !fail_on_entry && target == b"second",
                _ => false,
            };
            if refused {
                Err(EncodeError::Invalid("metadata sink failure"))
            } else {
                Ok(())
            }
        };
        let error = Decoder::new(data.as_slice())
            .decode(&mut sink)
            .expect_err("sink refused metadata");
        assert!(matches!(
            error,
            DecodeError::Sink(EncodeError::Invalid("metadata sink failure"))
        ));
        assert_eq!(
            calls,
            if fail_on_entry { 4 } else { 5 },
            "no events after rejected metadata"
        );
    }
}

#[test]
fn reused_metadata_buffers_preserve_name_target_and_depth_limits() {
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
        let data = archive(directory([(name, symlink(b"target"))]));
        assert!(matches!(
            Decoder::new(data.as_slice()).decode(&mut Events::default()),
            Err(DecodeError::NonCanonical(_))
        ));
    }
    let duplicate = archive(directory([
        (b"a".as_slice(), regular(b"", false)),
        (b"a".as_slice(), regular(b"", false)),
    ]));
    assert!(matches!(
        Decoder::new(duplicate.as_slice()).decode(&mut Events::default()),
        Err(DecodeError::NonCanonical(_))
    ));

    let invalid_target = archive(symlink(b"a\0b"));
    assert!(matches!(
        Decoder::new(invalid_target.as_slice()).decode(&mut Events::default()),
        Err(DecodeError::NonCanonical(_))
    ));
    let long_target = archive(symlink(b"long"));
    let limits = Limits {
        max_symlink_target_bytes: 3,
        ..Limits::default()
    };
    assert!(matches!(
        Decoder::with_limits(long_target.as_slice(), limits).decode(&mut Events::default()),
        Err(DecodeError::LimitExceeded {
            what: "string length",
            limit: 3,
            actual: 4
        })
    ));
    let long_name = archive(directory([(b"long".as_slice(), regular(b"", false))]));
    let limits = Limits {
        max_name_bytes: 3,
        ..Limits::default()
    };
    assert!(matches!(
        Decoder::with_limits(long_name.as_slice(), limits).decode(&mut Events::default()),
        Err(DecodeError::LimitExceeded {
            what: "string length",
            limit: 3,
            actual: 4
        })
    ));

    // Unlike upstream's fixed 64-level implementation, our configured bound
    // remains authoritative. No capacity optimization may silently lower it.
    let root = (0..80).fold(regular(b"body", false), |child, _| {
        directory([(b"nested".as_slice(), child)])
    });
    let data = archive(root);
    let mut sink = |_: Event<'_>| Ok::<(), Infallible>(());
    let limits = Limits {
        max_depth: 80,
        ..Limits::default()
    };
    Decoder::with_limits(data.as_slice(), limits)
        .decode(&mut sink)
        .expect("configured depth above 64");
    let limits = Limits {
        max_depth: 79,
        ..Limits::default()
    };
    assert!(matches!(
        Decoder::with_limits(data.as_slice(), limits).decode(&mut sink),
        Err(DecodeError::LimitExceeded {
            what: "directory depth",
            limit: 79,
            actual: 80
        })
    ));
}

#[test]
fn rejects_noncanonical_directory_order() {
    let data = archive(directory([
        (b"b".as_slice(), regular(b"b", false)),
        (b"a".as_slice(), regular(b"a", false)),
    ]));
    let decoder = Decoder::new(io::Cursor::new(data));
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
    let decoder = Decoder::with_limits(io::Cursor::new(data), limits);
    let mut events = Events::default();
    assert!(matches!(
        decoder.decode(&mut events),
        Err(DecodeError::LimitExceeded { .. })
    ));
}

#[test]
fn hashes_the_complete_canonical_byte_stream() {
    let data = archive(regular(b"hello", false));
    let decoder = Decoder::new(io::Cursor::new(&data));
    let mut events = Events::default();
    let summary = decoder.decode(&mut events).expect("decode");
    let expected = Sha256::digest(&data);
    assert_eq!(summary.raw_size, data.len() as u64);
    assert_eq!(summary.raw_sha256.as_slice(), expected.as_slice());
}

#[test]
fn retries_interrupted_reads_in_tokens_file_chunks_and_the_final_eof_probe() {
    let contents = b"interrupt-retry-file-contents";
    let data = archive(regular(contents, false));
    let contents_offset = data
        .windows(contents.len())
        .position(|window| window == contents)
        .expect("locate file payload");
    let reader = ScriptedReader::with_actions(
        data.clone(),
        [
            (0, ReadAction::interruptions(3)),
            (contents_offset, ReadAction::interruptions(2)),
            (data.len(), ReadAction::interruptions(4)),
        ],
    );
    let mut events = Events::default();
    let summary = Decoder::new(reader)
        .decode(&mut events)
        .expect("Interrupted is retried at every NAR input boundary");

    assert_eq!(events.file_chunks.concat(), contents);
    assert_eq!(summary.raw_size, data.len() as u64);
    assert_eq!(
        summary.raw_sha256.as_slice(),
        Sha256::digest(&data).as_slice()
    );
}

#[test]
fn non_interrupted_reader_errors_remain_io_errors_at_each_read_boundary() {
    let contents = b"reader-error-file-contents";
    let data = archive(regular(contents, false));
    let contents_offset = data
        .windows(contents.len())
        .position(|window| window == contents)
        .expect("locate file payload");

    for error_offset in [0, contents_offset, data.len()] {
        let reader = ScriptedReader::with_actions(
            data.clone(),
            [(error_offset, ReadAction::failure(io::ErrorKind::BrokenPipe))],
        );
        let error = Decoder::new(reader)
            .decode(&mut Events::default())
            .expect_err("a non-interruption source error must propagate");
        assert!(
            matches!(error, DecodeError::Io(ref error) if error.kind() == io::ErrorKind::BrokenPipe),
            "source error at offset {error_offset} must remain an I/O error: {error:?}"
        );
    }
}

#[test]
fn trailing_bytes_remain_a_structural_error_after_eof_retries() {
    let mut data = archive(regular(b"contents", false));
    let archive_length = data.len();
    data.push(b'!');
    let mut events = Events::default();

    assert!(matches!(
        Decoder::new(ScriptedReader::with_actions(
            data,
            [(archive_length, ReadAction::interruptions(3))],
        ))
        .decode(&mut events),
        Err(DecodeError::Invalid(message)) if message == "trailing bytes after root node"
    ));
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
    let decoder = Decoder::new(io::Cursor::new(data));
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
    let decoder = Decoder::with_limits(io::Cursor::new(data.clone()), limits);
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
    let decoder = Decoder::with_limits(io::Cursor::new(data), limits);
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
            let decoder = Decoder::new(io::Cursor::new(data));
            let mut events = Events::default();
            let _ = decoder.decode(&mut events);
        }));
        assert!(result.is_ok(), "decoder panicked for seed {seed}");
    }
}
