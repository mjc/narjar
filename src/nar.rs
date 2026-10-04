//! Bounded, streaming reader for the Nix Archive (NAR) format.
//!
//! This is deliberately a decoder only. It exposes NAR structure to research
//! tools while hashing and counting the original byte stream independently of
//! the semantic events. Input is read incrementally; file bodies are delivered
//! as borrowed chunks and are never retained by the decoder.

use std::{fmt, io, io::Read};

use sha2::{Digest, Sha256};

const CHUNK_SIZE: usize = 64 * 1024;
const TOKEN_LIMIT: u64 = 256;

/// Owns only grammar bytes; variable-length metadata uses separate storage.
struct ControlToken {
    bytes: [u8; TOKEN_LIMIT as usize],
    length: usize,
}

impl ControlToken {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[derive(Default)]
struct DirectoryNames {
    previous: Vec<u8>,
    incoming: Vec<u8>,
}

impl DirectoryNames {
    fn accept_ordered_name<E>(&mut self) -> Result<&[u8], DecodeError<E>> {
        if self.previous >= self.incoming {
            return Err(DecodeError::NonCanonical(
                "directory entries are not strictly ordered",
            ));
        }
        std::mem::swap(&mut self.previous, &mut self.incoming);
        self.incoming.clear();
        release_oversized_metadata_capacity(&mut self.incoming);
        Ok(&self.previous)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The type of a NAR node.
pub enum RootKind {
    /// A directory node, which can contain entries.
    Directory,
    /// A regular file node.
    Regular,
    /// A symbolic-link node.
    Symlink,
}

#[derive(Clone, Debug)]
/// Resource limits applied while decoding a NAR.
///
/// `Default` permits up to 1,024 levels of node nesting, 10 million entries,
/// 64 GiB per file, and 128 GiB of encoded NAR bytes. All limits are checked
/// while input is read.
pub struct Limits {
    /// Maximum node nesting depth. The root is depth zero; each child node
    /// adds one level, whether it is a directory, file, or symlink.
    pub max_depth: usize,
    /// Maximum byte length of one directory entry name.
    pub max_name_bytes: u64,
    /// Maximum byte length of one symbolic-link target.
    pub max_symlink_target_bytes: u64,
    /// Maximum number of directory entries.
    pub max_entries: u64,
    /// Maximum byte length of one regular file.
    pub max_file_bytes: u64,
    /// Maximum byte length of the complete encoded NAR stream, including
    /// framing, names, file contents, and padding.
    pub max_total_bytes: u64,
    /// Maximum decoder work units, limiting adversarially expensive structure.
    pub max_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 1_024,
            max_name_bytes: 1024 * 1024,
            max_symlink_target_bytes: 1024 * 1024,
            max_entries: 10_000_000,
            max_file_bytes: 64 * 1024 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024 * 1024,
            max_work: 1 << 34,
        }
    }
}

/// An error encountered while decoding a NAR or delivering one of its events.
///
/// `E` is the error type chosen by the event sink. Input and structural errors
/// remain represented by the decoder's own variants.
#[derive(Debug)]
/// A decoding, validation, resource-limit, or event-sink error.
///
/// The generic parameter is the error returned by [`EventSink`].
pub enum DecodeError<E = io::Error> {
    /// Reading the encoded NAR failed.
    Io(io::Error),
    /// The consumer rejected an emitted event.
    Sink(E),
    /// The NAR has invalid structure or unexpected trailing bytes.
    Invalid(String),
    /// The NAR is structurally readable but violates canonical encoding rules.
    NonCanonical(&'static str),
    /// A configured decoder resource limit was exceeded.
    LimitExceeded {
        /// The resource whose limit was exceeded.
        what: &'static str,
        /// The configured maximum.
        limit: u64,
        /// The observed value.
        actual: u64,
    },
}

impl<E: fmt::Display> fmt::Display for DecodeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "NAR input: {error}"),
            Self::Sink(error) => write!(formatter, "NAR event sink: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid NAR: {message}"),
            Self::NonCanonical(message) => write!(formatter, "non-canonical NAR: {message}"),
            Self::LimitExceeded {
                what,
                limit,
                actual,
            } => write!(formatter, "NAR {what} limit exceeded: {actual} > {limit}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for DecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sink(error) => Some(error),
            Self::Invalid(_) | Self::NonCanonical(_) | Self::LimitExceeded { .. } => None,
        }
    }
}

#[derive(Debug)]
/// One structural event produced by [`Decoder`].
///
/// File chunks borrow the decoder's fixed-size buffer and are valid only for
/// the duration of the sink callback. Names and link targets also borrow
/// reusable metadata storage; sinks that retain them must explicitly copy them.
pub enum Event<'a> {
    /// A directory node begins at the given nesting depth.
    BeginDirectory {
        /// Zero identifies the root directory.
        depth: usize,
    },
    /// A directory entry begins; its name is the following node's basename.
    Entry {
        /// Raw NAR bytes for the entry name.
        name: &'a [u8],
    },
    /// A regular file node begins with its complete declared body size.
    BeginFile {
        /// Whether the executable marker is present.
        executable: bool,
        /// Declared number of file-body bytes.
        size: u64,
        /// Offset of this file's body in the decoded NAR byte stream.
        offset: u64,
    },
    /// A borrowed segment of the current regular file body.
    FileChunk(&'a [u8]),
    /// The current regular file node has ended.
    EndFile,
    /// A symbolic-link node with a borrowed target.
    Symlink {
        /// Raw NAR bytes for the link target.
        target: &'a [u8],
    },
    /// The current directory node has ended.
    EndDirectory,
}

/// Receives parsed NAR events and supplies its concrete delivery error type.
pub trait EventSink {
    /// The error returned when delivering an event fails.
    type Error: std::error::Error + 'static;

    /// Processes one event before the decoder continues reading.
    fn event(&mut self, event: Event<'_>) -> Result<(), Self::Error>;
}

impl<F, E> EventSink for F
where
    F: for<'a> FnMut(Event<'a>) -> Result<(), E>,
    E: std::error::Error + 'static,
{
    type Error = E;

    fn event(&mut self, event: Event<'_>) -> Result<(), Self::Error> {
        self(event)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Measurements computed from the complete decoded NAR byte stream.
pub struct DecodeSummary {
    /// Type of the root node.
    pub root: RootKind,
    /// Number of bytes in the encoded NAR stream.
    pub raw_size: u64,
    /// SHA-256 digest of the exact encoded NAR bytes.
    pub raw_sha256: [u8; 32],
    /// Number of directory entries.
    pub entries: u64,
    /// Number of regular files.
    pub files: u64,
    /// Number of symbolic links.
    pub symlinks: u64,
}

/// Incrementally decodes one NAR from a [`Read`] source.
///
/// The decoder owns its reader and can be consumed only once by
/// [`Decoder::decode`].
pub struct Decoder<R> {
    reader: InterruptedRetryReader<R>,
    limits: Limits,
    digest: Sha256,
    raw_bytes: u64,
    work: u64,
    file_buffer: [u8; CHUNK_SIZE],
    symlink_target: Vec<u8>,
    control_token: ControlToken,
}

impl<R: Read> Decoder<R> {
    /// Creates a decoder using [`Limits::default`].
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, Limits::default())
    }

    /// Creates a decoder with explicit input and work limits.
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self {
            reader: InterruptedRetryReader(reader),
            limits,
            digest: Sha256::new(),
            raw_bytes: 0,
            work: 0,
            file_buffer: [0; CHUNK_SIZE],
            symlink_target: Vec::new(),
            control_token: ControlToken {
                bytes: [0; TOKEN_LIMIT as usize],
                length: 0,
            },
        }
    }

    /// Reads one complete NAR and emits its events to `sink`.
    ///
    /// Success means the root is complete and the reader reached EOF; trailing
    /// bytes are rejected. The summary hashes the original NAR bytes, not a
    /// re-encoding of the emitted events.
    pub fn decode<S: EventSink>(
        mut self,
        sink: &mut S,
    ) -> Result<DecodeSummary, DecodeError<S::Error>> {
        self.expect(b"nix-archive-1")?;
        let mut counters = Counters::default();
        let root = self.decode_node(0, sink, &mut counters)?;

        let mut trailing = [0_u8; 1];
        if self.reader.read(&mut trailing).map_err(DecodeError::Io)? != 0 {
            return Err(DecodeError::Invalid(
                "trailing bytes after root node".into(),
            ));
        }

        let digest = self.digest.clone().finalize();
        let mut raw_sha256 = [0_u8; 32];
        raw_sha256.copy_from_slice(&digest);
        Ok(DecodeSummary {
            root,
            raw_size: self.raw_bytes,
            raw_sha256,
            entries: counters.entries,
            files: counters.files,
            symlinks: counters.symlinks,
        })
    }

    fn decode_node<S: EventSink>(
        &mut self,
        depth: usize,
        sink: &mut S,
        counters: &mut Counters,
    ) -> Result<RootKind, DecodeError<S::Error>> {
        self.bump_work()?;
        if depth > self.limits.max_depth {
            return Err(DecodeError::LimitExceeded {
                what: "directory depth",
                limit: self.limits.max_depth as u64,
                actual: depth as u64,
            });
        }
        match self.read_node_kind()? {
            RootKind::Directory => self.decode_directory_node(depth, sink, counters),
            RootKind::Regular => self.decode_regular_file_node(sink, counters),
            RootKind::Symlink => self.decode_symlink_node(sink, counters),
        }
    }

    fn read_node_kind<E>(&mut self) -> Result<RootKind, DecodeError<E>> {
        self.expect(b"(")?;
        self.expect(b"type")?;
        match self.read_control_token()?.as_bytes() {
            b"directory" => Ok(RootKind::Directory),
            b"regular" => Ok(RootKind::Regular),
            b"symlink" => Ok(RootKind::Symlink),
            _ => Err(DecodeError::Invalid("unknown NAR node type".into())),
        }
    }

    fn decode_directory_node<S: EventSink>(
        &mut self,
        depth: usize,
        sink: &mut S,
        counters: &mut Counters,
    ) -> Result<RootKind, DecodeError<S::Error>> {
        sink.event(Event::BeginDirectory { depth })
            .map_err(DecodeError::Sink)?;
        let mut names = DirectoryNames::default();
        std::iter::from_fn(|| {
            self.decode_directory_entry_if_present(depth, &mut names, sink, counters)
                .transpose()
        })
        .try_for_each(|result| result)?;
        sink.event(Event::EndDirectory).map_err(DecodeError::Sink)?;
        Ok(RootKind::Directory)
    }

    fn decode_directory_entry_if_present<S: EventSink>(
        &mut self,
        depth: usize,
        names: &mut DirectoryNames,
        sink: &mut S,
        counters: &mut Counters,
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        let Some(name) = self.read_next_directory_entry_name(names, counters)? else {
            return Ok(None);
        };
        sink.event(Event::Entry { name })
            .map_err(DecodeError::Sink)?;
        self.expect(b"node")?;
        self.decode_node(depth + 1, sink, counters)?;
        self.expect(b")")?;
        Ok(Some(()))
    }

    fn read_next_directory_entry_name<'a, E>(
        &mut self,
        names: &'a mut DirectoryNames,
        counters: &mut Counters,
    ) -> Result<Option<&'a [u8]>, DecodeError<E>> {
        self.bump_work()?;
        let entry_kind = self.read_control_token()?;
        if entry_kind.as_bytes() == b")" {
            return Ok(None);
        }
        if entry_kind.as_bytes() != b"entry" {
            return Err(DecodeError::Invalid("directory entry expected".into()));
        }
        counters.entries = counters
            .entries
            .checked_add(1)
            .ok_or(DecodeError::LimitExceeded {
                what: "entry count",
                limit: self.limits.max_entries,
                actual: u64::MAX,
            })?;
        if counters.entries > self.limits.max_entries {
            return Err(DecodeError::LimitExceeded {
                what: "entry count",
                limit: self.limits.max_entries,
                actual: counters.entries,
            });
        }
        self.expect(b"(")?;
        self.expect(b"name")?;
        self.read_string_into(self.limits.max_name_bytes, &mut names.incoming)?;
        self.validate_name(&names.incoming)?;
        names.accept_ordered_name().map(Some)
    }

    fn decode_regular_file_node<S: EventSink>(
        &mut self,
        sink: &mut S,
        counters: &mut Counters,
    ) -> Result<RootKind, DecodeError<S::Error>> {
        let executable = self.read_regular_file_executable_flag()?;
        let size = self.read_u64()?;
        if size > self.limits.max_file_bytes {
            return Err(DecodeError::LimitExceeded {
                what: "file size",
                limit: self.limits.max_file_bytes,
                actual: size,
            });
        }
        let offset = self.raw_bytes;
        sink.event(Event::BeginFile {
            executable,
            size,
            offset,
        })
        .map_err(DecodeError::Sink)?;
        self.stream_file_contents(size, sink)?;
        sink.event(Event::EndFile).map_err(DecodeError::Sink)?;
        self.expect(b")")?;
        counters.files = counters.files.saturating_add(1);
        Ok(RootKind::Regular)
    }

    fn read_regular_file_executable_flag<E>(&mut self) -> Result<bool, DecodeError<E>> {
        let field = self.read_control_token()?;
        if field.as_bytes() == b"contents" {
            return Ok(false);
        }
        if field.as_bytes() != b"executable" {
            return Err(DecodeError::Invalid("regular contents expected".into()));
        }
        if !self.read_control_token()?.as_bytes().is_empty() {
            return Err(DecodeError::NonCanonical(
                "the executable marker must have an empty value",
            ));
        }
        self.expect(b"contents")?;
        Ok(true)
    }

    fn decode_symlink_node<S: EventSink>(
        &mut self,
        sink: &mut S,
        counters: &mut Counters,
    ) -> Result<RootKind, DecodeError<S::Error>> {
        self.read_symlink_target()?;
        sink.event(Event::Symlink {
            target: &self.symlink_target,
        })
        .map_err(DecodeError::Sink)?;
        self.expect(b")")?;
        counters.symlinks = counters.symlinks.saturating_add(1);
        Ok(RootKind::Symlink)
    }

    fn read_symlink_target<E>(&mut self) -> Result<(), DecodeError<E>> {
        self.expect(b"target")?;
        let length = self.read_bounded_string_length(self.limits.max_symlink_target_bytes)?;
        self.symlink_target.resize(length, 0);
        release_oversized_metadata_capacity(&mut self.symlink_target);
        read_hashed_limited_bytes(
            &mut self.reader,
            &mut self.digest,
            &mut self.raw_bytes,
            &self.limits,
            &mut self.symlink_target,
        )?;
        self.read_padding(length as u64)?;
        if self.symlink_target.contains(&0) {
            return Err(DecodeError::NonCanonical("symlink target contains NUL"));
        }
        Ok(())
    }

    fn stream_file_contents<S: EventSink>(
        &mut self,
        size: u64,
        sink: &mut S,
    ) -> Result<(), DecodeError<S::Error>> {
        (0..size).step_by(CHUNK_SIZE).try_for_each(|offset| {
            let length = (size - offset).min(CHUNK_SIZE as u64) as usize;
            self.read_file_chunk(length, sink)
        })?;
        self.read_padding(size)
    }

    fn read_file_chunk<S: EventSink>(
        &mut self,
        length: usize,
        sink: &mut S,
    ) -> Result<(), DecodeError<S::Error>> {
        let Self {
            reader,
            limits,
            digest,
            raw_bytes,
            file_buffer,
            ..
        } = self;
        read_hashed_limited_bytes(
            reader,
            digest,
            raw_bytes,
            limits,
            &mut file_buffer[..length],
        )?;
        sink.event(Event::FileChunk(&file_buffer[..length]))
            .map_err(DecodeError::Sink)
    }

    fn read_u64<E>(&mut self) -> Result<u64, DecodeError<E>> {
        let mut bytes = [0_u8; 8];
        self.read_raw(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_string_into<E>(&mut self, max: u64, value: &mut Vec<u8>) -> Result<(), DecodeError<E>> {
        let length = self.read_bounded_string_length(max)?;
        value.resize(length, 0);
        release_oversized_metadata_capacity(value);
        self.read_raw(value)?;
        self.read_padding(length as u64)
    }

    fn read_control_token<E>(&mut self) -> Result<&ControlToken, DecodeError<E>> {
        let length = self.read_bounded_string_length(TOKEN_LIMIT)?;
        read_hashed_limited_bytes(
            &mut self.reader,
            &mut self.digest,
            &mut self.raw_bytes,
            &self.limits,
            &mut self.control_token.bytes[..length],
        )?;
        self.read_padding(length as u64)?;
        self.control_token.length = length;
        Ok(&self.control_token)
    }

    fn read_bounded_string_length<E>(&mut self, max: u64) -> Result<usize, DecodeError<E>> {
        let length = self.read_u64()?;
        if length > max {
            return Err(DecodeError::LimitExceeded {
                what: "string length",
                limit: max,
                actual: length,
            });
        }
        usize::try_from(length)
            .map_err(|_| DecodeError::Invalid("string does not fit in memory".into()))
    }

    fn read_padding<E>(&mut self, length: u64) -> Result<(), DecodeError<E>> {
        let padding = (8 - length % 8) % 8;
        if padding == 0 {
            return Ok(());
        }
        let mut bytes = [0_u8; 8];
        self.read_raw(&mut bytes[..padding as usize])?;
        if bytes[..padding as usize].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonCanonical("non-zero string padding"));
        }
        Ok(())
    }

    fn expect<E>(&mut self, expected: &[u8]) -> Result<(), DecodeError<E>> {
        let actual = self.read_control_token()?;
        if actual.as_bytes() == expected {
            Ok(())
        } else {
            Err(DecodeError::Invalid(format!(
                "expected {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(actual.as_bytes())
            )))
        }
    }

    fn validate_name<E>(&self, name: &[u8]) -> Result<(), DecodeError<E>> {
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
        {
            return Err(DecodeError::NonCanonical("invalid directory entry name"));
        }
        Ok(())
    }

    fn bump_work<E>(&mut self) -> Result<(), DecodeError<E>> {
        self.work = self.work.saturating_add(1);
        if self.work > self.limits.max_work {
            return Err(DecodeError::LimitExceeded {
                what: "work",
                limit: self.limits.max_work,
                actual: self.work,
            });
        }
        Ok(())
    }

    fn read_raw<E>(&mut self, buffer: &mut [u8]) -> Result<(), DecodeError<E>> {
        read_hashed_limited_bytes(
            &mut self.reader,
            &mut self.digest,
            &mut self.raw_bytes,
            &self.limits,
            buffer,
        )
    }
}

/// Ordinary filesystem metadata fits within 4 KiB. Retain that scratch, but
/// don't carry historical huge names down a short-named subtree. A large value
/// still in use keeps its capacity; only substantial shrink triggers release.
pub(crate) fn release_oversized_metadata_capacity(bytes: &mut Vec<u8>) {
    if bytes.capacity() > 4096 && bytes.capacity() / 4 > bytes.len() {
        bytes.shrink_to_fit();
    }
}

fn read_hashed_limited_bytes<R: Read, E>(
    reader: &mut R,
    digest: &mut Sha256,
    raw_bytes: &mut u64,
    limits: &Limits,
    buffer: &mut [u8],
) -> Result<(), DecodeError<E>> {
    let requested = buffer.len() as u64;
    let Some(next) = raw_bytes.checked_add(requested) else {
        return Err(DecodeError::LimitExceeded {
            what: "raw size",
            limit: limits.max_total_bytes,
            actual: u64::MAX,
        });
    };
    if next > limits.max_total_bytes {
        return Err(DecodeError::LimitExceeded {
            what: "raw size",
            limit: limits.max_total_bytes,
            actual: next,
        });
    }
    reader.read_exact(buffer).map_err(DecodeError::Io)?;
    digest.update(buffer);
    *raw_bytes = next;
    Ok(())
}

/// Retries `Interrupted` at the only reader boundary used by the decoder.
struct InterruptedRetryReader<R>(R);

impl<R: Read> Read for InterruptedRetryReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let result = self.0.read(buffer);
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::Interrupted)
            {
                continue;
            }
            return result;
        }
    }
}

#[derive(Default)]
struct Counters {
    entries: u64,
    files: u64,
    symlinks: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[test]
    fn grammar_reads_reuse_one_buffer_and_ignore_previous_token_tails() {
        let mut bytes = Vec::new();
        for token in [b"nix-archive-1".as_slice(), b"(", b"", b"type"] {
            bytes.extend_from_slice(&(token.len() as u64).to_le_bytes());
            bytes.extend_from_slice(token);
            bytes.resize(bytes.len() + (8 - token.len() % 8) % 8, 0);
        }
        let mut decoder = Decoder::new(bytes.as_slice());
        let first = decoder.read_control_token::<Infallible>().unwrap();
        let buffer = first.as_bytes().as_ptr();
        assert_eq!(first.as_bytes(), b"nix-archive-1");
        for expected in [b"(".as_slice(), b"", b"type"] {
            let token = decoder.read_control_token::<Infallible>().unwrap();
            assert_eq!(token.as_bytes(), expected);
            assert_eq!(
                token.as_bytes().as_ptr(),
                buffer,
                "grammar parsing must borrow the same bounded scratch, not move a full token"
            );
        }
        assert_eq!(decoder.raw_bytes, bytes.len() as u64);
        assert_eq!(
            decoder.digest.finalize().as_slice(),
            Sha256::digest(&bytes).as_slice()
        );
    }
}
