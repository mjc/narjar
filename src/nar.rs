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
/// the duration of the sink callback. Names and link targets are owned.
pub enum Event<'a> {
    /// A directory node begins at the given nesting depth.
    BeginDirectory {
        /// Zero identifies the root directory.
        depth: usize,
    },
    /// A directory entry begins; its name is the following node's basename.
    Entry {
        /// Raw NAR bytes for the entry name.
        name: Vec<u8>,
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
    /// A symbolic-link node with an owned target.
    Symlink {
        /// Raw NAR bytes for the link target.
        target: Vec<u8>,
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
    reader: R,
    limits: Limits,
    digest: Sha256,
    raw_bytes: u64,
    work: u64,
    file_buffer: [u8; CHUNK_SIZE],
}

impl<R: Read> Decoder<R> {
    /// Creates a decoder using [`Limits::default`].
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, Limits::default())
    }

    /// Creates a decoder with explicit input and work limits.
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self {
            reader,
            limits,
            digest: Sha256::new(),
            raw_bytes: 0,
            work: 0,
            file_buffer: [0; CHUNK_SIZE],
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
        self.expect(b"(")?;
        self.expect(b"type")?;
        let kind = self.read_string(TOKEN_LIMIT)?;
        match kind.as_slice() {
            b"directory" => {
                sink.event(Event::BeginDirectory { depth })
                    .map_err(DecodeError::Sink)?;
                let mut previous_name = None;
                loop {
                    self.bump_work()?;
                    let entry_kind = self.read_string(TOKEN_LIMIT)?;
                    if entry_kind == b")" {
                        sink.event(Event::EndDirectory).map_err(DecodeError::Sink)?;
                        return Ok(RootKind::Directory);
                    }
                    if entry_kind != b"entry" {
                        return Err(DecodeError::Invalid("directory entry expected".into()));
                    }
                    counters.entries =
                        counters
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
                    let name = self.read_string(self.limits.max_name_bytes)?;
                    self.validate_name(&name)?;
                    if previous_name
                        .as_ref()
                        .is_some_and(|previous| previous >= &name)
                    {
                        return Err(DecodeError::NonCanonical(
                            "directory entries are not strictly ordered",
                        ));
                    }
                    previous_name = Some(name.clone());
                    sink.event(Event::Entry { name })
                        .map_err(DecodeError::Sink)?;
                    self.expect(b"node")?;
                    self.decode_node(depth + 1, sink, counters)?;
                    self.expect(b")")?;
                }
            }
            b"regular" => {
                let mut field = self.read_string(TOKEN_LIMIT)?;
                let executable = if field == b"executable" {
                    if !self.read_string(TOKEN_LIMIT)?.is_empty() {
                        return Err(DecodeError::NonCanonical(
                            "the executable marker must have an empty value",
                        ));
                    }
                    field = self.read_string(TOKEN_LIMIT)?;
                    true
                } else {
                    false
                };
                if field != b"contents" {
                    return Err(DecodeError::Invalid("regular contents expected".into()));
                }
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
                self.read_file(size, sink)?;
                sink.event(Event::EndFile).map_err(DecodeError::Sink)?;
                self.expect(b")")?;
                counters.files = counters.files.saturating_add(1);
                Ok(RootKind::Regular)
            }
            b"symlink" => {
                self.expect(b"target")?;
                let target = self.read_string(self.limits.max_symlink_target_bytes)?;
                if target.contains(&0) {
                    return Err(DecodeError::NonCanonical("symlink target contains NUL"));
                }
                sink.event(Event::Symlink { target })
                    .map_err(DecodeError::Sink)?;
                self.expect(b")")?;
                counters.symlinks = counters.symlinks.saturating_add(1);
                Ok(RootKind::Symlink)
            }
            _ => Err(DecodeError::Invalid("unknown NAR node type".into())),
        }
    }

    fn read_file<S: EventSink>(
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

    fn read_string<E>(&mut self, max: u64) -> Result<Vec<u8>, DecodeError<E>> {
        let length = self.read_u64()?;
        if length > max {
            return Err(DecodeError::LimitExceeded {
                what: "string length",
                limit: max,
                actual: length,
            });
        }
        let length = usize::try_from(length)
            .map_err(|_| DecodeError::Invalid("string does not fit in memory".into()))?;
        let mut value = vec![0_u8; length];
        self.read_raw(&mut value)?;
        self.read_padding(length as u64)?;
        Ok(value)
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
        let actual = self.read_string(TOKEN_LIMIT)?;
        if actual == expected {
            Ok(())
        } else {
            Err(DecodeError::Invalid(format!(
                "expected {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&actual)
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
    let mut offset = 0;
    while offset < buffer.len() {
        let read = reader
            .read(&mut buffer[offset..])
            .map_err(DecodeError::Io)?;
        if read == 0 {
            return Err(DecodeError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected end of NAR",
            )));
        }
        digest.update(&buffer[offset..offset + read]);
        *raw_bytes += read as u64;
        offset += read;
    }
    Ok(())
}

#[derive(Default)]
struct Counters {
    entries: u64,
    files: u64,
    symlinks: u64,
}
