//! Bounded, streaming reader for the Nix Archive (NAR) format.
//!
//! This is deliberately a decoder only. It exposes NAR structure to research
//! tools while hashing and counting the original byte stream independently of
//! the semantic events.

use std::{fmt, io, io::Read};

use sha2::{Digest, Sha256};

const CHUNK_SIZE: usize = 64 * 1024;
const TOKEN_LIMIT: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKind {
    Directory,
    Regular,
    Symlink,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_depth: usize,
    pub max_name_bytes: u64,
    pub max_symlink_target_bytes: u64,
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
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

#[derive(Debug)]
pub enum DecodeError {
    Io(io::Error),
    Sink(io::Error),
    Invalid(String),
    NonCanonical(&'static str),
    LimitExceeded {
        what: &'static str,
        limit: u64,
        actual: u64,
    },
}

impl fmt::Display for DecodeError {
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

impl std::error::Error for DecodeError {}

#[derive(Debug)]
pub enum Event<'a> {
    BeginDirectory {
        depth: usize,
    },
    Entry {
        name: Vec<u8>,
    },
    BeginFile {
        executable: bool,
        size: u64,
        offset: u64,
    },
    FileChunk(&'a [u8]),
    EndFile,
    Symlink {
        target: Vec<u8>,
    },
    EndDirectory,
}

pub trait EventSink {
    fn event(&mut self, event: Event<'_>) -> io::Result<()>;
}

impl<F> EventSink for F
where
    F: for<'a> FnMut(Event<'a>) -> io::Result<()>,
{
    fn event(&mut self, event: Event<'_>) -> io::Result<()> {
        self(event)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeSummary {
    pub root: RootKind,
    pub raw_size: u64,
    pub raw_sha256: [u8; 32],
    pub entries: u64,
    pub files: u64,
    pub symlinks: u64,
}

pub struct Decoder<R> {
    reader: R,
    limits: Limits,
    digest: Sha256,
    raw_bytes: u64,
    work: u64,
}

impl<R: Read> Decoder<R> {
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, Limits::default())
    }

    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self {
            reader,
            limits,
            digest: Sha256::new(),
            raw_bytes: 0,
            work: 0,
        }
    }

    pub fn decode<S: EventSink>(&mut self, sink: &mut S) -> Result<DecodeSummary, DecodeError> {
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
    ) -> Result<RootKind, DecodeError> {
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

    fn read_file<S: EventSink>(&mut self, size: u64, sink: &mut S) -> Result<(), DecodeError> {
        let mut remaining = size;
        let mut buffer = [0_u8; CHUNK_SIZE];
        while remaining != 0 {
            let length = remaining.min(buffer.len() as u64) as usize;
            self.read_raw(&mut buffer[..length])?;
            sink.event(Event::FileChunk(&buffer[..length]))
                .map_err(DecodeError::Sink)?;
            remaining -= length as u64;
        }
        self.read_padding(size)
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let mut bytes = [0_u8; 8];
        self.read_raw(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_string(&mut self, max: u64) -> Result<Vec<u8>, DecodeError> {
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

    fn read_padding(&mut self, length: u64) -> Result<(), DecodeError> {
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

    fn expect(&mut self, expected: &[u8]) -> Result<(), DecodeError> {
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

    fn validate_name(&self, name: &[u8]) -> Result<(), DecodeError> {
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

    fn bump_work(&mut self) -> Result<(), DecodeError> {
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

    fn read_raw(&mut self, buffer: &mut [u8]) -> Result<(), DecodeError> {
        let requested = buffer.len() as u64;
        let Some(next) = self.raw_bytes.checked_add(requested) else {
            return Err(DecodeError::LimitExceeded {
                what: "raw size",
                limit: self.limits.max_total_bytes,
                actual: u64::MAX,
            });
        };
        if next > self.limits.max_total_bytes {
            return Err(DecodeError::LimitExceeded {
                what: "raw size",
                limit: self.limits.max_total_bytes,
                actual: next,
            });
        }
        let mut offset = 0;
        while offset < buffer.len() {
            let read = self
                .reader
                .read(&mut buffer[offset..])
                .map_err(DecodeError::Io)?;
            if read == 0 {
                return Err(DecodeError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of NAR",
                )));
            }
            self.digest.update(&buffer[offset..offset + read]);
            self.raw_bytes += read as u64;
            offset += read;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Counters {
    entries: u64,
    files: u64,
    symlinks: u64,
}
