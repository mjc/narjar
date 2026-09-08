//! Versioned, bounded-memory streaming encoder for canonical NAR bytes.
//!
//! The encoder consumes semantic events rather than a filesystem or a storage
//! representation. Directory ordering is checked at the boundary, while file
//! bodies are written and hashed as they arrive.

use std::{fmt, io, io::Write};

use sha2::{Digest, Sha256};

use crate::nar::RootKind;

/// The compatibility version of this event-to-byte contract.
pub const ENCODER_VERSION: u32 = 1;

#[derive(Debug)]
pub enum EncodeError {
    Io(io::Error),
    Invalid(&'static str),
    NonCanonical(&'static str),
    LimitExceeded {
        what: &'static str,
        limit: u64,
        actual: u64,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "NAR output: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid NAR events: {message}"),
            Self::NonCanonical(message) => write!(formatter, "non-canonical NAR events: {message}"),
            Self::LimitExceeded {
                what,
                limit,
                actual,
            } => write!(
                formatter,
                "NAR encoder {what} limit exceeded: {actual} > {limit}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Representation-neutral events accepted by [`Encoder`].
pub enum Event<'a> {
    BeginDirectory,
    Entry(&'a [u8]),
    BeginFile { executable: bool, size: u64 },
    FileChunk(&'a [u8]),
    EndFile,
    Symlink(&'a [u8]),
    EndDirectory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodeSummary {
    pub version: u32,
    pub root: RootKind,
    pub raw_size: u64,
    pub raw_sha256: [u8; 32],
    pub entries: u64,
    pub files: u64,
    pub symlinks: u64,
}

enum Node {
    Directory {
        last_name: Option<Vec<u8>>,
        child_open: bool,
    },
    Regular {
        remaining: u64,
        size: u64,
    },
}

/// Writes canonical NAR bytes without retaining file bodies or the completed
/// archive. Directory memory is bounded by nesting depth and one previous
/// entry name per open directory.
pub struct Encoder<W> {
    writer: W,
    limits: crate::nar::Limits,
    digest: Sha256,
    raw_size: u64,
    root: Option<RootKind>,
    stack: Vec<Node>,
    finished: bool,
    entries: u64,
    files: u64,
    symlinks: u64,
    work: u64,
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Result<Self, EncodeError> {
        Self::with_limits(writer, crate::nar::Limits::default())
    }

    pub fn with_limits(writer: W, limits: crate::nar::Limits) -> Result<Self, EncodeError> {
        let mut encoder = Self {
            writer,
            limits,
            digest: Sha256::new(),
            raw_size: 0,
            root: None,
            stack: Vec::new(),
            finished: false,
            entries: 0,
            files: 0,
            symlinks: 0,
            work: 0,
        };
        encoder.string(b"nix-archive-1")?;
        Ok(encoder)
    }

    pub fn push(&mut self, event: Event<'_>) -> Result<(), EncodeError> {
        self.bump_work()?;
        match event {
            Event::BeginDirectory => self.begin_directory(),
            Event::Entry(name) => self.entry(name),
            Event::BeginFile { executable, size } => self.begin_file(executable, size),
            Event::FileChunk(chunk) => self.file_chunk(chunk),
            Event::EndFile => self.end_file(),
            Event::Symlink(target) => self.symlink(target),
            Event::EndDirectory => self.end_directory(),
        }
    }

    pub fn finish(self) -> Result<(W, EncodeSummary), EncodeError> {
        if !self.finished || !self.stack.is_empty() {
            return Err(EncodeError::Invalid("the root node is incomplete"));
        }
        let root = self.root.ok_or(EncodeError::Invalid("missing root node"))?;
        let digest = self.digest.finalize();
        let mut raw_sha256 = [0_u8; 32];
        raw_sha256.copy_from_slice(&digest);
        Ok((
            self.writer,
            EncodeSummary {
                version: ENCODER_VERSION,
                root,
                raw_size: self.raw_size,
                raw_sha256,
                entries: self.entries,
                files: self.files,
                symlinks: self.symlinks,
            },
        ))
    }

    fn begin_directory(&mut self) -> Result<(), EncodeError> {
        self.begin_node(RootKind::Directory)?;
        self.string(b"(")?;
        self.string(b"type")?;
        self.string(b"directory")?;
        self.stack.push(Node::Directory {
            last_name: None,
            child_open: false,
        });
        Ok(())
    }

    fn entry(&mut self, name: &[u8]) -> Result<(), EncodeError> {
        self.ensure_open()?;
        let name_length = name.len() as u64;
        if name_length > self.limits.max_name_bytes {
            return Err(EncodeError::LimitExceeded {
                what: "name length",
                limit: self.limits.max_name_bytes,
                actual: name_length,
            });
        }
        let next_entries = self
            .entries
            .checked_add(1)
            .ok_or(EncodeError::LimitExceeded {
                what: "entry count",
                limit: self.limits.max_entries,
                actual: u64::MAX,
            })?;
        if next_entries > self.limits.max_entries {
            return Err(EncodeError::LimitExceeded {
                what: "entry count",
                limit: self.limits.max_entries,
                actual: next_entries,
            });
        }
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
        {
            return Err(EncodeError::NonCanonical("invalid directory entry name"));
        }

        let Some(Node::Directory {
            last_name,
            child_open,
        }) = self.stack.last_mut()
        else {
            return Err(EncodeError::Invalid("entry outside a directory"));
        };
        if *child_open {
            return Err(EncodeError::Invalid("directory entry is missing its child"));
        }
        if last_name
            .as_deref()
            .is_some_and(|previous| previous >= name)
        {
            return Err(EncodeError::NonCanonical(
                "directory entries are not strictly ordered",
            ));
        }
        *last_name = Some(name.to_vec());
        *child_open = true;
        self.string(b"entry")?;
        self.string(b"(")?;
        self.string(b"name")?;
        self.string(name)?;
        self.string(b"node")?;
        self.entries = next_entries;
        Ok(())
    }

    fn begin_file(&mut self, executable: bool, size: u64) -> Result<(), EncodeError> {
        if size > self.limits.max_file_bytes {
            return Err(EncodeError::LimitExceeded {
                what: "file size",
                limit: self.limits.max_file_bytes,
                actual: size,
            });
        }
        self.begin_node(RootKind::Regular)?;
        self.string(b"(")?;
        self.string(b"type")?;
        self.string(b"regular")?;
        if executable {
            self.string(b"executable")?;
            self.string(b"")?;
        }
        self.string(b"contents")?;
        self.u64(size)?;
        self.stack.push(Node::Regular {
            remaining: size,
            size,
        });
        Ok(())
    }

    fn file_chunk(&mut self, chunk: &[u8]) -> Result<(), EncodeError> {
        let Some(Node::Regular { remaining, .. }) = self.stack.last() else {
            return Err(EncodeError::Invalid("file chunk outside a regular node"));
        };
        let length = u64::try_from(chunk.len()).expect("slice length fits in u64");
        if length > *remaining {
            return Err(EncodeError::Invalid(
                "file body is larger than its declared size",
            ));
        }
        self.bytes(chunk)?;
        let Some(Node::Regular { remaining, .. }) = self.stack.last_mut() else {
            unreachable!("file node remains open while writing a file chunk");
        };
        *remaining -= length;
        Ok(())
    }

    fn end_file(&mut self) -> Result<(), EncodeError> {
        let Some(Node::Regular { remaining, size }) = self.stack.last() else {
            return Err(EncodeError::Invalid("file end outside a regular node"));
        };
        if *remaining != 0 {
            return Err(EncodeError::Invalid(
                "file body is smaller than its declared size",
            ));
        }
        self.padding(*size)?;
        self.finish_node(RootKind::Regular)?;
        self.files = self.files.saturating_add(1);
        Ok(())
    }

    fn symlink(&mut self, target: &[u8]) -> Result<(), EncodeError> {
        let target_length = target.len() as u64;
        if target_length > self.limits.max_symlink_target_bytes {
            return Err(EncodeError::LimitExceeded {
                what: "symlink target length",
                limit: self.limits.max_symlink_target_bytes,
                actual: target_length,
            });
        }
        if target.contains(&0) {
            return Err(EncodeError::NonCanonical("symlink target contains NUL"));
        }
        self.begin_node(RootKind::Symlink)?;
        self.string(b"(")?;
        self.string(b"type")?;
        self.string(b"symlink")?;
        self.string(b"target")?;
        self.string(target)?;
        self.finish_atomic(RootKind::Symlink)?;
        self.symlinks = self.symlinks.saturating_add(1);
        Ok(())
    }

    fn end_directory(&mut self) -> Result<(), EncodeError> {
        if !matches!(
            self.stack.last(),
            Some(Node::Directory {
                child_open: false,
                ..
            })
        ) {
            return Err(EncodeError::Invalid(
                "directory end is outside a directory or has an open child",
            ));
        }
        self.finish_node(RootKind::Directory)
    }

    fn begin_node(&mut self, kind: RootKind) -> Result<(), EncodeError> {
        self.ensure_open()?;
        let depth = self.stack.len() as u64;
        if depth > self.limits.max_depth as u64 {
            return Err(EncodeError::LimitExceeded {
                what: "directory depth",
                limit: self.limits.max_depth as u64,
                actual: depth,
            });
        }
        match self.stack.last() {
            Some(Node::Directory {
                child_open: true, ..
            }) => {}
            Some(Node::Directory {
                child_open: false, ..
            }) => {
                return Err(EncodeError::Invalid(
                    "node is not preceded by a directory entry",
                ));
            }
            Some(Node::Regular { .. }) => {
                return Err(EncodeError::Invalid("node is nested under a regular file"));
            }
            None => {}
        }
        if self.stack.is_empty() {
            if self.root.is_some() {
                return Err(EncodeError::Invalid("multiple root nodes"));
            }
            self.root = Some(kind);
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), EncodeError> {
        if self.finished {
            Err(EncodeError::Invalid("events follow the completed root"))
        } else {
            Ok(())
        }
    }

    fn bump_work(&mut self) -> Result<(), EncodeError> {
        self.work = self.work.saturating_add(1);
        if self.work > self.limits.max_work {
            return Err(EncodeError::LimitExceeded {
                what: "work",
                limit: self.limits.max_work,
                actual: self.work,
            });
        }
        Ok(())
    }

    fn finish_atomic(&mut self, kind: RootKind) -> Result<(), EncodeError> {
        self.string(b")")?;
        self.finish_parent(kind)
    }

    fn finish_node(&mut self, kind: RootKind) -> Result<(), EncodeError> {
        let actual = match self.stack.pop() {
            Some(Node::Directory { .. }) => RootKind::Directory,
            Some(Node::Regular { .. }) => RootKind::Regular,
            None => return Err(EncodeError::Invalid("node end without a node")),
        };
        if actual != kind {
            return Err(EncodeError::Invalid(
                "node end does not match the open node",
            ));
        }
        self.string(b")")?;
        self.finish_parent(kind)
    }

    fn finish_parent(&mut self, _kind: RootKind) -> Result<(), EncodeError> {
        let has_directory_parent = match self.stack.last() {
            Some(Node::Directory { child_open, .. }) => {
                if !*child_open {
                    return Err(EncodeError::Invalid("completed node has no parent entry"));
                }
                true
            }
            Some(Node::Regular { .. }) => {
                return Err(EncodeError::Invalid("node is nested under a regular file"));
            }
            None => false,
        };
        if has_directory_parent {
            self.string(b")")?;
            let Some(Node::Directory { child_open, .. }) = self.stack.last_mut() else {
                unreachable!("directory parent remains open after writing its entry close");
            };
            *child_open = false;
        } else if self.stack.is_empty() {
            self.finished = true;
        } else {
            return Err(EncodeError::Invalid("node has an invalid parent"));
        }
        Ok(())
    }

    fn u64(&mut self, value: u64) -> Result<(), EncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn string(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        self.u64(u64::try_from(value.len()).expect("slice length fits in u64"))?;
        self.bytes(value)?;
        self.padding(value.len() as u64)
    }

    fn padding(&mut self, length: u64) -> Result<(), EncodeError> {
        const ZEROES: [u8; 8] = [0; 8];
        let padding = (8 - length % 8) % 8;
        self.bytes(&ZEROES[..padding as usize])
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let length = bytes.len() as u64;
        let next = self
            .raw_size
            .checked_add(length)
            .ok_or(EncodeError::LimitExceeded {
                what: "raw size",
                limit: self.limits.max_total_bytes,
                actual: u64::MAX,
            })?;
        if next > self.limits.max_total_bytes {
            return Err(EncodeError::LimitExceeded {
                what: "raw size",
                limit: self.limits.max_total_bytes,
                actual: next,
            });
        }
        self.writer.write_all(bytes).map_err(EncodeError::Io)?;
        self.digest.update(bytes);
        self.raw_size = next;
        Ok(())
    }
}
