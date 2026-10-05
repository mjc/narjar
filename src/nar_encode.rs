//! Versioned, bounded-memory streaming encoder for canonical NAR bytes.
//!
//! The encoder consumes semantic events rather than a filesystem or a storage
//! representation. Directory ordering is checked at the boundary, while file
//! bodies are written and hashed as they arrive. The output writer is returned
//! by [`Encoder::finish`] so callers retain ownership of their destination.

use std::{io, io::Write};

use sha2::{Digest, Sha256};

use crate::nar::RootKind;

/// The compatibility version of this event-to-byte contract.
pub const ENCODER_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
/// An output, event-sequence, canonicality, or resource-limit error.
///
/// An encoding attempt is terminal after any such error. The encoder may have
/// already written bytes or advanced its event state; discard the encoder and
/// treat its destination as incomplete rather than retrying or calling
/// [`Encoder::finish`]. An I/O error can also follow a partial write.
pub enum EncodeError {
    /// Writing canonical NAR bytes failed.
    #[error("NAR output: {0}")]
    Io(#[source] io::Error),
    /// The event sequence cannot describe a complete NAR.
    #[error("invalid NAR events: {0}")]
    Invalid(&'static str),
    /// An event value violates canonical NAR rules.
    #[error("non-canonical NAR events: {0}")]
    NonCanonical(&'static str),
    /// A configured encoding resource limit was exceeded.
    #[error("NAR encoder {what} limit exceeded: {actual} > {limit}")]
    LimitExceeded {
        /// The resource whose limit was exceeded.
        what: &'static str,
        /// The configured maximum.
        limit: u64,
        /// The observed value.
        actual: u64,
    },
}

/// Representation-neutral events accepted by [`Encoder`].
pub enum Event<'a> {
    /// Begin a directory node.
    BeginDirectory,
    /// Begin an entry in the current directory using its raw basename bytes.
    Entry(&'a [u8]),
    /// Begin a regular file with its executable bit and declared body size.
    BeginFile {
        /// Whether the encoded file is marked executable.
        executable: bool,
        /// Number of body bytes that must be supplied before `EndFile`.
        size: u64,
    },
    /// Write the next bytes of the current regular file body.
    FileChunk(&'a [u8]),
    /// Finish the current regular file after exactly its declared byte count.
    EndFile,
    /// Write a symbolic-link node with its raw target bytes.
    Symlink(&'a [u8]),
    /// Finish the current directory after all entries have ended.
    EndDirectory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Version, root kind, byte identity, and node counts for encoded output.
pub struct EncodeSummary {
    /// Event-to-byte compatibility version.
    pub version: u32,
    /// Type of the root node.
    pub root: RootKind,
    /// Number of bytes written to the NAR destination.
    pub raw_size: u64,
    /// SHA-256 digest of the exact bytes written.
    pub raw_sha256: [u8; 32],
    /// Number of directory entries.
    pub entries: u64,
    /// Number of regular files.
    pub files: u64,
    /// Number of symbolic links.
    pub symlinks: u64,
}

enum Node {
    Directory(DirectoryState),
    Regular { remaining: u64, size: u64 },
}

enum DirectoryState {
    Ready { last_name: Option<Vec<u8>> },
    ChildOpen { name: Vec<u8> },
}

#[derive(Clone, Copy)]
enum RootState {
    Awaiting,
    Open(RootKind),
    Complete(RootKind),
}

/// Writes canonical NAR bytes without retaining file bodies or the completed
/// archive. Directory memory is bounded by nesting depth and one previous
/// entry name per open directory. If any operation returns [`EncodeError`],
/// discard the encoder and treat the destination as incomplete; output and
/// event state are not rolled back.
pub struct Encoder<W> {
    writer: W,
    limits: crate::nar::Limits,
    digest: Sha256,
    raw_size: u64,
    root: RootState,
    stack: Vec<Node>,
    entries: u64,
    files: u64,
    symlinks: u64,
    work: u64,
}

impl<W: Write> Encoder<W> {
    /// Starts a canonical NAR encoder with [`crate::nar::Limits::default`].
    pub fn new(writer: W) -> Result<Self, EncodeError> {
        Self::with_limits(writer, crate::nar::Limits::default())
    }

    /// Starts a canonical NAR encoder with explicit structural and size limits.
    pub fn with_limits(writer: W, limits: crate::nar::Limits) -> Result<Self, EncodeError> {
        let mut encoder = Self {
            writer,
            limits,
            digest: Sha256::new(),
            raw_size: 0,
            root: RootState::Awaiting,
            stack: Vec::new(),
            entries: 0,
            files: 0,
            symlinks: 0,
            work: 0,
        };
        encoder.string(b"nix-archive-1")?;
        Ok(encoder)
    }

    /// Applies one event, writing its bytes before returning.
    ///
    /// File chunks are borrowed only for this call. Directory entries must be
    /// in canonical byte order, and each file must receive exactly its declared
    /// size before [`Event::EndFile`].
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

    /// Finishes the root node and returns the original writer and output facts.
    ///
    /// Returns [`EncodeError::Invalid`] if the event stream left any node open
    /// or never supplied a root.
    pub fn finish(self) -> Result<(W, EncodeSummary), EncodeError> {
        let RootState::Complete(root) = self.root else {
            return Err(EncodeError::Invalid("the root node is incomplete"));
        };
        let raw_sha256: [u8; 32] = self.digest.finalize().into();
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
        self.stack
            .push(Node::Directory(DirectoryState::Ready { last_name: None }));
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

        match self.stack.last_mut() {
            Some(Node::Directory(state)) => match state {
                DirectoryState::Ready { last_name } => {
                    if last_name
                        .as_deref()
                        .is_some_and(|previous| previous >= name)
                    {
                        return Err(EncodeError::NonCanonical(
                            "directory entries are not strictly ordered",
                        ));
                    }
                    let mut owned_name = last_name.take().unwrap_or_default();
                    owned_name.clear();
                    owned_name.extend_from_slice(name);
                    crate::nar::release_oversized_metadata_capacity(&mut owned_name);
                    *state = DirectoryState::ChildOpen { name: owned_name };
                }
                DirectoryState::ChildOpen { .. } => {
                    return Err(EncodeError::Invalid("directory entry is missing its child"));
                }
            },
            Some(Node::Regular { .. }) | None => {
                return Err(EncodeError::Invalid("entry outside a directory"));
            }
        }
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
        self.finish_atomic()?;
        self.symlinks = self.symlinks.saturating_add(1);
        Ok(())
    }

    fn end_directory(&mut self) -> Result<(), EncodeError> {
        match self.stack.last() {
            Some(Node::Directory(DirectoryState::Ready { .. })) => {
                self.finish_node(RootKind::Directory)
            }
            Some(Node::Directory(DirectoryState::ChildOpen { .. }))
            | Some(Node::Regular { .. })
            | None => Err(EncodeError::Invalid(
                "directory end is outside a directory or has an open child",
            )),
        }
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
            Some(Node::Directory(DirectoryState::ChildOpen { .. })) => {}
            Some(Node::Directory(DirectoryState::Ready { .. })) => {
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
            match self.root {
                RootState::Awaiting => self.root = RootState::Open(kind),
                RootState::Open(_) => {
                    return Err(EncodeError::Invalid("multiple root nodes"));
                }
                RootState::Complete(_) => {
                    return Err(EncodeError::Invalid("events follow the completed root"));
                }
            }
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), EncodeError> {
        match self.root {
            RootState::Complete(_) => Err(EncodeError::Invalid("events follow the completed root")),
            RootState::Awaiting | RootState::Open(_) => Ok(()),
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

    fn finish_atomic(&mut self) -> Result<(), EncodeError> {
        self.string(b")")?;
        self.finish_parent()
    }

    fn finish_node(&mut self, kind: RootKind) -> Result<(), EncodeError> {
        let actual = match self.stack.pop() {
            Some(Node::Directory(_)) => RootKind::Directory,
            Some(Node::Regular { .. }) => RootKind::Regular,
            None => return Err(EncodeError::Invalid("node end without a node")),
        };
        if actual != kind {
            return Err(EncodeError::Invalid(
                "node end does not match the open node",
            ));
        }
        self.string(b")")?;
        self.finish_parent()
    }

    fn finish_parent(&mut self) -> Result<(), EncodeError> {
        match self.stack.last() {
            Some(Node::Directory(DirectoryState::ChildOpen { .. })) => self.close_directory_entry(),
            Some(Node::Directory(DirectoryState::Ready { .. })) => {
                Err(EncodeError::Invalid("completed node has no parent entry"))
            }
            Some(Node::Regular { .. }) => {
                Err(EncodeError::Invalid("node is nested under a regular file"))
            }
            None => self.complete_root(),
        }
    }

    fn close_directory_entry(&mut self) -> Result<(), EncodeError> {
        self.string(b")")?;
        let Some(Node::Directory(state)) = self.stack.last_mut() else {
            unreachable!("validated parent remains an open directory");
        };
        let DirectoryState::ChildOpen { name } =
            std::mem::replace(state, DirectoryState::Ready { last_name: None })
        else {
            unreachable!("validated parent has an open child");
        };
        *state = DirectoryState::Ready {
            last_name: Some(name),
        };
        Ok(())
    }

    fn complete_root(&mut self) -> Result<(), EncodeError> {
        let RootState::Open(root) = self.root else {
            return Err(EncodeError::Invalid("the root node is incomplete"));
        };
        self.root = RootState::Complete(root);
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

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &EncodeError::Invalid("detail"),
                "invalid NAR events: detail",
            ),
            (
                &EncodeError::NonCanonical("detail"),
                "non-canonical NAR events: detail",
            ),
            (
                &EncodeError::LimitExceeded {
                    what: "bytes",
                    limit: 8,
                    actual: 9,
                },
                "NAR encoder bytes limit exceeded: 9 > 8",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_encode_io_source_keeps_io_layer() {
        use std::error::Error as _;
        let error = EncodeError::Io(io::Error::other("write failure"));
        assert_eq!(error.to_string(), "NAR output: write failure");
        assert!(error.source().unwrap().is::<io::Error>());
        assert!(error.source().unwrap().source().is_none());
    }
}
