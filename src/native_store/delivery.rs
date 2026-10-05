use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    ops::Range,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

use crate::verified_stream::{VerifiedStream, read_uninterrupted_chunk};
use narjar::__private::filesystem::{
    open_directory, open_directory_at, open_regular_at, read_dir_names,
};
use narjar::{
    nar_encode::{EncodeSummary, Encoder, Event},
    object::{LogicalNar, NarIdentity},
};
use rustix::fs::{self, AtFlags, FileType};

use super::lease::NativeStoreLease;

#[path = "directory_entry.rs"]
mod directory_entry;
use directory_entry::NativeDirectoryEntry;

const FILE_BUFFER_SIZE: usize = 64 * 1024;
const DISCARD_BUFFER_SIZE: usize = 64 * 1024;

#[cfg(test)]
#[path = "../../tests/support/allocations.rs"]
mod test_allocations;

#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: test_allocations::CountingAllocator = test_allocations::CountingAllocator;

pub(crate) struct NativeNarDelivery {
    identity: NarIdentity,
    reader: VerifiedStream<LogicalNar>,
}

impl NativeNarDelivery {
    pub(crate) fn new(lease: NativeStoreLease, identity: NarIdentity) -> io::Result<Self> {
        let active_delivery = lease
            .begin_active_delivery()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let reader = VerifiedStream::spawn(identity, "narjar-native-nar", move |writer| {
            let _active_delivery = active_delivery;
            write_leased_nar(&lease, writer).map(|_| ())
        })?;
        Ok(Self { identity, reader })
    }

    pub(crate) fn content_length(&self) -> u64 {
        self.identity.size().get()
    }

    pub(crate) fn into_reader(self) -> impl Read + Send {
        self.reader
    }

    pub(crate) fn into_range_reader(self, range: Range<u64>) -> io::Result<impl Read + Send> {
        validate_delivery_range(range.clone(), self.identity.size().get())?;
        Ok(NativeNarRangeReader {
            source: self.reader,
            range,
            position: 0,
            state: RangeReadState::Serving,
        })
    }
}

struct NativeNarRangeReader {
    source: VerifiedStream<LogicalNar>,
    range: Range<u64>,
    position: u64,
    state: RangeReadState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RangeReadState {
    Serving,
    Complete,
    Failed,
}

impl Read for NativeNarRangeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        match self.state {
            RangeReadState::Serving => self.read_serving_range(buffer),
            RangeReadState::Complete => Ok(0),
            RangeReadState::Failed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native NAR range stream is in a failed state",
            )),
        }
    }
}

impl NativeNarRangeReader {
    fn read_serving_range(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.discard_until(self.range.start)?;
        if self.position == self.range.end {
            self.finish_range()?;
            return Ok(0);
        }
        let range_remaining = usize::try_from(self.range.end - self.position).unwrap_or(usize::MAX);
        let read_capacity = buffer.len().min(range_remaining);
        let length = self.source.read(&mut buffer[..read_capacity])?;
        self.position = self.position.saturating_add(length as u64);
        if self.position == self.range.end {
            self.finish_range()?;
        }
        Ok(length)
    }

    fn discard_until(&mut self, target: u64) -> io::Result<()> {
        let mut buffer = [0; DISCARD_BUFFER_SIZE];
        while self.position < target {
            let remaining = usize::try_from(target - self.position).unwrap_or(usize::MAX);
            let read_capacity = buffer.len().min(remaining);
            let length = self.source.read(&mut buffer[..read_capacity])?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "native NAR ended while skipping to requested range",
                ));
            }
            self.position = self.position.saturating_add(length as u64);
        }
        Ok(())
    }

    fn finish_range(&mut self) -> io::Result<()> {
        match self.discard_until_end() {
            Ok(()) => {
                self.state = RangeReadState::Complete;
                Ok(())
            }
            Err(error) => {
                self.state = RangeReadState::Failed;
                Err(error)
            }
        }
    }

    fn discard_until_end(&mut self) -> io::Result<()> {
        let mut buffer = [0; DISCARD_BUFFER_SIZE];
        loop {
            let length = self.source.read(&mut buffer)?;
            if length == 0 {
                return Ok(());
            }
            self.position = self.position.saturating_add(length as u64);
        }
    }
}

fn validate_delivery_range(range: Range<u64>, length: u64) -> io::Result<()> {
    if range.start <= range.end && range.end <= length {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native NAR response range is outside the declared identity",
        ))
    }
}

fn write_leased_nar<W: Write>(lease: &NativeStoreLease, output: W) -> io::Result<EncodeSummary> {
    let path = lease.store_path().as_path();
    let parent = path
        .parent()
        .ok_or_else(|| invalid_path("native store path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid_path("native store path has no basename"))?;
    let parent = open_directory(parent)?;
    let mut encoder = Encoder::new(output).map_err(encode_io_error)?;
    emit_node_at(&mut encoder, &parent, name)?;
    encoder
        .finish()
        .map(|(_, summary)| summary)
        .map_err(encode_io_error)
}

fn emit_node_at<W: Write>(encoder: &mut Encoder<W>, parent: &File, name: &OsStr) -> io::Result<()> {
    let metadata = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    match FileType::from_raw_mode(metadata.st_mode) {
        FileType::Directory => emit_directory_at(encoder, parent, name),
        FileType::RegularFile => emit_regular_file_at(encoder, parent, name),
        FileType::Symlink => emit_symlink_at(encoder, parent, name),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAR cannot represent this native filesystem object",
        )),
    }
}

fn emit_directory_at<W: Write>(
    encoder: &mut Encoder<W>,
    parent: &File,
    name: &OsStr,
) -> io::Result<()> {
    let directory = open_directory_at(parent, name)?;
    encoder
        .push(Event::BeginDirectory)
        .map_err(encode_io_error)?;
    for entry in sorted_directory_entries(&directory)? {
        encoder
            .push(Event::Entry(entry.nar_name().as_bytes()))
            .map_err(encode_io_error)?;
        emit_node_at(encoder, &directory, &entry.filesystem_name)?;
    }
    encoder.push(Event::EndDirectory).map_err(encode_io_error)
}

fn emit_regular_file_at<W: Write>(
    encoder: &mut Encoder<W>,
    parent: &File,
    name: &OsStr,
) -> io::Result<()> {
    let mut file = open_regular_at(parent, name)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native file changed type before it could be read",
        ));
    }
    let executable = metadata.mode() & 0o100 != 0;
    encoder
        .push(Event::BeginFile {
            executable,
            size: metadata.len(),
        })
        .map_err(encode_io_error)?;
    let mut buffer = [0; FILE_BUFFER_SIZE];
    encode_regular_file_contents(encoder, &mut file, &mut buffer)?;
    encoder.push(Event::EndFile).map_err(encode_io_error)
}

fn encode_regular_file_contents<W: Write>(
    encoder: &mut Encoder<W>,
    source: &mut impl Read,
    buffer: &mut [u8],
) -> io::Result<()> {
    std::iter::from_fn(|| match read_uninterrupted_chunk(source, buffer) {
        Ok(0) => None,
        Ok(length) => Some(
            encoder
                .push(Event::FileChunk(&buffer[..length]))
                .map_err(encode_io_error),
        ),
        Err(error) => Some(Err(error)),
    })
    .try_for_each(std::convert::identity)
}

fn emit_symlink_at<W: Write>(
    encoder: &mut Encoder<W>,
    parent: &File,
    name: &OsStr,
) -> io::Result<()> {
    let target = fs::readlinkat(parent, name, Vec::new())?;
    encoder
        .push(Event::Symlink(target.as_bytes()))
        .map_err(encode_io_error)
}

fn sorted_directory_entries(directory: &File) -> io::Result<Vec<NativeDirectoryEntry>> {
    let mut entries = directory_entries(directory)?;
    entries.sort_unstable_by(|left, right| {
        left.nar_name().as_bytes().cmp(right.nar_name().as_bytes())
    });
    Ok(entries)
}

fn directory_entries(directory: &File) -> io::Result<Vec<NativeDirectoryEntry>> {
    Ok(read_dir_names(directory)?
        .into_iter()
        .map(NativeDirectoryEntry::new)
        .collect())
}

fn invalid_path(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn encode_io_error(error: narjar::nar_encode::EncodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::{
        ffi::{OsStr, OsString},
        fs::{self, File},
        io::{self, Read},
        num::{NonZeroU64, NonZeroUsize},
        os::unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::PermissionsExt,
        },
        path::{Path, PathBuf},
        sync::Arc,
    };

    use narjar::{
        nar::{Decoder, Event},
        object::{NarHash, NarIdentity, NarSize},
    };
    use sha2::Digest;
    use sqlite::Connection;

    use super::{NativeNarDelivery, open_directory, open_regular_at, write_leased_nar};
    use crate::native_store::lease::NativeStoreLeaseManager;

    #[test]
    fn native_name_projection_borrows_filesystem_bytes() {
        use std::hint::black_box;
        let names: Vec<_> = (0..4096)
            .map(|index| OsString::from(format!("package-{index:06}-payload")))
            .collect();
        let run = || {
            for name in &names {
                black_box(super::directory_entry::nar_entry_name_for_filesystem_name(
                    black_box(name),
                ));
            }
        };
        let (_, counts) = super::test_allocations::measure(run);
        assert_eq!(
            counts.calls, 0,
            "projecting a filesystem name must not allocate: {counts:?}"
        );
    }

    struct NativeDeliveryFixture {
        _temporary: tempfile::TempDir,
        manager: NativeStoreLeaseManager,
        store_path: crate::native_store::lease::NativeStorePath,
        physical_path: PathBuf,
    }

    impl NativeDeliveryFixture {
        fn new() -> Self {
            Self::with_store_object(|path| {
                fs::create_dir(path).expect("create store object");
                fs::write(path.join("z"), b"last").expect("write z");
                fs::write(path.join("a"), b"first").expect("write a");
                fs::create_dir(path.join("empty")).expect("create empty directory");
                let executable = path.join("run");
                fs::write(&executable, b"#!/bin/sh\n").expect("write executable");
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
                    .expect("mark executable");
                std::os::unix::fs::symlink("a", path.join("link")).expect("write symlink");
            })
        }

        fn symlink() -> Self {
            Self::with_store_object(|path| {
                let target = path.with_file_name("native-symlink-target");
                fs::create_dir(&target).expect("create symlink target");
                std::os::unix::fs::symlink("native-symlink-target", path)
                    .expect("create native store symlink object");
            })
        }

        fn with_store_object(create_object: impl FnOnce(&Path)) -> Self {
            let temporary = tempfile::tempdir().expect("create fixture root");
            let store_dir = temporary.path().join("store");
            let state_dir = temporary.path().join("state");
            let roots_dir = temporary.path().join("roots");
            fs::create_dir(&store_dir).expect("create store");
            fs::create_dir_all(state_dir.join("db")).expect("create state");
            File::create(state_dir.join("gc.lock")).expect("create Nix GC lock");
            fs::create_dir(&roots_dir).expect("create roots");
            let path = store_dir.join("00000000000000000000000000000000-native");
            create_store_database(
                &state_dir.join("db/db.sqlite"),
                path.to_str().expect("fixture path should be UTF-8"),
            );
            create_object(&path);
            let database = open_read_only_database(&state_dir.join("db/db.sqlite"));
            let manager = NativeStoreLeaseManager::open(
                store_dir,
                state_dir,
                roots_dir,
                NonZeroU64::new(30).unwrap(),
                NonZeroUsize::new(10).unwrap(),
                database,
            )
            .expect("open lease manager");
            let store_path = manager
                .validate_store_path(&path)
                .expect("valid store path");
            Self {
                _temporary: temporary,
                manager,
                store_path,
                physical_path: path,
            }
        }

        fn lease(&self) -> crate::native_store::lease::NativeStoreLease {
            self.manager
                .acquire(self.store_path.clone(), 2)
                .expect("acquire lease")
        }
    }

    fn create_store_database(path: &Path, store_path: &str) {
        let database = Connection::open(path).expect("open lease database");
        database
            .execute(format!(
                "CREATE TABLE ValidPaths (id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL);
                 INSERT INTO ValidPaths (id, path) VALUES (1, '{store_path}');"
            ))
            .expect("create lease lookup table");
    }

    fn open_read_only_database(path: &Path) -> Arc<sqlite::ConnectionThreadSafe> {
        Arc::new(
            sqlite::Connection::open_thread_safe_with_flags(
                path,
                sqlite::OpenFlags::new().with_read_only(),
            )
            .expect("read-only lease database should open"),
        )
    }

    fn raw_nar_bytes(lease: crate::native_store::lease::NativeStoreLease) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_leased_nar(&lease, &mut bytes).expect("write native NAR");
        bytes
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
    fn verified_delivery_retries_interrupted_chunk_reads_and_final_eof_probe() {
        for offset in [0, 3, 6] {
            let bytes = b"narjar".to_vec();
            let expected = NarIdentity::new(
                NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
                NarSize::new(bytes.len() as u64),
            );
            let (sender, producer) = std::sync::mpsc::channel();
            sender.send(Ok(())).expect("successful producer completion");
            let source = InterruptAtOffset {
                source: io::Cursor::new(bytes.clone()),
                interrupt_at: Some(offset),
            };
            let mut reader = super::VerifiedStream::new(expected, source, producer);
            let mut actual = Vec::new();
            let mut chunk = [0; 3];
            for _ in 0..2 {
                let length = reader
                    .read(&mut chunk)
                    .expect("interruption is retried internally");
                actual.extend_from_slice(&chunk[..length]);
            }
            assert_eq!(actual, bytes);
            assert_eq!(reader.read(&mut chunk).expect("verified EOF"), 0);
        }
    }

    #[test]
    fn native_regular_file_encoding_retries_interruption_after_progress() {
        let mut source = InterruptAtOffset {
            source: io::Cursor::new(b"narjar".to_vec()),
            interrupt_at: Some(3),
        };
        let mut encoder = narjar::nar_encode::Encoder::new(Vec::new()).expect("encoder");
        encoder
            .push(narjar::nar_encode::Event::BeginFile {
                executable: false,
                size: 6,
            })
            .expect("file declaration");
        super::encode_regular_file_contents(&mut encoder, &mut source, &mut [0; 3])
            .expect("interruption must not abort a file after the first chunk");
        encoder
            .push(narjar::nar_encode::Event::EndFile)
            .expect("complete body");
        let (bytes, _) = encoder.finish().expect("complete NAR");
        let mut body = Vec::new();
        Decoder::new(bytes.as_slice())
            .decode(&mut |event: Event<'_>| {
                if let Event::FileChunk(chunk) = event {
                    body.extend_from_slice(chunk);
                }
                Ok::<(), std::convert::Infallible>(())
            })
            .expect("encoded stream is valid");
        assert_eq!(body, b"narjar");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_dump_uses_canonical_case_hacked_names_and_rejects_collisions() {
        let files = [
            ("empty", "empty~nix~case~hack~"),
            ("nonnumeric", "nonnumeric~nix~case~hack~x"),
            ("repeated", "repeated~nix~case~hack~1~nix~case~hack~2"),
        ];
        let fixture = NativeDeliveryFixture::with_store_object(|path| {
            fs::create_dir(path).expect("directory");
            for (_, name) in files {
                fs::write(path.join(name), name.as_bytes()).expect("case-hacked file");
            }
        });
        // Explicit canonical names are independent of the projection helper.
        let mut encoder = narjar::nar_encode::Encoder::new(Vec::new()).expect("encoder");
        encoder
            .push(narjar::nar_encode::Event::BeginDirectory)
            .expect("directory");
        for (name, contents) in files {
            encoder
                .push(narjar::nar_encode::Event::Entry(name.as_bytes()))
                .expect("entry");
            encoder
                .push(narjar::nar_encode::Event::BeginFile {
                    executable: false,
                    size: contents.len() as u64,
                })
                .expect("file");
            encoder
                .push(narjar::nar_encode::Event::FileChunk(contents.as_bytes()))
                .expect("body");
            encoder
                .push(narjar::nar_encode::Event::EndFile)
                .expect("end file");
        }
        encoder
            .push(narjar::nar_encode::Event::EndDirectory)
            .expect("end directory");
        let (expected, _) = encoder.finish().expect("canonical NAR");
        assert_eq!(raw_nar_bytes(fixture.lease()), expected);

        fs::write(fixture.physical_path.join("empty"), b"colliding name")
            .expect("case-hack collision");
        let error = write_leased_nar(&fixture.lease(), io::sink())
            .expect_err("distinct filesystem names cannot share one NAR name");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn emits_canonical_nar_from_a_leased_native_store_path() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let mut names = Vec::new();
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            if let Event::Entry { name } = event {
                names.push(name.to_vec());
            }
            Ok(())
        };

        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode native NAR");

        assert_eq!(
            names,
            [
                b"a".to_vec(),
                b"empty".to_vec(),
                b"link".to_vec(),
                b"run".to_vec(),
                b"z".to_vec(),
            ]
        );
    }

    #[test]
    fn preserves_empty_directories_and_executable_bits() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let mut names = Vec::new();
        let mut executable_files = 0;
        let mut empty_depth = None;
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            match event {
                Event::Entry { name } => {
                    if name == b"empty" {
                        empty_depth = Some(1);
                    }
                    names.push(name.to_vec());
                }
                Event::BeginFile {
                    executable: true, ..
                } => executable_files += 1,
                _ => {}
            }
            Ok(())
        };

        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode native NAR");

        assert!(names.contains(&b"empty".to_vec()));
        assert_eq!(executable_files, 1);
        assert_eq!(empty_depth, Some(1));
    }

    #[test]
    fn only_owner_execute_bit_marks_a_native_file_executable() {
        let fixture = NativeDeliveryFixture::with_store_object(|path| {
            fs::create_dir(path).expect("create store object");
            write_file_with_mode(&path.join("group-exec"), 0o654);
            write_file_with_mode(&path.join("owner-exec"), 0o744);
            write_file_with_mode(&path.join("other-exec"), 0o645);
            write_file_with_mode(&path.join("plain"), 0o644);
        });
        let bytes = raw_nar_bytes(fixture.lease());

        let executable_by_name = decoded_file_executable_flags(&bytes);

        assert_eq!(
            executable_by_name.get(b"owner-exec".as_slice()),
            Some(&true)
        );
        assert_eq!(
            executable_by_name.get(b"group-exec".as_slice()),
            Some(&false)
        );
        assert_eq!(
            executable_by_name.get(b"other-exec".as_slice()),
            Some(&false)
        );
        assert_eq!(executable_by_name.get(b"plain".as_slice()), Some(&false));
    }

    #[test]
    fn preserves_raw_entry_names_when_the_filesystem_accepts_them() {
        let raw_name = OsString::from_vec(vec![0xff, b'-', b'r', b'a', b'w']);
        let fixture = NativeDeliveryFixture::with_store_object(|path| {
            fs::create_dir(path).expect("create store object");
            match fs::write(path.join(&raw_name), b"raw") {
                Ok(()) => {}
                Err(error)
                    if error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) => {}
                Err(error) => panic!("write raw-byte filename: {error}"),
            }
        });
        if !fixture.physical_path.join(&raw_name).exists() {
            return;
        }
        let bytes = raw_nar_bytes(fixture.lease());
        let mut names = Vec::new();
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            if let Event::Entry { name } = event {
                names.push(name.to_vec());
            }
            Ok(())
        };

        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode raw-byte native NAR");

        assert_eq!(names, [vec![0xff, b'-', b'r', b'a', b'w']]);
    }

    #[test]
    fn directory_enumeration_restarts_without_consuming_the_borrowed_descriptor() {
        let fixture = NativeDeliveryFixture::new();
        let directory = open_directory(&fixture.physical_path).expect("open store directory");
        let names = || {
            super::sorted_directory_entries(&directory)
                .expect("enumerate store directory")
                .into_iter()
                .map(|entry| entry.filesystem_name)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            names(),
            ["a", "empty", "link", "run", "z"].map(OsString::from)
        );
        assert_eq!(
            names(),
            ["a", "empty", "link", "run", "z"].map(OsString::from)
        );
    }

    #[test]
    fn preserves_long_non_utf8_symlink_targets() {
        let mut target = b"segment/".repeat(80);
        target.push(0xff);
        let fixture = NativeDeliveryFixture::with_store_object(|path| {
            std::os::unix::fs::symlink(OsStr::from_bytes(&target), path)
                .expect("create raw-byte symlink");
        });
        let bytes = raw_nar_bytes(fixture.lease());
        let mut targets = Vec::new();
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            if let Event::Symlink { target } = event {
                targets.push(target.to_vec());
            }
            Ok(())
        };
        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode raw-byte symlink NAR");

        assert_eq!(targets, [target]);
    }

    #[test]
    fn leased_symlink_store_object_is_encoded_as_a_symlink_not_followed() {
        let fixture = NativeDeliveryFixture::symlink();
        let bytes = raw_nar_bytes(fixture.lease());
        let mut symlink_targets = Vec::new();
        let mut directories = 0;
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            match event {
                Event::Symlink { target } => symlink_targets.push(target.to_vec()),
                Event::BeginDirectory { .. } => directories += 1,
                _ => {}
            }
            Ok(())
        };

        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode native symlink NAR");

        assert_eq!(symlink_targets, [b"native-symlink-target".to_vec()]);
        assert_eq!(directories, 0);
    }

    #[test]
    fn delivery_reader_verifies_the_declared_native_identity_at_eof() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
            NarSize::new(bytes.len() as u64),
        );
        let delivery =
            NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
        assert_eq!(delivery.content_length(), bytes.len() as u64);
        let mut reader = delivery.into_reader();
        let mut actual = Vec::new();

        reader
            .read_to_end(&mut actual)
            .expect("read verified native delivery");

        assert_eq!(actual, bytes);
    }

    #[test]
    fn delivery_reader_rejects_identity_mismatch_without_successful_eof() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest([1; 32]),
            NarSize::new(bytes.len() as u64),
        );
        let delivery =
            NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
        let mut reader = delivery.into_reader();

        let error = io::copy(&mut reader, &mut io::sink())
            .expect_err("wrong native identity should fail delivery");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("identity mismatch"));
    }

    #[test]
    fn delivery_reader_rejects_a_source_changed_after_identity_measurement() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
            NarSize::new(bytes.len() as u64),
        );
        fs::write(fixture.physical_path.join("a"), b"changed").expect("mutate native source");
        let delivery =
            NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
        let mut reader = delivery.into_reader();

        let error = io::copy(&mut reader, &mut io::sink())
            .expect_err("changed native source should fail delivery");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("identity mismatch"));
    }

    #[test]
    fn range_delivery_yields_only_the_requested_bytes_and_still_finishes_the_nar() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
            NarSize::new(bytes.len() as u64),
        );
        let ranges = [0..1, 2..6, bytes.len() as u64 - 3..bytes.len() as u64];

        for range in ranges {
            let delivery =
                NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
            let mut reader = delivery
                .into_range_reader(range.clone())
                .expect("open native range delivery");
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).expect("read native range");

            assert_eq!(actual, bytes[range.start as usize..range.end as usize]);
        }
    }

    #[test]
    fn range_delivery_rejects_corruption_after_the_requested_prefix() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
            NarSize::new(bytes.len() as u64),
        );
        fs::write(fixture.physical_path.join("z"), b"changed after prefix")
            .expect("mutate native source after measured prefix");
        let delivery =
            NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
        let mut reader = delivery
            .into_range_reader(0..1)
            .expect("open native prefix range");
        let mut actual = Vec::new();

        let error = reader
            .read_to_end(&mut actual)
            .expect_err("corrupt suffix should fail range completion");

        assert_eq!(actual, Vec::<u8>::new());
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("identity mismatch"));
    }

    #[test]
    fn range_delivery_rejects_corrupt_suffix_before_bounded_consumers_get_the_prefix() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
            NarSize::new(bytes.len() as u64),
        );
        fs::write(fixture.physical_path.join("z"), b"changed after prefix")
            .expect("mutate native source after measured prefix");
        let delivery =
            NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
        let mut reader = delivery
            .into_range_reader(0..1)
            .expect("open native prefix range")
            .take(1);
        let mut actual = Vec::new();

        let error = reader
            .read_to_end(&mut actual)
            .expect_err("corrupt suffix should fail before bounded prefix delivery");

        assert_eq!(actual, Vec::<u8>::new());
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("identity mismatch"));
    }

    #[test]
    fn failed_range_reader_stays_failed_on_later_reads() {
        let fixture = NativeDeliveryFixture::new();
        let bytes = raw_nar_bytes(fixture.lease());
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(&bytes).into()),
            NarSize::new(bytes.len() as u64),
        );
        fs::write(fixture.physical_path.join("z"), b"changed after prefix")
            .expect("mutate native source after measured prefix");
        let delivery =
            NativeNarDelivery::new(fixture.lease(), identity).expect("open native delivery");
        let mut reader = delivery
            .into_range_reader(0..1)
            .expect("open native prefix range");
        let mut byte = [0; 1];

        let first_error = reader
            .read(&mut byte)
            .expect_err("corrupt suffix should fail first read");
        let second_error = reader
            .read(&mut byte)
            .expect_err("failed range should remain failed");

        assert_eq!(first_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(second_error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn unsupported_native_filesystem_objects_fail_closed() {
        let fixture = NativeDeliveryFixture::with_store_object(|path| {
            fs::create_dir(path).expect("create store object");
            make_fifo(&path.join("fifo"));
        });

        let error = write_leased_nar(&fixture.lease(), io::sink())
            .expect_err("FIFO store object should not be representable as NAR");

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn regular_file_open_fails_closed_when_a_child_path_is_a_fifo() {
        let temporary = tempfile::tempdir().expect("create fixture root");
        let parent = temporary.path().join("parent");
        fs::create_dir(&parent).expect("create parent directory");
        make_fifo(&parent.join("fifo"));
        let parent = open_directory(&parent).expect("open fixture parent");

        let error = open_regular_at(&parent, OsStr::new("fifo"))
            .expect_err("FIFO should not open as a regular native file");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn write_file_with_mode(path: &Path, mode: u32) {
        fs::write(path, b"content").expect("write fixture file");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
    }

    fn decoded_file_executable_flags(bytes: &[u8]) -> std::collections::BTreeMap<Vec<u8>, bool> {
        let mut current_entry = None;
        let mut executable_by_name = std::collections::BTreeMap::new();
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            match event {
                Event::Entry { name } => current_entry = Some(name.to_vec()),
                Event::BeginFile { executable, .. } => {
                    let name = current_entry
                        .take()
                        .expect("file event should be preceded by entry event");
                    executable_by_name.insert(name, executable);
                }
                _ => {}
            }
            Ok(())
        };
        Decoder::new(bytes)
            .decode(&mut sink)
            .expect("decode native NAR executable flags");
        executable_by_name
    }

    fn make_fifo(path: &Path) {
        #[cfg(not(target_vendor = "apple"))]
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .expect("mkfifo fixture should succeed");

        // rustix 1.1.5 has no mkfifo and excludes mkfifoat on Apple targets.
        #[cfg(target_vendor = "apple")]
        {
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())
                .expect("fixture path should not contain NUL");
            // SAFETY: name is NUL-terminated and mkfifo does not retain it.
            let result = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
            assert_eq!(
                result,
                0,
                "mkfifo fixture failed: {}",
                io::Error::last_os_error()
            );
        }
    }
}
