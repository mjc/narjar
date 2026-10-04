use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, PipeReader, Read, Take, Write},
    ops::Range,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
    path::Path,
    sync::mpsc::{self, Receiver},
    thread,
};

use narjar::{
    nar_encode::{EncodeSummary, Encoder, Event},
    object::{NarHash, NarIdentity},
};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};

use super::lease::NativeStoreLease;

const FILE_BUFFER_SIZE: usize = 64 * 1024;
const DISCARD_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) struct NativeNarDelivery {
    identity: NarIdentity,
    reader: VerifiedNativeNarReader,
}

impl NativeNarDelivery {
    pub(crate) fn new(lease: NativeStoreLease, identity: NarIdentity) -> io::Result<Self> {
        let reader = VerifiedNativeNarReader::spawn(identity, lease)?;
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
    source: VerifiedNativeNarReader,
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

enum VerifiedNativeNarReader {
    Streaming(StreamingNativeNar),
    Complete,
    Failed,
}

struct StreamingNativeNar {
    reader: Take<PipeReader>,
    producer: Receiver<io::Result<()>>,
    expected: NarIdentity,
    digest: Sha256,
}

impl VerifiedNativeNarReader {
    fn spawn(expected: NarIdentity, lease: NativeStoreLease) -> io::Result<Self> {
        let active_delivery = lease
            .begin_active_delivery()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (reader, mut writer) = io::pipe()?;
        let (sender, producer) = mpsc::channel();
        thread::Builder::new()
            .name("narjar-native-nar".into())
            .spawn(move || {
                let _active_delivery = active_delivery;
                let result = write_leased_nar(&lease, &mut writer);
                drop(writer);
                let _ = sender.send(result.map(|_| ()));
            })?;
        Ok(Self::Streaming(StreamingNativeNar {
            reader: reader.take(expected.size().get()),
            producer,
            expected,
            digest: Sha256::new(),
        }))
    }

    fn read_next(self, buffer: &mut [u8]) -> io::Result<(Self, usize)> {
        match self {
            Self::Streaming(mut stream) => {
                let length = stream.read_chunk(buffer)?;
                let next = match stream.reader.limit() {
                    0 => {
                        stream.finish()?;
                        Self::Complete
                    }
                    _ => Self::Streaming(stream),
                };
                Ok((next, length))
            }
            Self::Complete => Ok((Self::Complete, 0)),
            Self::Failed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified native NAR stream is in a failed state",
            )),
        }
    }
}

impl Read for VerifiedNativeNarReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let current = std::mem::replace(self, Self::Failed);
        let (next, length) = current.read_next(buffer)?;
        *self = next;
        Ok(length)
    }
}

impl StreamingNativeNar {
    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = self.reader.read(buffer)?;
        if length == 0 && self.reader.limit() != 0 {
            wait_for_native_nar_producer(&self.producer)?;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native NAR producer ended before the declared size",
            ));
        }
        self.digest.update(&buffer[..length]);
        Ok(length)
    }

    fn finish(self) -> io::Result<()> {
        let Self {
            reader: mut bounded_reader,
            producer,
            expected,
            digest,
        } = self;
        let actual_hash = NarHash::from_digest(digest.finalize().into());
        if actual_hash != expected.hash() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "native NAR identity mismatch: expected {}/{}; got {}/{}",
                    expected.hash(),
                    expected.size(),
                    actual_hash,
                    expected.size(),
                ),
            ));
        }
        if bounded_reader.get_mut().read(&mut [0; 1])? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native NAR producer exceeded the declared size",
            ));
        }
        wait_for_native_nar_producer(&producer)
    }
}

fn wait_for_native_nar_producer(producer: &Receiver<io::Result<()>>) -> io::Result<()> {
    producer
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native NAR result was dropped"))?
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
            .push(Event::Entry(entry.nar_name.as_bytes()))
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
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        encoder
            .push(Event::FileChunk(&buffer[..length]))
            .map_err(encode_io_error)?;
    }
    encoder.push(Event::EndFile).map_err(encode_io_error)
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
    entries.sort_unstable_by(|left, right| left.nar_name.as_bytes().cmp(right.nar_name.as_bytes()));
    Ok(entries)
}

struct NativeDirectoryEntry {
    filesystem_name: OsString,
    nar_name: OsString,
}

fn directory_entries(directory: &File) -> io::Result<Vec<NativeDirectoryEntry>> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            let filesystem_name = OsString::from_vec(name.to_vec());
            entries.push(NativeDirectoryEntry {
                nar_name: nar_entry_name_for_filesystem_name(&filesystem_name),
                filesystem_name,
            });
        }
    }
    Ok(entries)
}

fn nar_entry_name_for_filesystem_name(name: &OsStr) -> OsString {
    OsString::from_vec(nar_entry_name_bytes_for_filesystem_name(name.as_bytes()).to_vec())
}

fn darwin_case_hack_decoded_name(name: &[u8]) -> &[u8] {
    const CASE_HACK_MARKER: &[u8] = b"~nix~case~hack~";
    let Some(marker_start) = name
        .windows(CASE_HACK_MARKER.len())
        .rposition(|window| window == CASE_HACK_MARKER)
    else {
        return name;
    };
    let suffix_start = marker_start + CASE_HACK_MARKER.len();
    if suffix_start < name.len() && name[suffix_start..].iter().all(u8::is_ascii_digit) {
        &name[..marker_start]
    } else {
        name
    }
}

#[cfg(target_os = "macos")]
fn nar_entry_name_bytes_for_filesystem_name(name: &[u8]) -> &[u8] {
    darwin_case_hack_decoded_name(name)
}

#[cfg(not(target_os = "macos"))]
fn nar_entry_name_bytes_for_filesystem_name(name: &[u8]) -> &[u8] {
    name
}

fn open_directory(path: &Path) -> io::Result<File> {
    Ok(fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}

fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    Ok(fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}

fn open_regular_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let file: File = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native file changed type before it could be read",
        ))
    }
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
                Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => (),
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
                targets.push(target);
            }
            Ok(())
        };
        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode raw-byte symlink NAR");

        assert_eq!(targets, [target]);
    }

    #[test]
    fn darwin_case_hack_suffix_is_removed_only_when_it_has_decimal_disambiguator() {
        assert_eq!(
            super::darwin_case_hack_decoded_name(b"README~nix~case~hack~1"),
            b"README"
        );
        assert_eq!(
            super::darwin_case_hack_decoded_name(b"README~nix~case~hack~12"),
            b"README"
        );
        assert_eq!(
            super::darwin_case_hack_decoded_name(b"README~nix~case~hack~"),
            b"README~nix~case~hack~"
        );
        assert_eq!(
            super::darwin_case_hack_decoded_name(b"README~nix~case~hack~x"),
            b"README~nix~case~hack~x"
        );
    }

    #[test]
    fn leased_symlink_store_object_is_encoded_as_a_symlink_not_followed() {
        let fixture = NativeDeliveryFixture::symlink();
        let bytes = raw_nar_bytes(fixture.lease());
        let mut symlink_targets = Vec::new();
        let mut directories = 0;
        let mut sink = |event: Event<'_>| -> Result<(), std::convert::Infallible> {
            match event {
                Event::Symlink { target } => symlink_targets.push(target),
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
