use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, PipeReader, Read, Take, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    sync::mpsc::{self, Receiver},
    thread,
};

use narjar::{
    nar_encode::{EncodeSummary, Encoder, Event},
    object::{NarHash, NarIdentity},
};
use sha2::{Digest, Sha256};

use super::lease::NativeStoreLease;

const FILE_BUFFER_SIZE: usize = 64 * 1024;

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
        let (reader, mut writer) = io::pipe()?;
        let (sender, producer) = mpsc::channel();
        thread::Builder::new()
            .name("narjar-native-nar".into())
            .spawn(move || {
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
    let metadata = symlink_metadata_at(parent, name)?;
    let mode = metadata.st_mode;
    if mode & libc::S_IFMT == libc::S_IFDIR {
        emit_directory_at(encoder, parent, name)
    } else if mode & libc::S_IFMT == libc::S_IFREG {
        emit_regular_file_at(encoder, parent, name)
    } else if mode & libc::S_IFMT == libc::S_IFLNK {
        emit_symlink_at(encoder, parent, name)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAR cannot represent this native filesystem object",
        ))
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
    for entry in sorted_directory_entry_names(&directory)? {
        encoder
            .push(Event::Entry(entry.as_bytes()))
            .map_err(encode_io_error)?;
        emit_node_at(encoder, &directory, &entry)?;
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
    let executable = metadata.mode() & 0o111 != 0;
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
    let target = read_link_at(parent, name)?;
    encoder
        .push(Event::Symlink(&target))
        .map_err(encode_io_error)
}

fn sorted_directory_entry_names(directory: &File) -> io::Result<Vec<OsString>> {
    let mut names = directory_entry_names(directory)?;
    names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

fn directory_entry_names(directory: &File) -> io::Result<Vec<OsString>> {
    let fd = duplicate_fd(directory)?;
    // SAFETY: fdopendir takes ownership of the duplicated descriptor on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed, so ownership was not transferred.
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::last_os_error());
    }
    DirectoryStream { stream }.read_entry_names()
}

struct DirectoryStream {
    stream: *mut libc::DIR,
}

impl DirectoryStream {
    fn read_entry_names(&mut self) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        loop {
            // SAFETY: stream is a valid DIR* owned by DirectoryStream.
            let entry = unsafe { libc::readdir(self.stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: d_name is NUL-terminated for the returned directory entry.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(OsString::from_vec(name.to_bytes().to_vec()));
            }
        }
        Ok(names)
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: stream is owned by this guard and closed exactly once here.
        unsafe {
            libc::closedir(self.stream);
        }
    }
}

fn symlink_metadata_at(parent: &File, name: &OsStr) -> io::Result<libc::stat> {
    let name = c_string(name)?;
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent fd and C string are valid for the call; fstatat initializes
    // metadata when it succeeds.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: fstatat succeeded and initialized metadata.
        Ok(unsafe { metadata.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn read_link_at(parent: &File, name: &OsStr) -> io::Result<Vec<u8>> {
    let name = c_string(name)?;
    let mut capacity = 256;
    loop {
        let mut buffer = vec![0; capacity];
        // SAFETY: parent fd, C string, and buffer are valid for the call.
        let length = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length)
            .map_err(|_| io::Error::other("native symlink target length overflowed usize"))?;
        if length < capacity {
            buffer.truncate(length);
            return Ok(buffer);
        }
        capacity = capacity
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("native symlink target is too large"))?;
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

fn open_regular_at(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

fn open_at(parent: &File, name: &OsStr, flags: i32) -> io::Result<File> {
    let name = c_string(name)?;
    // SAFETY: parent fd and C string are valid for the call; on success the fd is
    // owned by the returned File.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0) };
    if fd >= 0 {
        // SAFETY: openat returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn duplicate_fd(file: &File) -> io::Result<i32> {
    let duplicate = file.try_clone()?.into_raw_fd();
    Ok(duplicate)
}

fn c_string(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| invalid_path("native path contains a NUL byte"))
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
        fs::{self, File},
        io::{self, Read},
        num::{NonZeroU64, NonZeroUsize},
        path::{Path, PathBuf},
        sync::Arc,
    };

    use narjar::{
        nar::{Decoder, Event},
        object::{NarHash, NarIdentity, NarSize},
    };
    use sha2::Digest;
    use sqlite::Connection;

    use super::{NativeNarDelivery, write_leased_nar};
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
                names.push(name);
            }
            Ok(())
        };

        Decoder::new(&bytes[..])
            .decode(&mut sink)
            .expect("decode native NAR");

        assert_eq!(names, [b"a".to_vec(), b"link".to_vec(), b"z".to_vec()]);
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
}
