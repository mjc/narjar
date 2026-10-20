use std::{fs::File, io, path::Path};

use crate::cache::filesystem::{FilePrivacy, open_regular, set_file_privacy};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as host;
#[cfg(windows)]
use windows as host;

pub(crate) use host::{non_unicode_name, symlink};

#[derive(Clone, Copy)]
pub(crate) enum InjectedIoFailure {
    AccessDenied,
    ReadFailure,
    Unsupported,
    NoSpace,
    QuotaExceeded,
    ReadOnly,
    ConnectionReset,
    Busy,
}

impl InjectedIoFailure {
    pub(crate) fn code(self) -> i32 {
        host::error_code(self)
    }
    pub(crate) fn error(self) -> io::Error {
        io::Error::from_raw_os_error(self.code())
    }
}

pub(crate) fn make_private_file(path: impl AsRef<Path>) -> io::Result<()> {
    let file = open_regular(path.as_ref())?;
    set_file_privacy(&file, FilePrivacy::Private)
}

pub(crate) fn make_public_file(path: impl AsRef<Path>) -> io::Result<()> {
    let file = open_regular(path.as_ref())?;
    set_file_privacy(&file, FilePrivacy::Public)
}

pub(crate) fn private_file(path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let parent = crate::cache::filesystem::open_directory(path.parent().unwrap())?;
    crate::cache::filesystem::PreparedFile::write(&parent, FilePrivacy::Private, |file| {
        std::io::Write::write_all(file, bytes)
    })?
    .replace(path.file_name().unwrap())
}

pub(crate) fn private_directory(path: &Path) -> io::Result<File> {
    crate::cache::filesystem::create_private_directory_tree(path)
}

pub(crate) fn accept_before_deadline(
    listener: &std::net::TcpListener,
    deadline: std::time::Instant,
) -> std::net::TcpStream {
    use mio::{Events, Interest, Poll, Token};
    listener.set_nonblocking(true).unwrap();
    let _restore = scopeguard::guard(listener, |listener| {
        listener.set_nonblocking(false).unwrap()
    });
    let mut socket = mio::net::TcpListener::from_std(listener.try_clone().unwrap());
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut socket, Token(0), Interest::READABLE)
        .unwrap();
    let mut events = Events::with_capacity(8);
    loop {
        match socket.accept() {
            Ok((stream, _)) => {
                let stream = std::net::TcpStream::from(stream);
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .expect("test listener deadline expired");
                assert!(!remaining.is_zero(), "test listener deadline expired");
                poll.poll(&mut events, Some(remaining)).unwrap();
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => panic!("test listener accept failed: {error}"),
        }
    }
}
