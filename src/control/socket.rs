use std::{
    fs::{self, File, Metadata, Permissions},
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use narjar::__private::filesystem::{open_directory, open_directory_at};

pub(super) const CONTROL_DIRECTORY: &str = ".narjar-control";
const SOCKET_NAME: &str = "gc.sock";

pub(super) fn socket_path(root: &Path) -> PathBuf {
    root.join(CONTROL_DIRECTORY).join(SOCKET_NAME)
}

/// Owns only the inode created by this daemon. A replacement is never unlinked.
pub(super) struct BoundSocket {
    pub(super) listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    _directory: File,
}

impl BoundSocket {
    /// Call only after the daemon has acquired the storage process lease.
    pub(super) fn bind(root: &Path) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        let directory = prepare_private_directory(&root)?;
        let path = socket_path(&root);
        let endpoint = directory_socket_address(&directory, &path)?;
        remove_stale_socket(&path, &endpoint)?;
        let listener = UnixListener::bind(&endpoint)?;
        let metadata = fs::symlink_metadata(&path)?;
        let bound = Self {
            listener,
            path,
            identity: identity(&metadata),
            _directory: directory,
        };
        fs::set_permissions(&bound.path, Permissions::from_mode(0o600))?;
        bound.listener.set_nonblocking(true)?;
        Ok(bound)
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && identity(&metadata) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) fn connect(root: &Path) -> io::Result<UnixStream> {
    let directory = open_directory_at(open_directory(root)?, CONTROL_DIRECTORY)?;
    require_private_owner(&directory.metadata()?)?;
    let path = socket_path(root);
    let metadata = fs::symlink_metadata(&path)?;
    require_private_owner(&metadata)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control path is not a socket",
        ));
    }
    connect_before_deadline(
        &directory_socket_address(&directory, &path)?,
        Instant::now() + super::REQUEST_TIMEOUT,
    )
}

fn directory_socket_address(directory: &File, path: &Path) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = path;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            directory.as_raw_fd(),
            SOCKET_NAME
        )))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        rustix::net::SocketAddrUnix::new(path).map_err(|error| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "online GC socket pathname exceeds this platform's Unix socket limit: {error}"
                ),
            )
        })?;
        Ok(path.to_owned())
    }
}

enum ConnectionAttempt {
    Connected(UnixStream),
    Retry,
}

fn connect_before_deadline(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let address = rustix::net::SocketAddrUnix::new(path)?;
    std::iter::repeat_with(|| attempt_socket_connection(&address, deadline))
        .find_map(|attempt| match attempt {
            Ok(ConnectionAttempt::Connected(connection)) => Some(Ok(connection)),
            Ok(ConnectionAttempt::Retry) => None,
            Err(error) => Some(Err(error)),
        })
        .expect("connection retries terminate at their deadline")
}

fn attempt_socket_connection(
    address: &rustix::net::SocketAddrUnix,
    deadline: Instant,
) -> io::Result<ConnectionAttempt> {
    let remaining = connection_time_remaining(deadline)?;
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    let stream = UnixStream::from(socket);
    match rustix::net::connect(&stream, address) {
        Ok(()) => {
            stream.set_nonblocking(false)?;
            Ok(ConnectionAttempt::Connected(stream))
        }
        Err(rustix::io::Errno::AGAIN) => {
            // A full Unix backlog can require retrying connect rather than polling this socket.
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
            Ok(ConnectionAttempt::Retry)
        }
        Err(rustix::io::Errno::INPROGRESS) => {
            complete_pending_connection(stream, deadline).map(ConnectionAttempt::Connected)
        }
        Err(error) => Err(error.into()),
    }
}

fn complete_pending_connection(stream: UnixStream, deadline: Instant) -> io::Result<UnixStream> {
    let timeout = rustix::event::Timespec::try_from(connection_time_remaining(deadline)?)
        .map_err(io::Error::other)?;
    let mut descriptor = [rustix::event::PollFd::new(
        &stream,
        rustix::event::PollFlags::OUT,
    )];
    if rustix::event::poll(&mut descriptor, Some(&timeout))? == 0 {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn connection_time_remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn prepare_private_directory(root: &Path) -> io::Result<File> {
    let parent = open_directory(root)?;
    match rustix::fs::mkdirat(
        &parent,
        CONTROL_DIRECTORY,
        rustix::fs::Mode::from_raw_mode(0o700),
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let directory = open_directory_at(&parent, CONTROL_DIRECTORY)?;
    require_private_owner(&directory.metadata()?)?;
    Ok(directory)
}

fn require_private_owner(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control path must be private and owned by the invoking user",
        ));
    }
    Ok(())
}

fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn remove_stale_socket(path: &Path, endpoint: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "refusing to remove a non-socket control path",
        ));
    }
    require_private_owner(&metadata)?;
    match connect_before_deadline(endpoint, Instant::now() + super::REQUEST_TIMEOUT) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "control socket is already listening",
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn a_full_listening_backlog_cannot_make_connect_or_stale_detection_wait_forever() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        rustix::net::listen(&bound.listener, 0).unwrap();
        let queued = connect(root.path()).unwrap();
        let endpoint = directory_socket_address(&bound._directory, &bound.path).unwrap();
        let address = rustix::net::SocketAddrUnix::new(&endpoint).unwrap();
        assert!(
            matches!(
                attempt_socket_connection(&address, Instant::now() + Duration::from_secs(1))
                    .unwrap(),
                ConnectionAttempt::Retry
            ),
            "the fixture must actually saturate the backlog before testing its deadline"
        );
        let error = connect_before_deadline(&endpoint, Instant::now() + Duration::from_millis(25))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            bound.path.exists(),
            "a listening socket must never be removed as stale"
        );
        drop(queued);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn descriptor_relative_control_sockets_support_long_data_directory_paths() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("long-cache-root-".repeat(12));
        fs::create_dir(&data).unwrap();
        let bound = BoundSocket::bind(&data).unwrap();
        let connection = connect(&data).unwrap();
        assert!(bound.listener.accept().is_ok());
        drop(connection);
        drop(bound);
        assert!(!socket_path(&data).exists());
    }

    #[test]
    fn only_owned_stale_sockets_are_removed_and_the_live_socket_is_private() {
        let root = tempfile::tempdir().unwrap();
        prepare_private_directory(root.path()).unwrap();
        let path = socket_path(root.path());
        let stale = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        drop(stale);
        let bound = BoundSocket::bind(root.path()).unwrap();
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(BoundSocket::bind(root.path()).is_err());
        assert!(connect(root.path()).is_ok());
        drop(bound);
        assert!(!path.exists());
    }

    #[test]
    fn binding_refuses_unrelated_files_symlinks_and_public_control_directories() {
        let root = tempfile::tempdir().unwrap();
        let directory = prepare_private_directory(root.path()).unwrap();
        let path = socket_path(root.path());
        fs::write(&path, b"not a socket").unwrap();
        assert!(BoundSocket::bind(root.path()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not a socket");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(root.path(), &path).unwrap();
        assert!(BoundSocket::bind(root.path()).is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&path).unwrap();
        directory
            .set_permissions(Permissions::from_mode(0o755))
            .unwrap();
        assert!(BoundSocket::bind(root.path()).is_err());
    }

    #[test]
    fn socket_cleanup_does_not_remove_a_replacement_inode() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        let path = socket_path(root.path());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        drop(bound);
        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }
}
