use std::{
    fs::{File, TryLockError},
    io,
    path::Path,
};

use crate::cache::filesystem::{
    FilePrivacy, LeaseCreation, open_process_lease_at, validate_directory, validate_file_privacy,
};

use super::{super::StorageError, Directory};

pub(super) fn validate_data_directory(file: &File, _: &Path) -> io::Result<()> {
    validate_directory(file, "data directory").map(drop)
}

/// The no-delete handle keeps the locked file bound to this opened DATA directory.
#[derive(Debug)]
pub(in super::super) struct ProcessLock {
    file: File,
}

impl ProcessLock {
    pub(in super::super) fn acquire(
        root: &Directory,
        creation: LeaseCreation,
    ) -> Result<Self, StorageError> {
        let file = open_process_lease_at(root.file(), creation)
            .map_err(|error| io::Error::new(error.kind(), format!("lock: {error}")))?;
        validate_file_privacy(&file, FilePrivacy::Private)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(TryLockError::WouldBlock) => Err(StorageError::Locked),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_lease_contends_even_through_the_same_directory_capability() {
        let root = tempfile::tempdir().unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let first = ProcessLock::acquire(&directory, LeaseCreation::CreateIfMissing).unwrap();
        assert!(matches!(
            ProcessLock::acquire(&directory, LeaseCreation::Existing),
            Err(StorageError::Locked)
        ));
        assert!(std::fs::remove_file(root.path().join("lock")).is_err());
        drop(first);
        assert!(ProcessLock::acquire(&directory, LeaseCreation::Existing).is_ok());
    }

    #[test]
    fn a_live_lease_pins_data_and_reacquires_the_retained_directory_after_a_move() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("data");
        std::fs::create_dir(&path).unwrap();
        let original = Directory::open(&path).unwrap();
        let held = ProcessLock::acquire(&original, LeaseCreation::CreateIfMissing).unwrap();
        assert_eq!(
            std::fs::rename(&path, parent.path().join("moved"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(matches!(
            ProcessLock::acquire(&original, LeaseCreation::Existing),
            Err(StorageError::Locked)
        ));
        drop(held);
        std::fs::rename(&path, parent.path().join("moved")).unwrap();
        let held = ProcessLock::acquire(&original, LeaseCreation::CreateIfMissing).unwrap();
        std::fs::create_dir(&path).unwrap();
        let replacement = Directory::open(&path).unwrap();
        assert!(matches!(
            ProcessLock::acquire(&original, LeaseCreation::Existing),
            Err(StorageError::Locked)
        ));
        let independent =
            ProcessLock::acquire(&replacement, LeaseCreation::CreateIfMissing).unwrap();
        drop(held);
        assert!(ProcessLock::acquire(&original, LeaseCreation::Existing).is_ok());
        drop(independent);
    }

    #[test]
    fn killing_the_owner_releases_the_process_lease() {
        use std::{
            io::Read,
            net::TcpListener,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };

        struct ChildOwner(std::process::Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut child = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cache::storage::directory::platform::tests::lease_child",
                    "--nocapture",
                ])
                .env("NARJAR_WINDOWS_LEASE_ROOT", root.path())
                .env(
                    "NARJAR_WINDOWS_LEASE_READY",
                    listener.local_addr().unwrap().to_string(),
                )
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut connection = std::iter::repeat_with(|| listener.accept())
            .find_map(|result| match result {
                Ok((connection, _)) => Some(connection),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "lease child exited before acquiring"
                    );
                    assert!(
                        Instant::now() < deadline,
                        "lease child never acquired the lease"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
                Err(error) => panic!("lease child readiness: {error}"),
            })
            .unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut marker = [0];
        connection.read_exact(&mut marker).unwrap();
        assert_eq!(
            marker,
            [1],
            "the selected child actually acquired the lease"
        );
        let directory = Directory::open(root.path()).unwrap();
        assert!(matches!(
            ProcessLock::acquire(&directory, LeaseCreation::Existing),
            Err(StorageError::Locked)
        ));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(ProcessLock::acquire(&directory, LeaseCreation::Existing).is_ok());
    }

    #[test]
    fn lease_child() {
        use std::io::{Read, Write};

        let Some(root) = std::env::var_os("NARJAR_WINDOWS_LEASE_ROOT") else {
            return;
        };
        let directory = Directory::open(Path::new(&root)).unwrap();
        let _lease = ProcessLock::acquire(&directory, LeaseCreation::CreateIfMissing).unwrap();
        let mut ready =
            std::net::TcpStream::connect(std::env::var("NARJAR_WINDOWS_LEASE_READY").unwrap())
                .unwrap();
        ready.write_all(&[1]).unwrap();
        let _ = ready.read(&mut [0]);
    }
}
