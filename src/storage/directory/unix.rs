use std::{fs::File, io, os::unix::fs::PermissionsExt, path::Path};

use rustix::fs::{self, FlockOperation, Mode, OFlags};

use super::super::StorageError;
use super::Directory;
use crate::cache::filesystem::open_directory;

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = open_directory(path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidData => {
                invalid_data_directory_error(path)
            }
            _ if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
                invalid_data_directory_error(path)
            }
            _ => error,
        })?;
        if file.metadata()?.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("data directory has unsafe permissions: {}", path.display()),
            ));
        }
        Ok(Self {
            file,
            #[cfg(test)]
            path: path.to_owned(),
        })
    }
}

fn invalid_data_directory_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("data directory is not a directory: {}", path.display()),
    )
}

/// Leases the opened DATA directory, independently of `DATA/lock` and other handles.
/// Uses local-filesystem directory flocks; distributed filesystems are not covered.
#[derive(Debug)]
pub(in super::super) struct ProcessLock {
    file: File,
}

impl ProcessLock {
    pub(in super::super) fn acquire(root: &Directory) -> Result<Self, StorageError> {
        // Reopen rather than clone: other directory handles must not extend the lease.
        let file: File = fs::openat(
            root.file(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?
        .into();
        match fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { file }),
            Err(rustix::io::Errno::AGAIN) => Err(StorageError::Locked),
            Err(error) => Err(io::Error::from(error).into()),
        }
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        // Unlock before closing, independently of unrelated directory descriptors.
        let _ = fs::flock(&self.file, FlockOperation::Unlock);
    }
}
