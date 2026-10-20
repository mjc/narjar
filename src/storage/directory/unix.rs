use std::{fs::File, io, os::unix::fs::PermissionsExt, path::Path};

use rustix::fs::{self, FlockOperation, Mode, OFlags};

use super::super::StorageError;
use super::Directory;
pub(super) fn validate_data_directory(file: &File, path: &Path) -> io::Result<()> {
    match file.metadata()?.permissions().mode() & 0o022 {
        0 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("data directory has unsafe permissions: {}", path.display()),
        )),
    }
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
