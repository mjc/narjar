use std::{fs::File, io, path::Path};

use narjar::__private::filesystem::open_regular_at;
use rustix::fs::{CWD, FlockOperation, Mode, OFlags};

/// Excludes Nix GC while live store paths are checked and roots are installed.
pub(crate) struct GcReadLock {
    _file: File,
}

impl GcReadLock {
    pub(crate) fn acquire(state_dir: &Path) -> io::Result<Self> {
        let file = open_or_create_gc_lock(&state_dir.join("gc.lock"))?;
        lock_file(&file, FlockOperation::LockShared)?;
        Ok(Self { _file: file })
    }
}

fn open_or_create_gc_lock(path: &Path) -> io::Result<File> {
    match open_regular_at(CWD, path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match rustix::fs::openat(
                CWD,
                path,
                OFlags::RDONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => Ok(file.into()),
                // Nix or another pusher created the lock after our lookup.
                Err(rustix::io::Errno::EXIST) => open_regular_at(CWD, path),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn lock_file(file: &File, mode: FlockOperation) -> io::Result<()> {
    std::iter::repeat_with(|| rustix::fs::flock(file, mode))
        .find(|result| *result != Err(rustix::io::Errno::INTR))
        .expect("flock eventually returns a non-interrupted result")
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_writable_store_gets_a_gc_lock_before_rooting() {
        let directory = tempfile::tempdir().unwrap();
        let guard = GcReadLock::acquire(directory.path()).expect("create the initial Nix GC lock");
        let collector = File::open(directory.path().join("gc.lock")).unwrap();
        assert!(rustix::fs::flock(&collector, FlockOperation::NonBlockingLockExclusive).is_err());
        drop(guard);
        lock_file(&collector, FlockOperation::NonBlockingLockExclusive).unwrap();
    }

    #[test]
    fn gc_is_excluded_only_while_the_guard_is_owned() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gc.lock");
        File::create(&path).unwrap();
        let collector = File::open(path).unwrap();
        let guard = GcReadLock::acquire(directory.path()).unwrap();
        let error =
            rustix::fs::flock(&collector, FlockOperation::NonBlockingLockExclusive).unwrap_err();
        assert_eq!(io::Error::from(error).kind(), io::ErrorKind::WouldBlock);
        drop(guard);
        lock_file(&collector, FlockOperation::NonBlockingLockExclusive).unwrap();
    }
}
