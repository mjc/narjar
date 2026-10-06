use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
    process,
    sync::{Arc, Mutex},
};

use super::{
    gc::{GcReadLock, lock_file},
    lease::NativeStorePath,
};
use narjar::__private::filesystem::{ensure_directory_at, open_directory};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};

static ROOT_FILES: Mutex<Vec<ProcessFile>> = Mutex::new(Vec::new());

struct ProcessFile {
    directory: (u64, u64),
    file: Arc<Mutex<RootFile>>,
}

struct RootFile {
    file: File,
    // Pin the directory inode used as the registry identity until final close.
    _directory: File,
    complete_bytes: u64,
}

enum ProcessFileLocation {
    Named,
    Detached,
}

/// Nix's `temproots/<pid>` protocol: an exclusive flock protects NUL-separated
/// absolute store paths. GC ignores and unlinks files it can exclusively lock.
/// See Nix 2.34.8 `src/libstore/gc.cc`: createTempRootsFile/addTempRoot/findTempRoots.
/// Registration holds the global GC lock, so no GC socket handshake is needed.
/// Guards in the same state directory share the file; records remain until the
/// last guard releases it. Process death releases it without running Drop.
pub(crate) struct TemporaryRoots {
    // Taken during Drop so the last FD closes under the registry mutex, before
    // another guard can open the same PID file. No live PID file is unlinked.
    file: Option<Arc<Mutex<RootFile>>>,
}

impl TemporaryRoots {
    pub(crate) fn hold(
        state_dir: &Path,
        targets: &[NativeStorePath],
        _gc_lock: &GcReadLock,
    ) -> io::Result<Self> {
        let roots = Self::acquire_process_file(state_dir)?;
        roots
            .file
            .as_ref()
            .expect("owned until drop")
            .lock()
            .map_err(|_| io::Error::other("temporary roots file poisoned"))?
            .append(targets)?;
        Ok(roots)
    }

    fn acquire_process_file(state_dir: &Path) -> io::Result<Self> {
        let state = open_directory(state_dir)?;
        let directory = ensure_directory_at(
            &state,
            OsStr::new("temproots"),
            "Nix temporary roots directory",
        )?;
        let metadata = directory.metadata()?;
        let identity = (metadata.dev(), metadata.ino());
        let mut active = ROOT_FILES
            .lock()
            .map_err(|_| io::Error::other("temporary roots registry poisoned"))?;
        let file = match active.iter().find(|entry| entry.directory == identity) {
            Some(entry) => Arc::clone(&entry.file),
            None => {
                let file = Arc::new(Mutex::new(RootFile {
                    file: open_process_file(&directory)?,
                    _directory: directory,
                    complete_bytes: 0,
                }));
                active.push(ProcessFile {
                    directory: identity,
                    file: Arc::clone(&file),
                });
                file
            }
        };
        Ok(Self { file: Some(file) })
    }
}

impl Drop for TemporaryRoots {
    fn drop(&mut self) {
        let mut active = ROOT_FILES.lock().unwrap_or_else(|error| error.into_inner());
        let file = self.file.take().expect("owned until drop");
        // The registry plus this guard are the only owners at final release.
        if Arc::strong_count(&file) == 2 {
            active.retain(|entry| !Arc::ptr_eq(&entry.file, &file));
        }
        drop(file);
    }
}

impl RootFile {
    fn append(&mut self, targets: &[NativeStorePath]) -> io::Result<()> {
        // A failed append can leave an unterminated record, which Nix ignores.
        // Remove that tail before another guard appends to the shared file.
        self.file.set_len(self.complete_bytes)?;
        for target in targets {
            self.file
                .write_all(target.as_path().as_os_str().as_bytes())?;
            self.file.write_all(&[0])?;
            self.complete_bytes = self.file.metadata()?.len();
        }
        Ok(())
    }
}

fn open_process_file(directory: &File) -> io::Result<File> {
    let name = process::id().to_string();
    for _ in 0..128 {
        let file: File = rustix::fs::openat(
            directory,
            name.as_str(),
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::APPEND
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )?
        .into();
        match lock_named_file(&file, directory, &name)? {
            ProcessFileLocation::Named => {
                // No live guard owns this inode. Discard old roots or a tombstone
                // under the global GC lock, without unlinking any other open FD.
                file.set_len(0)?;
                return Ok(file);
            }
            ProcessFileLocation::Detached => {}
        }
    }
    Err(io::Error::other("temporary roots file kept being replaced"))
}

fn lock_named_file(file: &File, directory: &File, name: &str) -> io::Result<ProcessFileLocation> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary roots file is not regular",
        ));
    }
    lock_file(file, FlockOperation::NonBlockingLockExclusive)?;
    let metadata = file.metadata()?;
    // If GC unlinked and tombstoned a candidate before its lock was acquired,
    // it is no longer discoverable. Reopen instead of registering in that FD.
    // Production holds gc.lock before opening, excluding this race outright.
    if metadata.nlink() == 0 {
        return Ok(ProcessFileLocation::Detached);
    }
    if metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary roots file has unsafe ownership or links",
        ));
    }
    let named = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(ProcessFileLocation::Detached),
        Err(error) => return Err(error.into()),
    };
    Ok(
        if named.st_dev as u64 == metadata.dev() && named.st_ino as u64 == metadata.ino() {
            ProcessFileLocation::Named
        } else {
            ProcessFileLocation::Detached
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn a_collector_unlink_and_tombstone_cannot_leave_registration_in_a_detached_fd() {
        let state = tempfile::tempdir().unwrap();
        fs::create_dir(state.path().join("temproots")).unwrap();
        let directory = open_directory(&state.path().join("temproots")).unwrap();
        let name = process::id().to_string();
        let path = state.path().join("temproots").join(&name);
        let candidate = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut collector = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lock_file(&collector, FlockOperation::NonBlockingLockExclusive).unwrap();
        fs::remove_file(&path).unwrap();
        collector.write_all(b"d").unwrap();
        drop(collector);
        let _gc_lock = GcReadLock::acquire(state.path()).unwrap();
        assert!(matches!(
            lock_named_file(&candidate, &directory, &name).unwrap(),
            ProcessFileLocation::Detached
        ));
        assert_eq!(candidate.metadata().unwrap().nlink(), 0);
        let registered = open_process_file(&directory).unwrap();
        assert_ne!(
            registered.metadata().unwrap().ino(),
            candidate.metadata().unwrap().ino()
        );
        assert_eq!(registered.metadata().unwrap().nlink(), 1);
        assert_eq!(registered.metadata().unwrap().len(), 0);
    }

    #[test]
    fn stale_pid_records_and_tombstones_are_not_inherited_by_a_new_guard() {
        for stale in [
            b"/nix/store/00000000000000000000000000000000-stale\0".as_slice(),
            b"d",
        ] {
            let state = tempfile::tempdir().unwrap();
            fs::create_dir(state.path().join("temproots")).unwrap();
            let path = state
                .path()
                .join("temproots")
                .join(process::id().to_string());
            fs::write(&path, stale).unwrap();
            let _gc_lock = GcReadLock::acquire(state.path()).unwrap();
            let directory = open_directory(&state.path().join("temproots")).unwrap();
            let file = open_process_file(&directory).unwrap();
            assert!(fs::read(&path).unwrap().is_empty());
            let collector = File::open(&path).unwrap();
            assert_eq!(
                lock_file(&collector, FlockOperation::NonBlockingLockExclusive)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            drop(file);
            lock_file(&collector, FlockOperation::NonBlockingLockExclusive).unwrap();
        }
    }

    #[test]
    fn unsafe_pid_files_fail_closed_without_truncating_external_data() {
        for kind in ["symlink", "hardlink", "directory", "writable"] {
            let state = tempfile::tempdir().unwrap();
            fs::create_dir(state.path().join("temproots")).unwrap();
            let path = state
                .path()
                .join("temproots")
                .join(process::id().to_string());
            let external = state.path().join("external");
            fs::write(&external, b"must survive").unwrap();
            match kind {
                "symlink" => std::os::unix::fs::symlink(&external, &path).unwrap(),
                "hardlink" => fs::hard_link(&external, &path).unwrap(),
                "directory" => fs::create_dir(&path).unwrap(),
                "writable" => {
                    fs::write(&path, b"must survive").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
                }
                _ => unreachable!(),
            }
            let _gc_lock = GcReadLock::acquire(state.path()).unwrap();
            let directory = open_directory(&state.path().join("temproots")).unwrap();
            let error = open_process_file(&directory).unwrap_err();
            assert!(
                !matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
                ),
                "unsafe {kind} must not silently use daemon fallback: {error}"
            );
            assert_eq!(fs::read(&external).unwrap(), b"must survive");
            if kind == "writable" {
                assert_eq!(fs::read(&path).unwrap(), b"must survive");
            }
        }
    }

    #[test]
    fn partial_record_tail_is_removed_before_the_next_registration() {
        let state = tempfile::tempdir().unwrap();
        let targets = ["first", "second"].map(|name| {
            let path = state
                .path()
                .join(format!("00000000000000000000000000000000-{name}"));
            fs::write(&path, b"live").unwrap();
            NativeStorePath::validate(state.path(), &path).unwrap()
        });
        let gc_lock = GcReadLock::acquire(state.path()).unwrap();
        let first = TemporaryRoots::hold(state.path(), &targets[..1], &gc_lock).unwrap();
        {
            let mut root_file = first.file.as_ref().unwrap().lock().unwrap();
            root_file
                .file
                .write_all(b"/nix/store/incomplete-record")
                .unwrap();
        }
        let second = TemporaryRoots::hold(state.path(), &targets[1..], &gc_lock).unwrap();
        let expected = targets
            .iter()
            .flat_map(|path| {
                path.as_path()
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain([0])
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fs::read(
                state
                    .path()
                    .join("temproots")
                    .join(process::id().to_string())
            )
            .unwrap(),
            expected
        );
        drop(first);
        drop(second);
    }
}
