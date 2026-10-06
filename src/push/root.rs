use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use super::PushError;
use super::nar_stream::local_store_path;
use crate::native_store::{daemon_roots::DaemonRoots, gc::GcReadLock, lease::NativeStorePath};
use narjar::__private::filesystem::{ensure_directory_at, open_directory};
use rustix::fs::{AtFlags, symlinkat, unlinkat};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// Keeps the requested local store paths reachable while a push is in flight.
///
/// Nix treats symlinks below `gcroots/auto` as roots. The root is deliberately
/// owned by this value so it covers metadata lookup, every upload worker, and
/// all retry attempts. A failed cleanup leaves a harmless stale root for Nix's
/// normal root cleanup to remove later.
pub(super) enum StoreRoots {
    Local { _roots: LocalRoots },
    Daemon { _connection: DaemonRoots },
}

pub(super) struct LocalRoots {
    directory: File,
    entries: Vec<OsString>,
}

impl StoreRoots {
    pub(super) fn hold_while_reading_metadata<T>(
        store_paths: &[String],
        read_metadata: impl FnOnce(&Path) -> Result<T, PushError>,
    ) -> Result<(Self, T), PushError> {
        let state_dir = std::env::var_os("NIX_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nix/var/nix"));
        Self::hold_after_acquiring_gc_lock(
            &state_dir,
            store_paths,
            GcReadLock::acquire(&state_dir),
            read_metadata,
        )
    }

    fn hold_after_acquiring_gc_lock<T>(
        state_dir: &Path,
        store_paths: &[String],
        gc_lock: std::io::Result<GcReadLock>,
        read_metadata: impl FnOnce(&Path) -> Result<T, PushError>,
    ) -> Result<(Self, T), PushError> {
        match gc_lock {
            Ok(gc_lock) => {
                let targets = store_paths
                    .iter()
                    .map(|path| local_store_path(path))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::hold_and_read_metadata(
                    state_dir,
                    store_paths,
                    gc_lock,
                    Self::hold_in(state_dir, targets),
                    read_metadata,
                )
            }
            Err(error) => {
                let roots =
                    Self::hold_local_roots_or_use_daemon(state_dir, store_paths, Err(error))?;
                let metadata = read_metadata(state_dir)?;
                Ok((roots, metadata))
            }
        }
    }

    fn hold_local_roots_or_use_daemon(
        state_dir: &Path,
        store_paths: &[String],
        local_roots: io::Result<Self>,
    ) -> Result<Self, PushError> {
        match local_roots {
            Ok(roots) => Ok(roots),
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.kind() == std::io::ErrorKind::ReadOnlyFilesystem =>
            {
                let connection = DaemonRoots::hold(state_dir, store_paths).map_err(|error| {
                    PushError::new(format!(
                        "protecting store paths through the Nix daemon: {error}"
                    ))
                })?;
                Ok(Self::Daemon {
                    _connection: connection,
                })
            }
            Err(error) => Err(PushError::new(format!(
                "protecting store paths from Nix GC: {error}"
            ))),
        }
    }

    fn hold_and_read_metadata<T>(
        state_dir: &Path,
        store_paths: &[String],
        _gc_lock: GcReadLock,
        local_roots: io::Result<Self>,
        read_metadata: impl FnOnce(&Path) -> Result<T, PushError>,
    ) -> Result<(Self, T), PushError> {
        let roots = Self::hold_local_roots_or_use_daemon(state_dir, store_paths, local_roots)?;
        let metadata = read_metadata(state_dir)?;
        Ok((roots, metadata))
    }

    fn hold_in(state_dir: &Path, targets: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        let mut roots = LocalRoots {
            directory: open_automatic_root_directory(state_dir)?,
            entries: Vec::new(),
        };
        targets.into_iter().try_for_each(|target| {
            let store_dir = target.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "store path has no parent")
            })?;
            let target = NativeStorePath::validate(store_dir, &target)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let entry = allocate_root_entry(&roots.directory, target.as_path())?;
            roots.entries.push(entry);
            Ok::<(), io::Error>(())
        })?;
        Ok(Self::Local { _roots: roots })
    }
}

impl Drop for LocalRoots {
    fn drop(&mut self) {
        self.entries.iter().for_each(|entry| {
            let _ = unlinkat(&self.directory, entry, AtFlags::empty());
        });
    }
}

fn open_automatic_root_directory(state_dir: &Path) -> io::Result<File> {
    let state = open_directory(state_dir)?;
    let roots = ensure_directory_at(&state, OsStr::new("gcroots"), "Nix GC roots directory")?;
    ensure_directory_at(&roots, OsStr::new("auto"), "Nix automatic roots directory")
}

fn allocate_root_entry(automatic_roots: &File, target: &Path) -> io::Result<OsString> {
    (0..128)
        .find_map(|_| {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let entry = OsString::from(format!("narjar-push-{}-{sequence:016x}", process::id()));
            match symlinkat(target, automatic_roots, &entry) {
                Ok(()) => Some(Ok(entry)),
                Err(rustix::io::Errno::EXIST) => None,
                Err(error) => Some(Err(error.into())),
            }
        })
        .unwrap_or_else(|| Err(io::Error::other("could not allocate a unique Nix GC root")))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::StoreRoots;

    #[test]
    fn read_only_root_installation_uses_daemon_roots_under_the_acquired_gc_lock() {
        use std::{
            io::{self, Read, Write},
            os::unix::net::UnixListener,
            time::Duration,
        };

        let directory = tempdir().unwrap();
        let state_dir = directory.path();
        fs::create_dir(state_dir.join("daemon-socket")).unwrap();
        let listener = UnixListener::bind(state_dir.join("daemon-socket/socket")).unwrap();
        let path = "/nix/store/00000000000000000000000000000000-live";
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let read_number = |stream: &mut std::os::unix::net::UnixStream| {
                let mut bytes = [0; 8];
                stream.read_exact(&mut bytes).unwrap();
                u64::from_le_bytes(bytes)
            };
            assert_eq!(read_number(&mut stream), 0x6e69_7863);
            assert_eq!(read_number(&mut stream), 0x0112);
            stream.write_all(&0x6478_696fu64.to_le_bytes()).unwrap();
            stream.write_all(&0x0126u64.to_le_bytes()).unwrap();
            assert_eq!(read_number(&mut stream), 0);
            assert_eq!(read_number(&mut stream), 0);
            stream.write_all(&0x616c_7473u64.to_le_bytes()).unwrap();
            assert_eq!(read_number(&mut stream), 11);
            let length = read_number(&mut stream) as usize;
            assert_eq!(length, path.len());
            let mut registered = vec![0; length.next_multiple_of(8)];
            stream.read_exact(&mut registered).unwrap();
            assert_eq!(&registered[..length], path.as_bytes());
            stream.write_all(&0x616c_7473u64.to_le_bytes()).unwrap();
            stream.write_all(&1u64.to_le_bytes()).unwrap();
            assert_eq!(
                stream.read(&mut [0]).unwrap(),
                0,
                "root connection closes on drop"
            );
        });
        let gc_lock = crate::native_store::gc::GcReadLock::acquire(state_dir).unwrap();
        let collector = fs::File::open(state_dir.join("gc.lock")).unwrap();
        let (roots, ()) = StoreRoots::hold_and_read_metadata(
            state_dir,
            &[path.to_owned()],
            gc_lock,
            Err(io::Error::from(io::ErrorKind::ReadOnlyFilesystem)),
            |_| {
                let error = rustix::fs::flock(
                    &collector,
                    rustix::fs::FlockOperation::NonBlockingLockExclusive,
                )
                .unwrap_err();
                assert_eq!(io::Error::from(error).kind(), io::ErrorKind::WouldBlock);
                Ok(())
            },
        )
        .expect(
            "daemon protects the path before metadata lookup despite EROFS installing local roots",
        );
        assert!(matches!(roots, StoreRoots::Daemon { .. }));
        rustix::fs::flock(
            &collector,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        drop(roots);
        worker.join().unwrap();
    }

    #[test]
    fn inaccessible_local_gc_locks_use_the_daemon_but_other_failures_do_not() {
        use std::io::{self, ErrorKind};

        let directory = tempdir().unwrap();
        for kind in [ErrorKind::PermissionDenied, ErrorKind::ReadOnlyFilesystem] {
            let result = StoreRoots::hold_after_acquiring_gc_lock::<()>(
                directory.path(),
                &[],
                Err(io::Error::from(kind)),
                |_| panic!("metadata must wait for successful root protection"),
            );
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("fixture has no daemon socket"),
            };
            assert!(
                error.to_string().contains("through the Nix daemon"),
                "{error}"
            );
        }
        let result = StoreRoots::hold_after_acquiring_gc_lock::<()>(
            directory.path(),
            &[],
            Err(io::Error::from(ErrorKind::InvalidData)),
            |_| panic!("invalid lock must fail before metadata lookup"),
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid lock must fail closed"),
        };
        assert!(error.to_string().contains("from Nix GC"), "{error}");
    }

    #[test]
    fn a_fresh_writable_store_gets_automatic_root_directories() {
        let directory = tempdir().unwrap();
        let target = directory
            .path()
            .join("00000000000000000000000000000000-live");
        fs::write(&target, b"live").unwrap();
        let roots_directory = directory.path().join("gcroots/auto");
        let roots = StoreRoots::hold_in(directory.path(), [target])
            .expect("create missing root directories");
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 1);
        drop(roots);
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 0);
    }

    #[test]
    fn automatic_roots_cannot_escape_through_symlinked_directory_components() {
        for component in ["gcroots", "gcroots/auto"] {
            let directory = tempdir().unwrap();
            let outside = tempdir().unwrap();
            let target = directory
                .path()
                .join("00000000000000000000000000000000-live");
            fs::write(&target, b"live").unwrap();
            if component == "gcroots" {
                fs::create_dir(outside.path().join("auto")).unwrap();
            } else {
                fs::create_dir(directory.path().join("gcroots")).unwrap();
            }
            std::os::unix::fs::symlink(outside.path(), directory.path().join(component)).unwrap();
            assert!(
                StoreRoots::hold_in(directory.path(), [target]).is_err(),
                "{component} must be opened without following symlinks"
            );
        }
    }

    #[test]
    fn cleanup_uses_the_opened_root_directory_not_a_replacement_path() {
        let directory = tempdir().unwrap();
        let roots_directory = directory.path().join("gcroots/auto");
        fs::create_dir_all(&roots_directory).unwrap();
        let target = directory
            .path()
            .join("00000000000000000000000000000000-live");
        fs::write(&target, b"live").unwrap();
        let roots = StoreRoots::hold_in(directory.path(), [target]).unwrap();
        let entry = fs::read_dir(&roots_directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name();
        let renamed = directory.path().join("original-auto");
        fs::rename(&roots_directory, &renamed).unwrap();
        fs::create_dir(&roots_directory).unwrap();
        fs::write(roots_directory.join(&entry), b"replacement must survive").unwrap();
        drop(roots);
        assert_eq!(fs::read_dir(&renamed).unwrap().count(), 0);
        assert_eq!(
            fs::read(roots_directory.join(entry)).unwrap(),
            b"replacement must survive"
        );
    }

    #[test]
    fn roots_exist_before_metadata_lookup_and_gc_cannot_cross_that_boundary() {
        let directory = tempdir().unwrap();
        let state_dir = directory.path();
        let roots_directory = state_dir.join("gcroots/auto");
        fs::create_dir_all(&roots_directory).unwrap();
        fs::File::create(state_dir.join("gc.lock")).unwrap();
        let path = state_dir.join("00000000000000000000000000000000-test");
        fs::write(&path, b"root target").unwrap();
        let collector = fs::File::open(state_dir.join("gc.lock")).unwrap();
        let gc_lock = crate::native_store::gc::GcReadLock::acquire(state_dir).unwrap();
        let (roots, ()) = StoreRoots::hold_and_read_metadata(
            state_dir,
            &[],
            gc_lock,
            StoreRoots::hold_in(state_dir, [path.clone()]),
            |_| {
                assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 1);
                let error = rustix::fs::flock(
                    &collector,
                    rustix::fs::FlockOperation::NonBlockingLockExclusive,
                )
                .unwrap_err();
                assert_eq!(
                    std::io::Error::from(error).kind(),
                    std::io::ErrorKind::WouldBlock
                );
                Ok(())
            },
        )
        .unwrap();
        // Uploads retain roots, but do not keep the global GC lock held.
        rustix::fs::flock(
            &collector,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 1);
        drop(roots);
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 0);
    }

    #[test]
    fn a_missing_target_cannot_become_a_successful_gc_root() {
        let directory = tempdir().unwrap();
        let roots_directory = directory.path().join("gcroots/auto");
        fs::create_dir_all(&roots_directory).unwrap();
        let missing = directory
            .path()
            .join("00000000000000000000000000000000-missing");
        assert!(StoreRoots::hold_in(directory.path(), [missing]).is_err());
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 0);
    }

    #[test]
    fn a_late_missing_target_releases_roots_already_installed() {
        let directory = tempdir().unwrap();
        let roots_directory = directory.path().join("gcroots/auto");
        fs::create_dir_all(&roots_directory).unwrap();
        let live = directory
            .path()
            .join("00000000000000000000000000000000-live");
        let missing = directory
            .path()
            .join("00000000000000000000000000000000-missing");
        fs::write(&live, b"root target").unwrap();
        assert!(StoreRoots::hold_in(directory.path(), [live, missing]).is_err());
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 0);
    }

    #[test]
    fn failed_metadata_lookup_releases_roots_and_the_gc_lock() {
        let directory = tempdir().unwrap();
        let roots_directory = directory.path().join("gcroots/auto");
        fs::create_dir_all(&roots_directory).unwrap();
        fs::File::create(directory.path().join("gc.lock")).unwrap();
        let live = directory
            .path()
            .join("00000000000000000000000000000000-live");
        fs::write(&live, b"root target").unwrap();
        let gc_lock = crate::native_store::gc::GcReadLock::acquire(directory.path()).unwrap();
        let result = StoreRoots::hold_and_read_metadata(
            directory.path(),
            &[],
            gc_lock,
            StoreRoots::hold_in(directory.path(), [live]),
            |_| Err::<(), _>(super::PushError::new("metadata lookup failed")),
        );
        assert!(result.is_err());
        assert_eq!(fs::read_dir(&roots_directory).unwrap().count(), 0);
        let collector = fs::File::open(directory.path().join("gc.lock")).unwrap();
        rustix::fs::flock(
            &collector,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
    }

    #[test]
    fn roots_hold_targets_until_the_push_finishes() {
        let root_directory = tempdir().expect("create root directory");
        let automatic_roots = root_directory.path().join("gcroots/auto");
        fs::create_dir_all(&automatic_roots).expect("create automatic roots directory");
        let store_path = root_directory
            .path()
            .join("00000000000000000000000000000000-store-path");
        fs::write(&store_path, b"store object").expect("create store object");

        let roots = StoreRoots::hold_in(root_directory.path(), [store_path.clone()]);
        let roots = roots.expect("create automatic root");
        let entries = fs::read_dir(&automatic_roots)
            .expect("read automatic roots")
            .collect::<Result<Vec<_>, _>>()
            .expect("read automatic root entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            fs::read_link(entries[0].path()).expect("read automatic root"),
            store_path
        );

        drop(roots);
        assert_eq!(fs::read_dir(&automatic_roots).unwrap().count(), 0);
    }
}
