use std::{
    io,
    path::{Path, PathBuf},
};

use super::PushError;
use super::nar_stream::local_store_path;
use crate::native_store::{
    daemon_roots::DaemonRoots, gc::GcReadLock, lease::NativeStorePath, temp_roots::TemporaryRoots,
};

/// Keeps the requested local store paths reachable while a push is in flight.
///
/// Local guards share Nix's exclusively locked `temproots/<pid>` file. Its
/// NUL-separated roots cover metadata lookup, upload workers, and retries until
/// the last guard closes the FD. GC ignores and reclaims unlocked files, even
/// after SIGKILL. No persistent `gcroots/auto` link is installed.
pub(super) enum StoreRoots {
    Local { _roots: TemporaryRoots },
    Daemon { _connection: DaemonRoots },
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
                let roots = Self::hold_locked(state_dir, targets, &gc_lock);
                Self::hold_and_read_metadata(state_dir, store_paths, gc_lock, roots, read_metadata)
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

    #[cfg(test)]
    fn hold_in(state_dir: &Path, targets: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        let gc_lock = GcReadLock::acquire(state_dir)?;
        Self::hold_locked(state_dir, targets, &gc_lock)
    }

    fn hold_locked(
        state_dir: &Path,
        targets: impl IntoIterator<Item = PathBuf>,
        gc_lock: &GcReadLock,
    ) -> io::Result<Self> {
        let targets = validate_roots(targets)?;
        let roots = TemporaryRoots::hold(state_dir, &targets, gc_lock)?;
        Ok(Self::Local { _roots: roots })
    }
}

fn validate_roots(targets: impl IntoIterator<Item = PathBuf>) -> io::Result<Vec<NativeStorePath>> {
    targets
        .into_iter()
        .map(|target| {
            if !target.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "root is not absolute",
                ));
            }
            let store_dir = target.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "store path has no parent")
            })?;
            NativeStorePath::validate(store_dir, &target)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::StoreRoots;

    fn temporary_file(state_dir: &std::path::Path) -> std::path::PathBuf {
        state_dir
            .join("temproots")
            .join(std::process::id().to_string())
    }

    // Model findTempRoots, not deletion of any store object. An unlocked file
    // contributes no roots; Nix unlinks it and tombstones its still-open FD.
    fn collect_temporary_roots(state_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        use crate::native_store::gc::lock_file;
        use rustix::fs::FlockOperation;
        use std::io::{Read, Write};

        let gc = fs::File::open(state_dir.join("gc.lock")).unwrap();
        lock_file(&gc, FlockOperation::NonBlockingLockExclusive).unwrap();
        let entries = match fs::read_dir(state_dir.join("temproots")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("reading temporary roots: {error}"),
        };
        let mut roots = Vec::new();
        for entry in entries {
            let entry = entry.unwrap();
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(entry.path())
                .unwrap();
            match lock_file(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    fs::remove_file(entry.path()).unwrap();
                    file.write_all(b"d").unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut contents = Vec::new();
                    file.read_to_end(&mut contents).unwrap();
                    let mut records = contents.split(|byte| *byte == 0).collect::<Vec<_>>();
                    records.pop(); // Nix ignores any unterminated final record.
                    roots.extend(records.into_iter().map(|record| {
                        std::path::PathBuf::from(std::str::from_utf8(record).unwrap())
                    }));
                }
                Err(error) => panic!("collecting temporary roots: {error}"),
            }
        }
        roots
    }

    #[test]
    fn forced_exit_releases_local_roots() {
        use std::{
            io::Read,
            os::unix::net::UnixListener,
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };

        struct RootChild(Child);
        impl Drop for RootChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let directory = tempdir().unwrap();
        let state_dir = directory.path();
        let listener = UnixListener::bind(state_dir.join("ready.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut child = RootChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "push::root::tests::temporary_roots_child",
                    "--nocapture",
                ])
                .env("NARJAR_TEMP_ROOT_CHILD_STATE", state_dir)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut connection = loop {
            match listener.accept() {
                Ok((connection, _)) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(child.0.try_wait().unwrap().is_none(), "root child exited");
                    assert!(Instant::now() < deadline, "root child never registered");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("waiting for root child: {error}"),
            }
        };
        connection
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut ready = [0];
        connection.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [1], "child has installed roots before it is killed");
        let temporary = state_dir.join("temproots").join(child.0.id().to_string());
        let collector = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temporary)
            .expect("native temporary-root file is registered before termination");
        assert_eq!(
            crate::native_store::gc::lock_file(
                &collector,
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::WouldBlock,
        );
        let gc = fs::File::open(state_dir.join("gc.lock")).unwrap();
        crate::native_store::gc::lock_file(
            &gc,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .expect("the upload does not retain the global GC lock");
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());

        assert_eq!(
            fs::read_dir(state_dir.join("gcroots/auto"))
                .map(|entries| entries.count())
                .unwrap_or(0),
            0,
            "forced exit must not leave persistent direct GC roots"
        );
        crate::native_store::gc::lock_file(
            &collector,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .expect("the kernel releases the child's temporary-root lock after SIGKILL");
        // Nix ignores roots in an unlocked file, unlinks it, then writes a tombstone.
        fs::remove_file(temporary).unwrap();
        std::io::Write::write_all(&mut &collector, b"d").unwrap();
    }

    #[test]
    fn temporary_roots_child() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixStream,
        };

        let Some(state_dir) = std::env::var_os("NARJAR_TEMP_ROOT_CHILD_STATE") else {
            return; // Only the forced-exit test activates this subprocess probe.
        };
        let state_dir = std::path::PathBuf::from(state_dir);
        let target = state_dir.join("00000000000000000000000000000000-live");
        fs::write(&target, b"live").unwrap();
        let _roots = StoreRoots::hold_in(&state_dir, [target]).unwrap();
        let mut ready = UnixStream::connect(state_dir.join("ready.sock")).unwrap();
        ready.write_all(&[1]).unwrap();
        ready.read_exact(&mut [0]).unwrap();
    }

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
    fn a_fresh_writable_store_gets_a_native_temporary_root_file() {
        let directory = tempdir().unwrap();
        let target = directory
            .path()
            .join("00000000000000000000000000000000-live");
        fs::write(&target, b"live").unwrap();
        let roots = StoreRoots::hold_in(directory.path(), [target.clone()])
            .expect("create missing temporary roots directory");
        assert_eq!(collect_temporary_roots(directory.path()), [target]);
        assert!(!directory.path().join("gcroots").exists());
        drop(roots);
        assert!(collect_temporary_roots(directory.path()).is_empty());
        assert!(!temporary_file(directory.path()).exists());
    }

    #[test]
    fn temporary_roots_cannot_escape_through_symlinked_directory_components() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = directory
            .path()
            .join("00000000000000000000000000000000-live");
        fs::write(&target, b"live").unwrap();
        std::os::unix::fs::symlink(outside.path(), directory.path().join("temproots")).unwrap();
        assert!(
            StoreRoots::hold_in(directory.path(), [target]).is_err(),
            "temproots must be opened without following symlinks"
        );
    }

    #[test]
    fn release_closes_the_opened_file_without_mutating_a_replacement_path() {
        let directory = tempdir().unwrap();
        let roots_directory = directory.path().join("temproots");
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
        let renamed = directory.path().join("original-temproots");
        fs::rename(&roots_directory, &renamed).unwrap();
        fs::create_dir(&roots_directory).unwrap();
        fs::write(roots_directory.join(&entry), b"replacement must survive").unwrap();
        drop(roots);
        let original = fs::File::open(renamed.join(&entry)).unwrap();
        crate::native_store::gc::lock_file(
            &original,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .expect("release unlocks the original inode");
        assert_eq!(
            fs::read(roots_directory.join(entry)).unwrap(),
            b"replacement must survive"
        );
    }

    #[test]
    fn roots_exist_before_metadata_lookup_and_gc_cannot_cross_that_boundary() {
        let directory = tempdir().unwrap();
        let state_dir = directory.path();
        let roots_directory = state_dir.join("temproots");
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
                assert_eq!(
                    fs::read(temporary_file(state_dir)).unwrap(),
                    format!("{}\0", path.display()).as_bytes()
                );
                let root_file = fs::File::open(temporary_file(state_dir)).unwrap();
                assert!(
                    crate::native_store::gc::lock_file(
                        &root_file,
                        rustix::fs::FlockOperation::NonBlockingLockExclusive
                    )
                    .is_err()
                );
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
        let root_file = fs::File::open(temporary_file(state_dir)).unwrap();
        crate::native_store::gc::lock_file(
            &root_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
    }

    #[test]
    fn a_missing_target_cannot_become_a_successful_gc_root() {
        let directory = tempdir().unwrap();
        let missing = directory
            .path()
            .join("00000000000000000000000000000000-missing");
        assert!(StoreRoots::hold_in(directory.path(), [missing]).is_err());
        assert!(collect_temporary_roots(directory.path()).is_empty());
    }

    #[test]
    fn a_late_missing_target_releases_roots_already_installed() {
        let directory = tempdir().unwrap();
        let live = directory
            .path()
            .join("00000000000000000000000000000000-live");
        let missing = directory
            .path()
            .join("00000000000000000000000000000000-missing");
        fs::write(&live, b"root target").unwrap();
        assert!(StoreRoots::hold_in(directory.path(), [live, missing]).is_err());
        assert!(collect_temporary_roots(directory.path()).is_empty());
    }

    #[test]
    fn failed_metadata_lookup_releases_roots_and_the_gc_lock() {
        let directory = tempdir().unwrap();
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
        assert!(collect_temporary_roots(directory.path()).is_empty());
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
        let store_path = root_directory
            .path()
            .join("00000000000000000000000000000000-store-path");
        fs::write(&store_path, b"store object").expect("create store object");

        let roots = StoreRoots::hold_in(root_directory.path(), [store_path.clone()]);
        let roots = roots.expect("create native temporary root");
        assert_eq!(collect_temporary_roots(root_directory.path()), [store_path]);

        drop(roots);
        assert!(collect_temporary_roots(root_directory.path()).is_empty());
    }

    #[test]
    fn multiple_guards_share_the_pid_file_until_the_last_guard_finishes() {
        let directory = tempdir().unwrap();
        let first = directory
            .path()
            .join("00000000000000000000000000000000-first");
        let second = directory
            .path()
            .join("00000000000000000000000000000000-second");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let first_guard = StoreRoots::hold_in(directory.path(), [first.clone()]).unwrap();
        let second_guard = StoreRoots::hold_in(directory.path(), [second.clone()]).unwrap();
        assert_eq!(
            fs::read_dir(directory.path().join("temproots"))
                .unwrap()
                .count(),
            1
        );
        drop(first_guard);
        assert_eq!(
            collect_temporary_roots(directory.path()),
            [first, second.clone()]
        );
        drop(second_guard);
        assert!(collect_temporary_roots(directory.path()).is_empty());
        let next_guard = StoreRoots::hold_in(directory.path(), [second.clone()]).unwrap();
        assert_eq!(collect_temporary_roots(directory.path()), [second]);
        drop(next_guard);
    }

    #[test]
    fn concurrent_guards_register_complete_records_in_one_pid_file() {
        let directory = tempdir().unwrap();
        let mut targets = (0..4)
            .map(|number| {
                let path = directory
                    .path()
                    .join(format!("00000000000000000000000000000000-live-{number}"));
                fs::write(&path, b"live").unwrap();
                path
            })
            .collect::<Vec<_>>();
        let workers = targets
            .iter()
            .map(|target| {
                let state = directory.path().to_owned();
                let target = target.clone();
                std::thread::spawn(move || StoreRoots::hold_in(&state, [target]).unwrap())
            })
            .collect::<Vec<_>>();
        let guards = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        let mut registered = collect_temporary_roots(directory.path());
        registered.sort();
        targets.sort();
        assert_eq!(registered, targets);
        assert_eq!(
            fs::read_dir(directory.path().join("temproots"))
                .unwrap()
                .count(),
            1
        );
        drop(guards);
        assert!(collect_temporary_roots(directory.path()).is_empty());
    }

    #[test]
    fn final_guard_release_and_new_registration_do_not_split_the_pid_file() {
        let directory = tempdir().unwrap();
        let target = directory
            .path()
            .join("00000000000000000000000000000000-live");
        fs::write(&target, b"live").unwrap();
        for _ in 0..32 {
            let previous = StoreRoots::hold_in(directory.path(), [target.clone()]).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let ready = std::sync::Arc::clone(&barrier);
            let state = directory.path().to_owned();
            let next_target = target.clone();
            let next = std::thread::spawn(move || {
                ready.wait();
                StoreRoots::hold_in(&state, [next_target]).unwrap()
            });
            barrier.wait();
            drop(previous);
            let next = next.join().unwrap();
            let registered = collect_temporary_roots(directory.path());
            assert!(!registered.is_empty());
            assert!(registered.iter().all(|path| *path == target));
            assert_eq!(
                fs::read_dir(directory.path().join("temproots"))
                    .unwrap()
                    .count(),
                1
            );
            drop(next);
            assert!(collect_temporary_roots(directory.path()).is_empty());
        }
    }
}
