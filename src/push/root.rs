use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use super::PushError;
use super::nar_stream::local_store_path;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// Keeps the requested local store paths reachable while a push is in flight.
///
/// Nix treats symlinks below `gcroots/auto` as roots. The root is deliberately
/// owned by this value so it covers metadata lookup, every upload worker, and
/// all retry attempts. A failed cleanup leaves a harmless stale root for Nix's
/// normal root cleanup to remove later.
pub(super) struct StoreRoots {
    entries: Vec<PathBuf>,
}

impl StoreRoots {
    pub(super) fn hold(store_paths: &[String]) -> Result<Self, PushError> {
        let automatic_roots = std::env::var_os("NARJAR_PUSH_GCROOTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let state_dir = std::env::var_os("NIX_STATE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/nix/var/nix"));
                state_dir.join("gcroots/auto")
            });
        let targets = store_paths
            .iter()
            .map(|path| local_store_path(path))
            .collect::<Result<Vec<_>, _>>()?;
        Self::hold_in(&automatic_roots, targets)
    }

    fn hold_in(
        automatic_roots: &Path,
        targets: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, PushError> {
        let mut roots = Self {
            entries: Vec::new(),
        };
        for target in targets {
            let entry = allocate_root_entry(automatic_roots, &target)?;
            roots.entries.push(entry);
        }
        Ok(roots)
    }
}

impl Drop for StoreRoots {
    fn drop(&mut self) {
        self.entries.iter().for_each(|entry| {
            let _ = fs::remove_file(entry);
        });
    }
}

fn allocate_root_entry(automatic_roots: &Path, target: &Path) -> Result<PathBuf, PushError> {
    for _ in 0..128 {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let entry = automatic_roots.join(format!("narjar-push-{}-{sequence:016x}", process::id()));
        match std::os::unix::fs::symlink(target, &entry) {
            Ok(()) => return Ok(entry),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(
                    format!("creating Nix GC root for {}: {error}", target.display()).into(),
                );
            }
        }
    }
    Err("could not allocate a unique Nix GC root".into())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::StoreRoots;

    #[test]
    fn roots_hold_targets_until_the_push_finishes() {
        let root_directory = tempdir().expect("create root directory");
        let automatic_roots = root_directory.path().join("gcroots/auto");
        fs::create_dir_all(&automatic_roots).expect("create automatic roots directory");
        let store_path = root_directory.path().join("store-path");
        fs::write(&store_path, b"store object").expect("create store object");

        let roots = StoreRoots::hold_in(&automatic_roots, [store_path.clone()]);
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
