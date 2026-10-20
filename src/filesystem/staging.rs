use std::{ffi::OsString, fs::File, io};

use super::{
    FileAccess, FileCreation, FilePrivacy, hard_link_at, open_writable_at, rename_at,
    set_file_privacy, unlink_at,
};
use scopeguard::{ScopeGuard, guard};

/// Owns an unpublished name relative to the directory that created it.
struct TemporaryFile {
    directory: File,
    name: OsString,
    file: File,
}

impl TemporaryFile {
    fn create(directory: &File, privacy: FilePrivacy) -> io::Result<Self> {
        let directory = directory.try_clone()?;
        (0..128)
            .find_map(|_| {
                let mut random = [0; 16];
                if let Err(error) = getrandom::getrandom(&mut random) {
                    return Some(Err(io::Error::other(error)));
                }
                let name = OsString::from(format!(
                    ".narjar-credential-{}.tmp",
                    data_encoding::HEXLOWER.encode(&random)
                ));
                match open_writable_at(
                    &directory,
                    &name,
                    FileAccess::ReadWrite,
                    FileCreation::CreateNew,
                    privacy,
                ) {
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                    result => Some(result.map(|file| (name, file))),
                }
            })
            .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::AlreadyExists)))
            .map(|(name, file)| Self {
                directory,
                name,
                file,
            })
    }
}

fn remove_abandoned_temporary(temporary: TemporaryFile) {
    let _ = unlink_at(&temporary.directory, &temporary.name);
}

/// Complete, synchronized bytes; no caller can mutate them before publication.
pub(crate) struct PreparedFile(ScopeGuard<TemporaryFile, fn(TemporaryFile)>);

impl PreparedFile {
    pub(crate) fn write(
        directory: &File,
        privacy: FilePrivacy,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<Self> {
        let mut temporary = guard(
            TemporaryFile::create(directory, privacy)?,
            remove_abandoned_temporary as fn(TemporaryFile),
        );
        set_file_privacy(&temporary.file, privacy)?;
        write(&mut temporary.file)?;
        temporary.file.sync_all()?;
        Ok(Self(temporary))
    }

    pub(crate) fn publish_new(self, name: &std::ffi::OsStr) -> io::Result<()> {
        self.publish(|temporary| {
            hard_link_at(
                &temporary.directory,
                &temporary.name,
                &temporary.directory,
                name,
            )?;
            unlink_at(&temporary.directory, &temporary.name)
        })
    }

    pub(crate) fn replace(self, name: &std::ffi::OsStr) -> io::Result<()> {
        self.publish(|temporary| {
            rename_at(
                &temporary.directory,
                &temporary.name,
                &temporary.directory,
                name,
            )
        })
    }

    fn publish(self, commit: impl FnOnce(&TemporaryFile) -> io::Result<()>) -> io::Result<()> {
        commit(&self.0)?;
        let published = ScopeGuard::into_inner(self.0);
        published.directory.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, io::Write};

    use super::*;
    use crate::cache::filesystem::{open_directory, read_dir_names, validate_private_file};

    #[test]
    fn private_staging_is_private_before_the_first_byte_and_cleans_up_write_failures() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).unwrap();
        let error = PreparedFile::write(&directory, FilePrivacy::Private, |file| {
            validate_private_file(file)?;
            file.write_all(b"secret")?;
            Err(io::Error::other("failed serialization"))
        });
        assert!(error.is_err());
        assert!(read_dir_names(&directory).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn publication_and_abandonment_follow_the_directory_handle_after_replacement() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        let directory = open_directory(&original).unwrap();
        let ready = PreparedFile::write(&directory, FilePrivacy::Private, |file| {
            file.write_all(b"secret")
        })
        .unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        ready.publish_new(OsStr::new("secret")).unwrap();
        assert_eq!(std::fs::read(moved.join("secret")).unwrap(), b"secret");
        assert!(std::fs::read_dir(&original).unwrap().next().is_none());

        let abandoned = PreparedFile::write(&directory, FilePrivacy::Private, |_| Ok(())).unwrap();
        drop(abandoned);
        assert_eq!(
            read_dir_names(&directory).unwrap(),
            [OsString::from("secret")]
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_live_stage_pins_its_parent_and_a_retained_directory_still_follows_a_later_move() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        let directory = open_directory(&original).unwrap();
        let ready = PreparedFile::write(&directory, FilePrivacy::Private, |_| Ok(())).unwrap();
        assert_eq!(
            std::fs::rename(&original, &moved).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(ready);
        assert!(read_dir_names(&directory).unwrap().is_empty());
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        PreparedFile::write(&directory, FilePrivacy::Private, |file| {
            file.write_all(b"secret")
        })
        .unwrap()
        .publish_new(OsStr::new("secret"))
        .unwrap();
        assert_eq!(std::fs::read(moved.join("secret")).unwrap(), b"secret");
        assert!(std::fs::read_dir(&original).unwrap().next().is_none());
    }

    #[test]
    fn replacement_and_no_replace_publication_have_distinct_contracts() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).unwrap();
        let stage = |bytes: &[u8]| {
            PreparedFile::write(&directory, FilePrivacy::Private, |file| {
                file.write_all(bytes)
            })
            .unwrap()
        };
        stage(b"old").publish_new(OsStr::new("record")).unwrap();
        assert_eq!(
            stage(b"wrong")
                .publish_new(OsStr::new("record"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(root.path().join("record")).unwrap(), b"old");
        stage(b"new").replace(OsStr::new("record")).unwrap();
        assert_eq!(std::fs::read(root.path().join("record")).unwrap(), b"new");
        assert_eq!(read_dir_names(&directory).unwrap().len(), 1);
    }

    #[test]
    fn successful_publication_relinquishes_the_old_temporary_name() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).unwrap();
        let ready = PreparedFile::write(&directory, FilePrivacy::Private, |_| Ok(())).unwrap();
        let old_name = ready.0.name.clone();
        ready
            .publish(|temporary| {
                rename_at(
                    &temporary.directory,
                    &temporary.name,
                    &temporary.directory,
                    OsStr::new("published"),
                )?;
                let mut replacement = open_writable_at(
                    &temporary.directory,
                    &temporary.name,
                    FileAccess::ReadWrite,
                    FileCreation::CreateNew,
                    FilePrivacy::Private,
                )?;
                replacement.write_all(b"replacement")
            })
            .unwrap();
        assert_eq!(
            std::fs::read(root.path().join(old_name)).unwrap(),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_umasks_do_not_change_the_published_file_privacy_contract() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cache::filesystem::staging::tests::restrictive_umask_child",
                "--nocapture",
            ])
            .env("NARJAR_TEST_STAGING_UMASK_ROOT", root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("published both privacy modes"));
        for (name, mode) in [("private", 0o600), ("public", 0o644)] {
            assert_eq!(
                std::fs::metadata(root.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_umask_child() {
        let Some(path) = std::env::var_os("NARJAR_TEST_STAGING_UMASK_ROOT") else {
            return;
        };
        let directory = open_directory(std::path::Path::new(&path)).unwrap();
        // The child is isolated: no other test shares this process's umask.
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
        for (name, privacy) in [
            ("private", FilePrivacy::Private),
            ("public", FilePrivacy::Public),
        ] {
            PreparedFile::write(&directory, privacy, |file| file.write_all(b"credential"))
                .unwrap()
                .publish_new(OsStr::new(name))
                .unwrap();
        }
        println!("published both privacy modes");
    }
}
