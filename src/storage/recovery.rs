use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use sha2::{Digest, Sha256};

use super::{StorageError, entry_is_regular_at, open_at, open_regular_at, unlink_at};

#[derive(Debug)]
pub(super) struct RecoveryState {
    root: File,
}

impl RecoveryState {
    pub(super) fn new(root: &File) -> io::Result<Self> {
        Ok(Self {
            root: root.try_clone()?,
        })
    }

    pub(super) fn initialize_clean(&self) -> Result<(), StorageError> {
        self.create_marker(OsStr::new(".narjar-clean"))
    }

    pub(super) fn required(&self) -> Result<bool, StorageError> {
        Ok(!self.marker_exists(OsStr::new(".narjar-clean"))?
            || self.marker_exists(OsStr::new(".narjar-recovery"))?)
    }

    pub(super) fn required_for(&self, trusted_keys: &Path) -> Result<bool, StorageError> {
        if self.required()? {
            return Ok(true);
        }

        let digest = trusted_keys_digest(trusted_keys)?;
        Ok(self.clean_marker()? != digest.as_slice())
    }

    pub(super) fn finish(&self, trusted_keys: &Path) -> Result<(), StorageError> {
        self.write_clean_marker(trusted_keys_digest(trusted_keys)?.as_slice())?;
        self.clear_recovery_marker()
    }

    pub(super) fn require(&self) -> Result<(), StorageError> {
        self.create_marker(OsStr::new(".narjar-recovery"))
    }

    pub(super) fn finish_publication(&self) -> Result<(), StorageError> {
        self.create_marker(OsStr::new(".narjar-clean"))?;
        self.clear_recovery_marker()
    }

    fn clear_recovery_marker(&self) -> Result<(), StorageError> {
        match unlink_at(&self.root, OsStr::new(".narjar-recovery")) {
            Ok(()) => self.root.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn create_marker(&self, name: &OsStr) -> Result<(), StorageError> {
        match open_at(
            &self.root,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                file.sync_all()?;
                self.root.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.marker_exists(name)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn write_clean_marker(&self, contents: &[u8]) -> Result<(), StorageError> {
        let name = OsStr::new(".narjar-clean");
        self.create_marker(name)?;
        let mut marker = open_at(
            &self.root,
            name,
            libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        if !marker.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "clean recovery marker is not a regular file",
            )
            .into());
        }
        marker.write_all(contents)?;
        marker.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }

    fn clean_marker(&self) -> Result<Vec<u8>, StorageError> {
        let mut marker = open_regular_at(&self.root, OsStr::new(".narjar-clean"))?;
        let mut contents = Vec::new();
        marker.read_to_end(&mut contents)?;
        Ok(contents)
    }

    fn marker_exists(&self, name: &OsStr) -> Result<bool, StorageError> {
        match entry_is_regular_at(&self.root, name) {
            Ok(true) => {
                let marker = open_regular_at(&self.root, name)?;
                if marker.metadata()?.permissions().mode() & 0o133 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "recovery marker has unsafe permissions",
                    )
                    .into());
                }
                Ok(true)
            }
            Ok(false) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not a regular file", name.to_string_lossy()),
            )
            .into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

fn trusted_keys_digest(path: &Path) -> Result<[u8; 32], StorageError> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    Ok(Sha256::digest(contents).into())
}
