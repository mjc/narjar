use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{StorageError, sync_dir};

#[derive(Debug)]
pub(super) struct RecoveryState {
    root: PathBuf,
    clean: PathBuf,
    recovery: PathBuf,
}

impl RecoveryState {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            clean: root.join(".narjar-clean"),
            recovery: root.join(".narjar-recovery"),
            root: root.to_owned(),
        }
    }

    pub(super) fn root_is_empty(path: &Path) -> io::Result<bool> {
        match fs::read_dir(path) {
            Ok(mut entries) => Ok(entries.next().transpose()?.is_none()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    }

    pub(super) fn initialize_clean(&self) -> Result<(), StorageError> {
        self.create_marker(&self.clean)
    }

    pub(super) fn required(&self) -> Result<bool, StorageError> {
        Ok(!self.marker_exists(&self.clean)? || self.marker_exists(&self.recovery)?)
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
        self.create_marker(&self.recovery)
    }

    pub(super) fn finish_publication(&self) -> Result<(), StorageError> {
        self.create_marker(&self.clean)?;
        self.clear_recovery_marker()
    }

    fn clear_recovery_marker(&self) -> Result<(), StorageError> {
        match fs::remove_file(&self.recovery) {
            Ok(()) => sync_dir(&self.root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn create_marker(&self, path: &Path) -> Result<(), StorageError> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => {
                file.sync_all()?;
                sync_dir(&self.root)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.marker_exists(path)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn write_clean_marker(&self, contents: &[u8]) -> Result<(), StorageError> {
        self.create_marker(&self.clean)?;
        let mut marker = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.clean)?;
        marker.write_all(contents)?;
        marker.sync_all()?;
        sync_dir(&self.root)?;
        Ok(())
    }

    fn clean_marker(&self) -> Result<Vec<u8>, StorageError> {
        self.marker_exists(&self.clean)?;
        Ok(fs::read(&self.clean)?)
    }

    fn marker_exists(&self, path: &Path) -> Result<bool, StorageError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("recovery marker {} is not a regular file", path.display()),
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
