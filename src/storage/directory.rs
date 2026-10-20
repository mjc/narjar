use std::{fs::File, io, path::Path};

use crate::cache::filesystem::{EntryOpenFailure, open_directory};

#[cfg(test)]
use std::path::PathBuf;

#[cfg(unix)]
#[path = "directory/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "directory/windows.rs"]
mod platform;
pub(super) use platform::ProcessLock;

#[derive(Debug)]
pub struct Directory {
    file: File,
    #[cfg(test)]
    pub(super) path: PathBuf,
}

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let opened = open_directory(path).map_err(|error| {
            match (error.kind(), EntryOpenFailure::from(error)) {
                (io::ErrorKind::NotADirectory, _)
                | (_, EntryOpenFailure::Missing | EntryOpenFailure::Invalid) => io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("data directory is not a directory: {}", path.display()),
                ),
                (_, EntryOpenFailure::Io(error)) => error,
            }
        })?;
        platform::validate_data_directory(&opened, path)?;
        Ok(Self {
            file: opened,
            #[cfg(test)]
            path: path.to_owned(),
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }
}
