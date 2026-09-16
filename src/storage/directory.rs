use std::{fs::File, io, os::unix::fs::PermissionsExt, path::Path};

#[cfg(test)]
use std::path::PathBuf;

use super::fs::{open_directory, require_directory_at, require_private_file_at};

#[derive(Debug)]
pub struct Directory {
    pub(super) file: File,
    #[cfg(test)]
    pub(super) path: PathBuf,
}

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = open_directory(path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidData => {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("data directory is not a directory: {}", path.display()),
                )
            }
            _ if error.raw_os_error() == Some(libc::ELOOP) => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("data directory is not a directory: {}", path.display()),
            ),
            _ => error,
        })?;
        if file.metadata()?.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("data directory has unsafe permissions: {}", path.display()),
            ));
        }
        Ok(Self {
            file,
            #[cfg(test)]
            path: path.to_owned(),
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub fn validate_initialized(&self) -> io::Result<()> {
        let nar = require_directory_at(&self.file, "nar")?;
        require_directory_at(&nar, ".tmp")?;
        require_directory_at(&self.file, ".tmp")?;
        let realisations = require_directory_at(&self.file, "realisations")?;
        require_directory_at(&realisations, ".tmp")?;
        let auth = require_directory_at(&self.file, "auth")?;
        for name in ["nix-cache-info", "trusted-public-keys"] {
            require_private_file_at(&self.file, name, true)?;
        }
        require_private_file_at(&auth, "write.tokens", true)?;
        let clean = require_private_file_at(&self.file, ".narjar-clean", false)?;
        let recovery = require_private_file_at(&self.file, ".narjar-recovery", false)?;
        if clean || recovery {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "data directory is not initialized",
            ))
        }
    }
}
