use std::fs::File;

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
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
}
