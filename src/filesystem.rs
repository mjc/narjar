use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
};

#[path = "filesystem/identity.rs"]
mod identity;
pub(crate) use identity::{FileIdentity, FileStamp};
#[path = "filesystem/staging.rs"]
mod staging;
pub(crate) use staging::PreparedFile;

#[cfg(unix)]
#[path = "filesystem/unix.rs"]
mod unix;
#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
#[path = "filesystem/windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[derive(Clone, Copy, Debug)]
pub(crate) enum FileAccess {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FileCreation {
    Existing,
    CreateNew,
    OpenOrCreate,
    Truncate,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FilePrivacy {
    Private,
    Public,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    Directory,
    Regular,
    Other,
}

#[derive(Debug)]
pub(crate) struct EntryMetadata {
    pub(crate) kind: EntryKind,
    pub(crate) stamp: FileStamp,
}

pub(crate) enum EntryOpenFailure {
    Missing,
    Invalid,
    Io(io::Error),
}

impl From<io::Error> for EntryOpenFailure {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::Missing,
            io::ErrorKind::InvalidData => Self::Invalid,
            _ if is_link_traversal_error(&error) => Self::Invalid,
            _ => Self::Io(error),
        }
    }
}

pub fn exclude_dot_directory_entries(
    entries: impl Iterator<Item = io::Result<OsString>>,
) -> impl Iterator<Item = io::Result<OsString>> {
    entries.filter(|entry| match entry {
        Ok(name) => name != OsStr::new(".") && name != OsStr::new(".."),
        Err(_) => true,
    })
}

pub fn read_dir_names(directory: &File) -> io::Result<Vec<OsString>> {
    exclude_dot_directory_entries(directory_names(directory)?).collect()
}

pub(crate) fn create_private_directory_tree(path: &std::path::Path) -> io::Result<File> {
    let directory = ensure_private_directory_tree(path)?;
    set_file_privacy(&directory, FilePrivacy::Private)?;
    Ok(directory)
}

fn ensure_private_directory_tree(path: &std::path::Path) -> io::Result<File> {
    match open_directory(path) {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                ensure_private_directory_tree(parent)?;
            }
            match create_private_directory(path) {
                Ok(directory) => Ok(directory),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open_directory(path),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
