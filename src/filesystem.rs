use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
};

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
