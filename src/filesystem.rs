use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::Path,
};

use rustix::{
    fd::AsFd,
    fs::{self, Dir, Mode, OFlags},
};

enum ReadonlyKind {
    Directory,
    Regular,
}

fn open_readonly(parent: impl AsFd, path: &Path, kind: ReadonlyKind) -> io::Result<File> {
    let file: File = fs::openat(
        parent,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    let metadata = file.metadata()?;
    let valid = match kind {
        ReadonlyKind::Directory => metadata.is_dir(),
        ReadonlyKind::Regular => metadata.is_file(),
    };
    if !valid {
        let expected = match kind {
            ReadonlyKind::Directory => "a directory",
            ReadonlyKind::Regular => "a regular file",
        };
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not {expected}", path.display()),
        ));
    }
    Ok(file)
}

pub fn open_directory_at(parent: impl AsFd, path: impl AsRef<Path>) -> io::Result<File> {
    open_readonly(parent, path.as_ref(), ReadonlyKind::Directory)
}

pub fn open_regular_at(parent: impl AsFd, path: impl AsRef<Path>) -> io::Result<File> {
    open_readonly(parent, path.as_ref(), ReadonlyKind::Regular)
}

pub fn open_directory(path: &Path) -> io::Result<File> {
    open_directory_at(rustix::fs::CWD, path)
}

pub fn ensure_directory_at(parent: &File, name: &OsStr, label: &str) -> io::Result<File> {
    match open_directory_at(parent, name) {
        Ok(directory) => validate_directory(&directory, label),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Err(error) = fs::mkdirat(parent, name, Mode::from_raw_mode(0o755))
                && error != rustix::io::Errno::EXIST
            {
                return Err(error.into());
            }
            let directory = open_directory_at(parent, name)?;
            validate_directory(&directory, label)
        }
        Err(error) => Err(error),
    }
}

pub fn validate_directory(directory: &File, name: &str) -> io::Result<File> {
    if directory.metadata()?.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} has unsafe permissions"),
        ));
    }
    directory.try_clone()
}

pub fn directory_names(directory: &File) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
    // Each scan gets an independent cursor; the borrowed descriptor is not advanced.
    Ok(Dir::read_from(directory)?.map(|entry| {
        entry
            .map(|entry| OsString::from_vec(entry.file_name().to_bytes().to_vec()))
            .map_err(Into::into)
    }))
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
