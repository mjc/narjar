use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::{
        ffi::OsStringExt,
        fs::{DirBuilderExt, PermissionsExt},
    },
    path::Path,
};

use rustix::{
    fd::AsFd,
    fs::{self, Dir, Mode, OFlags},
};

use super::{EntryKind, EntryMetadata, FileAccess, FileCreation, FilePrivacy, FileStamp};

pub(super) fn is_link_traversal_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
}

pub(crate) fn entry_metadata_at(parent: &File, name: &OsStr) -> io::Result<EntryMetadata> {
    let metadata = fs::statat(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW)?;
    let kind = match fs::FileType::from_raw_mode(metadata.st_mode) {
        fs::FileType::Directory => EntryKind::Directory,
        fs::FileType::RegularFile => EntryKind::Regular,
        _ => EntryKind::Other,
    };
    Ok(EntryMetadata {
        kind,
        stamp: FileStamp::from_stat(&metadata),
    })
}

pub(crate) fn hard_link_at(
    source: &File,
    source_name: &OsStr,
    destination: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    fs::linkat(
        source,
        source_name,
        destination,
        destination_name,
        fs::AtFlags::empty(),
    )
    .map_err(Into::into)
}

pub(crate) fn rename_at(
    source: &File,
    source_name: &OsStr,
    destination: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    fs::renameat(source, source_name, destination, destination_name).map_err(Into::into)
}

pub(crate) fn unlink_at(directory: &File, name: &OsStr) -> io::Result<()> {
    fs::unlinkat(directory, name, fs::AtFlags::empty()).map_err(Into::into)
}

#[cfg(target_os = "linux")]
pub(crate) fn sync_filesystem(file: &File) -> io::Result<()> {
    fs::syncfs(file).map_err(Into::into)
}

pub(crate) fn validate_file_privacy(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let mode = file.metadata()?.permissions().mode();
    validate_mode(mode, privacy)
}

pub fn validate_private_file(file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a regular file is required",
        ));
    }
    validate_file_privacy(file, FilePrivacy::Private)
}

pub(crate) fn validate_file_privacy_at(
    parent: &File,
    name: &OsStr,
    privacy: FilePrivacy,
) -> io::Result<()> {
    let metadata = fs::statat(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if fs::FileType::from_raw_mode(metadata.st_mode) != fs::FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata record is not a regular file",
        ));
    }
    validate_mode(metadata.st_mode as u32, privacy)
}

fn validate_mode(mode: u32, privacy: FilePrivacy) -> io::Result<()> {
    let (valid, message) = match privacy {
        FilePrivacy::Private => (mode & 0o777 == 0o600, "file must have 0600 permissions"),
        FilePrivacy::Public => (mode & 0o133 == 0, "file has unsafe permissions"),
    };
    match valid {
        true => Ok(()),
        false => Err(io::Error::new(io::ErrorKind::InvalidData, message)),
    }
}

pub(crate) fn validate_managed_file_privacy(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let mode = match privacy {
        FilePrivacy::Private => 0o600,
        FilePrivacy::Public => 0o644,
    };
    let metadata = file.metadata()?;
    if metadata.is_file() && metadata.permissions().mode() & 0o777 == mode {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected a regular {mode:04o} file"),
        ))
    }
}

pub(crate) fn set_file_privacy(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let mode = match (privacy, file.metadata()?.is_dir()) {
        (FilePrivacy::Private, true) => 0o700,
        (FilePrivacy::Private, false) => 0o600,
        (FilePrivacy::Public, true) => 0o755,
        (FilePrivacy::Public, false) => 0o644,
    };
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

pub fn open_regular(path: &Path) -> io::Result<File> {
    open_regular_at(fs::CWD, path)
}

pub(crate) fn open_writable_at(
    parent: &File,
    name: &OsStr,
    access: FileAccess,
    creation: FileCreation,
    privacy: FilePrivacy,
) -> io::Result<File> {
    open_with_access(parent, name, access, creation, privacy)
}

fn open_with_access(
    parent: impl AsFd,
    name: impl AsRef<Path>,
    access: FileAccess,
    creation: FileCreation,
    privacy: FilePrivacy,
) -> io::Result<File> {
    let access = match access {
        FileAccess::Read => OFlags::RDONLY,
        FileAccess::Write => OFlags::WRONLY,
        FileAccess::ReadWrite => OFlags::RDWR,
    };
    let creation = match creation {
        FileCreation::Existing => OFlags::empty(),
        FileCreation::CreateNew => OFlags::CREATE | OFlags::EXCL,
        FileCreation::OpenOrCreate => OFlags::CREATE,
        FileCreation::Truncate => OFlags::TRUNC,
    };
    let mode = match privacy {
        FilePrivacy::Private => 0o600,
        FilePrivacy::Public => 0o644,
    };
    Ok(fs::openat(
        parent,
        name.as_ref(),
        access | creation | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::from_raw_mode(mode),
    )?
    .into())
}

enum ReadonlyKind {
    Directory,
    Regular,
}

fn open_readonly(parent: impl AsFd, path: &Path, kind: ReadonlyKind) -> io::Result<File> {
    let file = open_with_access(
        parent,
        path,
        FileAccess::Read,
        FileCreation::Existing,
        FilePrivacy::Public,
    )?;
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

pub fn create_private_directory(path: &Path) -> io::Result<File> {
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    let directory = open_directory(path)?;
    set_file_privacy(&directory, FilePrivacy::Private)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        open_directory(parent)?.sync_all()?;
    }
    Ok(directory)
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
