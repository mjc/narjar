use std::{io, os::windows::fs::MetadataExt, path::Path};

use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::cache::filesystem::{
    FileAccess, FileCreation, FilePrivacy, open_directory, open_writable_at, validate_directory,
    validate_private_file,
};

use super::{DoctorEntryKind, DoctorPath, DoctorSeverity};

pub(super) fn inspect_doctor_path(
    root: &Path,
    relative: &'static str,
    required: bool,
    directory: bool,
) -> DoctorPath {
    let mut report = DoctorPath {
        path: relative,
        required,
        kind: DoctorEntryKind::Missing,
        mode: None,
        uid: None,
        gid: None,
        severity: DoctorSeverity::Ok,
        detail: "optional".to_owned(),
    };
    let path = root.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => return report,
        Err(error) => {
            report.severity = if required {
                DoctorSeverity::Error
            } else {
                DoctorSeverity::Unavailable
            };
            report.detail = error.to_string();
            return report;
        }
    };
    report.kind = if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        DoctorEntryKind::Symlink
    } else if metadata.is_dir() {
        DoctorEntryKind::Directory
    } else if metadata.is_file() {
        DoctorEntryKind::File
    } else {
        DoctorEntryKind::Other
    };
    let validation = if directory {
        open_directory(&path).and_then(|file| validate_directory(&file, relative).map(|_| ()))
    } else {
        crate::cache::filesystem::open_regular(&path).and_then(|file| validate_private_file(&file))
    };
    match validation {
        Ok(()) => report.detail = "owner and DACL permit only the configured account, SYSTEM, and Administrators to modify this entry".to_owned(),
        Err(error) => { report.severity = DoctorSeverity::Error; report.detail = error.to_string(); }
    }
    report
}

pub(super) fn inspect_lease(root: &Path) -> io::Result<()> {
    let directory = open_directory(root)?;
    // A diagnostic never creates a missing lease file or initializes DATA.
    let file = open_writable_at(
        &directory,
        std::ffi::OsStr::new("lock"),
        FileAccess::ReadWrite,
        FileCreation::Existing,
        FilePrivacy::Private,
    )?;
    match file.try_lock() {
        Ok(()) => file.unlock(),
        Err(std::fs::TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}
