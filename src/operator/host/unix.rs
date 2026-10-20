use super::{DoctorEntryKind, DoctorPath, DoctorSeverity};
use crate::cache::storage::private_file_mode_is_valid;
use std::{fs, fs::File, io, os::unix::fs::MetadataExt, path::Path};

pub(super) fn inspect_doctor_path(
    root: &Path,
    relative: &'static str,
    required: bool,
    directory: bool,
) -> DoctorPath {
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return DoctorPath {
                path: relative,
                required,
                kind: DoctorEntryKind::Missing,
                mode: None,
                uid: None,
                gid: None,
                severity: DoctorSeverity::Ok,
                detail: "optional".to_owned(),
            };
        }
        Err(error) => {
            return DoctorPath {
                path: relative,
                required,
                kind: DoctorEntryKind::inspection_failure(&error),
                mode: None,
                uid: None,
                gid: None,
                severity: if required {
                    DoctorSeverity::Error
                } else {
                    DoctorSeverity::Unavailable
                },
                detail: error.to_string(),
            };
        }
    };
    let kind = if metadata.file_type().is_symlink() {
        DoctorEntryKind::Symlink
    } else if metadata.is_dir() {
        DoctorEntryKind::Directory
    } else if metadata.is_file() {
        DoctorEntryKind::File
    } else {
        DoctorEntryKind::Other
    };
    let mode = metadata.mode() & 0o7777;
    let wrong_type = (directory && kind != DoctorEntryKind::Directory)
        || (!directory && kind != DoctorEntryKind::File);
    let unsafe_mode = if directory {
        mode & 0o022 != 0
    } else {
        !private_file_mode_is_valid(mode)
    };
    let severity = if wrong_type || unsafe_mode {
        DoctorSeverity::Error
    } else {
        DoctorSeverity::Ok
    };
    let detail = if wrong_type {
        format!(
            "expected {}, found {kind}",
            if directory {
                "directory"
            } else {
                "regular file"
            }
        )
    } else if unsafe_mode {
        format!("unsafe permissions {mode:04o}")
    } else {
        "matches portable layout contract".to_owned()
    };
    DoctorPath {
        path: relative,
        required,
        kind,
        mode: Some(mode),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        severity,
        detail,
    }
}

pub(super) fn try_lease(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(Into::into)
}

pub(super) fn inspect_lease(root: &Path) -> io::Result<()> {
    let file = crate::cache::filesystem::open_directory(root)?;
    try_lease(&file)
}
