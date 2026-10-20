use std::{io, path::Path};
use windows_sys::Win32::Foundation::*;

use super::InjectedIoFailure;

pub(crate) fn remove_symlink(path: impl AsRef<Path>) -> io::Result<()> {
    use std::os::windows::fs::FileTypeExt;
    match std::fs::symlink_metadata(path.as_ref())?
        .file_type()
        .is_symlink_dir()
    {
        true => std::fs::remove_dir(path),
        false => std::fs::remove_file(path),
    }
}

pub(crate) fn non_unicode_name(suffix: &str) -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    let wide: Vec<_> = std::iter::once(0xd800)
        .chain(suffix.encode_utf16())
        .collect();
    std::ffi::OsString::from_wide(&wide)
}

pub(crate) fn symlink(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> io::Result<()> {
    match source.as_ref().is_dir() {
        true => std::os::windows::fs::symlink_dir(source, destination),
        false => std::os::windows::fs::symlink_file(source, destination),
    }
}

pub(super) fn error_code(failure: InjectedIoFailure) -> i32 {
    (match failure {
        InjectedIoFailure::AccessDenied => ERROR_ACCESS_DENIED,
        InjectedIoFailure::ReadFailure => ERROR_READ_FAULT,
        InjectedIoFailure::Unsupported => ERROR_NOT_SUPPORTED,
        InjectedIoFailure::NoSpace => ERROR_DISK_FULL,
        InjectedIoFailure::QuotaExceeded => ERROR_DISK_QUOTA_EXCEEDED,
        InjectedIoFailure::ReadOnly => ERROR_WRITE_PROTECT,
        InjectedIoFailure::ConnectionReset => {
            windows_sys::Win32::Networking::WinSock::WSAECONNRESET as u32
        }
        InjectedIoFailure::Busy => ERROR_BUSY,
    }) as i32
}
