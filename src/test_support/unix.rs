use super::InjectedIoFailure;

pub(crate) use std::os::unix::fs::symlink;

pub(crate) fn non_unicode_name(suffix: &str) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    let mut bytes = vec![0xff];
    bytes.extend_from_slice(suffix.as_bytes());
    std::ffi::OsString::from_vec(bytes)
}

pub(super) fn error_code(failure: InjectedIoFailure) -> i32 {
    use rustix::io::Errno;
    match failure {
        InjectedIoFailure::AccessDenied => Errno::ACCESS,
        InjectedIoFailure::ReadFailure => Errno::IO,
        InjectedIoFailure::Unsupported => Errno::OPNOTSUPP,
        InjectedIoFailure::NoSpace => Errno::NOSPC,
        InjectedIoFailure::QuotaExceeded => Errno::DQUOT,
        InjectedIoFailure::ReadOnly => Errno::ROFS,
        InjectedIoFailure::ConnectionReset => Errno::CONNRESET,
        InjectedIoFailure::Busy => Errno::BUSY,
    }
    .raw_os_error()
}
