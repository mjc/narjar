#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapacityErrorKind {
    NoSpace,
    Quota,
    Inodes,
    ReadOnly,
    Other,
}

use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    sync::{Arc, Mutex},
};

use super::publication::{StagingBudget, TemporaryFile};
use super::{StagingReservation, StorageError};

const COMPARE_BUFFER_BYTES: usize = 16 * 1024;

pub(super) enum BoundedRegularFile<T> {
    Missing,
    Invalid,
    Valid(T),
}

impl BoundedRegularFile<Vec<u8>> {
    pub(super) fn parse<T>(self, parse: impl FnOnce(&[u8]) -> Option<T>) -> BoundedRegularFile<T> {
        match self {
            Self::Missing => BoundedRegularFile::Missing,
            Self::Invalid => BoundedRegularFile::Invalid,
            Self::Valid(bytes) => parse(&bytes)
                .map(BoundedRegularFile::Valid)
                .unwrap_or(BoundedRegularFile::Invalid),
        }
    }
}

pub(super) fn read_bounded_regular_file(
    directory: &File,
    name: &OsStr,
    max_bytes: u64,
) -> Result<BoundedRegularFile<Vec<u8>>, StorageError> {
    let file = match open_regular_at(directory, name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BoundedRegularFile::Missing);
        }
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(BoundedRegularFile::Invalid);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Ok(BoundedRegularFile::Invalid);
    }
    Ok(BoundedRegularFile::Valid(bytes))
}

pub(crate) fn capacity_error_kind(raw_error: i32) -> CapacityErrorKind {
    match raw_error {
        libc::ENOSPC => CapacityErrorKind::NoSpace,
        libc::EDQUOT => CapacityErrorKind::Quota,
        libc::EROFS => CapacityErrorKind::ReadOnly,
        _ => CapacityErrorKind::Other,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FilesystemSpace {
    pub(super) total_bytes: u64,
    pub(super) available_bytes: u64,
    pub(super) total_inodes: u64,
    pub(super) available_inodes: u64,
    pub(super) read_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageCapacity {
    pub(crate) total_bytes: u64,
    pub(crate) available_bytes: u64,
    pub(crate) total_inodes: u64,
    pub(crate) available_inodes: u64,
    pub(crate) read_only: bool,
}

impl FilesystemSpace {
    pub(super) fn required_capacity(self, required_bytes: u64) -> Result<(), StorageError> {
        if self.read_only {
            return Err(StorageError::Io(io::Error::from_raw_os_error(libc::EROFS)));
        }
        if self.available_bytes < required_bytes {
            return Err(StorageError::InsufficientSpace);
        }
        if self.available_inodes == 0 {
            return Err(StorageError::InsufficientInodes);
        }
        Ok(())
    }
}

pub(super) fn reserve_staging_bytes(
    budget: &Arc<Mutex<StagingBudget>>,
    directory: &File,
    min_free_bytes: u64,
    bytes: u64,
) -> Result<StagingReservation, StorageError> {
    reserve_staging_bytes_with_measurement(budget, min_free_bytes, bytes, || {
        filesystem_space(directory)
    })
}

fn reserve_staging_bytes_with_measurement(
    budget: &Arc<Mutex<StagingBudget>>,
    min_free_bytes: u64,
    bytes: u64,
    measure: impl FnOnce() -> io::Result<FilesystemSpace>,
) -> Result<StagingReservation, StorageError> {
    let mut budget_guard = budget
        .lock()
        .map_err(|_| StorageError::Io(io::Error::other("staging budget lock poisoned")))?;
    budget_guard.reserve(measure()?, min_free_bytes, bytes)?;
    drop(budget_guard);
    Ok(StagingReservation {
        budget: Arc::clone(budget),
        bytes,
    })
}

#[cfg(test)]
pub(super) fn reserve_staging_bytes_for_test(
    budget: &Arc<Mutex<StagingBudget>>,
    min_free_bytes: u64,
    bytes: u64,
    measure: impl FnOnce() -> io::Result<FilesystemSpace>,
) -> Result<StagingReservation, StorageError> {
    reserve_staging_bytes_with_measurement(budget, min_free_bytes, bytes, measure)
}

pub(super) fn filesystem_space(directory: &File) -> io::Result<FilesystemSpace> {
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();

    // SAFETY: directory owns a valid descriptor for the duration of the call,
    // and statistics points to writable storage for one statvfs value.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fstatvfs returned success, so it initialized statistics.
    let statistics = unsafe { statistics.assume_init() };
    let total = (statistics.f_blocks as u128).saturating_mul(statistics.f_frsize as u128);
    let available = (statistics.f_bavail as u128).saturating_mul(statistics.f_frsize as u128);
    let total_inodes = statistics.f_files as u128;
    let inodes = statistics.f_favail as u128;
    Ok(FilesystemSpace {
        total_bytes: total.min(u128::from(u64::MAX)) as u64,
        available_bytes: available.min(u128::from(u64::MAX)) as u64,
        total_inodes: total_inodes.min(u128::from(u64::MAX)) as u64,
        available_inodes: inodes.min(u128::from(u64::MAX)) as u64,
        read_only: statistics.f_flag & libc::ST_RDONLY != 0,
    })
}

pub(super) fn ensure_directory_at(parent: &File, name: &OsStr, label: &str) -> io::Result<File> {
    match open_directory_at(parent, name) {
        Ok(directory) => validate_directory(&directory, label),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = CString::new(name.as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "storage entry name contains a NUL byte",
                )
            })?;
            // SAFETY: parent owns a live directory descriptor, name is
            // NUL-terminated, and mkdirat does not retain the pointer.
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            let directory = open_directory_at(parent, OsStr::from_bytes(name.as_bytes()))?;
            validate_directory(&directory, label)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn validate_directory(directory: &File, name: &str) -> io::Result<File> {
    if directory.metadata()?.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} has unsafe permissions"),
        ));
    }
    directory.try_clone()
}

pub(super) fn require_directory_at(parent: &File, name: &str) -> io::Result<File> {
    let directory = open_directory_at(parent, OsStr::new(name))
        .map_err(|error| io::Error::new(error.kind(), format!("{name} is unavailable: {error}")))?;
    validate_directory(&directory, name)
}

pub(super) fn require_private_file_at(
    parent: &File,
    name: &str,
    required: bool,
) -> io::Result<bool> {
    match open_regular_at(parent, OsStr::new(name)) {
        Ok(file) if file.metadata()?.permissions().mode() & 0o777 == 0o600 => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} must have 0600 permissions"),
        )),
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("{name} is unavailable: {error}"),
        )),
    }
}

pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a directory", path.display()),
        ));
    }
    Ok(directory)
}

pub(crate) fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let directory = open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a directory", name.to_string_lossy()),
        ));
    }
    Ok(directory)
}

pub(crate) fn open_regular_at(directory: &File, name: &OsStr) -> io::Result<File> {
    let file = open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", name.to_string_lossy()),
        ));
    }
    Ok(file)
}

pub(crate) fn entry_is_regular_at(directory: &File, name: &OsStr) -> io::Result<bool> {
    Ok(entry_mode_at(directory, name)? & libc::S_IFMT == libc::S_IFREG)
}

pub(crate) fn entry_is_directory_at(directory: &File, name: &OsStr) -> io::Result<bool> {
    Ok(entry_mode_at(directory, name)? & libc::S_IFMT == libc::S_IFDIR)
}

pub(crate) fn entry_identity_at(
    directory: &File,
    name: &OsStr,
) -> io::Result<(u64, u64, i64, i64)> {
    let metadata = entry_stat_at(directory, name)?;
    let (change_time_seconds, change_time_nanoseconds) = metadata_change_time(&metadata);
    Ok((
        metadata.st_dev as u64,
        metadata.st_ino as u64,
        change_time_seconds,
        change_time_nanoseconds,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn metadata_change_time(metadata: &libc::stat) -> (i64, i64) {
    (metadata.st_ctime, metadata.st_ctime_nsec)
}

pub(super) fn entry_mode_at(directory: &File, name: &OsStr) -> io::Result<libc::mode_t> {
    Ok(entry_stat_at(directory, name)?.st_mode as libc::mode_t)
}

pub(super) fn entry_stat_at(directory: &File, name: &OsStr) -> io::Result<libc::stat> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory owns a live descriptor, name is NUL-terminated, and
    // metadata points to writable storage for one stat value.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned success, so it initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    Ok(metadata)
}

pub(super) fn open_optional_at(
    directory: &File,
    name: &OsStr,
) -> Result<Option<File>, StorageError> {
    match open_regular_at(directory, name) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn open_at(parent: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: parent owns a live directory descriptor, name is NUL-terminated,
    // and the returned descriptor is transferred to File exactly once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn read_dir_names(directory: &File) -> io::Result<Vec<OsString>> {
    read_dir_names_with(directory, read_next_directory_entry)
}

fn read_dir_names_with(
    directory: &File,
    read_entry: impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    let mut stream = DirectoryStream::open(directory)?;
    let visit_result = stream.visit_names(read_entry, |name| {
        names.push(name.to_owned());
        Ok(DirectoryVisit::Continue)
    });
    visit_result.and(stream.close())?;
    Ok(names)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryVisit {
    Continue,
    Stop,
}

pub(crate) fn for_each_dir_name<F>(directory: &File, visit: F) -> io::Result<()>
where
    F: FnMut(&OsStr) -> io::Result<DirectoryVisit>,
{
    let mut stream = DirectoryStream::open(directory)?;
    let visit_result = stream.visit_names(read_next_directory_entry, visit);
    visit_result.and(stream.close())
}

struct DirectoryStream(Option<std::ptr::NonNull<libc::DIR>>);

impl DirectoryStream {
    fn open(directory: &File) -> io::Result<Self> {
        let directory = open_at(
            directory,
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let fd = directory.into_raw_fd();
        // SAFETY: fd is a newly opened directory descriptor. On success,
        // fdopendir transfers ownership to the DIR handle.
        let stream = unsafe { libc::fdopendir(fd) };
        let Some(stream) = std::ptr::NonNull::new(stream) else {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not transfer ownership.
            unsafe { libc::close(fd) };
            return Err(error);
        };
        Ok(Self(Some(stream)))
    }

    fn visit_names(
        &mut self,
        mut read_entry: impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
        mut visit: impl FnMut(&OsStr) -> io::Result<DirectoryVisit>,
    ) -> io::Result<()> {
        loop {
            clear_errno();
            let stream = self.0.expect("open directory stream").as_ptr();
            let entry = read_entry(stream);
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return match error.raw_os_error() {
                    Some(0) => Ok(()),
                    _ => Err(error),
                };
            }
            // SAFETY: d_name is NUL-terminated and owned by the DIR stream;
            // the callback finishes before the next call can invalidate it.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            match name.to_bytes() {
                b"." | b".." => continue,
                name => match visit(OsStr::from_bytes(name))? {
                    DirectoryVisit::Continue => {}
                    DirectoryVisit::Stop => return Ok(()),
                },
            }
        }
    }

    fn close(mut self) -> io::Result<()> {
        let stream = self.0.take().expect("open directory stream");
        // SAFETY: taking the handle transfers its sole ownership to closedir.
        if unsafe { libc::closedir(stream.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            // SAFETY: this guard owns the handle and closes it during unwinding
            // or when the caller returns before explicitly calling `close`.
            unsafe { libc::closedir(stream.as_ptr()) };
        }
    }
}

fn read_next_directory_entry(stream: *mut libc::DIR) -> *mut libc::dirent {
    // SAFETY: callers pass the live stream owned by DirectoryStream.
    unsafe { libc::readdir(stream) }
}

fn clear_errno() {
    set_errno(0);
}

fn set_errno(errno: libc::c_int) {
    #[cfg(target_os = "linux")]
    // SAFETY: errno is thread-local writable storage provided by libc.
    unsafe {
        *libc::__errno_location() = errno;
    }
    #[cfg(target_os = "macos")]
    // SAFETY: errno is thread-local writable storage provided by libc.
    unsafe {
        *libc::__error() = errno;
    }
}

#[cfg(target_os = "linux")]
pub(super) fn directory_is_empty(directory: &File) -> io::Result<bool> {
    let directory = open_at(
        directory,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    let mut buffer = [0u8; 1024];

    loop {
        // SAFETY: directory owns a live directory descriptor and buffer is
        // valid writable storage for the requested byte count.
        let bytes = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if bytes < 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = bytes as usize;
        if bytes == 0 {
            return Ok(true);
        }

        let mut offset = 0;
        while offset < bytes {
            if bytes - offset < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short getdents64 record",
                ));
            }
            let reclen = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if reclen < 19 || reclen > bytes - offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid getdents64 record length",
                ));
            }
            let name = &buffer[offset + 19..offset + reclen];
            let name = name
                .iter()
                .position(|byte| *byte == 0)
                .map_or(name, |end| &name[..end]);
            if name != b"." && name != b".." {
                return Ok(false);
            }
            offset += reclen;
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn directory_is_empty(directory: &File) -> io::Result<bool> {
    read_dir_names(directory).map(|names| names.is_empty())
}

pub(super) fn rollback_link_at(directory: &File, name: &OsStr) -> Result<(), StorageError> {
    unlink_at(directory, name)?;
    directory.sync_all()?;
    Ok(())
}

pub(super) fn lock_exclusive(file: &File) -> Result<(), StorageError> {
    // SAFETY: file owns this live descriptor for the entire call. flock neither
    // dereferences Rust memory nor retains the descriptor after returning.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    let code = error.raw_os_error();
    if error.kind() == io::ErrorKind::WouldBlock
        || code == Some(libc::EAGAIN)
        || code == Some(libc::EWOULDBLOCK)
    {
        Err(StorageError::Locked)
    } else {
        Err(error.into())
    }
}

/// Flush every dirty object and metadata change on the filesystem containing
/// `file`. Chunked publication uses this once after linking all immutable
/// chunks and before publishing the authoritative manifest.
#[cfg(target_os = "linux")]
pub(super) fn sync_filesystem(file: &File) -> io::Result<()> {
    // SAFETY: `file` owns a live descriptor for the duration of this call.
    // `syncfs` only reads that descriptor, does not retain it, and does not
    // dereference any Rust-managed memory.
    if unsafe { libc::syncfs(file.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn sync_filesystem(file: &File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(test)]
pub(super) fn sync_dir(path: &Path) -> io::Result<()> {
    open_directory(path)?.sync_all()
}

pub(super) fn files_equal_at(
    left_directory: &File,
    left_name: &OsStr,
    right_directory: &File,
    right_name: &OsStr,
) -> io::Result<bool> {
    let mut left = open_regular_at(left_directory, left_name)?;
    let mut right = open_regular_at(right_directory, right_name)?;
    if left.metadata()?.len() != right.metadata()?.len() {
        return Ok(false);
    }

    let mut left_buffer = [0; COMPARE_BUFFER_BYTES];
    let mut right_buffer = [0; COMPARE_BUFFER_BYTES];

    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

pub(super) fn hard_link_at(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source_name = CString::new(source_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    let destination_name = CString::new(destination_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: both directory descriptors are live, both names are
    // NUL-terminated, and linkat does not retain either pointer.
    let result = unsafe {
        libc::linkat(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            destination_directory.as_raw_fd(),
            destination_name.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn rename_at(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source_name = CString::new(source_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    let destination_name = CString::new(destination_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: both directory descriptors are live, both names are
    // NUL-terminated, and renameat does not retain either pointer.
    let result = unsafe {
        libc::renameat(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            destination_directory.as_raw_fd(),
            destination_name.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn unlink_at(directory: &File, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage entry name contains a NUL byte",
        )
    })?;
    // SAFETY: directory owns a live descriptor, name is NUL-terminated, and
    // unlinkat does not retain the pointer.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn remove_temp(temp: &TemporaryFile) -> io::Result<()> {
    unlink_at(&temp.directory, &temp.name).and_then(|()| temp.directory.sync_all())
}

#[cfg(test)]
mod directory_scan_tests {
    use super::{
        DirectoryStream, read_dir_names, read_dir_names_with, read_next_directory_entry, set_errno,
    };
    use std::{
        ffi::{CStr, OsStr, OsString},
        fs::File,
        io,
        os::unix::ffi::OsStrExt,
        path::Path,
    };

    fn directory_with_file(name: &str) -> (tempfile::TempDir, File) {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        std::fs::write(temporary.path().join(name), b"payload").expect("create directory entry");
        let directory = super::super::fs::open_directory(Path::new(temporary.path()))
            .expect("open temporary directory");
        (temporary, directory)
    }

    #[test]
    fn directory_scan_returns_readdir_error_instead_of_a_partial_name_list() {
        let (_temporary, directory) = directory_with_file("live.narinfo");
        let mut returned_live_name = false;
        let result = read_dir_names_with(&directory, |stream| {
            if returned_live_name {
                set_errno(libc::EIO);
                return std::ptr::null_mut();
            }
            // SAFETY: the callback receives the live DIR handle owned by the
            // DirectoryStream created by read_dir_names_with.
            let entry = unsafe { libc::readdir(stream) };
            if !entry.is_null() {
                // SAFETY: readdir returned a live dirent with a NUL-terminated
                // name, valid until the next readdir call.
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                returned_live_name |= name.to_bytes() == b"live.narinfo";
            }
            entry
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn readdir_clears_stale_errno_before_recognizing_eof() {
        let (_temporary, directory) = directory_with_file("entry");
        let mut stream = DirectoryStream::open(&directory).expect("open directory stream");
        set_errno(libc::EIO);

        let result = stream.visit_names(
            |_| std::ptr::null_mut(),
            |_| panic!("EOF must not visit a directory entry"),
        );

        assert!(result.is_ok());
        stream.close().expect("close directory stream");
    }

    #[test]
    fn streaming_scan_borrows_names_and_propagates_visitor_errors() {
        let (_temporary, directory) = directory_with_file("live.narinfo");
        let mut stream = DirectoryStream::open(&directory).expect("open directory stream");
        let mut visited = Vec::new();

        let result = stream.visit_names(read_next_directory_entry, |name| {
            assert_eq!(name, OsStr::from_bytes(b"live.narinfo"));
            visited.push(name.as_bytes().to_vec());
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        });

        assert_eq!(visited, [b"live.narinfo".to_vec()]);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EINVAL));
        stream.close().expect("close directory stream");
    }

    #[test]
    fn production_directory_scan_skips_dot_entries_and_collects_names() {
        let (_temporary, directory) = directory_with_file("live.narinfo");

        let names = read_dir_names(&directory).expect("read directory names");

        assert_eq!(names, [OsString::from("live.narinfo")]);
    }
}
