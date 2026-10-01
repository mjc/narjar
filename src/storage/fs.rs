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
    ptr::NonNull,
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
pub struct StorageCapacity {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
    pub read_only: bool,
}

impl StorageCapacity {
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
    measure: impl FnOnce() -> io::Result<StorageCapacity>,
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
    measure: impl FnOnce() -> io::Result<StorageCapacity>,
) -> Result<StagingReservation, StorageError> {
    reserve_staging_bytes_with_measurement(budget, min_free_bytes, bytes, measure)
}

pub(super) fn filesystem_space(directory: &File) -> io::Result<StorageCapacity> {
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();

    // SAFETY: directory owns a valid descriptor for the duration of the call,
    // and statistics points to writable storage for one statvfs value.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fstatvfs returned success, so it initialized statistics.
    let statistics = unsafe { statistics.assume_init() };
    Ok(capacity_from_statvfs(&statistics))
}

pub fn capacity_from_statvfs(statistics: &libc::statvfs) -> StorageCapacity {
    let scale = statistics.f_frsize as u128;
    let bytes = |blocks: libc::fsblkcnt_t| {
        (blocks as u128)
            .saturating_mul(scale)
            .min(u128::from(u64::MAX)) as u64
    };
    StorageCapacity {
        total_bytes: bytes(statistics.f_blocks),
        available_bytes: bytes(statistics.f_bavail),
        total_inodes: (statistics.f_files as u128).min(u128::from(u64::MAX)) as u64,
        available_inodes: (statistics.f_favail as u128).min(u128::from(u64::MAX)) as u64,
        read_only: statistics.f_flag & libc::ST_RDONLY != 0,
    }
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
    read_dir_names_with(directory, |stream| {
        // SAFETY: the callback receives the live stream owned by
        // DirectoryStream.
        unsafe { libc::readdir(stream) }
    })
}

fn read_dir_names_with(
    directory: &File,
    read_entry: impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    let outcome = for_each_dir_name_with(directory, read_entry, |name| {
        names.push(name.to_owned());
        Ok(DirectoryEntryAction::Continue)
    })?;
    debug_assert_eq!(outcome, DirectoryScanOutcome::Complete);
    Ok(names)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryEntryAction {
    Continue,
    Stop,
}

/// Whether directory enumeration reached EOF or the visitor stopped it early.
#[must_use = "check whether directory enumeration completed or stopped early"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryScanOutcome {
    Complete,
    StoppedEarly,
}

pub(crate) fn for_each_dir_name<F>(directory: &File, visit: F) -> io::Result<DirectoryScanOutcome>
where
    F: FnMut(&OsStr) -> io::Result<DirectoryEntryAction>,
{
    for_each_dir_name_with(
        directory,
        |stream| {
            // SAFETY: the callback receives the live stream owned by
            // DirectoryStream.
            unsafe { libc::readdir(stream) }
        },
        visit,
    )
}

fn for_each_dir_name_with<F>(
    directory: &File,
    mut read_entry: impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
    mut visit: F,
) -> io::Result<DirectoryScanOutcome>
where
    F: FnMut(&OsStr) -> io::Result<DirectoryEntryAction>,
{
    let stream = DirectoryStream::open(directory)?;
    let scan_result = visit_readdir_entries(
        || next_readdir_entry_with(|| read_entry(stream.as_ptr())),
        &mut visit,
    );
    let close_result = stream.close();
    scan_result.and_then(|outcome| close_result.map(|()| outcome))
}

struct DirectoryStream(Option<NonNull<libc::DIR>>);

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
        let Some(stream) = NonNull::new(stream) else {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not transfer ownership.
            unsafe { libc::close(fd) };
            return Err(error);
        };
        Ok(Self(Some(stream)))
    }

    fn as_ptr(&self) -> *mut libc::DIR {
        self.0.expect("directory stream is open").as_ptr()
    }

    fn close(mut self) -> io::Result<()> {
        let stream = self.0.take().expect("directory stream is open");
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
            // SAFETY: this guard owns the stream and closes it during
            // unwinding or when explicit close was not reached.
            unsafe { libc::closedir(stream.as_ptr()) };
        }
    }
}

fn visit_readdir_entries<F>(
    mut next_entry: impl FnMut() -> io::Result<Option<NonNull<libc::dirent>>>,
    mut visit: F,
) -> io::Result<DirectoryScanOutcome>
where
    F: FnMut(&OsStr) -> io::Result<DirectoryEntryAction>,
{
    use std::ops::ControlFlow;

    let mut entries = std::iter::from_fn(|| match next_entry() {
        Ok(Some(entry)) => Some(Ok(entry)),
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    });

    match entries.try_for_each(|entry| {
        let action = entry.and_then(|entry| visit_readdir_name(entry, &mut visit));
        match action {
            Ok(DirectoryEntryAction::Continue) => ControlFlow::Continue(()),
            Ok(DirectoryEntryAction::Stop) => {
                ControlFlow::Break(Ok(DirectoryScanOutcome::StoppedEarly))
            }
            Err(error) => ControlFlow::Break(Err(error)),
        }
    }) {
        ControlFlow::Continue(()) => Ok(DirectoryScanOutcome::Complete),
        ControlFlow::Break(result) => result,
    }
}

fn visit_readdir_name<F>(
    entry: NonNull<libc::dirent>,
    visit: &mut F,
) -> io::Result<DirectoryEntryAction>
where
    F: FnMut(&OsStr) -> io::Result<DirectoryEntryAction>,
{
    // SAFETY: the DIR stream owns this entry and it remains valid until
    // the next call to readdir.
    let name = unsafe { CStr::from_ptr(entry.as_ref().d_name.as_ptr()) };
    if name.to_bytes() == b"." || name.to_bytes() == b".." {
        return Ok(DirectoryEntryAction::Continue);
    }
    visit(OsStr::from_bytes(name.to_bytes()))
}

fn next_readdir_entry_with(
    mut read_entry: impl FnMut() -> *mut libc::dirent,
) -> io::Result<Option<NonNull<libc::dirent>>> {
    clear_errno();
    let entry = read_entry();
    if let Some(entry) = NonNull::new(entry) {
        return Ok(Some(entry));
    }
    let error_code = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default();
    classify_readdir_result(std::ptr::null_mut(), error_code)
}

fn classify_readdir_result(
    entry: *mut libc::dirent,
    error_code: i32,
) -> io::Result<Option<NonNull<libc::dirent>>> {
    match NonNull::new(entry) {
        Some(entry) => Ok(Some(entry)),
        None if error_code == 0 => Ok(None),
        None => Err(io::Error::from_raw_os_error(error_code)),
    }
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: this accesses the current thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: this accesses the current thread's errno slot.
    unsafe { *libc::__error() = 0 };
}

#[cfg(test)]
fn set_errno(error_code: libc::c_int) {
    #[cfg(target_os = "linux")]
    // SAFETY: this sets the current thread's errno slot for a controlled test.
    unsafe {
        *libc::__errno_location() = error_code;
    }
    #[cfg(target_os = "macos")]
    // SAFETY: this sets the current thread's errno slot for a controlled test.
    unsafe {
        *libc::__error() = error_code;
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
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn statvfs_capacity_conversion_saturates_bytes_and_inode_counts() {
        // SAFETY: `statvfs` contains only integer fields and integer arrays on
        // the supported Unix targets; zero is a valid initial value for each.
        let mut statistics: libc::statvfs = unsafe { std::mem::zeroed() };
        statistics.f_frsize = libc::c_ulong::MAX;
        statistics.f_blocks = libc::fsblkcnt_t::MAX;
        statistics.f_bavail = libc::fsblkcnt_t::MAX;
        statistics.f_files = libc::fsfilcnt_t::MAX;
        statistics.f_favail = libc::fsfilcnt_t::MAX;
        statistics.f_flag = libc::ST_RDONLY;

        let capacity = capacity_from_statvfs(&statistics);

        assert_eq!(capacity.total_bytes, u64::MAX);
        assert_eq!(capacity.available_bytes, u64::MAX);
        let maximum_inode_count =
            u128::from(libc::fsfilcnt_t::MAX).min(u128::from(u64::MAX)) as u64;
        assert_eq!(capacity.total_inodes, maximum_inode_count);
        assert_eq!(capacity.available_inodes, maximum_inode_count);
        assert!(capacity.read_only);
    }

    #[test]
    fn null_readdir_result_is_eof_only_when_errno_is_clear() {
        assert!(
            classify_readdir_result(ptr::null_mut(), 0)
                .expect("clean null result should be EOF")
                .is_none()
        );

        let error = classify_readdir_result(ptr::null_mut(), libc::EIO)
            .expect_err("readdir error must not be treated as EOF");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn readdir_eof_clears_errno_left_by_an_unrelated_syscall() {
        set_errno(libc::EIO);

        let entry = next_readdir_entry_with(std::ptr::null_mut::<libc::dirent>)
            .expect("EOF must not reuse stale errno as a scan failure");

        assert!(entry.is_none(), "a null result with clear errno is EOF");
    }

    #[test]
    fn injected_readdir_error_propagates() {
        let result = visit_readdir_entries(
            || Err(io::Error::from_raw_os_error(libc::EIO)),
            |_| Ok(DirectoryEntryAction::Continue),
        );

        assert_eq!(
            result
                .expect_err("incomplete enumeration must fail")
                .raw_os_error(),
            Some(libc::EIO)
        );
    }

    #[test]
    fn name_collection_rejects_readdir_error_after_a_real_entry() {
        let directory_path = tempfile::tempdir().expect("directory should be created");
        std::fs::write(directory_path.path().join("live.narinfo"), b"metadata")
            .expect("directory entry should be created");
        let directory = open_directory(directory_path.path()).expect("directory should open");
        let mut returned_live_name = false;

        let error = read_dir_names_with(&directory, |stream| {
            if returned_live_name {
                set_errno(libc::EIO);
                return std::ptr::null_mut();
            }
            // SAFETY: the callback receives the live stream owned by
            // DirectoryStream, and the entry is copied before the next read.
            let entry = unsafe { libc::readdir(stream) };
            if let Some(entry) = NonNull::new(entry) {
                // SAFETY: readdir returned a live, NUL-terminated name.
                let name = unsafe { CStr::from_ptr(entry.as_ref().d_name.as_ptr()) };
                returned_live_name |= name.to_bytes() == b"live.narinfo";
            }
            entry
        })
        .expect_err("a partial name list must not be returned as success");

        assert!(
            returned_live_name,
            "the real entry must precede the injected error"
        );
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn visitor_stop_is_reported_separately_from_successful_eof() {
        let directory = tempfile::tempdir().expect("directory should be created");
        std::fs::write(directory.path().join("entry"), b"entry").expect("entry should be written");
        let directory = open_directory(directory.path()).expect("directory should open");

        let outcome = for_each_dir_name(&directory, |_| Ok(DirectoryEntryAction::Stop))
            .expect("deliberate stop should not be an enumeration error");

        assert_eq!(outcome, DirectoryScanOutcome::StoppedEarly);
    }

    #[test]
    fn visitor_errors_remain_errors() {
        let directory = tempfile::tempdir().expect("directory should be created");
        std::fs::write(directory.path().join("entry"), b"entry").expect("entry should be written");
        let directory = open_directory(directory.path()).expect("directory should open");

        let error = for_each_dir_name(&directory, |_| {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        })
        .expect_err("visitor error should propagate");

        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn callback_panic_closes_directory_stream() {
        let directory_path = tempfile::tempdir().expect("directory should be created");
        std::fs::write(directory_path.path().join("entry"), b"entry")
            .expect("entry should be written");
        let directory = open_directory(directory_path.path()).expect("directory should open");
        let open_handles_for_directory = || {
            std::fs::read_dir("/proc/self/fd")
                .expect("process file descriptors should be readable")
                .filter_map(Result::ok)
                .filter_map(|descriptor| std::fs::read_link(descriptor.path()).ok())
                .filter(|target| target == directory_path.path())
                .count()
        };
        let handles_before_scan = open_handles_for_directory();

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = for_each_dir_name(&directory, |_| -> io::Result<DirectoryEntryAction> {
                panic!("injected visitor panic")
            });
        }));

        assert!(panic.is_err(), "the injected callback should panic");
        assert_eq!(
            open_handles_for_directory(),
            handles_before_scan,
            "unwinding must close the owned directory stream"
        );
    }
}
