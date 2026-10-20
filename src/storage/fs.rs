use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
};

use super::StorageError;
use super::publication::TemporaryFile;
#[cfg(test)]
use crate::cache::filesystem::open_directory;
pub(super) use crate::cache::filesystem::open_writable_at as open_at;
#[cfg(target_os = "linux")]
pub(super) use crate::cache::filesystem::sync_filesystem;
use crate::cache::filesystem::{
    EntryKind, FilePrivacy, FileStamp, entry_metadata_at, validate_file_privacy,
};
use crate::cache::filesystem::{directory_names, exclude_dot_directory_entries};
pub(super) use crate::cache::filesystem::{ensure_directory_at, validate_directory};
pub(super) use crate::cache::filesystem::{hard_link_at, rename_at, unlink_at};
pub(crate) use crate::cache::filesystem::{open_directory_at, open_regular_at, read_dir_names};
#[cfg(test)]
use std::path::Path;

const COMPARE_BUFFER_BYTES: usize = 16 * 1024;

pub(super) fn require_directory_at(parent: &File, name: &str) -> io::Result<File> {
    let directory = open_directory_at(parent, OsStr::new(name))
        .map_err(|error| io::Error::new(error.kind(), format!("{name} is unavailable: {error}")))?;
    validate_directory(&directory, name)
}

/// Required permission bits for private layout and policy files.
pub const fn private_file_mode_is_valid(mode: u32) -> bool {
    mode & 0o777 == 0o600
}

pub(super) fn require_private_file_at(
    parent: &File,
    name: &str,
    required: bool,
) -> io::Result<bool> {
    match open_regular_at(parent, OsStr::new(name)) {
        Ok(file) => {
            validate_file_privacy(&file, FilePrivacy::Private)
                .map_err(|error| io::Error::new(error.kind(), format!("{name}: {error}")))?;
            Ok(true)
        }
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("{name} is unavailable: {error}"),
        )),
    }
}

pub(crate) fn entry_is_regular_at(directory: &File, name: &OsStr) -> io::Result<bool> {
    Ok(entry_metadata_at(directory, name)?.kind == EntryKind::Regular)
}

pub(crate) fn entry_is_directory_at(directory: &File, name: &OsStr) -> io::Result<bool> {
    Ok(entry_metadata_at(directory, name)?.kind == EntryKind::Directory)
}

pub(crate) fn entry_identity_at(directory: &File, name: &OsStr) -> io::Result<FileStamp> {
    Ok(entry_metadata_at(directory, name)?.stamp)
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

#[cfg(test)]
fn read_dir_names_with(
    entries: impl Iterator<Item = io::Result<OsString>>,
) -> io::Result<Vec<OsString>> {
    exclude_dot_directory_entries(entries).collect()
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
    visit_directory_names(directory_names(directory)?, visit)
}

fn visit_directory_names(
    entries: impl Iterator<Item = io::Result<OsString>>,
    mut visit: impl FnMut(&OsStr) -> io::Result<DirectoryEntryAction>,
) -> io::Result<DirectoryScanOutcome> {
    for name in exclude_dot_directory_entries(entries) {
        let name = name?;
        match visit(&name)? {
            DirectoryEntryAction::Continue => {}
            DirectoryEntryAction::Stop => return Ok(DirectoryScanOutcome::StoppedEarly),
        }
    }
    Ok(DirectoryScanOutcome::Complete)
}

pub(super) fn rollback_link_at(directory: &File, name: &OsStr) -> Result<(), StorageError> {
    unlink_at(directory, name)?;
    directory.sync_all()?;
    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImmutableLinkOutcome {
    Created,
    Identical,
    Collision,
}

/// Place immutable bytes without overwriting; synchronization and cleanup belong to the caller.
pub(super) fn link_or_compare_immutable(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<ImmutableLinkOutcome> {
    match hard_link_at(
        source_directory,
        source_name,
        destination_directory,
        destination_name,
    ) {
        Ok(()) => Ok(ImmutableLinkOutcome::Created),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            match files_equal_at(
                source_directory,
                source_name,
                destination_directory,
                destination_name,
            )? {
                true => Ok(ImmutableLinkOutcome::Identical),
                false => Ok(ImmutableLinkOutcome::Collision),
            }
        }
        Err(error) => Err(error),
    }
}

pub(super) fn remove_temp(temp: &TemporaryFile) -> io::Result<()> {
    unlink_at(&temp.directory, &temp.name).and_then(|()| temp.directory.sync_all())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn immutable_link_classifies_retries_without_overwriting_destinations() {
        let root = tempfile::tempdir().expect("create directory");
        let directory = open_directory(root.path()).expect("open directory");
        let source = OsStr::new("source");
        let destination = OsStr::new("destination");
        std::fs::write(root.path().join(source), b"original").unwrap();
        assert_eq!(
            link_or_compare_immutable(&directory, source, &directory, destination).unwrap(),
            ImmutableLinkOutcome::Created
        );
        std::fs::write(root.path().join("retry"), b"original").unwrap();
        assert_eq!(
            link_or_compare_immutable(&directory, OsStr::new("retry"), &directory, destination)
                .unwrap(),
            ImmutableLinkOutcome::Identical
        );
        std::fs::write(root.path().join("different"), b"modified").unwrap();
        assert_eq!(
            link_or_compare_immutable(&directory, OsStr::new("different"), &directory, destination)
                .unwrap(),
            ImmutableLinkOutcome::Collision
        );
        assert_eq!(
            std::fs::read(root.path().join(destination)).unwrap(),
            b"original"
        );
        assert!(root.path().join("retry").exists());
        assert!(root.path().join("different").exists());
        assert_eq!(
            link_or_compare_immutable(&directory, OsStr::new("missing"), &directory, destination)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn relative_filesystem_operations_preserve_bytes_and_symlinks_after_directory_rename() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create root");
        let directory_path = root.path().join("original");
        std::fs::create_dir(&directory_path).expect("create directory");
        let directory = open_directory(&directory_path).expect("open directory");
        std::fs::rename(&directory_path, root.path().join("moved")).expect("move directory");
        let moved = root.path().join("moved");
        let source = OsStr::new("source");
        symlink("missing-target", moved.join(source)).expect("create dangling symlink");
        let (link, renamed) = match hard_link_at(
            &directory,
            source,
            &directory,
            OsStr::from_bytes(b"link-\xff"),
        ) {
            Ok(()) => (
                OsStr::from_bytes(b"link-\xff"),
                OsStr::from_bytes(b"renamed-\xff"),
            ),
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) => {
                hard_link_at(&directory, source, &directory, OsStr::new("link"))
                    .expect("hard link symlink itself");
                (OsStr::new("link"), OsStr::new("renamed"))
            }
            Err(error) => panic!("hard link raw-byte name: {error}"),
        };
        let metadata = std::fs::symlink_metadata(moved.join(source)).expect("stat symlink");
        let identity = entry_identity_at(&directory, link).expect("relative nofollow stat");
        assert_eq!(identity, FileStamp::from_metadata(&metadata));
        assert!(!entry_is_regular_at(&directory, link).expect("classify symlink"));
        assert_eq!(
            open_regular_at(&directory, link)
                .expect_err("must not follow symlink")
                .raw_os_error(),
            Some(rustix::io::Errno::LOOP.raw_os_error()),
        );

        rename_at(&directory, link, &directory, renamed).expect("rename raw-byte link");
        assert_eq!(
            std::fs::read_link(moved.join(renamed)).expect("read symlink"),
            Path::new("missing-target")
        );
        unlink_at(&directory, renamed).expect("unlink raw-byte link");
        assert_eq!(
            entry_metadata_at(&directory, renamed)
                .expect_err("link removed")
                .raw_os_error(),
            Some(rustix::io::Errno::NOENT.raw_os_error())
        );
        assert!(
            entry_metadata_at(&directory, source).is_ok(),
            "original link survives"
        );
    }

    #[test]
    fn name_iterator_eof_completes_scan() {
        let outcome = visit_directory_names(std::iter::empty(), |_| {
            panic!("empty iterator must not visit a name");
        })
        .expect("EOF completes scan");
        assert_eq!(outcome, DirectoryScanOutcome::Complete);
    }

    #[test]
    fn dot_entries_are_skipped() {
        let entries = [".", "..", "entry"].map(|name| Ok(OsString::from(name)));
        let names = read_dir_names_with(entries.into_iter()).expect("collect names");
        assert_eq!(names, [OsString::from("entry")]);
    }

    #[test]
    fn injected_readdir_error_propagates() {
        let result = visit_directory_names(
            std::iter::once(Err(io::Error::from_raw_os_error(
                rustix::io::Errno::IO.raw_os_error(),
            ))),
            |_| Ok(DirectoryEntryAction::Continue),
        );

        assert_eq!(
            result
                .expect_err("incomplete enumeration must fail")
                .raw_os_error(),
            Some(rustix::io::Errno::IO.raw_os_error())
        );
    }

    #[test]
    fn name_collection_rejects_readdir_error_after_a_real_entry() {
        let directory_path = tempfile::tempdir().expect("directory should be created");
        std::fs::write(directory_path.path().join("live.narinfo"), b"metadata")
            .expect("directory entry should be created");
        let directory = open_directory(directory_path.path()).expect("directory should open");
        let mut entries = directory_names(&directory).expect("open directory iterator");
        let mut returned_live_name = false;

        let error = read_dir_names_with(std::iter::from_fn(|| {
            if returned_live_name {
                return Some(Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::IO.raw_os_error(),
                )));
            }
            let entry = entries.next()?;
            if let Ok(name) = &entry {
                returned_live_name |= name == "live.narinfo";
            }
            Some(entry)
        }))
        .expect_err("a partial name list must not be returned as success");

        assert!(
            returned_live_name,
            "the real entry must precede the injected error"
        );
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::IO.raw_os_error())
        );
    }

    #[test]
    fn repeated_enumeration_restarts_after_early_stop() {
        let directory = tempfile::tempdir().expect("create directory");
        std::fs::write(directory.path().join("entry"), b"entry").expect("write entry");
        let directory = open_directory(directory.path()).expect("open directory");
        assert_eq!(
            for_each_dir_name(&directory, |_| Ok(DirectoryEntryAction::Stop))
                .expect("stop enumeration"),
            DirectoryScanOutcome::StoppedEarly,
        );
        for _ in 0..2 {
            assert_eq!(
                read_dir_names(&directory).expect("rescan"),
                [OsString::from("entry")]
            );
        }
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
            Err(io::Error::from_raw_os_error(
                rustix::io::Errno::ACCESS.raw_os_error(),
            ))
        })
        .expect_err("visitor error should propagate");

        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::ACCESS.raw_os_error())
        );
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
