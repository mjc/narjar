//! Windows directory capabilities. Paths are used only to bootstrap a drive
//! root; every subsequent lookup and namespace change uses retained handles.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io, mem,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};

use fs_at::os::windows::OpenOptionsExt as AtOpenOptionsExt;
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_LINK_INFORMATION, FILE_NON_DIRECTORY_FILE,
            FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
            FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
            FILE_SYNCHRONOUS_IO_NONALERT, FileLinkInformation, FileRenameInformationEx,
            NtCreateFile, NtSetInformationFile,
        },
    },
    Win32::{
        Foundation::{
            INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
        },
        Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FileDispositionInfoEx, GetFileType,
            READ_CONTROL, ReOpenFile, SYNCHRONIZE, SetFileInformationByHandle, WRITE_DAC,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

use super::{
    EntryKind, EntryMetadata, FileAccess, FileCreation, FilePrivacy, FileStamp, LeaseCreation,
};

pub(super) fn is_link_traversal_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_CANT_ACCESS_FILE as i32)
}

#[path = "windows/control.rs"]
mod control;
#[path = "windows/enumeration.rs"]
mod enumeration;
#[path = "windows/security.rs"]
mod security;
pub(crate) use control::ControlPipeName;

const DIRECTORY_TRAVERSAL_ACCESS: u32 = FILE_READ_ATTRIBUTES | READ_CONTROL;

pub(crate) fn validate_file_privacy_at(
    parent: &File,
    name: &OsStr,
    privacy: FilePrivacy,
) -> io::Result<()> {
    let file = inspect_entry_at(parent, name)?;
    require_kind(&file, Kind::Regular)?;
    validate_file_privacy(&file, privacy)
}

#[derive(Clone, Copy)]
enum Kind {
    Directory,
    Regular,
}

/// A single unambiguous NTFS child name, preserved as UTF-16 without conversion.
struct ChildName(OsString);

impl ChildName {
    fn new(name: &OsStr) -> io::Result<Self> {
        let wide: Vec<u16> = name.encode_wide().collect();
        if wide.is_empty() || wide.len() > 255 {
            return Err(invalid_input(
                "child name must contain 1 to 255 UTF-16 code units",
            ));
        }
        if wide
            .iter()
            .any(|unit| *unit < 32 || b"<>:\"/\\|?*".iter().any(|byte| u16::from(*byte) == *unit))
            || wide.last() == Some(&u16::from(b'.'))
            || wide.last() == Some(&u16::from(b' '))
        {
            return Err(invalid_input(
                "child name contains an ADS, separator, or ambiguous Windows suffix",
            ));
        }
        let stem = wide
            .split(|unit| *unit == u16::from(b'.'))
            .next()
            .unwrap_or(&[]);
        let stem_end = stem
            .iter()
            .rposition(|unit| *unit != u16::from(b' '))
            .map_or(0, |index| index + 1);
        let stem = &stem[..stem_end];
        let upper: Vec<u16> = stem
            .iter()
            .map(|unit| {
                if (u16::from(b'a')..=u16::from(b'z')).contains(unit) {
                    unit - 32
                } else {
                    *unit
                }
            })
            .collect();
        let reserved = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
            .iter()
            .any(|name| upper.iter().copied().eq(name.encode_utf16()));
        let numbered_device = upper.len() == 4
            && (upper.starts_with(&[67, 79, 77]) || upper.starts_with(&[76, 80, 84]))
            && ((48..=57).contains(&upper[3]) || [0x00b9, 0x00b2, 0x00b3].contains(&upper[3]));
        if reserved || numbered_device {
            return Err(invalid_input("DOS device names are not storage names"));
        }
        Ok(Self(name.to_owned()))
    }

    fn path(&self) -> &Path {
        Path::new(&self.0)
    }
}

fn relative_names(path: &Path) -> io::Result<Vec<ChildName>> {
    path.components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            Component::Normal(name) => Some(ChildName::new(name)),
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => Some(Err(
                invalid_input("child paths must be relative and cannot contain '..'"),
            )),
        })
        .collect()
}

fn require_kind(file: &File, kind: Kind) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid_data("reparse points are not supported"));
    }
    // SAFETY: file is borrowed for the call; GetFileType does not consume it.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(invalid_data("a disk filesystem object is required"));
    }
    let valid = match kind {
        Kind::Directory => metadata.is_dir(),
        Kind::Regular => metadata.is_file(),
    };
    if !valid {
        return Err(invalid_data("filesystem object has the wrong type"));
    }
    Ok(())
}

fn open_child(parent: &File, name: &Path, kind: Kind, access: u32) -> io::Result<File> {
    require_kind(parent, Kind::Directory)?;
    // fs_at 0.2.1 sends this one component to NtCreateFile.RootDirectory.
    // Inspect the opened kind ourselves: NT's NON_DIRECTORY_FILE mismatch is
    // ACCESS_DENIED, which would hide invalid entries as operational I/O errors.
    let file = fs_at::OpenOptions::default()
        .desired_access(access | FILE_READ_ATTRIBUTES | READ_CONTROL)
        .create_options(FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT)
        .object_attributes(OBJ_CASE_INSENSITIVE)
        .open_path_at(parent, name)?;
    require_kind(&file, kind)?;
    Ok(file)
}

/// Opens the single named entry itself for structural inspection. A reparse
/// object is returned as-is; callers must classify the opened object's type
/// before treating it as a directory or a serving file.
pub(crate) fn inspect_entry_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = ChildName::new(name)?;
    require_kind(parent, Kind::Directory)?;
    // open_path_at uses NtCreateFile.RootDirectory and deliberately does not
    // reject the opened link. No DIRECTORY_FILE or NON_DIRECTORY_FILE flag is
    // set: inventory must be able to inspect unexpected types as well.
    fs_at::OpenOptions::default()
        .desired_access(FILE_READ_ATTRIBUTES | READ_CONTROL)
        .create_options(FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT)
        .object_attributes(OBJ_CASE_INSENSITIVE)
        .open_path_at(parent, name.path())
}

pub(crate) fn entry_metadata_at(parent: &File, name: &OsStr) -> io::Result<EntryMetadata> {
    let handle = inspect_entry_at(parent, name)?;
    let metadata = handle.metadata()?;
    let kind = if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryKind::Other
    } else if metadata.is_dir() {
        EntryKind::Directory
    } else if metadata.is_file() {
        EntryKind::Regular
    } else {
        EntryKind::Other
    };
    Ok(EntryMetadata {
        kind,
        stamp: FileStamp::from_file(&handle)?,
    })
}

fn walk_directories(parent: &File, names: &[ChildName], final_access: u32) -> io::Result<File> {
    match names.split_last() {
        Some((name, ancestors)) => {
            let directory = open_directory_ancestors(parent, ancestors)?;
            open_child(&directory, name.path(), Kind::Directory, final_access)
        }
        None => reopen(parent, Kind::Directory, final_access),
    }
}

fn open_directory_ancestors(parent: &File, names: &[ChildName]) -> io::Result<File> {
    names
        .iter()
        .try_fold(parent.try_clone()?, |directory, name| {
            open_child(
                &directory,
                name.path(),
                Kind::Directory,
                DIRECTORY_TRAVERSAL_ACCESS,
            )
        })
}

fn reopen(file: &File, kind: Kind, access: u32) -> io::Result<File> {
    match kind {
        // An empty NT name reopens this retained directory itself. It never
        // resolves the old pathname and gives enumeration an independent cursor.
        Kind::Directory => open_child(file, Path::new(""), kind, access),
        Kind::Regular => reopen_regular_file(file, access),
    }
}

fn reopen_regular_file(file: &File, access: u32) -> io::Result<File> {
    require_kind(file, Kind::Regular)?;
    // SAFETY: file is retained throughout this synchronous, handle-bound
    // reopen. The returned handle owns a new file object and independent cursor.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            access | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ReOpenFile succeeded and transferred one owned file handle.
    let reopened = unsafe { File::from_raw_handle(handle) };
    require_kind(&reopened, Kind::Regular)?;
    Ok(reopened)
}

fn host_path(path: &Path) -> io::Result<(PathBuf, Vec<ChildName>)> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        if path.has_root()
            || path.components().any(|component| match component {
                Component::Prefix(_) => true,
                _ => false,
            })
        {
            return Err(invalid_input(
                "drive-relative and rooted-without-drive paths are unsupported",
            ));
        }
        std::env::current_dir()?.join(path)
    };
    let mut components = absolute.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err(invalid_input("DATA requires a local drive path")),
        },
        _ => return Err(invalid_input("an absolute local drive path is required")),
    };
    match components.next() {
        Some(Component::RootDir) => {}
        _ => return Err(invalid_input("an absolute local drive path is required")),
    }
    let names = components
        .filter_map(|component| match component {
            Component::Normal(name) => Some(ChildName::new(name)),
            Component::CurDir => None,
            _ => Some(Err(invalid_input("parent traversal is unsupported"))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    // This names only the drive root. No child path is reconstructed from an
    // opened handle, and no operation depends on DATA retaining its pathname.
    Ok((
        PathBuf::from(format!("\\\\?\\{}:\\", char::from(drive))),
        names,
    ))
}

fn open_host_parent(path: &Path) -> io::Result<(File, Vec<ChildName>)> {
    let (root, names) = host_path(path)?;
    let directory = OpenOptions::new()
        .access_mode(DIRECTORY_TRAVERSAL_ACCESS)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(root)?;
    require_kind(&directory, Kind::Directory)?;
    Ok((directory, names))
}

pub fn open_directory(path: &Path) -> io::Result<File> {
    let (root, names) = open_host_parent(path)?;
    walk_directories(&root, &names, FILE_GENERIC_READ | FILE_GENERIC_WRITE)
}

pub fn open_directory_at(parent: &File, path: impl AsRef<Path>) -> io::Result<File> {
    walk_directories(
        parent,
        &relative_names(path.as_ref())?,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
    )
}

pub fn open_regular_at(parent: &File, path: impl AsRef<Path>) -> io::Result<File> {
    let names = relative_names(path.as_ref())?;
    let (name, ancestors) = names
        .split_last()
        .ok_or_else(|| invalid_input("a regular-file name is required"))?;
    let directory = walk_directories(parent, ancestors, DIRECTORY_TRAVERSAL_ACCESS)?;
    open_child(
        &directory,
        name.path(),
        Kind::Regular,
        regular_access_rights(FileAccess::Read),
    )
}

pub fn open_regular(path: &Path) -> io::Result<File> {
    let (root, names) = open_host_parent(path)?;
    let (name, ancestors) = names
        .split_last()
        .ok_or_else(|| invalid_input("a regular-file name is required"))?;
    let directory = walk_directories(&root, ancestors, DIRECTORY_TRAVERSAL_ACCESS)?;
    open_child(
        &directory,
        name.path(),
        Kind::Regular,
        regular_access_rights(FileAccess::Read),
    )
}

fn create_child(
    parent: &File,
    name: &ChildName,
    kind: Kind,
    access: u32,
    disposition: u32,
    privacy: FilePrivacy,
) -> io::Result<File> {
    create_child_with_sharing(
        parent,
        name,
        kind,
        access,
        disposition,
        privacy,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

fn create_child_with_sharing(
    parent: &File,
    name: &ChildName,
    kind: Kind,
    access: u32,
    disposition: u32,
    privacy: FilePrivacy,
    sharing: u32,
) -> io::Result<File> {
    require_kind(parent, Kind::Directory)?;
    let descriptor = security::Descriptor::for_creation(
        privacy,
        match kind {
            Kind::Directory => true,
            Kind::Regular => false,
        },
    )?;
    let mut wide: Vec<u16> = name.0.encode_wide().collect();
    let length =
        u16::try_from(wide.len() * 2).map_err(|_| invalid_input("child name is too long"))?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.as_ptr(),
        SecurityQualityOfService: ptr::null(),
    };
    let type_flag = match kind {
        Kind::Directory => FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
        Kind::Regular => FILE_NON_DIRECTORY_FILE,
    };
    let mut handle = ptr::null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer references initialized storage retained through
    // this synchronous call. The protected descriptor is installed at birth;
    // no secret is written before its ACL exists. The name is one component.
    nt_result(unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            sharing,
            disposition,
            type_flag | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    })?;
    // SAFETY: successful NtCreateFile transfers one owned file handle.
    let file = unsafe { File::from_raw_handle(handle) };
    require_kind(&file, kind)?;
    security::validate(&file, privacy)?;
    Ok(file)
}

/// Opens an independent lease-file handle relative to the retained DATA
/// directory. Omitting delete sharing prevents lock replacement while this
/// handle lives; acquiring and releasing the process lock belongs to its owner.
pub(crate) fn open_process_lease_at(root: &File, creation: LeaseCreation) -> io::Result<File> {
    let name = ChildName::new(OsStr::new("lock"))?;
    create_child_with_sharing(
        root,
        &name,
        Kind::Regular,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        match creation {
            LeaseCreation::Existing => FILE_OPEN,
            LeaseCreation::CreateIfMissing => FILE_OPEN_IF,
        },
        FilePrivacy::Private,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

pub fn ensure_directory_at(parent: &File, name: &OsStr, label: &str) -> io::Result<File> {
    let name = ChildName::new(name)?;
    let directory = create_child(
        parent,
        &name,
        Kind::Directory,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC,
        FILE_OPEN_IF,
        FilePrivacy::Public,
    )?;
    validate_directory(&directory, label)
}

pub fn validate_directory(directory: &File, label: &str) -> io::Result<File> {
    require_kind(directory, Kind::Directory)?;
    security::validate(directory, FilePrivacy::Public).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{label} has unsafe permissions: {error}"),
        )
    })?;
    directory.try_clone()
}

pub fn directory_names(directory: &File) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
    let cursor = reopen(directory, Kind::Directory, FILE_GENERIC_READ)?;
    enumeration::Names::new(cursor)
}

pub(crate) fn open_writable_at(
    parent: &File,
    name: &OsStr,
    access: FileAccess,
    creation: FileCreation,
    privacy: FilePrivacy,
) -> io::Result<File> {
    let name = ChildName::new(name)?;
    let desired = regular_access_rights(access);
    if let (FileAccess::Read, FileCreation::Truncate) = (access, creation) {
        return Err(invalid_input("truncation requires write access"));
    }
    let file = match creation {
        FileCreation::Existing | FileCreation::Truncate => {
            open_child(parent, name.path(), Kind::Regular, desired)?
        }
        FileCreation::CreateNew => {
            create_child(parent, &name, Kind::Regular, desired, FILE_CREATE, privacy)?
        }
        FileCreation::OpenOrCreate => {
            create_child(parent, &name, Kind::Regular, desired, FILE_OPEN_IF, privacy)?
        }
    };
    security::validate(&file, privacy)?;
    // Never use FILE_OVERWRITE_IF: it can convert a reparse object before
    // validation. Truncate the validated regular-file handle instead.
    if let FileCreation::Truncate = creation {
        file.set_len(0)?;
    }
    Ok(file)
}

fn regular_access_rights(access: FileAccess) -> u32 {
    match access {
        FileAccess::Read => FILE_GENERIC_READ,
        FileAccess::Write => FILE_GENERIC_WRITE | WRITE_DAC,
        FileAccess::ReadWrite => FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC,
    }
}

pub fn validate_private_file(file: &File) -> io::Result<()> {
    require_kind(file, Kind::Regular)?;
    security::validate(file, FilePrivacy::Private)
}

pub(crate) fn validate_private_directory(directory: &File) -> io::Result<()> {
    require_kind(directory, Kind::Directory)?;
    security::validate(directory, FilePrivacy::Private)
}

pub(crate) fn validate_managed_file_privacy(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    require_kind(file, Kind::Regular)?;
    security::validate(file, privacy)
}

pub(crate) fn validate_file_privacy(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let kind = if file.metadata()?.is_dir() {
        Kind::Directory
    } else {
        Kind::Regular
    };
    require_kind(file, kind)?;
    security::validate(file, privacy)
}

/// Reopens the same object for WRITE_DAC without resolving its pathname.
pub(crate) fn set_file_privacy(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let kind = if file.metadata()?.is_dir() {
        Kind::Directory
    } else {
        Kind::Regular
    };
    require_kind(file, kind)?;
    let writable_security = reopen(file, kind, WRITE_DAC)?;
    security::set(&writable_security, privacy)
}

/// Creates the final directory exclusively; ancestors must already exist.
pub fn create_private_directory(path: &Path) -> io::Result<File> {
    let (root, names) = open_host_parent(path)?;
    let (name, ancestors) = names
        .split_last()
        .ok_or_else(|| invalid_input("a new directory name is required"))?;
    let parent = walk_directories(
        &root,
        ancestors,
        DIRECTORY_TRAVERSAL_ACCESS | FILE_GENERIC_WRITE,
    )?;
    let directory = create_child(
        &parent,
        name,
        Kind::Directory,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC,
        FILE_CREATE,
        FilePrivacy::Private,
    )?;
    // Establish the new name before callers depend on the private directory.
    parent.sync_all()?;
    Ok(directory)
}

struct NameBuffer(Vec<usize>);

impl NameBuffer {
    fn new<T>(name: &ChildName, name_offset: usize) -> Self {
        let length = name.0.encode_wide().count() * 2;
        Self(vec![
            0;
            mem::size_of::<T>()
                .max(name_offset + length)
                .div_ceil(mem::size_of::<usize>())
        ])
    }

    fn copy_name(&mut self, name: &ChildName, offset: usize) -> u32 {
        let wide: Vec<u16> = name.0.encode_wide().collect();
        // SAFETY: new() allocated the complete fixed header and UTF-16 tail;
        // the SDK name offsets are u16 aligned and neither allocation aliases.
        unsafe {
            ptr::copy_nonoverlapping(
                wide.as_ptr(),
                self.0.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                wide.len(),
            );
        }
        (wide.len() * 2) as u32
    }
}

pub fn hard_link_at(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source = ChildName::new(source_name)?;
    let destination = ChildName::new(destination_name)?;
    require_kind(destination_directory, Kind::Directory)?;
    let file = open_child(
        source_directory,
        source.path(),
        Kind::Regular,
        FILE_READ_ATTRIBUTES | DELETE,
    )?;
    let offset = mem::offset_of!(FILE_LINK_INFORMATION, FileName);
    let mut buffer = NameBuffer::new::<FILE_LINK_INFORMATION>(&destination, offset);
    let mut info = FILE_LINK_INFORMATION::default();
    info.RootDirectory = destination_directory.as_raw_handle();
    info.FileNameLength = (destination.0.encode_wide().count() * 2) as u32;
    // SAFETY: NameBuffer is usize aligned and sized for this SDK structure.
    // The default union has ReplaceIfExists=false: immutable publication.
    unsafe {
        ptr::write(buffer.0.as_mut_ptr().cast::<FILE_LINK_INFORMATION>(), info);
    }
    buffer.copy_name(&destination, offset);
    set_name_information(&file, &buffer, FileLinkInformation)
}

pub fn rename_at(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source = ChildName::new(source_name)?;
    let destination = ChildName::new(destination_name)?;
    require_kind(destination_directory, Kind::Directory)?;
    let file = open_child(
        source_directory,
        source.path(),
        Kind::Regular,
        FILE_READ_ATTRIBUTES | DELETE,
    )?;
    let offset = mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let mut buffer = NameBuffer::new::<FILE_RENAME_INFORMATION>(&destination, offset);
    let mut info = FILE_RENAME_INFORMATION::default();
    info.Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
    info.RootDirectory = destination_directory.as_raw_handle();
    info.FileNameLength = (destination.0.encode_wide().count() * 2) as u32;
    // SAFETY: NameBuffer has the SDK structure's alignment and full tail size.
    unsafe {
        ptr::write(
            buffer.0.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>(),
            info,
        );
    }
    buffer.copy_name(&destination, offset);
    set_name_information(&file, &buffer, FileRenameInformationEx)
}

fn set_name_information(file: &File, buffer: &NameBuffer, class: i32) -> io::Result<()> {
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: file was opened for synchronous IO; this call completes before
    // the aligned, initialized name buffer or the status block is dropped.
    nt_result(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            buffer.0.as_ptr().cast(),
            (buffer.0.len() * mem::size_of::<usize>()) as u32,
            class,
        )
    })
}

pub fn unlink_at(directory: &File, name: &OsStr) -> io::Result<()> {
    let name = ChildName::new(name)?;
    let file = open_child(
        directory,
        name.path(),
        Kind::Regular,
        FILE_READ_ATTRIBUTES | DELETE,
    )?;
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: file remains open and the initialized fixed-size SDK structure
    // is borrowed for the synchronous call. Removal is bound to this handle.
    bool_result(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            mem::size_of_val(&disposition) as u32,
        )
    })?;
    drop(file);
    Ok(())
}

fn bool_result(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn nt_result(status: i32) -> io::Result<()> {
    if status < 0 {
        // SAFETY: this pure system mapping accepts every NTSTATUS value.
        Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ))
    } else {
        Ok(())
    }
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestors_can_deny_listing_without_blocking_child_creation_or_reads() {
        use std::io::{Read, Write};

        let root = tempfile::tempdir().unwrap();
        let root_directory = open_directory(root.path()).unwrap();
        let ancestor_path = root.path().join("unlisted");
        let ancestor = create_private_directory(&ancestor_path).unwrap();
        let payload_path = ancestor_path.join("payload");
        {
            // Give the payload its own protected ACL: changing its parent's
            // inheritance must deny listing, not remove the payload's grants.
            let mut payload = open_writable_at(
                &ancestor,
                OsStr::new("payload"),
                FileAccess::Write,
                FileCreation::CreateNew,
                FilePrivacy::Private,
            )
            .unwrap();
            payload.write_all(b"payload").unwrap();
        }
        let restore_permissions = scopeguard::guard(ancestor, |directory| {
            let _ = security::set(&directory, FilePrivacy::Private);
        });
        security::deny_directory_listing(&restore_permissions).unwrap();
        assert_eq!(
            open_directory(&ancestor_path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "the fixture must actually deny directory-list access"
        );

        let cache_path = ancestor_path.join("cache");
        let created = create_private_directory(&cache_path).unwrap();
        validate_private_directory(&created).unwrap();
        let reopened = open_directory(&cache_path).unwrap();
        assert!(reopened.metadata().unwrap().is_dir());
        for mut file in [
            open_regular(&payload_path).unwrap(),
            open_regular_at(&root_directory, Path::new("unlisted").join("payload")).unwrap(),
        ] {
            validate_private_file(&file).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"payload");
        }
    }

    #[test]
    fn a_directory_at_a_regular_file_location_is_invalid_content_not_access_denial() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("record")).unwrap();
        let directory = open_directory(root.path()).unwrap();
        assert_eq!(
            open_regular_at(&directory, "record").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn independent_directory_handles_have_the_access_required_for_enumeration() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).expect("open writable directory capability");
        let cursor = reopen(&directory, Kind::Directory, FILE_GENERIC_READ)
            .expect("reopen an independent read-only directory cursor");
        let entries = enumeration::Names::new(cursor)
            .expect("start directory enumeration")
            .collect::<io::Result<Vec<_>>>()
            .expect("finish directory enumeration");
        assert!(
            crate::cache::filesystem::exclude_dot_directory_entries(entries.into_iter().map(Ok))
                .next()
                .is_none()
        );
    }

    #[test]
    fn private_directory_creation_can_set_and_verify_its_dacl() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private");
        let directory =
            create_private_directory(&path).expect("create directory with private DACL");
        set_file_privacy(&directory, FilePrivacy::Private)
            .expect("normalize private directory DACL");
        validate_private_directory(&directory).expect("verify normalized directory DACL");
        directory
            .sync_all()
            .expect("synchronize writable directory");
    }
}
