use std::{fs::File, io, os::windows::io::AsRawHandle, ptr};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_NAME_OPENED, GetDiskFreeSpaceExW, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, VOLUME_NAME_GUID,
};

use super::{InodeCapacity, StorageCapacity};

const READ_ONLY_VOLUME: u32 = 0x0008_0000;
const VOLUME_ROOT_UNITS: usize = 49;
const MAX_PATH_UNITS: usize = 32_768;

pub(crate) fn filesystem_space(directory: &File) -> io::Result<StorageCapacity> {
    let root = volume_guid_root(directory)?;
    let mut total_bytes = 0;
    let mut available_bytes = 0;
    let mut flags = 0;
    // SAFETY: root is NUL-terminated and every output points to a live u64.
    // The volume GUID comes from the retained handle, not the caller's DATA path.
    let measured = unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            &mut available_bytes,
            &mut total_bytes,
            ptr::null_mut(),
        )
    };
    if measured == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the borrowed handle stays open; only flags is requested and it
    // points to a live u32. Unrequested output buffers are null with zero lengths.
    let measured = unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            ptr::null_mut(),
            0,
        )
    };
    if measured == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(StorageCapacity {
        total_bytes,
        available_bytes,
        inodes: InodeCapacity::NotReported,
        read_only: flags & READ_ONLY_VOLUME != 0,
    })
}

fn volume_guid_root(directory: &File) -> io::Result<[u16; VOLUME_ROOT_UNITS + 1]> {
    let mut path = vec![0; 512];
    let required = query_volume_guid_path(directory, &mut path)?;
    if required >= path.len() {
        if required > MAX_PATH_UNITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "volume path exceeds the Windows path limit",
            ));
        }
        path.resize(required, 0);
        if query_volume_guid_path(directory, &mut path)? >= path.len() {
            return Err(io::Error::other(
                "volume path changed while measuring capacity",
            ));
        }
    }
    let mut root = [0; VOLUME_ROOT_UNITS + 1];
    root[..VOLUME_ROOT_UNITS].copy_from_slice(&path[..VOLUME_ROOT_UNITS]);
    if !root.starts_with(&r"\\?\Volume{".encode_utf16().collect::<Vec<_>>())
        || root[VOLUME_ROOT_UNITS - 2] != u16::from(b'}')
        || root[VOLUME_ROOT_UNITS - 1] != u16::from(b'\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage requires a local Windows volume",
        ));
    }
    Ok(root)
}

fn query_volume_guid_path(directory: &File, path: &mut [u16]) -> io::Result<usize> {
    // SAFETY: the borrowed handle and writable UTF-16 buffer outlive the call;
    // the declared length is the actual allocated buffer length.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            directory.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID | FILE_NAME_OPENED,
        )
    };
    match length {
        0 => Err(io::Error::last_os_error()),
        length => Ok(length as usize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_uses_the_retained_volume_after_the_data_directory_is_moved() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("data");
        std::fs::create_dir(&path).unwrap();
        let directory = crate::cache::filesystem::open_directory(&path).unwrap();
        let before = volume_guid_root(&directory).unwrap();
        std::fs::rename(&path, parent.path().join("moved")).unwrap();
        assert_eq!(volume_guid_root(&directory).unwrap(), before);
        let capacity = filesystem_space(&directory).unwrap();
        assert!(capacity.total_bytes > 0);
        assert!(capacity.available_bytes <= capacity.total_bytes);
        assert_eq!(capacity.inodes, InodeCapacity::NotReported);
        assert!(!capacity.read_only);
    }
}
