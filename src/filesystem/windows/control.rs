//! Named-pipe namespace and security, independent of DATA's current pathname.

use std::{fs::File, io, mem, os::windows::io::FromRawHandle, ptr, time::Duration};

use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{GetLengthSid, GetSecurityDescriptorOwner, IsValidSid, SECURITY_ATTRIBUTES},
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::Pipes::{
        CreateNamedPipeW, GetNamedPipeInfo, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_SERVER_END, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_WAIT, WaitNamedPipeW,
    },
};

use super::{FilePrivacy, bool_result, invalid_data, security};
use crate::cache::filesystem::FileIdentity;

const MAX_INSTANCES: u32 = 16;
const BUFFER_BYTES: u32 = 16 * 1024;

/// Constructed only from a retained directory identity and the process's SID.
pub(crate) struct ControlPipeName(Vec<u16>);

impl ControlPipeName {
    pub(crate) fn for_directory(directory: &File) -> io::Result<Self> {
        let descriptor = security::Descriptor::for_creation(FilePrivacy::Private, false)?;
        let mut sid = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: the Windows-created descriptor and both outputs live through
        // the call. The returned SID borrows descriptor, which is retained below.
        bool_result(unsafe {
            GetSecurityDescriptorOwner(
                descriptor.as_ptr().cast_mut().cast(),
                &mut sid,
                &mut defaulted,
            )
        })?;
        // SAFETY: GetSecurityDescriptorOwner supplied this retained SID.
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(invalid_data(
                "control namespace requires a valid account SID",
            ));
        }
        // SAFETY: IsValidSid accepted the SID within the retained descriptor.
        let length = unsafe { GetLengthSid(sid) } as usize;
        // SAFETY: GetLengthSid gives the size of this Windows-supplied SID;
        // descriptor retains its allocation until the encoding is complete.
        let sid = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
        let identity = FileIdentity::from_file(directory)?.namespace_bytes();
        let name = format!(
            "\\\\.\\pipe\\narjar-control-v1-{}-{}",
            data_encoding::HEXLOWER.encode(sid),
            data_encoding::HEXLOWER.encode(&identity),
        );
        if name.len() > 256 {
            return Err(invalid_data(
                "control pipe namespace exceeds the Windows limit",
            ));
        }
        Ok(Self(name.encode_utf16().chain(Some(0)).collect()))
    }

    pub(crate) fn create_first(&self) -> io::Result<File> {
        self.create_instance(FILE_FLAG_FIRST_PIPE_INSTANCE)
    }

    pub(crate) fn create_next(&self) -> io::Result<File> {
        self.create_instance(0)
    }

    fn create_instance(&self, ownership_flag: u32) -> io::Result<File> {
        let descriptor = security::Descriptor::for_creation(FilePrivacy::Private, false)?;
        self.create_with_descriptor(ownership_flag, &descriptor)
    }

    fn create_with_descriptor(
        &self,
        ownership_flag: u32,
        descriptor: &security::Descriptor,
    ) -> io::Result<File> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr().cast_mut().cast(),
            bInheritHandle: 0,
        };
        // SAFETY: name is terminated by construction; attributes and its
        // self-relative descriptor live through the call, which copies the SD.
        let handle = unsafe {
            CreateNamedPipeW(
                self.0.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | ownership_flag,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                BUFFER_BYTES,
                BUFFER_BYTES,
                2_000,
                &attributes,
            )
        };
        owned_pipe(handle)
    }

    /// No application bytes are sent before checking the actual opened pipe.
    pub(crate) fn open_client(&self) -> io::Result<File> {
        // SAFETY: this is a locally constructed, terminated pipe name. SQOS
        // identification prevents a server from impersonating the client.
        let handle = unsafe {
            CreateFileW(
                self.0.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        let file = owned_pipe(handle)?;
        let mut flags = 0;
        // SAFETY: the live pipe is borrowed and flags is a valid output.
        bool_result(unsafe {
            GetNamedPipeInfo(
                std::os::windows::io::AsRawHandle::as_raw_handle(&file),
                &mut flags,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })?;
        if flags & (PIPE_SERVER_END | PIPE_TYPE_MESSAGE) != 0 {
            return Err(invalid_data(
                "control endpoint is not a byte-stream pipe client",
            ));
        }
        // Named pipes support SE_FILE_OBJECT GetSecurityInfo. Deliberately do
        // not use the disk-file kind check in validate_private_file here.
        security::validate(&file, FilePrivacy::Private)?;
        Ok(file)
    }

    pub(crate) fn wait_available(&self, remaining: Duration) -> io::Result<()> {
        // Zero selects the server default, and MAX selects an infinite wait.
        // Neither is appropriate for an explicit remaining deadline.
        let milliseconds = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .clamp(1, u128::from(u32::MAX - 1)) as u32;
        // SAFETY: name is locally constructed and NUL terminated.
        bool_result(unsafe { WaitNamedPipeW(self.0.as_ptr(), milliseconds) })
    }
}

fn owned_pipe(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<File> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe creation/open transfers exactly one owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::filesystem::open_directory;

    #[test]
    fn pipe_creation_is_private_and_first_instance_cannot_be_stolen() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).unwrap();
        let name = ControlPipeName::for_directory(&directory).unwrap();
        let first = name.create_first().unwrap();
        security::validate(&first, FilePrivacy::Private).unwrap();
        assert!(name.create_first().is_err());
        let next = name.create_next().unwrap();
        security::validate(&next, FilePrivacy::Private).unwrap();
    }

    #[test]
    fn a_client_rejects_a_pipe_with_broad_read_permissions() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).unwrap();
        let name = ControlPipeName::for_directory(&directory).unwrap();
        let public = security::Descriptor::for_creation(FilePrivacy::Public, false).unwrap();
        let _server = name
            .create_with_descriptor(FILE_FLAG_FIRST_PIPE_INSTANCE, &public)
            .unwrap();
        assert_eq!(
            name.open_client().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
