//! Handle-bound owner and DACL checks. Unknown ACE forms fail closed.

use std::{
    ffi::c_void,
    fs::File,
    io, mem,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorDacl,
        GetTokenInformation, IsValidAcl, IsValidSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_EXECUTE, FILE_READ_DATA, FILE_READ_EA,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use super::{FilePrivacy, bool_result, invalid_data};

/// Owns an allocation returned by an API documented to require LocalFree.
struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this pointer came from GetSecurityInfo, the SDDL converter,
        // or the SID string converter, all of which specify LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) struct Descriptor(LocalAllocation);

impl Descriptor {
    pub(super) fn for_creation(privacy: FilePrivacy, directory: bool) -> io::Result<Self> {
        let account = Account::current()?;
        let sid = account.string_sid()?;
        let inheritance = if directory { "OICI" } else { "" };
        let mut sddl = format!(
            "O:{sid}D:P(A;{inheritance};FA;;;{sid})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)"
        );
        match privacy {
            FilePrivacy::Private => {}
            FilePrivacy::Public => {
                let rights = if directory { "FRFX" } else { "FR" };
                sddl.push_str(&format!("(A;{inheritance};{rights};;;WD)"));
            }
        }
        Self::from_sddl(&sddl)
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the input is NUL terminated and lives for the call; the
        // output is an owned self-relative descriptor allocated by Windows.
        bool_result(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        })?;
        Ok(Self(LocalAllocation(descriptor)))
    }

    pub(super) fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        self.0.0.cast()
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        // SAFETY: the descriptor is a live allocation supplied by Windows;
        // all outputs point to initialized stack storage.
        bool_result(unsafe {
            GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted)
        })?;
        if present == 0 || dacl.is_null() {
            return Err(invalid_data("a present, non-null DACL is required"));
        }
        Ok(dacl)
    }
}

struct Account {
    // usize alignment is sufficient for TOKEN_USER and its embedded SID.
    token_user: Vec<usize>,
}

impl Account {
    fn current() -> io::Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle; token
        // receives an independently owned handle on successful return.
        bool_result(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
        // SAFETY: OpenProcessToken succeeded and transferred this handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut required = 0;
        // SAFETY: a null/zero buffer requests the required byte count.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required < mem::size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::last_os_error());
        }
        let mut token_user = vec![0usize; (required as usize).div_ceil(mem::size_of::<usize>())];
        // SAFETY: the aligned allocation covers required bytes and remains
        // alive after Windows writes TOKEN_USER and the SID it points into.
        bool_result(unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                token_user.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        })?;
        Ok(Self { token_user })
    }

    fn sid(&self) -> PSID {
        // SAFETY: a successful TokenUser query initialized this aligned
        // header; its SID points into the same retained allocation.
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn string_sid(&self) -> io::Result<String> {
        let mut string = ptr::null_mut();
        // SAFETY: sid() is a live SID supplied by the token query.
        bool_result(unsafe { ConvertSidToStringSidW(self.sid(), &mut string) })?;
        let allocation = LocalAllocation(string.cast());
        let mut length = 0;
        // SAFETY: the converter returns a NUL-terminated UTF-16 string. The
        // LocalFree guard retains its allocation throughout this scan.
        unsafe {
            while *string.add(length) != 0 {
                length += 1;
            }
            let value = String::from_utf16(std::slice::from_raw_parts(string, length))
                .map_err(|_| invalid_data("Windows returned a non-Unicode SID"));
            drop(allocation);
            value
        }
    }
}

pub(super) fn validate(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut allocation = ptr::null_mut();
    // SAFETY: file remains open and outputs are writable. Windows allocates
    // the descriptor; owner borrows that allocation until the guard drops.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut allocation,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let descriptor = Descriptor(LocalAllocation(allocation));
    let account = Account::current()?;
    if !trusted_sid(owner, &account)? {
        return Err(invalid_data(
            "owner must be the current account, SYSTEM, or Administrators",
        ));
    }
    let dacl = descriptor.dacl()?;
    // SAFETY: dacl borrows the live descriptor and is checked before parsing.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(invalid_data("invalid DACL"));
    }
    // SAFETY: IsValidAcl accepted the complete ACL supplied by Windows.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..count {
        validate_ace(dacl, u32::from(index), &account, privacy)?;
    }
    Ok(())
}

fn trusted_sid(sid: PSID, account: &Account) -> io::Result<bool> {
    // SAFETY: all callers pass SID pointers inside Windows-supplied security
    // buffers. IsValidSid checks the SID format before any comparisons.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid_data("missing or invalid security principal"));
    }
    // SAFETY: both SID arguments are valid for the duration of this call.
    if unsafe { EqualSid(sid, account.sid()) } != 0 {
        return Ok(true);
    }
    // SAFETY: IsValidSid accepted this retained SID; the predicates only read
    // it and compare with Windows' fixed SYSTEM and Administrators identities.
    Ok(unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    })
}

fn validate_ace(
    dacl: *const ACL,
    index: u32,
    account: &Account,
    privacy: FilePrivacy,
) -> io::Result<()> {
    let mut ace = ptr::null_mut();
    // SAFETY: the ACL was validated, index is below its AceCount, and the
    // descriptor allocation remains alive for this whole operation.
    bool_result(unsafe { GetAce(dacl, index, &mut ace) })?;
    // SAFETY: GetAce succeeded; every ACE begins with this header.
    let header: ACE_HEADER = unsafe { ptr::read_unaligned(ace.cast()) };
    match header.AceType {
        1 => return Ok(()), // ACCESS_DENIED_ACE can only restrict access.
        0 => {}
        _ => return Err(invalid_data("unsupported DACL ACE type")),
    }
    let sid_offset = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if usize::from(header.AceSize) < sid_offset + 8 {
        return Err(invalid_data("truncated access-allowed ACE"));
    }
    // SAFETY: a validated access-allowed ACE contains Mask and its SID;
    // read_unaligned avoids assuming alignment of an arbitrary ACE.
    let mask = unsafe {
        ptr::read_unaligned(
            ace.cast::<u8>()
                .add(mem::offset_of!(ACCESS_ALLOWED_ACE, Mask))
                .cast::<u32>(),
        )
    };
    // SAFETY: sid_offset is within the validated ACE's SidStart field.
    let sid_bytes = unsafe { ace.cast::<u8>().add(sid_offset) };
    // SAFETY: the minimum eight-byte SID header was checked above.
    let subauthorities = usize::from(unsafe { *sid_bytes.add(1) });
    if subauthorities > 15 || sid_offset + 8 + subauthorities * 4 > usize::from(header.AceSize) {
        return Err(invalid_data("SID exceeds its access-allowed ACE"));
    }
    let sid = sid_bytes.cast();
    if trusted_sid(sid, account)? {
        return Ok(());
    }
    let writes = GENERIC_ALL
        | GENERIC_WRITE
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_DELETE_CHILD
        | 0x0200_0000; // MAXIMUM_ALLOWED
    let forbidden = match privacy {
        FilePrivacy::Public => writes,
        FilePrivacy::Private => {
            writes | GENERIC_READ | GENERIC_EXECUTE | FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE
        }
    };
    // Include inherit-only grants: directory policy must not grant unsafe
    // access to subsequently inherited children either.
    if mask & forbidden != 0 {
        return Err(invalid_data(
            "DACL grants unsafe access to another principal",
        ));
    }
    Ok(())
}

pub(super) fn set(file: &File, privacy: FilePrivacy) -> io::Result<()> {
    let descriptor = Descriptor::for_creation(privacy, file.metadata()?.is_dir())?;
    replace_dacl(file, &descriptor)?;
    validate(file, privacy)
}

fn replace_dacl(file: &File, descriptor: &Descriptor) -> io::Result<()> {
    let dacl = descriptor.dacl()?;
    // SAFETY: file is retained, dacl borrows descriptor, and SetSecurityInfo
    // copies the ACL. WRITE_DAC must have been requested on the file handle.
    let error = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn deny_directory_listing(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY;

    let sid = Account::current()?.string_sid()?;
    let descriptor = Descriptor::from_sddl(&format!(
        "O:{sid}D:P(D;;{FILE_LIST_DIRECTORY:#x};;;{sid})(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
    ))?;
    replace_dacl(file, &descriptor)
}
