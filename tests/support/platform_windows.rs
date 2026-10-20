use std::{io, path::Path};
use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;

pub(super) fn configure_server_process(command: &mut std::process::Command) -> io::Result<()> {
    use std::{os::windows::process::CommandExt, sync::OnceLock};
    use windows_sys::Win32::System::{
        Console::{AllocConsole, GetConsoleCP},
        Threading::CREATE_NEW_PROCESS_GROUP,
    };
    static CONSOLE: OnceLock<Result<(), i32>> = OnceLock::new();
    (*CONSOLE.get_or_init(|| {
        // SAFETY: console allocation is process-wide and serialized by OnceLock.
        if unsafe { GetConsoleCP() } != 0 || unsafe { AllocConsole() } != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(ERROR_INVALID_HANDLE as i32))
        }
    }))
    .map_err(io::Error::from_raw_os_error)?;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    Ok(())
}

pub(super) fn request_shutdown(process: u32) -> io::Result<()> {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    // SAFETY: configure_server_process makes this retained child's PID its
    // console process-group ID. Other test/server groups do not receive it.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn deny_fixture_data_reads(path: &Path) -> impl Drop {
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(0)
        .open(path)
        .unwrap();
    assert!(
        crate::cache::filesystem::open_regular(path).is_err(),
        "fixture must deny actual data access"
    );
    scopeguard::guard(file, drop)
}
