use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use windows_sys::Win32::System::{
    Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    },
    Threading::{CreateEventW, ExitProcess, SetEvent, WaitForSingleObject},
};

struct ShutdownContext {
    stopping: Arc<AtomicBool>,
    requests: AtomicUsize,
    complete: OwnedHandle,
}

// Windows may keep a callback in flight after it is unregistered. The context
// and its event therefore live until process exit, never behind a borrowed pointer.
static SHUTDOWN: OnceLock<ShutdownContext> = OnceLock::new();

pub(super) struct ShutdownRegistration;

pub(super) fn install_shutdown(stopping: Arc<AtomicBool>) -> io::Result<ShutdownRegistration> {
    // SAFETY: null security attributes produce a non-inheritable, unnamed event.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateEventW transfers this independently owned handle.
    let complete = unsafe { OwnedHandle::from_raw_handle(event) };
    SHUTDOWN
        .set(ShutdownContext {
            stopping,
            requests: AtomicUsize::new(0),
            complete,
        })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a shutdown handler is already registered",
            )
        })?;
    // SAFETY: console_control has the documented ABI and uses only static state.
    if unsafe { SetConsoleCtrlHandler(Some(console_control), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ShutdownRegistration)
}

impl Drop for ShutdownRegistration {
    fn drop(&mut self) {
        if let Some(context) = SHUTDOWN.get() {
            // SAFETY: the context owns this event until process exit. All server
            // resources have been dropped before this registration guard.
            unsafe {
                SetEvent(context.complete.as_raw_handle());
            }
        }
        // SAFETY: unregister the exact static callback originally installed.
        unsafe {
            SetConsoleCtrlHandler(Some(console_control), 0);
        }
    }
}

unsafe extern "system" fn console_control(event: u32) -> i32 {
    let close_wait = match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => false,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => true,
        _ => return 0,
    };
    let Some(context) = SHUTDOWN.get() else {
        return 0;
    };
    if context.requests.fetch_add(1, Ordering::Relaxed) > 0 {
        // SAFETY: a second interrupt intentionally terminates without cleanup.
        unsafe {
            ExitProcess(0xC000_013A);
        }
    }
    context.stopping.store(true, Ordering::Release);
    if close_wait {
        // SAFETY: this event remains live in static state. Console-close handlers
        // must not return before cleanup: Windows terminates the process afterward.
        // Stay below the normal five-second console-close deadline.
        unsafe {
            WaitForSingleObject(context.complete.as_raw_handle(), 4_500);
        }
    }
    1
}

pub(super) fn notify_service_ready(socket: Option<&std::ffi::OsStr>) -> io::Result<()> {
    match socket {
        None => Ok(()),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NOTIFY_SOCKET requires a Unix service manager",
        )),
    }
}

pub(super) fn accept_error_kind(error: &io::Error) -> io::ErrorKind {
    match error.kind() {
        io::ErrorKind::ConnectionReset => io::ErrorKind::ConnectionAborted,
        kind => kind,
    }
}
