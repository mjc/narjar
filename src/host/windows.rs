use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use windows_sys::Win32::System::{
    Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    },
    Threading::{CreateEventW, GetCurrentProcess, SetEvent, TerminateProcess, WaitForSingleObject},
};

struct ShutdownContext {
    stopping: Arc<AtomicBool>,
    requests: AtomicUsize,
    complete: OwnedHandle,
}

// Each callback clones the active context before releasing this lock. Its event
// therefore survives unregistration until that callback returns.
static ACTIVE_SHUTDOWN: Mutex<Option<Arc<ShutdownContext>>> = Mutex::new(None);

pub(crate) struct ShutdownRegistration(Arc<ShutdownContext>);

impl ShutdownRegistration {
    pub(crate) fn complete(self) {
        // SAFETY: the caller has finished its work and released its resources.
        // This registration owns its completion event, not a later command's.
        unsafe {
            SetEvent(self.0.complete.as_raw_handle());
        }
    }
}

pub(crate) fn install_shutdown(stopping: Arc<AtomicBool>) -> io::Result<ShutdownRegistration> {
    // SAFETY: null security attributes produce a non-inheritable, unnamed event.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateEventW transfers this independently owned handle.
    let complete = unsafe { OwnedHandle::from_raw_handle(event) };
    let context = Arc::new(ShutdownContext {
        stopping,
        requests: AtomicUsize::new(0),
        complete,
    });
    {
        let mut active = ACTIVE_SHUTDOWN
            .lock()
            .map_err(|_| io::Error::other("the shutdown context registry is poisoned"))?;
        match active.as_ref() {
            None => *active = Some(Arc::clone(&context)),
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a shutdown handler is already registered",
                ));
            }
        }
    }
    // SAFETY: console_control has the documented ABI and uses only static state.
    if unsafe { SetConsoleCtrlHandler(Some(console_control), 1) } == 0 {
        let error = io::Error::last_os_error();
        clear_active_shutdown();
        return Err(error);
    }
    Ok(ShutdownRegistration(context))
}

fn active_shutdown_context() -> Option<Arc<ShutdownContext>> {
    ACTIVE_SHUTDOWN
        .lock()
        .ok()
        .and_then(|active| active.clone())
}

fn clear_active_shutdown() {
    if let Ok(mut active) = ACTIVE_SHUTDOWN.lock() {
        *active = None;
    }
}

impl Drop for ShutdownRegistration {
    fn drop(&mut self) {
        // SAFETY: unregister the exact static callback originally installed.
        unsafe {
            SetConsoleCtrlHandler(Some(console_control), 0);
        }
        clear_active_shutdown();
    }
}

unsafe extern "system" fn console_control(event: u32) -> i32 {
    let close_wait = match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => false,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => true,
        _ => return 0,
    };
    let Some(context) = active_shutdown_context() else {
        return 0;
    };
    if context.requests.fetch_add(1, Ordering::Relaxed) > 0 {
        // SAFETY: a second interrupt intentionally terminates without cleanup.
        unsafe {
            TerminateProcess(GetCurrentProcess(), 0xC000_013A);
        }
    }
    context.stopping.store(true, Ordering::Release);
    if close_wait {
        // SAFETY: this callback owns its context and event until the wait ends.
        // Console-close handlers must not return before cleanup: Windows
        // terminates the process afterward. Stay below its normal five seconds.
        unsafe {
            WaitForSingleObject(context.complete.as_raw_handle(), 4_500);
        }
    }
    1
}

pub(crate) fn notify_service_ready(socket: Option<&std::ffi::OsStr>) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        Foundation::WAIT_TIMEOUT,
        System::Console::{AllocConsole, GetConsoleCP},
    };

    #[test]
    fn sequential_shutdown_registrations_reset_state_and_retain_inflight_contexts() {
        // SAFETY: nextest runs this test in its own process; console allocation
        // is needed only when the runner launched it without an attached console.
        if unsafe { GetConsoleCP() } == 0 {
            assert_ne!(unsafe { AllocConsole() }, 0);
        }
        let first_stopping = Arc::new(AtomicBool::new(false));
        let first = install_shutdown(Arc::clone(&first_stopping)).unwrap();
        let first_context = active_shutdown_context().unwrap();
        assert!(matches!(
            install_shutdown(Arc::new(AtomicBool::new(false))),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        // SAFETY: invoke the registered handler once with its documented event.
        assert_eq!(unsafe { console_control(CTRL_C_EVENT) }, 1);
        assert!(first_stopping.load(Ordering::Acquire));
        drop(first);
        assert!(active_shutdown_context().is_none());

        let second_stopping = Arc::new(AtomicBool::new(false));
        let second = install_shutdown(Arc::clone(&second_stopping)).unwrap();
        let second_context = active_shutdown_context().unwrap();
        assert!(!Arc::ptr_eq(&first_context, &second_context));
        assert_eq!(second_context.requests.load(Ordering::Relaxed), 0);
        assert!(!second_stopping.load(Ordering::Acquire));
        // SAFETY: the retained first context models a callback still in flight.
        assert_eq!(
            unsafe { WaitForSingleObject(first_context.complete.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        // SAFETY: the fresh registration must treat this as its first interrupt.
        assert_eq!(unsafe { console_control(CTRL_BREAK_EVENT) }, 1);
        assert!(second_stopping.load(Ordering::Acquire));
        assert_eq!(first_context.requests.load(Ordering::Relaxed), 1);
        second.complete();
        assert!(active_shutdown_context().is_none());

        let third = install_shutdown(Arc::new(AtomicBool::new(false))).unwrap();
        // SAFETY: completion of the retired registration cannot signal this event.
        assert_eq!(
            unsafe { WaitForSingleObject(third.0.complete.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        third.complete();
    }
}
