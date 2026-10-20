use signal_hook::{
    SigId,
    consts::{SIGINT, SIGTERM},
    low_level,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

pub(super) fn notify_service_ready(socket: Option<&std::ffi::OsStr>) -> io::Result<()> {
    let Some(socket) = socket else {
        return Ok(());
    };
    let sender = std::os::unix::net::UnixDatagram::unbound()?;
    sender.set_nonblocking(true)?;
    match socket.as_encoded_bytes() {
        [b'/', ..] => sender.send_to(b"READY=1", std::path::Path::new(socket))?,
        #[cfg(target_os = "linux")]
        [b'@', name @ ..] => {
            use std::os::linux::net::SocketAddrExt;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            sender.send_to_addr(b"READY=1", &address)?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET must be an absolute Unix socket path or Linux abstract address",
            ));
        }
    };
    Ok(())
}

pub(super) struct ShutdownRegistration(Vec<SigId>);

impl ShutdownRegistration {
    pub(super) fn complete(self) {}
}

impl Drop for ShutdownRegistration {
    fn drop(&mut self) {
        self.0.drain(..).for_each(|id| {
            low_level::unregister(id);
        });
    }
}

pub(super) fn install_shutdown(stopping: Arc<AtomicBool>) -> io::Result<ShutdownRegistration> {
    let signal_count = Arc::new(AtomicUsize::new(0));
    [SIGINT, SIGTERM].into_iter().try_fold(
        ShutdownRegistration(Vec::new()),
        |mut registration, signal| {
            let stopping = Arc::clone(&stopping);
            let signal_count = Arc::clone(&signal_count);
            // SAFETY: the handler only uses atomic operations and async-signal-safe _exit.
            let id = unsafe {
                low_level::register(signal, move || {
                    if signal_count.fetch_add(1, Ordering::Relaxed) > 0 {
                        low_level::exit(128 + signal);
                    }
                    stopping.store(true, Ordering::Release);
                })
            }?;
            registration.0.push(id);
            Ok(registration)
        },
    )
}

pub(super) fn accept_error_kind(error: &io::Error) -> io::ErrorKind {
    pending_connection_error_kind(error)
}

#[cfg(target_os = "linux")]
fn pending_connection_error_kind(error: &io::Error) -> io::ErrorKind {
    use rustix::io::Errno;
    // Linux exposes pending per-connection network errors through accept(2).
    match error.raw_os_error().map(Errno::from_raw_os_error) {
        Some(
            Errno::NETDOWN
            | Errno::PROTO
            | Errno::NOPROTOOPT
            | Errno::HOSTDOWN
            | Errno::NONET
            | Errno::HOSTUNREACH
            | Errno::OPNOTSUPP
            | Errno::NETUNREACH,
        ) => io::ErrorKind::WouldBlock,
        _ => error.kind(),
    }
}

#[cfg(not(target_os = "linux"))]
fn pending_connection_error_kind(error: &io::Error) -> io::ErrorKind {
    error.kind()
}
