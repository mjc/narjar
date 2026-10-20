//! Local named-pipe transport. Only the listener retains pending I/O between calls.

use std::{
    cell::{Cell, UnsafeCell},
    fs::File,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr,
    sync::{Mutex, TryLockError},
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NO_DATA,
        ERROR_NO_SYSTEM_RESOURCES, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_ENOUGH_QUOTA,
        ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
        ERROR_SEM_TIMEOUT, ERROR_TOO_MANY_OPEN_FILES, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::ConnectNamedPipe,
        Threading::{CreateEventW, INFINITE, WaitForSingleObject},
    },
};

use crate::cache::filesystem::{ControlPipeName, open_directory};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct BoundSocket {
    pub(super) listener: Listener,
}

pub(super) struct Listener {
    name: ControlPipeName,
    pending: Mutex<Operation>,
    // Keep the identity allocated even if DATA's last directory name is removed.
    _directory: File,
}

impl BoundSocket {
    /// The caller must already hold DATA's process lease.
    pub(super) fn bind(root: &Path) -> io::Result<Self> {
        let directory = open_directory(root)?;
        let name = ControlPipeName::for_directory(&directory)?;
        let pending = start_accept(name.create_first()?)?;
        Ok(Self {
            listener: Listener {
                name,
                pending: Mutex::new(pending),
                _directory: directory,
            },
        })
    }
}

pub(super) fn accept(listener: &Listener) -> io::Result<Stream> {
    let mut pending = match listener.pending.try_lock() {
        Ok(pending) => pending,
        Err(TryLockError::WouldBlock) => return Err(io::ErrorKind::WouldBlock.into()),
        Err(TryLockError::Poisoned(_)) => {
            return Err(io::Error::other("control listener poisoned"));
        }
    };
    let result = pending.poll();
    if let Err(error) = &result {
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
    // Retain the old instance until its replacement exists: no namespace gap,
    // including when allocation of the next listener instance fails.
    let replacement = start_accept(listener.name.create_next()?)?;
    let completed = std::mem::replace(&mut *pending, replacement);
    result?;
    let file = completed.file.try_clone()?;
    Ok(Stream::new(file))
}

pub(super) fn connect(root: &Path) -> io::Result<Stream> {
    let directory = open_directory(root)?;
    let name = ControlPipeName::for_directory(&directory)?;
    let deadline = Instant::now() + DEFAULT_TIMEOUT;
    loop {
        time_remaining(deadline)?;
        match name.open_client() {
            Ok(file) => {
                time_remaining(deadline)?;
                return Ok(Stream::new(file));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                match name.wait_available(time_remaining(deadline)?) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) => {
                        time_remaining(deadline)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn configure_connection(connection: &Stream) -> io::Result<()> {
    connection.set_write_timeout(Some(DEFAULT_TIMEOUT))
}

pub(super) fn read_before_deadline(
    connection: &mut Stream,
    bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<usize> {
    connection.read_until(bytes, deadline)
}

pub(super) fn retryable_accept_error(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => true,
        _ => error.raw_os_error().is_some_and(|code| {
            [
                ERROR_NO_DATA,
                ERROR_PIPE_NOT_CONNECTED,
                ERROR_OPERATION_ABORTED,
                ERROR_TOO_MANY_OPEN_FILES,
                ERROR_NOT_ENOUGH_MEMORY,
                ERROR_NOT_ENOUGH_QUOTA,
                ERROR_NO_SYSTEM_RESOURCES,
                ERROR_PIPE_BUSY,
            ]
            .into_iter()
            .any(|retryable| code == retryable as i32)
        }),
    }
}

/// Each I/O call completes or cancels and drains before returning its buffer.
/// File and Cell are Send; no raw-pointer Send/Sync assertion is needed here.
pub(super) struct Stream {
    file: File,
    write_timeout: Cell<Option<Duration>>,
}

impl Stream {
    fn new(file: File) -> Self {
        Self {
            file,
            write_timeout: Cell::new(Some(DEFAULT_TIMEOUT)),
        }
    }

    pub(super) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero control write timeout",
            ));
        }
        timeout_deadline(timeout)?;
        self.write_timeout.set(timeout);
        Ok(())
    }

    fn read_until(&mut self, bytes: &mut [u8], deadline: Instant) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        time_remaining(deadline)?;
        let mut operation = Operation::new(&self.file)?;
        let length = bytes.len().min(u32::MAX as usize) as u32;
        // SAFETY: bytes is exclusively borrowed until operation is completed
        // or cancelled and drained by Drop. The OVERLAPPED/event are retained.
        let started = unsafe {
            ReadFile(
                operation.file.as_raw_handle(),
                bytes.as_mut_ptr(),
                length,
                ptr::null_mut(),
                operation.pointer(),
            )
        };
        let result = operation
            .record(started)
            .and_then(|()| operation.wait(Some(deadline)));
        match result {
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(0),
            result => result.map(|length| length as usize),
        }
    }

    fn write_until(&mut self, bytes: &[u8], deadline: Option<Instant>) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if let Some(deadline) = deadline {
            time_remaining(deadline)?;
        }
        let mut operation = Operation::new(&self.file)?;
        let length = bytes.len().min(u32::MAX as usize) as u32;
        // SAFETY: bytes cannot be changed or released until this operation is
        // completed or cancelled and drained; its OVERLAPPED is heap stable.
        let started = unsafe {
            WriteFile(
                operation.file.as_raw_handle(),
                bytes.as_ptr(),
                length,
                ptr::null_mut(),
                operation.pointer(),
            )
        };
        operation.record(started)?;
        operation.wait(deadline).map(|length| length as usize)
    }
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_until(bytes, Instant::now() + DEFAULT_TIMEOUT)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_until(bytes, timeout_deadline(self.write_timeout.get())?)
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        let deadline = timeout_deadline(self.write_timeout.get())?;
        while !bytes.is_empty() {
            let length = self.write_until(bytes, deadline)?;
            if length == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[length..];
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        // No Rust-side buffer. FlushFileBuffers on a pipe would wait without
        // a deadline for the peer to consume data; neither flush nor Drop does it.
        Ok(())
    }
}

fn timeout_deadline(timeout: Option<Duration>) -> io::Result<Option<Instant>> {
    timeout
        .map(|timeout| {
            Instant::now().checked_add(timeout).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "control timeout exceeds clock range",
                )
            })
        })
        .transpose()
}

fn time_remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

enum Completion {
    Idle,
    Pending,
    Complete(u32),
    Failed(i32),
}

/// Owns every resource a pending kernel operation can access. No data buffer
/// is retained between calls; only ConnectNamedPipe may outlive its issuer.
struct Operation {
    file: File,
    event: OwnedHandle,
    overlapped: Box<UnsafeCell<OVERLAPPED>>,
    completion: Completion,
}

// SAFETY: moving Operation leaves its heap-allocated OVERLAPPED at the same
// address. Its pointer fields are only the owned event and zero offsets; no
// Rust-thread-local data is referenced. Windows allows cancellation/completion
// on another thread (CancelIoEx). Listener serializes access with Mutex; this
// does not assert Sync. Read/write operations never escape their buffer borrow.
unsafe impl Send for Operation {}

impl Operation {
    fn new(file: &File) -> io::Result<Self> {
        let file = file.try_clone()?;
        // SAFETY: an unnamed, noninheritable manual-reset event has no borrowed
        // name or security storage. A successful call transfers its handle.
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateEventW succeeded and returned an owned event handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        Ok(Self {
            file,
            event,
            overlapped: Box::new(UnsafeCell::new(overlapped)),
            completion: Completion::Idle,
        })
    }

    fn pointer(&self) -> *mut OVERLAPPED {
        self.overlapped.get()
    }

    fn record(&mut self, result: i32) -> io::Result<()> {
        if result != 0 {
            self.completion = Completion::Pending;
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
            self.completion = Completion::Pending;
            Ok(())
        } else {
            self.completion = Completion::Failed(error.raw_os_error().unwrap_or(0));
            Err(error)
        }
    }

    fn poll(&mut self) -> io::Result<u32> {
        match self.completion {
            Completion::Complete(length) => return Ok(length),
            Completion::Failed(code) => return Err(io::Error::from_raw_os_error(code)),
            Completion::Idle => return Err(io::Error::other("control operation was not issued")),
            Completion::Pending => {}
        }
        let mut length = 0;
        // SAFETY: both the handle and initialized OVERLAPPED are retained;
        // Windows synchronizes reading completion state. This does not wait.
        let result = unsafe {
            GetOverlappedResult(self.file.as_raw_handle(), self.pointer(), &mut length, 0)
        };
        if result != 0 {
            self.completion = Completion::Complete(length);
            return Ok(length);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32) {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            self.completion = Completion::Failed(error.raw_os_error().unwrap_or(0));
            Err(error)
        }
    }

    fn wait(&mut self, deadline: Option<Instant>) -> io::Result<u32> {
        loop {
            if let Some(deadline) = deadline {
                time_remaining(deadline)?;
            }
            match self.poll() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
            let milliseconds = match deadline {
                Some(deadline) => time_remaining(deadline)?
                    .as_nanos()
                    .div_ceil(1_000_000)
                    .min(u128::from(u32::MAX - 1)) as u32,
                None => INFINITE,
            };
            // SAFETY: the event is retained until I/O completes or is drained.
            match unsafe { WaitForSingleObject(self.event.as_raw_handle(), milliseconds) } {
                WAIT_OBJECT_0 | WAIT_TIMEOUT => {}
                WAIT_FAILED => return Err(io::Error::last_os_error()),
                _ => return Err(io::Error::other("unexpected control event wait result")),
            }
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if let Completion::Pending = self.completion {
            let mut length = 0;
            // SAFETY: cancel this exact operation, then observe completion
            // before releasing OVERLAPPED/event/file or the caller's buffer.
            // ERROR_NOT_FOUND can mean it completed before cancellation. Even
            // then GetOverlappedResult must drain it. No peer flush is involved.
            // Windows promises no hard cancellation-completion latency; the
            // drain cannot be skipped without releasing kernel-borrowed memory.
            unsafe {
                CancelIoEx(self.file.as_raw_handle(), self.pointer());
                GetOverlappedResult(self.file.as_raw_handle(), self.pointer(), &mut length, 1);
            }
        }
    }
}

fn start_accept(file: File) -> io::Result<Operation> {
    let mut operation = Operation::new(&file)?;
    // SAFETY: Operation owns a stable OVERLAPPED/event and a pipe-handle
    // duplicate. ConnectNamedPipe borrows no additional data buffer.
    let result = unsafe { ConnectNamedPipe(operation.file.as_raw_handle(), operation.pointer()) };
    if result != 0 {
        operation.completion = Completion::Complete(0);
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == ERROR_PIPE_CONNECTED as i32 => {
                operation.completion = Completion::Complete(0)
            }
            Some(code) if code == ERROR_IO_PENDING as i32 => {
                operation.completion = Completion::Pending
            }
            _ => return Err(error),
        }
    }
    Ok(operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(listener: &Listener) -> Stream {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match accept(listener) {
                Ok(stream) => return stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    time_remaining(deadline).unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    }

    #[test]
    fn accepting_without_a_client_is_nonblocking_and_listener_can_move_threads() {
        fn send<T: Send>() {}
        fn send_sync<T: Send + Sync>() {}
        send::<Stream>();
        send_sync::<Listener>();
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        assert_eq!(
            accept(&bound.listener).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        let worker = std::thread::spawn(move || {
            let mut server = accepted(&bound.listener);
            server.write_all(b"reply").unwrap();
            // CloseHandle, not DisconnectNamedPipe/FlushFileBuffers: unread
            // reply bytes must remain available to the connected client.
        });
        let mut client = connect(root.path()).unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        worker.join().unwrap();
    }

    #[test]
    fn simultaneous_connections_have_independent_bytes_and_closing_one_does_not_close_another() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        let mut first = connect(root.path()).unwrap();
        let mut first_server = accepted(&bound.listener);
        let mut second = connect(root.path()).unwrap();
        let mut second_server = accepted(&bound.listener);
        first.write_all(b"a").unwrap();
        second.write_all(b"b").unwrap();
        let mut byte = [0];
        first_server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
        second_server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"b");
        drop(first);
        assert_eq!(first_server.read(&mut byte).unwrap(), 0);
        second_server.write_all(b"c").unwrap();
        second.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"c");
    }

    #[test]
    fn partial_reads_keep_the_original_deadline_and_cancelled_reads_are_drained() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        let mut client = connect(root.path()).unwrap();
        let mut server = accepted(&bound.listener);
        client.write_all(b"a").unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut byte = [0];
        assert_eq!(
            read_before_deadline(&mut server, &mut byte, deadline).unwrap(),
            1
        );
        assert_eq!(byte, *b"a");
        assert_eq!(
            read_before_deadline(&mut server, &mut byte, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(Instant::now() < deadline + Duration::from_secs(2));
        client.write_all(b"b").unwrap();
        read_before_deadline(&mut server, &mut byte, Instant::now() + DEFAULT_TIMEOUT).unwrap();
        assert_eq!(byte, *b"b");
    }

    #[test]
    fn expired_deadlines_do_not_consume_already_available_bytes() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        let mut client = connect(root.path()).unwrap();
        let mut server = accepted(&bound.listener);
        client.write_all(b"a").unwrap();
        let mut byte = [0];
        assert_eq!(
            read_before_deadline(&mut server, &mut byte, Instant::now())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
    }

    #[test]
    fn write_timeouts_cancel_backpressure_and_zero_timeouts_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        let mut client = connect(root.path()).unwrap();
        let _server = accepted(&bound.listener);
        assert_eq!(
            client
                .set_write_timeout(Some(Duration::ZERO))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        configure_connection(&client).unwrap();
        assert_eq!(client.write_timeout.get(), Some(DEFAULT_TIMEOUT));
        client
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let started = Instant::now();
        assert_eq!(
            client
                .write_all(&vec![0; 2 * 1024 * 1024])
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn moving_data_preserves_the_endpoint_but_replacing_its_path_does_not() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        let bound = BoundSocket::bind(&original).unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        assert!(connect(&original).is_err());
        let mut client = connect(&moved).unwrap();
        let mut server = accepted(&bound.listener);
        client.write_all(b"moved").unwrap();
        let mut bytes = [0; 5];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"moved");
    }

    #[test]
    fn dropping_a_listener_never_removes_another_live_instance() {
        let root = tempfile::tempdir().unwrap();
        let bound = BoundSocket::bind(root.path()).unwrap();
        let mut client = connect(root.path()).unwrap();
        let mut server = accepted(&bound.listener);
        drop(bound);
        assert!(BoundSocket::bind(root.path()).is_err());
        client.write_all(b"a").unwrap();
        let mut byte = [0];
        server.read_exact(&mut byte).unwrap();
        drop(client);
        drop(server);
        let rebound = BoundSocket::bind(root.path()).unwrap();
        assert_eq!(
            accept(&rebound.listener).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
