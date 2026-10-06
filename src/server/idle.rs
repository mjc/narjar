use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::{AcceptedRequest, Metrics};

pub(super) struct IdleConnections {
    sender: Sender<WaitingConnection>,
    wake: UnixStream,
    timeout: Duration,
}

struct WaitingConnection {
    accepted: AcceptedRequest,
    deadline: Instant,
}

impl WaitingConnection {
    fn new(accepted: AcceptedRequest, timeout: Duration) -> io::Result<Self> {
        accepted.stream.set_nonblocking(true)?;
        Ok(Self {
            accepted,
            deadline: Instant::now() + timeout,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Readiness {
    Waiting,
    Request,
    Closed,
}

impl IdleConnections {
    pub(super) fn start(
        ready: Sender<AcceptedRequest>,
        metrics: Arc<Metrics>,
        stopping: Arc<AtomicBool>,
        capacity: usize,
        timeout: Duration,
    ) -> io::Result<(Arc<Self>, thread::JoinHandle<io::Result<()>>)> {
        let (wake_reader, wake) = UnixStream::pair()?;
        wake_reader.set_nonblocking(true)?;
        wake.set_nonblocking(true)?;
        let (sender, receiver) = bounded(capacity);
        let handle = thread::Builder::new()
            .name("narjar-idle-connections".into())
            .spawn(move || {
                let result =
                    monitor_idle_connections(receiver, wake_reader, ready, metrics, &stopping);
                stopping.store(true, Ordering::Release);
                result
            })?;
        Ok((
            Arc::new(Self {
                sender,
                wake,
                timeout,
            }),
            handle,
        ))
    }

    pub(super) fn park(&self, accepted: AcceptedRequest) {
        let waiting = match WaitingConnection::new(accepted, self.timeout) {
            Ok(waiting) => waiting,
            Err(_) => return,
        };
        // Each waiting connection still owns an admission, so this bounded
        // queue cannot exceed the server's connection limit.
        if self.sender.try_send(waiting).is_ok() {
            // WouldBlock means a wakeup is already pending. A disconnected
            // monitor drops the queued connection and its admission.
            let _ = (&self.wake).write(&[1]);
        }
    }
}

fn monitor_idle_connections(
    receiver: Receiver<WaitingConnection>,
    mut wake: UnixStream,
    ready: Sender<AcceptedRequest>,
    metrics: Arc<Metrics>,
    stopping: &AtomicBool,
) -> io::Result<()> {
    let mut waiting = Vec::new();
    std::iter::from_fn(|| (!stopping.load(Ordering::Acquire)).then_some(())).try_for_each(|()| {
        waiting.extend(receiver.try_iter());
        let states = poll_waiting_connections(&waiting, &wake)?;
        drain_wake_notifications(&mut wake)?;
        waiting = waiting
            .drain(..)
            .zip(states)
            .filter_map(|(connection, state)| match state {
                Readiness::Waiting => Some(connection),
                Readiness::Closed => None,
                Readiness::Request => {
                    enqueue_ready_connection(connection.accepted, &ready, &metrics);
                    None
                }
            })
            .collect();
        Ok(())
    })
}

fn poll_waiting_connections(
    waiting: &[WaitingConnection],
    wake: &UnixStream,
) -> io::Result<Vec<Readiness>> {
    let mut descriptors: Vec<_> = waiting
        .iter()
        .map(|connection| PollFd::new(&connection.accepted.stream, PollFlags::IN))
        .chain(std::iter::once(PollFd::new(wake, PollFlags::IN)))
        .collect();
    // The wake socket handles completed responses immediately. This bound
    // also checks shutdown and idle expiry when no socket becomes readable.
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(_) | Err(rustix::io::Errno::INTR) => {}
        Err(error) => return Err(error.into()),
    }
    let now = Instant::now();
    Ok(waiting
        .iter()
        .zip(descriptors)
        .map(|(connection, descriptor)| {
            classify_waiting_connection(connection, descriptor.revents(), now)
        })
        .collect())
}

fn classify_waiting_connection(
    connection: &WaitingConnection,
    events: PollFlags,
    now: Instant,
) -> Readiness {
    if now >= connection.deadline {
        return Readiness::Closed;
    }
    if events.is_empty() {
        return Readiness::Waiting;
    }
    // poll reports both data and EOF as readable. Peeking leaves the request
    // byte for Request::read and does not change its header-read timeout.
    match connection.accepted.stream.peek(&mut [0]) {
        Ok(0) => Readiness::Closed,
        Ok(_) => Readiness::Request,
        Err(error) => match error.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                Readiness::Waiting
            }
            _ => Readiness::Closed,
        },
    }
}

fn drain_wake_notifications(wake: &mut UnixStream) -> io::Result<()> {
    std::iter::repeat_with(|| wake.read(&mut [0; 256]))
        .try_for_each(|result| match result {
            Ok(0) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        })
        .or_else(|error| match error.kind() {
            io::ErrorKind::WouldBlock => Ok(()),
            _ => Err(error),
        })
}

fn enqueue_ready_connection(
    accepted: AcceptedRequest,
    ready: &Sender<AcceptedRequest>,
    metrics: &Metrics,
) {
    if accepted.stream.set_nonblocking(false).is_err() {
        return;
    }
    metrics.connection_queued();
    match ready.try_send(accepted) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => metrics.connection_dequeued(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::*;
    use crate::server::{Admissions, configure_accepted_socket};

    fn connection_pair() -> (WaitingConnection, TcpStream, Arc<Admissions>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        configure_accepted_socket(&stream, Duration::from_millis(100)).unwrap();
        let admissions = Arc::new(Admissions::new(1, Arc::new(Metrics::default())));
        let accepted = AcceptedRequest {
            stream,
            _admission: admissions.try_acquire().unwrap(),
        };
        (
            WaitingConnection::new(accepted, Duration::from_secs(30)).unwrap(),
            client,
            admissions,
        )
    }

    #[test]
    fn idle_deadline_closes_the_connection_without_consuming_a_worker() {
        let (connection, _client, admissions) = connection_pair();
        assert_eq!(
            classify_waiting_connection(&connection, PollFlags::empty(), connection.deadline),
            Readiness::Closed
        );
        drop(connection);
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn readiness_preserves_the_header_timeout_and_first_request_byte() {
        let (connection, mut client, _) = connection_pair();
        client.write_all(b"G").unwrap();
        let (wake, _writer) = UnixStream::pair().unwrap();
        assert_eq!(
            poll_waiting_connections(std::slice::from_ref(&connection), &wake).unwrap(),
            [Readiness::Request]
        );
        assert_eq!(
            connection.accepted.stream.read_timeout().unwrap(),
            Some(Duration::from_millis(100))
        );
        connection.accepted.stream.set_nonblocking(false).unwrap();
        let error = match super::super::Request::read(connection.accepted.stream) {
            Ok(_) => panic!("a partial request must still hit its header timeout"),
            Err((_, error)) => error,
        };
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn clean_idle_disconnect_is_not_dispatched_as_a_request() {
        let (connection, client, _) = connection_pair();
        drop(client);
        let (wake, _writer) = UnixStream::pair().unwrap();
        assert_eq!(
            poll_waiting_connections(&[connection], &wake).unwrap(),
            [Readiness::Closed]
        );
    }

    #[test]
    fn idle_socket_without_data_remains_parked() {
        let (connection, _client, _) = connection_pair();
        assert_eq!(
            classify_waiting_connection(&connection, PollFlags::empty(), Instant::now()),
            Readiness::Waiting
        );
    }
}
