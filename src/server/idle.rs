use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use mio::{Events, Interest, Poll, Registry, Token, Waker, net::TcpStream};

use super::{AcceptedRequest, Metrics};

const WAKE_TOKEN: Token = Token(0);
const SHUTDOWN_CHECK_INTERVAL: Duration = Duration::from_millis(50);

pub(super) struct IdleConnections {
    sender: Sender<WaitingConnection>,
    wake: Waker,
    timeout: Duration,
}

struct WaitingConnection {
    accepted: AcceptedRequest<TcpStream>,
    deadline: Instant,
}

impl WaitingConnection {
    fn new(accepted: AcceptedRequest, timeout: Duration) -> io::Result<Self> {
        accepted.stream.set_nonblocking(true)?;
        Ok(Self {
            accepted: AcceptedRequest {
                stream: TcpStream::from_std(accepted.stream),
                _admission: accepted._admission,
            },
            deadline: Instant::now() + timeout,
        })
    }

    fn readiness(&self, now: Instant) -> Readiness {
        if now >= self.deadline {
            return Readiness::Closed;
        }
        // Readability includes EOF. Peeking preserves the request byte and
        // rearms Windows readiness when the socket reports WouldBlock.
        match self.accepted.stream.peek(&mut [0]) {
            Ok(0) => Readiness::Closed,
            Ok(_) => Readiness::Request,
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut => Readiness::Waiting,
                _ => Readiness::Closed,
            },
        }
    }

    fn deregister(mut self, registry: &Registry) -> io::Result<Self> {
        registry.deregister(&mut self.accepted.stream)?;
        Ok(self)
    }

    fn resume(self) -> io::Result<AcceptedRequest> {
        let stream = std::net::TcpStream::from(self.accepted.stream);
        stream.set_nonblocking(false)?;
        Ok(AcceptedRequest {
            stream,
            _admission: self.accepted._admission,
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
        let monitor = IdleMonitor::new()?;
        let wake = Waker::new(monitor.poll.registry(), WAKE_TOKEN)?;
        let (sender, receiver) = bounded(capacity);
        let handle = thread::Builder::new()
            .name("narjar-idle-connections".into())
            .spawn(move || {
                let result = monitor.run(receiver, &ready, &metrics, &stopping);
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
        // Each parked connection retains its admission, bounding both the
        // pending queue and registered sockets by the server connection limit.
        if self.sender.try_send(waiting).is_ok() {
            let _ = self.wake.wake();
        }
    }
}

struct IdleMonitor {
    // Drop registered socket owners before their poller.
    sockets: ParkedSockets,
    poll: Poll,
    events: Events,
}

#[derive(Default)]
struct ParkedSockets {
    waiting: HashMap<Token, WaitingConnection>,
    last_token: usize,
}

impl IdleMonitor {
    fn new() -> io::Result<Self> {
        Ok(Self {
            poll: Poll::new()?,
            events: Events::with_capacity(128),
            sockets: ParkedSockets::default(),
        })
    }

    fn run(
        mut self,
        receiver: Receiver<WaitingConnection>,
        ready: &Sender<AcceptedRequest>,
        metrics: &Metrics,
        stopping: &AtomicBool,
    ) -> io::Result<()> {
        std::iter::from_fn(|| (!stopping.load(Ordering::Acquire)).then_some(())).try_for_each(
            |()| {
                receiver
                    .try_iter()
                    .try_for_each(|waiting| self.sockets.register(self.poll.registry(), waiting))?;
                self.poll_once(ready, metrics)?;
                self.sockets.expire(Instant::now());
                Ok(())
            },
        )
    }

    fn poll_once(&mut self, ready: &Sender<AcceptedRequest>, metrics: &Metrics) -> io::Result<()> {
        match self
            .poll
            .poll(&mut self.events, Some(SHUTDOWN_CHECK_INTERVAL))
        {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(()),
            Err(error) => return Err(error),
        }
        let now = Instant::now();
        self.events.iter().try_for_each(|event| {
            self.sockets
                .dispatch(self.poll.registry(), event.token(), now, ready, metrics)
        })
    }
}

impl ParkedSockets {
    fn register(&mut self, registry: &Registry, mut waiting: WaitingConnection) -> io::Result<()> {
        // Never reuse keys: a queued event must not identify a later socket.
        self.last_token = self
            .last_token
            .checked_add(1)
            .ok_or_else(|| io::Error::other("idle connection tokens exhausted"))?;
        let token = Token(self.last_token);
        registry.register(&mut waiting.accepted.stream, token, Interest::READABLE)?;
        self.waiting.insert(token, waiting);
        Ok(())
    }

    fn dispatch(
        &mut self,
        registry: &Registry,
        token: Token,
        now: Instant,
        ready: &Sender<AcceptedRequest>,
        metrics: &Metrics,
    ) -> io::Result<()> {
        match self.waiting.remove(&token) {
            // Wakes and stale events do not have a parked socket owner.
            None => Ok(()),
            Some(mut waiting) => match waiting.readiness(now) {
                Readiness::Waiting => {
                    registry.reregister(&mut waiting.accepted.stream, token, Interest::READABLE)?;
                    self.waiting.insert(token, waiting);
                    Ok(())
                }
                Readiness::Closed => waiting.deregister(registry).map(drop),
                Readiness::Request => {
                    enqueue_ready_connection(
                        waiting.deregister(registry)?.resume()?,
                        ready,
                        metrics,
                    );
                    Ok(())
                }
            },
        }
    }

    fn expire(&mut self, now: Instant) {
        self.waiting.retain(|_, waiting| now < waiting.deadline);
    }
}

fn enqueue_ready_connection(
    accepted: AcceptedRequest,
    ready: &Sender<AcceptedRequest>,
    metrics: &Metrics,
) {
    metrics.connection_queued();
    match ready.try_send(accepted) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => metrics.connection_dequeued(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{Admissions, configure_accepted_socket};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
    };

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

    fn register(monitor: &mut IdleMonitor, waiting: WaitingConnection) {
        monitor
            .sockets
            .register(monitor.poll.registry(), waiting)
            .unwrap();
    }

    fn receive_ready_connection(
        monitor: &mut IdleMonitor,
        sender: &Sender<AcceptedRequest>,
        receiver: &Receiver<AcceptedRequest>,
    ) -> AcceptedRequest {
        let deadline = Instant::now() + Duration::from_secs(5);
        std::iter::from_fn(|| {
            (Instant::now() < deadline).then(|| {
                monitor.poll_once(sender, &Metrics::default()).unwrap();
                receiver.try_recv().ok()
            })
        })
        .flatten()
        .next()
        .expect("readable socket must reach the worker queue")
    }

    fn poll_until_socket_is_retired(monitor: &mut IdleMonitor, sender: &Sender<AcceptedRequest>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        // Readiness polling can return spuriously, even when the peer has
        // already sent data or closed. Wait for the ownership transition.
        std::iter::from_fn(|| {
            (!monitor.sockets.waiting.is_empty() && Instant::now() < deadline)
                .then(|| monitor.poll_once(sender, &Metrics::default()).unwrap())
        })
        .for_each(drop);
        assert!(monitor.sockets.waiting.is_empty());
    }

    #[test]
    fn idle_deadline_closes_the_connection_without_consuming_a_worker() {
        let (connection, _client, admissions) = connection_pair();
        assert_eq!(connection.readiness(connection.deadline), Readiness::Closed);
        drop(connection);
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn readiness_preserves_the_header_timeout_and_first_request_byte() {
        let (connection, mut client, _) = connection_pair();
        client.write_all(b"G").unwrap();
        let mut monitor = IdleMonitor::new().unwrap();
        let (sender, receiver) = bounded(1);
        register(&mut monitor, connection);
        let ready = receive_ready_connection(&mut monitor, &sender, &receiver);
        assert_eq!(
            ready.stream.read_timeout().unwrap(),
            Some(Duration::from_millis(100))
        );
        let error = match super::super::Request::read(ready.stream) {
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
        let (connection, client, admissions) = connection_pair();
        drop(client);
        let mut monitor = IdleMonitor::new().unwrap();
        let (sender, receiver) = bounded(1);
        register(&mut monitor, connection);
        poll_until_socket_is_retired(&mut monitor, &sender);
        assert!(receiver.is_empty());
        assert!(monitor.sockets.waiting.is_empty());
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn idle_socket_without_data_remains_parked() {
        let (connection, _client, _) = connection_pair();
        assert_eq!(connection.readiness(Instant::now()), Readiness::Waiting);
    }

    #[test]
    fn registered_idle_expiry_releases_its_admission_without_dispatch() {
        let (connection, _client, admissions) = connection_pair();
        let deadline = connection.deadline;
        let mut monitor = IdleMonitor::new().unwrap();
        register(&mut monitor, connection);
        assert!(admissions.try_acquire().is_none());
        monitor.sockets.expire(deadline);
        assert!(monitor.sockets.waiting.is_empty());
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn repeated_parking_preserves_the_socket_and_admission() {
        let (connection, mut client, admissions) = connection_pair();
        let mut monitor = IdleMonitor::new().unwrap();
        let (sender, receiver) = bounded(1);
        let mut waiting = connection;
        for byte in b"GET" {
            client.write_all(&[*byte]).unwrap();
            register(&mut monitor, waiting);
            let mut ready = receive_ready_connection(&mut monitor, &sender, &receiver);
            let mut actual = [0];
            ready.stream.read_exact(&mut actual).unwrap();
            assert_eq!(actual, [*byte]);
            assert!(admissions.try_acquire().is_none());
            waiting = WaitingConnection::new(ready, Duration::from_secs(30)).unwrap();
        }
        drop(waiting);
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn dropping_the_monitor_releases_all_parked_admissions() {
        let (connection, _client, admissions) = connection_pair();
        let mut monitor = IdleMonitor::new().unwrap();
        register(&mut monitor, connection);
        drop(monitor);
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn full_ready_queue_drops_the_connection_and_releases_its_admission() {
        let (connection, mut client, admissions) = connection_pair();
        let mut monitor = IdleMonitor::new().unwrap();
        let (sender, _receiver) = bounded(0);
        client.write_all(b"G").unwrap();
        register(&mut monitor, connection);
        poll_until_socket_is_retired(&mut monitor, &sender);
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn wake_notification_survives_until_the_next_wait() {
        let mut monitor = IdleMonitor::new().unwrap();
        let wake = Waker::new(monitor.poll.registry(), WAKE_TOKEN).unwrap();
        wake.wake().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let observed = std::iter::from_fn(|| {
            (Instant::now() < deadline).then(|| {
                monitor
                    .poll
                    .poll(&mut monitor.events, Some(SHUTDOWN_CHECK_INTERVAL))
                    .unwrap();
                monitor
                    .events
                    .iter()
                    .any(|event| event.token() == WAKE_TOKEN)
            })
        })
        .any(|notified| notified);
        assert!(
            observed,
            "queued notification must survive spurious poll returns"
        );
    }

    #[test]
    fn stale_readiness_cannot_dispatch_a_new_socket_after_expiry() {
        let (old, _old_client, old_admissions) = connection_pair();
        let deadline = old.deadline;
        let mut monitor = IdleMonitor::new().unwrap();
        register(&mut monitor, old);
        let old_token = Token(monitor.sockets.last_token);
        monitor.sockets.expire(deadline);
        assert!(old_admissions.try_acquire().is_some());

        let (new, mut client, _) = connection_pair();
        register(&mut monitor, new);
        assert_ne!(old_token, Token(monitor.sockets.last_token));
        let (sender, receiver) = bounded(1);
        monitor
            .sockets
            .dispatch(
                monitor.poll.registry(),
                old_token,
                Instant::now(),
                &sender,
                &Metrics::default(),
            )
            .unwrap();
        assert!(receiver.is_empty());
        assert_eq!(monitor.sockets.waiting.len(), 1);
        client.write_all(b"N").unwrap();
        let mut ready = receive_ready_connection(&mut monitor, &sender, &receiver);
        let mut byte = [0];
        ready.stream.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"N");
    }

    #[test]
    fn spurious_readiness_keeps_the_socket_armed_for_later_data() {
        let (waiting, mut client, admissions) = connection_pair();
        let mut monitor = IdleMonitor::new().unwrap();
        register(&mut monitor, waiting);
        let (sender, receiver) = bounded(1);
        monitor
            .sockets
            .dispatch(
                monitor.poll.registry(),
                Token(monitor.sockets.last_token),
                Instant::now(),
                &sender,
                &Metrics::default(),
            )
            .unwrap();
        assert!(receiver.is_empty());
        assert!(admissions.try_acquire().is_none());
        client.write_all(b"G").unwrap();
        let _ready = receive_ready_connection(&mut monitor, &sender, &receiver);
        assert!(monitor.sockets.waiting.is_empty());
    }

    #[test]
    fn an_expired_readable_socket_is_closed_instead_of_dispatched() {
        let (waiting, mut client, admissions) = connection_pair();
        let deadline = waiting.deadline;
        let mut monitor = IdleMonitor::new().unwrap();
        register(&mut monitor, waiting);
        client.write_all(b"G").unwrap();
        let (sender, receiver) = bounded(1);
        monitor
            .sockets
            .dispatch(
                monitor.poll.registry(),
                Token(monitor.sockets.last_token),
                deadline,
                &sender,
                &Metrics::default(),
            )
            .unwrap();
        assert!(receiver.is_empty());
        assert!(admissions.try_acquire().is_some());
    }
}
