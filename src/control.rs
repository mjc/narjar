//! Private daemon maintenance; this is not part of the binary-cache protocol.

use std::{
    io::{self, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::cache::{
    metrics::{Metrics, OnlineGcOutcome},
    narinfo::TrustedPublicKeys,
    storage::{
        Storage, StorageError,
        gc::{GcOptions, GcReport},
    },
};
use crossbeam_channel::{Sender, bounded};
use serde::{Deserialize, Serialize};

mod protocol;
mod retry;
pub(crate) use retry::RetryPolicy;
#[cfg(unix)]
mod socket;
#[cfg(windows)]
#[path = "control/windows.rs"]
mod socket;
use socket::{Listener, Stream};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const REPORT_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Serialize, Deserialize)]
enum Reply {
    Completed(Box<GcReport>),
    Failed(ControlFailure),
}

impl Reply {
    fn outcome(&self) -> OnlineGcOutcome {
        match self {
            Self::Completed(report) => match report.target_met {
                true => OnlineGcOutcome::Success,
                false => OnlineGcOutcome::TargetNotReached,
            },
            Self::Failed(ControlFailure::Busy) => OnlineGcOutcome::Busy,
            Self::Failed(ControlFailure::Changed) => OnlineGcOutcome::InventoryChanged,
            Self::Failed(
                ControlFailure::BackendMismatch
                | ControlFailure::Stopping
                | ControlFailure::Policy(_)
                | ControlFailure::Storage(_),
            ) => OnlineGcOutcome::Failure,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
enum ControlFailure {
    #[error("online collection is busy; retry later")]
    Busy,
    #[error("online collection inventory changed; retry later")]
    Changed,
    #[error("requested storage backend differs from the running daemon")]
    BackendMismatch,
    #[error("daemon is shutting down")]
    Stopping,
    #[error("invalid retention policy: {0}")]
    Policy(String),
    #[error("collection failed: {0}")]
    Storage(String),
}

pub(crate) fn collect(
    data_dir: &Path,
    options: GcOptions,
    retry: RetryPolicy,
) -> io::Result<GcReport> {
    retry::request_with_retry(
        retry,
        || request_collection(data_dir, &options),
        thread::sleep,
    )
}

fn request_collection(data_dir: &Path, options: &GcOptions) -> io::Result<Reply> {
    let mut connection = socket::connect(data_dir).map_err(|error| io::Error::new(error.kind(), format!("cannot connect to running narjar: {error}; online GC does not fall back to offline GC")))?;
    connection.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    protocol::write_frame(&mut connection, &options)?;
    protocol::read_frame(DeadlineReader::new(&mut connection, REPORT_TIMEOUT))
}

struct CollectionJob {
    connection: Stream,
    options: GcOptions,
}

impl CollectionJob {
    fn receive_bounded_request(mut connection: Stream) -> io::Result<Self> {
        socket::configure_connection(&connection)?;
        let options = protocol::read_frame(DeadlineReader::new(&mut connection, REQUEST_TIMEOUT))?;
        Ok(Self {
            connection,
            options,
        })
    }

    fn reply_with_rejection(mut self, failure: ControlFailure, metrics: &Metrics) {
        send_recorded_reply(&mut self.connection, Reply::Failed(failure), metrics);
    }
}

/// Two fixed threads: bounded request parsing and one maintenance operation.
pub(crate) struct ControlService {
    shutdown: ControlShutdown,
    dispatcher: JoinHandle<io::Result<()>>,
    collector: JoinHandle<()>,
}

impl ControlService {
    pub(crate) fn start(
        root: &Path,
        storage: Arc<Storage>,
        trusted: Arc<TrustedPublicKeys>,
        metrics: Arc<Metrics>,
        daemon_stopping: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let data_dir = root.to_owned();
        let samples = Arc::clone(&metrics);
        Self::start_with_collector(root, daemon_stopping, metrics, move |options| {
            let reply = run_collection(&data_dir, &storage, &trusted, options);
            samples.sample_maintenance_sidecar(&data_dir);
            reply
        })
    }

    fn start_with_collector(
        root: &Path,
        daemon_stopping: Arc<AtomicBool>,
        metrics: Arc<Metrics>,
        mut collect: impl FnMut(GcOptions) -> Reply + Send + 'static,
    ) -> io::Result<Self> {
        let socket = socket::BoundSocket::bind(root)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let busy = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = bounded::<CollectionJob>(1);
        let collector = {
            let busy = Arc::clone(&busy);
            let stopping = Arc::clone(&stopping);
            let daemon_stopping = Arc::clone(&daemon_stopping);
            let metrics = Arc::clone(&metrics);
            thread::Builder::new()
                .name("narjar-gc".into())
                .spawn(move || {
                    for mut job in receiver {
                        let _active = ActiveCollection(&busy);
                        let reply = if is_stopping(&stopping, &daemon_stopping) {
                            Reply::Failed(ControlFailure::Stopping)
                        } else {
                            collect(job.options)
                        };
                        send_recorded_reply(&mut job.connection, reply, &metrics);
                    }
                })?
        };
        let dispatcher = {
            let stopping = Arc::clone(&stopping);
            match thread::Builder::new()
                .name("narjar-control".into())
                .spawn(move || {
                    dispatch_requests(
                        socket,
                        sender,
                        &busy,
                        &stopping,
                        &daemon_stopping,
                        &metrics,
                        socket::accept,
                    )
                }) {
                Ok(dispatcher) => dispatcher,
                Err(error) => {
                    let _ = collector.join();
                    return Err(error);
                }
            }
        };
        Ok(Self {
            shutdown: ControlShutdown {
                stopping,
                dispatcher: dispatcher.thread().clone(),
            },
            dispatcher,
            collector,
        })
    }

    pub(crate) fn finish(self, deadline: Instant) -> io::Result<()> {
        self.shutdown.stop();
        std::iter::repeat_with(|| self.dispatcher.is_finished() && self.collector.is_finished())
            .take_while(|finished| !finished)
            .try_for_each(|_| wait_within_shutdown_deadline(deadline))?;
        self.dispatcher
            .join()
            .map_err(|_| io::Error::other("control dispatcher panicked"))??;
        self.collector
            .join()
            .map_err(|_| io::Error::other("collector panicked"))
    }
}

struct ControlShutdown {
    stopping: Arc<AtomicBool>,
    dispatcher: thread::Thread,
}

impl ControlShutdown {
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.dispatcher.unpark();
    }
}

impl Drop for ControlShutdown {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ActiveCollection<'a>(&'a AtomicBool);

impl Drop for ActiveCollection<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn is_stopping(local: &AtomicBool, daemon: &AtomicBool) -> bool {
    local.load(Ordering::Acquire) || daemon.load(Ordering::Acquire)
}

fn dispatch_requests(
    bound: socket::BoundSocket,
    jobs: Sender<CollectionJob>,
    busy: &AtomicBool,
    stopping: &AtomicBool,
    daemon_stopping: &AtomicBool,
    metrics: &Metrics,
    mut accept: impl FnMut(&Listener) -> io::Result<Stream>,
) -> io::Result<()> {
    std::iter::repeat_with(|| ())
        .take_while(|_| !is_stopping(stopping, daemon_stopping))
        .try_for_each(|_| {
            match accept(&bound.listener) {
                Ok(connection) => {
                    let _ = queue_collection_request(connection, &jobs, busy, metrics);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(Duration::from_millis(100))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if socket::retryable_accept_error(&error) => {
                    eprintln!("narjar: online GC accept failed; retrying: {error}");
                    thread::park_timeout(Duration::from_millis(100));
                }
                Err(error) => return Err(error),
            }
            Ok(())
        })
}

fn queue_collection_request(
    connection: Stream,
    jobs: &Sender<CollectionJob>,
    busy: &AtomicBool,
    metrics: &Metrics,
) -> io::Result<()> {
    let job = CollectionJob::receive_bounded_request(connection)?;
    match busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => enqueue_admitted_collection_job(job, jobs, busy, metrics),
        Err(_) => job.reply_with_rejection(ControlFailure::Busy, metrics),
    }
    Ok(())
}

fn enqueue_admitted_collection_job(
    job: CollectionJob,
    jobs: &Sender<CollectionJob>,
    busy: &AtomicBool,
    metrics: &Metrics,
) {
    if let Err(error) = jobs.try_send(job) {
        busy.store(false, Ordering::Release);
        error
            .into_inner()
            .reply_with_rejection(ControlFailure::Stopping, metrics);
    }
}

fn send_recorded_reply(connection: &mut Stream, reply: Reply, metrics: &Metrics) {
    metrics.online_gc_completed(reply.outcome());
    let _ = protocol::write_frame(connection, &reply);
}

fn wait_within_shutdown_deadline(deadline: Instant) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "online collection exceeded shutdown grace",
            )
        })?;
    thread::sleep(remaining.min(Duration::from_millis(10)));
    Ok(())
}

fn run_collection(
    root: &Path,
    storage: &Storage,
    trusted: &TrustedPublicKeys,
    options: GcOptions,
) -> Reply {
    if options.backend != storage.backend() {
        return Reply::Failed(ControlFailure::BackendMismatch);
    }
    if let Err(error) = options.validate_policy() {
        return Reply::Failed(ControlFailure::Policy(error.to_string()));
    }
    match crate::operator::collect_online(root, options, storage, trusted) {
        Ok(report) => Reply::Completed(Box::new(report)),
        Err(StorageError::CollectionBusy) => Reply::Failed(ControlFailure::Busy),
        Err(StorageError::CollectionChanged) => Reply::Failed(ControlFailure::Changed),
        Err(error) => Reply::Failed(ControlFailure::Storage(error.to_string())),
    }
}

/// A total deadline: partial header/body reads cannot reset the timeout.
struct DeadlineReader<'a> {
    connection: &'a mut Stream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    fn new(connection: &'a mut Stream, timeout: Duration) -> Self {
        Self {
            connection,
            deadline: Instant::now() + timeout,
        }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match bytes {
            [] => Ok(0),
            bytes => socket::read_before_deadline(self.connection, bytes, self.deadline),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        maintenance::{self, Operation, Outcome},
        storage::{CachePolicies, Directory, StorageBackend, SupportedStorageBackend, gc::GcMode},
    };
    use std::{io::Write, sync::mpsc};

    #[cfg(unix)]
    mod unix;

    fn test_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        crate::cache::test_support::private_directory(root.path()).unwrap();
        root
    }

    fn stream_pair() -> (Stream, Stream) {
        let root = test_root();
        let bound = socket::BoundSocket::bind(root.path()).unwrap();
        let client = socket::connect(root.path()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let server = loop {
            match socket::accept(&bound.listener) {
                Ok(server) => break server,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "test accept deadline expired");
                    thread::park_timeout(Duration::from_millis(1));
                }
                Err(error) => panic!("test accept failed: {error}"),
            }
        };
        socket::configure_connection(&server).unwrap();
        client.set_write_timeout(Some(REQUEST_TIMEOUT)).unwrap();
        (server, client)
    }

    struct ReleaseCollectorOnDrop<'a>(&'a mpsc::Sender<()>);

    impl Drop for ReleaseCollectorOnDrop<'_> {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn a_paused_test_collector_is_released_when_an_assertion_panics() {
        let (release_tx, release_rx) = mpsc::channel();
        let panic = std::panic::catch_unwind(|| {
            let _release = ReleaseCollectorOnDrop(&release_tx);
            panic!("simulate a failed assertion while collection is paused");
        });
        assert!(panic.is_err());
        assert_eq!(release_rx.try_recv(), Ok(()));
    }

    #[test]
    fn a_buffered_control_reply_is_read_after_the_daemon_closes_its_socket() {
        let (mut daemon, mut client) = stream_pair();
        protocol::write_frame(&mut daemon, &Reply::Failed(ControlFailure::Busy)).unwrap();
        drop(daemon);

        let reply: Reply =
            protocol::read_frame(DeadlineReader::new(&mut client, REPORT_TIMEOUT)).unwrap();
        assert!(matches!(reply, Reply::Failed(ControlFailure::Busy)));
    }

    #[test]
    fn an_empty_control_read_does_not_wait_for_a_reply() {
        let (mut client, _daemon) = stream_pair();
        let mut reader = DeadlineReader::new(&mut client, REPORT_TIMEOUT);
        assert_eq!(reader.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn a_control_read_without_available_bytes_expires_at_its_deadline() {
        let (mut client, _daemon) = stream_pair();
        let mut reader = DeadlineReader::new(&mut client, Duration::from_millis(20));
        assert_eq!(
            reader.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    fn options() -> GcOptions {
        GcOptions {
            retention: Default::default(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age: None,
            min_age: Duration::ZERO,
            protected_roots: Default::default(),
            mode: GcMode::Apply,
            backend: StorageBackend::Flat,
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<Storage>, Arc<TrustedPublicKeys>) {
        let root = test_root();
        crate::operator::initialize_cache(
            root.path().to_owned(),
            30,
            false,
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let storage = Storage::open(&directory, SupportedStorageBackend::FLAT).unwrap();
        let (_, trusted) = CachePolicies::load(&directory).unwrap().into_parts();
        storage.recover_for_mutation(&trusted).unwrap();
        (root, Arc::new(storage), Arc::new(trusted))
    }

    #[test]
    fn a_roots_source_removed_after_client_loading_is_not_reopened_by_the_daemon() {
        let (root, storage, trusted) = fixture();
        let source = root.path().join("caller-roots");
        std::fs::write(&source, "00000000000000000000000000000000\n").unwrap();
        let mut request = options();
        request.protected_roots =
            crate::cache::storage::gc::ProtectedRoots::load(Some(&source)).unwrap();
        std::fs::remove_file(&source).unwrap();
        let service = ControlService::start(
            root.path(),
            storage,
            trusted,
            Arc::new(Metrics::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let report = collect(root.path(), request, RetryPolicy::default());
        service
            .finish(Instant::now() + Duration::from_secs(2))
            .unwrap();
        assert_eq!(report.unwrap().missing_roots, 1);
    }

    #[test]
    fn oversized_root_sets_never_send_a_partial_request_or_enter_collection() {
        let root = test_root();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let service = ControlService::start_with_collector(
            root.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Metrics::default()),
            move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Reply::Failed(ControlFailure::Stopping)
            },
        )
        .unwrap();
        let mut request = options();
        let oversized = (0..=protocol::MAX_FRAME_BYTES / 32)
            .map(|index| format!("{index:032}\n"))
            .collect::<String>();
        request.protected_roots =
            crate::cache::storage::gc::ProtectedRoots::parse(&oversized).unwrap();
        let result = collect(root.path(), request, RetryPolicy::default());
        service
            .finish(Instant::now() + Duration::from_secs(2))
            .unwrap();
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn daemon_owned_collection_round_trips_the_existing_report_and_maintenance_record() {
        let (root, storage, trusted) = fixture();
        let service = ControlService::start(
            root.path(),
            Arc::clone(&storage),
            trusted,
            Arc::new(Metrics::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let mut attempts = 0;
        let mut delays = 0;
        let report = retry::request_with_retry(
            RetryPolicy::new(std::num::NonZeroU32::new(3).unwrap(), Duration::ZERO).unwrap(),
            || {
                attempts += 1;
                match attempts {
                    1 => Ok(Reply::Failed(ControlFailure::Busy)),
                    2 => Ok(Reply::Failed(ControlFailure::Changed)),
                    _ => request_collection(root.path(), &options()),
                }
            },
            |_| delays += 1,
        )
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(delays, 2);
        assert!(!report.dry_run);
        assert_eq!(report.after_bytes, 0);
        assert!(report.target_met);
        let run =
            maintenance::read_snapshot(root.path()).unwrap().last_runs[Operation::Gc].unwrap();
        assert_eq!(run.outcome, Outcome::Success);
        assert_eq!(run.objects_selected, Some(0));
        assert_eq!(run.bytes_reclaimed, Some(0));
        assert!(
            Storage::open(
                &Directory::open(root.path()).unwrap(),
                SupportedStorageBackend::FLAT
            )
            .is_err(),
            "online collection keeps the daemon's process lease"
        );
        service
            .finish(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(socket::connect(root.path()).is_err());
    }

    #[test]
    fn online_errors_distinguish_policy_backend_and_absent_daemon_without_offline_fallback() {
        let (root, storage, trusted) = fixture();
        let error = match collect(root.path(), options(), RetryPolicy::default()) {
            Err(error) => error,
            Ok(_) => panic!("no daemon"),
        };
        assert!(error.to_string().contains("does not fall back"));
        let service = ControlService::start(
            root.path(),
            storage,
            trusted,
            Arc::new(Metrics::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let mut wrong_backend = options();
        wrong_backend.backend = StorageBackend::Chunked;
        let error = match collect(root.path(), wrong_backend, RetryPolicy::default()) {
            Err(error) => error,
            Ok(_) => panic!("backend mismatch"),
        };
        assert!(matches!(
            error.get_ref().unwrap().downcast_ref::<ControlFailure>(),
            Some(ControlFailure::BackendMismatch)
        ));
        let mut invalid = options();
        invalid.max_bytes = Some(1);
        invalid.target_bytes = Some(2);
        let error = match collect(root.path(), invalid, RetryPolicy::default()) {
            Err(error) => error,
            Ok(_) => panic!("invalid policy"),
        };
        assert!(matches!(
            error.get_ref().unwrap().downcast_ref::<ControlFailure>(),
            Some(ControlFailure::Policy(_))
        ));
        service
            .finish(Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[test]
    fn a_contending_request_is_rejected_before_the_active_collector_is_released() {
        let root = test_root();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let service = ControlService::start_with_collector(
            root.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Metrics::default()),
            move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Reply::Failed(ControlFailure::Changed)
            },
        )
        .unwrap();
        std::thread::scope(|scope| {
            let release = ReleaseCollectorOnDrop(&release_tx);
            let first = scope.spawn(|| collect(root.path(), options(), RetryPolicy::default()));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let second = match collect(root.path(), options(), RetryPolicy::default()) {
                Err(error) => error,
                Ok(_) => panic!("busy collector"),
            };
            assert!(matches!(
                second.get_ref().unwrap().downcast_ref::<ControlFailure>(),
                Some(ControlFailure::Busy)
            ));
            drop(release);
            assert!(matches!(
                first
                    .join()
                    .unwrap()
                    .err()
                    .unwrap()
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<ControlFailure>(),
                Some(ControlFailure::Changed)
            ));
        });
        service
            .finish(Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[test]
    fn malformed_frames_never_reach_collection_and_do_not_poison_the_next_request() {
        let root = test_root();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let service = ControlService::start_with_collector(
            root.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Metrics::default()),
            move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Reply::Failed(ControlFailure::Changed)
            },
        )
        .unwrap();
        let mut connection = socket::connect(root.path()).unwrap();
        connection.write_all(b"NGC3\xff\xff\xff\xff").unwrap();
        let mut byte = [0];
        assert_eq!(
            DeadlineReader::new(&mut connection, Duration::from_secs(5))
                .read(&mut byte)
                .unwrap(),
            0
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(collect(root.path(), options(), RetryPolicy::default()).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        service
            .finish(Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[test]
    fn an_incomplete_request_expires_without_entering_collection_or_poisoning_the_listener() {
        let root = test_root();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let service = ControlService::start_with_collector(
            root.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Metrics::default()),
            move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Reply::Failed(ControlFailure::Changed)
            },
        )
        .unwrap();
        let mut connection = socket::connect(root.path()).unwrap();
        connection.write_all(b"NGC3\0\0\0\x01").unwrap();
        assert_eq!(
            DeadlineReader::new(&mut connection, REQUEST_TIMEOUT + Duration::from_secs(3))
                .read(&mut [0])
                .unwrap(),
            0,
            "the daemon must close an incomplete request without waiting for client EOF"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        drop(connection);
        let error = collect(root.path(), options(), RetryPolicy::default())
            .err()
            .unwrap();
        assert!(matches!(
            error.get_ref().unwrap().downcast_ref::<ControlFailure>(),
            Some(ControlFailure::Changed)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        service
            .finish(Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[test]
    fn transport_neutral_transient_accept_errors_preserve_the_next_framed_request() {
        let root = test_root();
        let bound = socket::BoundSocket::bind(root.path()).unwrap();
        let mut client = socket::connect(root.path()).unwrap();
        protocol::write_frame(&mut client, &options()).unwrap();
        let (sender, receiver) = bounded(1);
        let busy = AtomicBool::new(false);
        let stopping = AtomicBool::new(false);
        let daemon_stopping = AtomicBool::new(false);
        let metrics = Metrics::default();
        let mut errors = [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
        ]
        .into_iter();
        dispatch_requests(
            bound,
            sender,
            &busy,
            &stopping,
            &daemon_stopping,
            &metrics,
            |listener| {
                if let Some(error) = errors.next() {
                    return Err(error.into());
                }
                let connection = socket::accept(listener)?;
                stopping.store(true, Ordering::Release);
                Ok(connection)
            },
        )
        .unwrap();
        let mut job = receiver.try_recv().expect("the request must be queued");
        assert_eq!(job.options.target_bytes, Some(0));
        send_recorded_reply(
            &mut job.connection,
            Reply::Failed(ControlFailure::Changed),
            &metrics,
        );
        assert!(matches!(
            protocol::read_frame::<Reply>(DeadlineReader::new(&mut client, REQUEST_TIMEOUT))
                .unwrap(),
            Reply::Failed(ControlFailure::Changed)
        ));
    }

    #[test]
    fn a_closed_collection_queue_releases_admission_and_reports_stopping() {
        let (connection, mut client) = stream_pair();
        protocol::write_frame(&mut client, &options()).unwrap();
        let (sender, receiver) = bounded(1);
        drop(receiver);
        let busy = AtomicBool::new(false);
        queue_collection_request(connection, &sender, &busy, &Metrics::default()).unwrap();
        assert!(
            !busy.load(Ordering::Acquire),
            "failed queue admission must not keep GC busy"
        );
        assert!(matches!(
            protocol::read_frame::<Reply>(&mut client).unwrap(),
            Reply::Failed(ControlFailure::Stopping)
        ));
    }

    #[test]
    fn expired_deadlines_reject_an_available_partial_frame_without_extending_the_budget() {
        let (mut connection, mut peer) = stream_pair();
        peer.write_all(b"NGC3").unwrap();
        let mut reader = DeadlineReader {
            connection: &mut connection,
            deadline: Instant::now(),
        };
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn shutdown_drains_an_active_collection_before_joining_and_removing_its_socket() {
        let root = test_root();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let service = ControlService::start_with_collector(
            root.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Metrics::default()),
            move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Reply::Failed(ControlFailure::Changed)
            },
        )
        .unwrap();
        thread::scope(|scope| {
            let release = ReleaseCollectorOnDrop(&release_tx);
            let client = scope.spawn(|| collect(root.path(), options(), RetryPolicy::default()));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            service.shutdown.stop();
            assert!(
                !service.collector.is_finished(),
                "shutdown must not detach active maintenance"
            );
            drop(release);
            service
                .finish(Instant::now() + Duration::from_secs(5))
                .unwrap();
            assert!(client.join().unwrap().is_err());
        });
        assert!(socket::connect(root.path()).is_err());
    }

    #[test]
    fn shutdown_has_a_deadline_even_when_the_active_collector_cannot_finish() {
        let root = test_root();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let service = ControlService::start_with_collector(
            root.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Metrics::default()),
            move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Reply::Failed(ControlFailure::Changed)
            },
        )
        .unwrap();
        thread::scope(|scope| {
            let release = ReleaseCollectorOnDrop(&release_tx);
            let client = scope.spawn(|| collect(root.path(), options(), RetryPolicy::default()));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let error = service.finish(Instant::now()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            drop(release);
            assert!(client.join().unwrap().is_err());
        });
    }
}
