//! Private daemon maintenance; this is not part of the binary-cache protocol.

use std::{
    io::{self, Read},
    os::unix::net::UnixStream,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crossbeam_channel::{Sender, bounded};
use narjar::__private::{
    metrics::{Metrics, OnlineGcOutcome},
    narinfo::TrustedPublicKeys,
    storage::{
        Storage, StorageError,
        gc::{GcOptions, GcReport},
    },
};
use serde::{Deserialize, Serialize};

mod protocol;
mod socket;

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

pub(crate) fn collect(mut options: GcOptions) -> io::Result<GcReport> {
    options.protected_roots = options
        .protected_roots
        .map(std::path::absolute)
        .transpose()?;
    let mut connection = socket::connect(&options.data_dir).map_err(|error| io::Error::new(error.kind(), format!("cannot connect to running narjar: {error}; online GC does not fall back to offline GC")))?;
    connection.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    protocol::write_frame(&mut connection, &options)?;
    let reply: Reply = protocol::read_frame(DeadlineReader::new(&mut connection, REPORT_TIMEOUT))?;
    match reply {
        Reply::Completed(report) => Ok(*report),
        Reply::Failed(error) => Err(io::Error::other(error)),
    }
}

struct CollectionJob {
    connection: UnixStream,
    options: GcOptions,
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
                    dispatch_requests(socket, sender, &busy, &stopping, &daemon_stopping, &metrics)
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
) -> io::Result<()> {
    std::iter::repeat_with(|| ())
        .take_while(|_| !is_stopping(stopping, daemon_stopping))
        .try_for_each(|_| {
            match bound.listener.accept() {
                Ok((connection, _)) => {
                    let _ = queue_collection_request(connection, &jobs, busy, metrics);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(Duration::from_millis(100))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
            Ok(())
        })
}

fn queue_collection_request(
    mut connection: UnixStream,
    jobs: &Sender<CollectionJob>,
    busy: &AtomicBool,
    metrics: &Metrics,
) -> io::Result<()> {
    connection.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    if let Ok(options) = protocol::read_frame(DeadlineReader::new(&mut connection, REQUEST_TIMEOUT))
    {
        match busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire) {
            Err(_) => send_recorded_reply(
                &mut connection,
                Reply::Failed(ControlFailure::Busy),
                metrics,
            ),
            Ok(_) => {
                if let Err(error) = jobs.try_send(CollectionJob {
                    connection,
                    options,
                }) {
                    busy.store(false, Ordering::Release);
                    send_recorded_reply(
                        &mut error.into_inner().connection,
                        Reply::Failed(ControlFailure::Stopping),
                        metrics,
                    );
                }
            }
        }
    }
    Ok(())
}

fn send_recorded_reply(connection: &mut UnixStream, reply: Reply, metrics: &Metrics) {
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
    mut options: GcOptions,
) -> Reply {
    if options.backend != storage.backend() {
        return Reply::Failed(ControlFailure::BackendMismatch);
    }
    if let Err(error) = options.validate_policy() {
        return Reply::Failed(ControlFailure::Policy(error.to_string()));
    }
    options.data_dir = root.to_owned();
    match crate::operator::collect_online(options, storage, trusted) {
        Ok(report) => Reply::Completed(Box::new(report)),
        Err(StorageError::CollectionBusy) => Reply::Failed(ControlFailure::Busy),
        Err(StorageError::CollectionChanged) => Reply::Failed(ControlFailure::Changed),
        Err(error) => Reply::Failed(ControlFailure::Storage(error.to_string())),
    }
}

/// A total deadline: partial header/body reads cannot reset the timeout.
struct DeadlineReader<'a> {
    connection: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    fn new(connection: &'a mut UnixStream, timeout: Duration) -> Self {
        Self {
            connection,
            deadline: Instant::now() + timeout,
        }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        self.connection.set_read_timeout(Some(remaining))?;
        self.connection.read(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use narjar::__private::{
        maintenance::{self, Operation, Outcome},
        storage::{CachePolicies, Directory, StorageBackend, SupportedStorageBackend, gc::GcMode},
    };
    use std::{io::Write, sync::mpsc};

    fn options(root: &Path) -> GcOptions {
        GcOptions {
            data_dir: root.to_owned(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age: None,
            min_age: Duration::ZERO,
            protected_roots: None,
            mode: GcMode::Apply,
            backend: StorageBackend::Flat,
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<Storage>, Arc<TrustedPublicKeys>) {
        let root = tempfile::tempdir().unwrap();
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
        let report = collect(options(root.path())).unwrap();
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
        assert!(!socket::socket_path(root.path()).exists());
    }

    #[test]
    fn online_errors_distinguish_policy_backend_and_absent_daemon_without_offline_fallback() {
        let (root, storage, trusted) = fixture();
        let error = match collect(options(root.path())) {
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
        let mut wrong_backend = options(root.path());
        wrong_backend.backend = StorageBackend::Chunked;
        let error = match collect(wrong_backend) {
            Err(error) => error,
            Ok(_) => panic!("backend mismatch"),
        };
        assert!(matches!(
            error.get_ref().unwrap().downcast_ref::<ControlFailure>(),
            Some(ControlFailure::BackendMismatch)
        ));
        let mut invalid = options(root.path());
        invalid.max_bytes = Some(1);
        invalid.target_bytes = Some(2);
        let error = match collect(invalid) {
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
        let root = tempfile::tempdir().unwrap();
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
            let first = scope.spawn(|| collect(options(root.path())));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let second = match collect(options(root.path())) {
                Err(error) => error,
                Ok(_) => panic!("busy collector"),
            };
            assert!(matches!(
                second.get_ref().unwrap().downcast_ref::<ControlFailure>(),
                Some(ControlFailure::Busy)
            ));
            release_tx.send(()).unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
        connection.write_all(b"NGC1\xff\xff\xff\xff").unwrap();
        connection.shutdown(std::net::Shutdown::Write).unwrap();
        let mut byte = [0];
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(connection.read(&mut byte).unwrap(), 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(collect(options(root.path())).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        service
            .finish(Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[test]
    fn expired_deadlines_reject_an_available_partial_frame_without_extending_the_budget() {
        let (mut connection, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"NGC1").unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
            let client = scope.spawn(|| collect(options(root.path())));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            service.shutdown.stop();
            assert!(
                !service.collector.is_finished(),
                "shutdown must not detach active maintenance"
            );
            release_tx.send(()).unwrap();
            service
                .finish(Instant::now() + Duration::from_secs(5))
                .unwrap();
            assert!(client.join().unwrap().is_err());
        });
        assert!(!socket::socket_path(root.path()).exists());
    }

    #[test]
    fn shutdown_has_a_deadline_even_when_the_active_collector_cannot_finish() {
        let root = tempfile::tempdir().unwrap();
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
            let client = scope.spawn(|| collect(options(root.path())));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let error = service.finish(Instant::now()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            release_tx.send(()).unwrap();
            assert!(client.join().unwrap().is_err());
        });
    }
}
