use std::{
    io::{self, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use narjar::{
    auth::Authorizer,
    http::{PublicationRequest, prepare_publication, respond},
    http_server::{Method, Request, StatusCode, write_status},
    inventory::Inventory,
    narinfo::TrustedPublicKeys,
    object::WireEncoding,
    storage::{Directory, NarUploadPolicy, StagingReservation, Storage, StorageError},
};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    low_level,
};

use crate::{config::ServeConfig, error::Error};
use narjar::metrics::{ConnectionOutcome, Metrics, PopulationScanFailure};

struct Admissions {
    limit: usize,
    in_flight: AtomicUsize,
    metrics: Arc<Metrics>,
}

impl Admissions {
    fn new(limit: usize, metrics: Arc<Metrics>) -> Self {
        Self {
            limit,
            in_flight: AtomicUsize::new(0),
            metrics,
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<Admission> {
        self.in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |in_flight| {
                (in_flight < self.limit).then_some(in_flight + 1)
            })
            .ok()?;
        self.metrics.connection_admitted();
        Some(Admission {
            admissions: Arc::clone(self),
            metrics: Arc::clone(&self.metrics),
        })
    }
}

struct Admission {
    admissions: Arc<Admissions>,
    metrics: Arc<Metrics>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        let in_flight = self.admissions.in_flight.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(in_flight > 0);
        self.metrics.connection_released();
    }
}

struct PublicationActivity(Arc<Metrics>);

impl PublicationActivity {
    fn start(metrics: Arc<Metrics>) -> Self {
        metrics.publication_worker_started();
        Self(metrics)
    }
}

impl Drop for PublicationActivity {
    fn drop(&mut self) {
        self.0.publication_worker_finished();
    }
}

struct AcceptedRequest {
    stream: TcpStream,
    _admission: Admission,
}

struct QueuedPublication {
    request: PublicationRequest,
    _admission: Admission,
    _staging: StagingReservation,
    queued_at: Instant,
}

#[derive(Clone)]
struct RequestWorkerContext {
    storage: Arc<Storage>,
    authorizer: Arc<Authorizer>,
    trusted_keys: Arc<TrustedPublicKeys>,
    metrics: Arc<Metrics>,
    publication_sender: Sender<QueuedPublication>,
    min_free_bytes: u64,
    max_nar_bytes: u64,
}

#[derive(Clone)]
struct PublicationWorkerContext {
    storage: Arc<Storage>,
    trusted_keys: Arc<TrustedPublicKeys>,
    metrics: Arc<Metrics>,
    upload_policy: NarUploadPolicy,
    egress_compression: WireEncoding,
}

fn spawn_publication_workers(
    workers: usize,
    receiver: Receiver<QueuedPublication>,
    context: PublicationWorkerContext,
) -> Result<Vec<thread::JoinHandle<()>>, Error> {
    (0..workers)
        .map(|index| {
            let receiver = receiver.clone();
            let context = context.clone();
            thread::Builder::new()
                .name(format!("narjar-publication-{index}"))
                .spawn(move || run_publication_worker(receiver, context))
                .map_err(|error| {
                    Error::runtime(format!("cannot start publication worker: {error}"))
                })
        })
        .collect()
}

fn run_publication_worker(
    receiver: Receiver<QueuedPublication>,
    context: PublicationWorkerContext,
) {
    while let Ok(publication) = receiver.recv() {
        let QueuedPublication {
            request,
            _admission,
            _staging,
            queued_at,
        } = publication;
        context.metrics.publication_dequeued(queued_at);
        let _activity = PublicationActivity::start(Arc::clone(&context.metrics));
        request.respond(
            &context.storage,
            &context.trusted_keys,
            context.upload_policy,
            context.egress_compression,
            &context.metrics,
            _staging,
        );
    }
}

fn spawn_request_workers(
    workers: usize,
    receiver: Receiver<AcceptedRequest>,
    context: RequestWorkerContext,
) -> Vec<thread::JoinHandle<()>> {
    (0..workers)
        .map(|_| {
            let receiver = receiver.clone();
            let context = context.clone();
            thread::spawn(move || run_request_worker(receiver, context))
        })
        .collect()
}

fn run_request_worker(receiver: Receiver<AcceptedRequest>, context: RequestWorkerContext) {
    while let Ok(accepted) = receiver.recv() {
        context.metrics.connection_dequeued();
        let AcceptedRequest {
            mut stream,
            _admission,
        } = accepted;
        let mut admission = Some(_admission);
        let mut has_served_request = false;
        while let Some(next_stream) =
            process_next_request(stream, &mut admission, &context, has_served_request)
        {
            stream = next_stream;
            has_served_request = true;
        }
    }
}

fn process_next_request(
    stream: TcpStream,
    admission: &mut Option<Admission>,
    context: &RequestWorkerContext,
    has_served_request: bool,
) -> Option<TcpStream> {
    if has_served_request {
        match keep_alive_request_is_waiting(&stream) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => {
                let mut stream = stream;
                report_request_read_failure(&mut stream, error, &context.metrics);
                return None;
            }
        }
    }
    match Request::read(stream) {
        Ok(request) => match request.method() {
            Method::Put => {
                queue_publication(request, admission, context);
                None
            }
            Method::Get | Method::Head | Method::Other => respond(
                request,
                &context.storage,
                &context.authorizer,
                &context.trusted_keys,
                &context.metrics,
                context.min_free_bytes,
            ),
        },
        Err((mut stream, error)) => {
            report_request_read_failure(&mut stream, error, &context.metrics);
            None
        }
    }
}

fn keep_alive_request_is_waiting(stream: &TcpStream) -> io::Result<bool> {
    let mut first_byte = [0; 1];
    loop {
        match stream.peek(&mut first_byte) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
}

fn queue_publication(
    request: Request,
    admission: &mut Option<Admission>,
    context: &RequestWorkerContext,
) {
    let Some(request) = prepare_publication(request, &context.authorizer, &context.metrics) else {
        return;
    };
    let staging = context.storage.reserve_staging(
        request.staging_bytes(context.max_nar_bytes).unwrap_or(0),
        context.min_free_bytes,
    );
    let staging = match staging {
        Ok(staging) => staging,
        Err(error) => {
            request.reject(&context.metrics, staging_reservation_status(&error));
            return;
        }
    };
    let publication = QueuedPublication {
        request,
        _admission: admission
            .take()
            .expect("connection admission remains until publication is queued"),
        _staging: staging,
        queued_at: Instant::now(),
    };
    context.metrics.publication_enqueued();
    match context.publication_sender.try_send(publication) {
        Ok(()) => {}
        Err(TrySendError::Full(publication) | TrySendError::Disconnected(publication)) => {
            context.metrics.publication_enqueue_failed();
            publication
                .request
                .reject(&context.metrics, StatusCode::TOO_MANY_REQUESTS);
        }
    }
}

fn report_request_read_failure(stream: &mut TcpStream, error: io::Error, metrics: &Metrics) {
    let outcome = request_read_failure_outcome(error.kind());
    metrics.record_connection_outcome(outcome);
    match outcome {
        ConnectionOutcome::MalformedRequest | ConnectionOutcome::TimedOut => {
            let _ = write_status(stream, StatusCode::BAD_REQUEST);
        }
        ConnectionOutcome::Admitted
        | ConnectionOutcome::AdmissionRejected
        | ConnectionOutcome::RequestQueueFull
        | ConnectionOutcome::Disconnected => {}
    }
}

fn try_dispatch(
    sender: &Sender<AcceptedRequest>,
    admissions: &Arc<Admissions>,
    metrics: &Metrics,
    stream: TcpStream,
) -> Option<TcpStream> {
    let admission = match admissions.try_acquire() {
        Some(admission) => admission,
        None => {
            metrics.record_connection_outcome(ConnectionOutcome::AdmissionRejected);
            return Some(stream);
        }
    };
    let accepted = AcceptedRequest {
        stream,
        _admission: admission,
    };

    metrics.connection_queued();
    match sender.try_send(accepted) {
        Ok(()) => None,
        Err(TrySendError::Full(accepted) | TrySendError::Disconnected(accepted)) => {
            metrics.connection_dequeued();
            metrics.record_connection_outcome(ConnectionOutcome::RequestQueueFull);
            Some(accepted.stream)
        }
    }
}

fn configure_socket_timeouts(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

fn request_read_failure_outcome(kind: io::ErrorKind) -> ConnectionOutcome {
    Metrics::socket_read_failure(kind).unwrap_or(ConnectionOutcome::MalformedRequest)
}

fn staging_reservation_status(error: &StorageError) -> StatusCode {
    match error {
        StorageError::InsufficientSpace | StorageError::InsufficientInodes => {
            StatusCode::INSUFFICIENT_STORAGE
        }
        StorageError::Io(error) if error.raw_os_error() == Some(libc::EROFS) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

struct ServerResources {
    storage: Arc<Storage>,
    authorizer: Arc<Authorizer>,
    trusted_keys: Arc<TrustedPublicKeys>,
}

fn initialize_server_resources(config: &ServeConfig) -> Result<ServerResources, Error> {
    let root_directory =
        Directory::open(&config.data_dir).map_err(|error| Error::runtime(error.to_string()))?;
    root_directory.validate_initialized().map_err(|error| {
        Error::runtime(format!(
            "data directory is not initialized at {}: {error}",
            config.data_dir.display()
        ))
    })?;
    let storage =
        Storage::initialize(&root_directory, config.storage_backend).map_err(|error| {
            Error::runtime(format!(
                "cannot initialize data directory {}: {error}",
                config.data_dir.display()
            ))
        })?;
    let authorizer = Authorizer::load(&root_directory)
        .map_err(|error| Error::runtime(format!("cannot load authorization policy: {error}")))?;
    let trusted_keys = TrustedPublicKeys::load(&root_directory)
        .map_err(|error| Error::runtime(format!("cannot load trusted public keys: {error}")))?;
    finish_required_recovery(&storage, &trusted_keys)?;
    Ok(ServerResources {
        storage: Arc::new(storage),
        authorizer: Arc::new(authorizer),
        trusted_keys: Arc::new(trusted_keys),
    })
}

fn finish_required_recovery(
    storage: &Storage,
    trusted_keys: &TrustedPublicKeys,
) -> Result<(), Error> {
    let recovery_required = storage
        .recovery_required_for()
        .map_err(|error| Error::runtime(format!("cannot inspect cache recovery state: {error}")))?;
    if recovery_required {
        let inventory_is_recoverable = Inventory::can_recover(storage, trusted_keys)
            .map_err(|error| Error::runtime(format!("cannot validate cache: {error}")))?;
        if !inventory_is_recoverable {
            return Err(Error::runtime(
                "cannot recover cache before serving: published inventory contains an invalid narinfo/NAR pair",
            ));
        }
        storage
            .finish_recovery()
            .map_err(|error| Error::runtime(format!("cannot complete cache recovery: {error}")))?;
    }
    Ok(())
}

fn spawn_metrics_sampler(
    config: &ServeConfig,
    metrics: Arc<Metrics>,
    stopping: Arc<AtomicBool>,
) -> io::Result<thread::JoinHandle<()>> {
    let filesystem_sample = config
        .stats_filesystem_sample
        .as_ref()
        .map(|path| (path.clone(), config.data_dir.clone()));
    let maintenance_root = config.data_dir.clone();
    thread::Builder::new()
        .name("narjar-metrics-sampler".to_owned())
        .spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                metrics.sample_periodic();
                metrics.sample_maintenance_sidecar(&maintenance_root);
                if let Some((path, root)) = &filesystem_sample {
                    metrics.sample_filesystem_sidecar(path, root);
                }
                thread::park_timeout(Duration::from_secs(5));
            }
        })
}

fn install_signal_handlers(
    stopping: Arc<AtomicBool>,
    signal_count: Arc<AtomicUsize>,
) -> Result<(), Error> {
    [SIGINT, SIGTERM].into_iter().try_for_each(|signal| {
        let stopping = Arc::clone(&stopping);
        let signal_count = Arc::clone(&signal_count);
        // SAFETY: the handler only performs atomic operations and `_exit`,
        // both of which are async-signal-safe.
        unsafe {
            low_level::register(signal, move || {
                if signal_count.fetch_add(1, Ordering::Relaxed) > 0 {
                    libc::_exit(128 + signal);
                }
                stopping.store(true, Ordering::Release);
            })
        }
        .map(|_| ())
        .map_err(|error| Error::runtime(format!("cannot install signal handler: {error}")))
    })
}

struct AcceptLoopContext {
    sender: Sender<AcceptedRequest>,
    admissions: Arc<Admissions>,
    metrics: Arc<Metrics>,
    stopping: Arc<AtomicBool>,
    io_timeout: Duration,
}

fn run_accept_loop(listener: TcpListener, context: AcceptLoopContext) -> Result<(), Error> {
    while !context.stopping.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if context.stopping.load(Ordering::Acquire) {
                    drop(stream);
                    break;
                }
                configure_socket_timeouts(&stream, context.io_timeout).map_err(|error| {
                    Error::runtime(format!("cannot configure socket timeouts: {error}"))
                })?;
                if let Some(mut stream) = try_dispatch(
                    &context.sender,
                    &context.admissions,
                    &context.metrics,
                    stream,
                ) {
                    let _ = write_status(&mut stream, StatusCode::TOO_MANY_REQUESTS);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::runtime(format!("cannot accept connection: {error}"))),
        }
    }
    Ok(())
}

pub(crate) fn serve(config: ServeConfig) -> Result<(), Error> {
    let ServerResources {
        storage,
        authorizer,
        trusted_keys,
    } = initialize_server_resources(&config)?;
    let metrics = Arc::new(Metrics::default());

    let listener = TcpListener::bind(config.listen)
        .map_err(|error| Error::runtime(format!("cannot listen on {}: {error}", config.listen)))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::runtime(format!("cannot configure listener: {error}")))?;
    let stopping = Arc::new(AtomicBool::new(false));
    let metrics_sampler =
        spawn_metrics_sampler(&config, Arc::clone(&metrics), Arc::clone(&stopping))
            .map_err(|error| Error::runtime(format!("cannot start metrics sampler: {error}")))?;
    let population_sampler = config
        .stats_inventory_interval_seconds
        .map(|interval| {
            spawn_population_sampler(
                Arc::clone(&storage),
                Arc::clone(&metrics),
                Arc::clone(&stopping),
                Duration::from_secs(interval.get()),
            )
        })
        .transpose()
        .map_err(|error| Error::runtime(format!("cannot start population sampler: {error}")))?;
    let signal_count = Arc::new(AtomicUsize::new(0));
    install_signal_handlers(Arc::clone(&stopping), signal_count)?;

    println!(
        "listening http://{} workers={} max_in_flight={} max_nar_bytes={} min_free_bytes={} shutdown_grace_seconds={} io_timeout_seconds={}",
        listener
            .local_addr()
            .map_err(|error| Error::runtime(format!("cannot inspect listener: {error}")))?,
        config.workers,
        config.max_in_flight,
        config.max_nar_bytes,
        config.min_free_bytes,
        config.shutdown_grace_seconds,
        config.io_timeout_seconds
    );
    io::stdout()
        .flush()
        .map_err(|error| Error::runtime(format!("cannot report listener: {error}")))?;

    let min_free_bytes = config.min_free_bytes;
    let egress_compression = config.egress_compression;
    let upload_policy = NarUploadPolicy::new(config.max_nar_bytes.get(), config.min_free_bytes);
    let max_nar_bytes = config.max_nar_bytes.get();
    let max_in_flight = config.max_in_flight.get();
    metrics.configure_pressure_limits(max_in_flight as u64, config.workers.get() as u64);
    let admissions = Arc::new(Admissions::new(max_in_flight, Arc::clone(&metrics)));
    let (sender, receiver) = bounded::<AcceptedRequest>(max_in_flight);
    let (publication_sender, publication_receiver) = bounded::<QueuedPublication>(max_in_flight);
    let publication_handles = spawn_publication_workers(
        config.workers.get(),
        publication_receiver.clone(),
        PublicationWorkerContext {
            storage: Arc::clone(&storage),
            trusted_keys: Arc::clone(&trusted_keys),
            metrics: Arc::clone(&metrics),
            upload_policy,
            egress_compression,
        },
    )?;
    drop(publication_receiver);
    let request_context = RequestWorkerContext {
        storage: Arc::clone(&storage),
        authorizer: Arc::clone(&authorizer),
        trusted_keys: Arc::clone(&trusted_keys),
        metrics: Arc::clone(&metrics),
        publication_sender: publication_sender.clone(),
        min_free_bytes,
        max_nar_bytes,
    };
    let handles = spawn_request_workers(config.workers.get(), receiver.clone(), request_context);
    drop(receiver);

    run_accept_loop(
        listener,
        AcceptLoopContext {
            sender,
            admissions,
            metrics: Arc::clone(&metrics),
            stopping: Arc::clone(&stopping),
            io_timeout: Duration::from_secs(config.io_timeout_seconds.get()),
        },
    )?;
    metrics_sampler.thread().unpark();
    if let Some(sampler) = &population_sampler {
        sampler.thread().unpark();
    }

    let deadline = Instant::now() + Duration::from_secs(config.shutdown_grace_seconds.get());
    while handles.iter().any(|handle| !handle.is_finished()) {
        if Instant::now() >= deadline {
            return Err(Error::runtime("shutdown grace period expired"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| Error::runtime("request worker panicked"))?;
    }
    drop(publication_sender);
    while publication_handles
        .iter()
        .any(|handle| !handle.is_finished())
    {
        if Instant::now() >= deadline {
            return Err(Error::runtime("shutdown grace period expired"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    for handle in publication_handles {
        handle
            .join()
            .map_err(|_| Error::runtime("publication worker panicked"))?;
    }
    metrics_sampler
        .join()
        .map_err(|_| Error::runtime("metrics sampler panicked"))?;
    if let Some(sampler) = population_sampler {
        sampler
            .join()
            .map_err(|_| Error::runtime("population sampler panicked"))?;
    }

    Ok(())
}

fn spawn_population_sampler(
    storage: Arc<Storage>,
    metrics: Arc<Metrics>,
    stopping: Arc<AtomicBool>,
    interval: Duration,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("narjar-population-sampler".to_owned())
        .spawn(move || {
            thread::park_timeout(Duration::from_secs(60));
            while !stopping.load(Ordering::Acquire) {
                let started = Instant::now();
                let started_at_unix_seconds = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let result = storage
                    .population_counts(&stopping)
                    .map_err(|_| PopulationScanFailure);
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                metrics.record_population_scan(
                    storage.backend(),
                    result,
                    started_at_unix_seconds,
                    started.elapsed().as_secs_f64(),
                );
                thread::park_timeout(interval);
            }
        })
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        net::{TcpListener, TcpStream},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
        thread,
        time::Duration,
    };

    use narjar::{http_server::Request, metrics::Metrics};

    use super::{
        Admissions, configure_socket_timeouts, keep_alive_request_is_waiting,
        request_read_failure_outcome,
    };
    use narjar::metrics::ConnectionOutcome;

    #[test]
    fn request_read_failures_keep_disconnect_timeout_and_malformed_distinct() {
        assert!(matches!(
            request_read_failure_outcome(io::ErrorKind::UnexpectedEof),
            ConnectionOutcome::Disconnected
        ));
        assert!(matches!(
            request_read_failure_outcome(io::ErrorKind::TimedOut),
            ConnectionOutcome::TimedOut
        ));
        assert!(matches!(
            request_read_failure_outcome(io::ErrorKind::InvalidData),
            ConnectionOutcome::MalformedRequest
        ));
    }

    #[test]
    fn admission_limit_counts_live_guards() {
        let admissions = Arc::new(Admissions::new(2, Arc::new(Metrics::default())));
        let first = admissions.try_acquire().expect("first admission");
        let second = admissions.try_acquire().expect("second admission");

        assert!(admissions.try_acquire().is_none());

        drop(first);
        assert!(admissions.try_acquire().is_some());
        drop(second);
    }

    #[test]
    fn admission_is_released_during_unwind() {
        let admissions = Arc::new(Admissions::new(1, Arc::new(Metrics::default())));

        let result = catch_unwind(AssertUnwindSafe({
            let admissions = Arc::clone(&admissions);
            move || {
                let _admission = admissions.try_acquire().expect("admission");
                panic!("handler panicked");
            }
        }));

        assert!(result.is_err());
        assert!(admissions.try_acquire().is_some());
    }

    #[test]
    fn socket_read_times_out_when_request_headers_stop_progressing() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let client = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\n")
                .expect("write partial request");
            thread::sleep(Duration::from_millis(200));
        });

        let (stream, _) = listener.accept().expect("accept test request");
        configure_socket_timeouts(&stream, Duration::from_millis(50))
            .expect("configure socket timeouts");
        let error = match Request::read(stream) {
            Ok(_) => panic!("incomplete headers should hit the read deadline"),
            Err((_, error)) => error,
        };

        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        client.join().expect("client should finish");
    }

    #[test]
    fn idle_keep_alive_timeout_has_no_next_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let client = thread::spawn(move || {
            let _stream = TcpStream::connect(address).expect("connect test listener");
            thread::sleep(Duration::from_millis(150));
        });

        let (stream, _) = listener.accept().expect("accept idle connection");
        configure_socket_timeouts(&stream, Duration::from_millis(30))
            .expect("configure socket timeout");
        assert!(!keep_alive_request_is_waiting(&stream).expect("peek idle connection"));
        client.join().expect("client should finish");
    }

    #[test]
    fn clean_keep_alive_close_has_no_next_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let client = thread::spawn(move || {
            drop(TcpStream::connect(address).expect("connect test listener"));
        });

        let (stream, _) = listener.accept().expect("accept closed connection");
        configure_socket_timeouts(&stream, Duration::from_millis(100))
            .expect("configure socket timeout");
        client.join().expect("client should close cleanly");
        assert!(!keep_alive_request_is_waiting(&stream).expect("peek closed connection"));
    }

    #[test]
    fn partial_keep_alive_request_is_not_mistaken_for_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect test listener");
            stream.write_all(b"G").expect("write start of next request");
            thread::sleep(Duration::from_millis(150));
        });

        let (stream, _) = listener.accept().expect("accept partial request");
        configure_socket_timeouts(&stream, Duration::from_millis(30))
            .expect("configure socket timeout");
        assert!(keep_alive_request_is_waiting(&stream).expect("peek partial request"));
        let error = match Request::read(stream) {
            Ok(_) => panic!("incomplete request should time out"),
            Err((_, error)) => error,
        };
        assert!(
            error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock
        );
        client.join().expect("client should finish");
    }
}
