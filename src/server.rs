use std::{
    io::{self, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use narjar::__private::{
    auth::Authorizer,
    http::{PublicationRequest, prepare_publication, respond},
    http_server::{Method, Request, StatusCode, write_status},
    narinfo::TrustedPublicKeys,
    object::WireEncoding,
    storage::{
        CachePolicies, Directory, NarUploadPolicy, RecoveryStatus, StagingReservation, Storage,
        StorageError,
    },
};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    low_level,
};

use crate::{
    config::{ServeConfig, ServeSource},
    error::Error,
};
use narjar::__private::metrics::{ConnectionOutcome, Metrics, PopulationScanFailure};

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

enum PublicationQueueState {
    Open(Sender<QueuedPublication>),
    Draining,
}

struct PublicationQueue {
    state: Mutex<PublicationQueueState>,
    metrics: Arc<Metrics>,
}

impl PublicationQueue {
    fn new(sender: Sender<QueuedPublication>, metrics: Arc<Metrics>) -> Self {
        Self {
            state: Mutex::new(PublicationQueueState::Open(sender)),
            metrics,
        }
    }

    fn begin_draining(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PublicationQueueState::Draining;
    }

    fn enqueue(&self, publication: QueuedPublication) {
        let rejected = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*state {
                PublicationQueueState::Draining => {
                    Some((publication, StatusCode::SERVICE_UNAVAILABLE))
                }
                PublicationQueueState::Open(sender) => {
                    self.metrics.publication_enqueued();
                    match sender.try_send(publication) {
                        Ok(()) => None,
                        Err(
                            TrySendError::Full(publication)
                            | TrySendError::Disconnected(publication),
                        ) => {
                            self.metrics.publication_enqueue_failed();
                            Some((publication, StatusCode::TOO_MANY_REQUESTS))
                        }
                    }
                }
            }
        };
        if let Some((publication, status)) = rejected {
            publication.request.reject(&self.metrics, status);
        }
    }
}

#[derive(Clone)]
struct RequestWorkerContext {
    storage: Arc<Storage>,
    authorizer: Arc<Authorizer>,
    metrics: Arc<Metrics>,
    publications: Arc<PublicationQueue>,
    stopping: Arc<AtomicBool>,
    min_free_bytes: u64,
    max_encoded_nar_bytes: u64,
}

#[derive(Clone, Copy)]
enum ConnectionPhase {
    FirstRequest,
    KeepAlive,
}

#[derive(Debug, Eq, PartialEq)]
enum ConnectionReadiness {
    Readable,
    Closed,
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
    receiver
        .iter()
        .for_each(|publication| respond_to_queued_publication(publication, &context));
}

fn respond_to_queued_publication(
    publication: QueuedPublication,
    context: &PublicationWorkerContext,
) {
    let QueuedPublication {
        mut request,
        _admission,
        _staging,
        queued_at,
    } = publication;
    context.metrics.publication_dequeued(queued_at);
    let _activity = PublicationActivity::start(Arc::clone(&context.metrics));
    if let Err(error) = request.acknowledge_body() {
        if let Some(outcome) = Metrics::socket_read_failure(error.kind()) {
            context.metrics.record_connection_outcome(outcome);
        }
        return;
    }
    request.respond(
        &context.storage,
        &context.trusted_keys,
        context.upload_policy,
        context.egress_compression,
        &context.metrics,
        _staging,
    );
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
    receiver.iter().for_each(|accepted| {
        context.metrics.connection_dequeued();
        let AcceptedRequest { stream, _admission } = accepted;
        let mut admission = Some(_admission);
        let mut phase = ConnectionPhase::FirstRequest;
        let mut next_stream = Some(stream);
        std::iter::from_fn(|| {
            let stream = next_stream.take()?;
            next_stream = process_next_request(stream, &mut admission, &context, phase);
            phase = ConnectionPhase::KeepAlive;
            Some(())
        })
        .for_each(drop);
    });
}

fn process_next_request(
    stream: TcpStream,
    admission: &mut Option<Admission>,
    context: &RequestWorkerContext,
    phase: ConnectionPhase,
) -> Option<TcpStream> {
    if context.stopping.load(Ordering::Acquire) {
        return None;
    }
    match phase {
        ConnectionPhase::FirstRequest => {}
        ConnectionPhase::KeepAlive => {
            match wait_for_keep_alive_request_or_shutdown(&stream, &context.stopping) {
                Ok(ConnectionReadiness::Readable) => {}
                Ok(ConnectionReadiness::Closed) => return None,
                Err(error) => {
                    let mut stream = stream;
                    report_request_read_failure(&mut stream, error, &context.metrics);
                    return None;
                }
            }
        }
    }
    match Request::read(stream) {
        Ok(_) if context.stopping.load(Ordering::Acquire) => None,
        Ok(request) => match request.method() {
            Method::Put => {
                queue_publication(request, admission, context);
                None
            }
            Method::Get | Method::Head | Method::Other => respond(
                request,
                &context.storage,
                &context.authorizer,
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

fn wait_for_keep_alive_request_or_shutdown(
    stream: &TcpStream,
    stopping: &AtomicBool,
) -> io::Result<ConnectionReadiness> {
    let timeout = stream.read_timeout()?;
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let poll_interval = Duration::from_millis(50);
    stream.set_read_timeout(Some(timeout.unwrap_or(poll_interval).min(poll_interval)))?;
    let result = std::iter::repeat_with(|| poll_keep_alive_connection(stream, stopping, deadline))
        .find_map(std::convert::identity)
        .expect("polling ends only with a readiness result");
    stream.set_read_timeout(timeout)?;
    result
}

fn poll_keep_alive_connection(
    stream: &TcpStream,
    stopping: &AtomicBool,
    deadline: Option<Instant>,
) -> Option<io::Result<ConnectionReadiness>> {
    if stopping.load(Ordering::Acquire)
        || deadline.is_some_and(|deadline| Instant::now() >= deadline)
    {
        return Some(Ok(ConnectionReadiness::Closed));
    }
    let mut first_byte = [0; 1];
    match stream.peek(&mut first_byte) {
        Ok(0) => Some(Ok(ConnectionReadiness::Closed)),
        Ok(_) => Some(Ok(ConnectionReadiness::Readable)),
        Err(error) => match error.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                None
            }
            _ => Some(Err(error)),
        },
    }
}

fn queue_publication(
    request: Request,
    admission: &mut Option<Admission>,
    context: &RequestWorkerContext,
) {
    let Some(request) = prepare_publication(
        request,
        &context.storage,
        &context.authorizer,
        &context.metrics,
        context.max_encoded_nar_bytes,
    ) else {
        return;
    };
    let staging = context
        .storage
        .reserve_staging(request.staging_bytes(), context.min_free_bytes);
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
    context.publications.enqueue(publication);
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

fn configure_accepted_socket(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
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
        StorageError::Io(error)
            if error.raw_os_error() == Some(rustix::io::Errno::ROFS.raw_os_error()) =>
        {
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
    let storage = Storage::open(&root_directory, config.storage_backend()).map_err(|error| {
        Error::runtime(format!(
            "data directory is not initialized at {}: {error}",
            config.data_dir.display()
        ))
    })?;
    let (authorizer, trusted_keys) = CachePolicies::load(&root_directory)
        .map_err(|error| {
            Error::runtime(format!("cannot load initialized cache policies: {error}"))
        })?
        .into_parts();
    match &config.source {
        ServeSource::FlatCache { .. } => {
            initialize_flat_cache_resources(storage, authorizer, trusted_keys)
        }
        ServeSource::NativeStore(settings) => {
            settings
                .validate(&config.data_dir, &trusted_keys)
                .map_err(|error| Error::runtime(error.to_string()))?;
            Err(Error::runtime(
                "native-store source passed startup validation, but native-store request serving is not implemented yet",
            ))
        }
    }
}

fn initialize_flat_cache_resources(
    storage: Storage,
    authorizer: Authorizer,
    trusted_keys: TrustedPublicKeys,
) -> Result<ServerResources, Error> {
    recover_server_storage(&storage, &trusted_keys)?;
    Ok(ServerResources {
        storage: Arc::new(storage),
        authorizer: Arc::new(authorizer),
        trusted_keys: Arc::new(trusted_keys),
    })
}

fn recover_server_storage(
    storage: &Storage,
    trusted_keys: &TrustedPublicKeys,
) -> Result<(), Error> {
    let started = Instant::now();
    let mut last_progress = Instant::now();
    if storage
        .recovery_required_for()
        .map_err(|error| Error::runtime(format!("cannot inspect cache recovery state: {error}")))?
    {
        eprintln!("narjar: recovery required; checking published narinfo references");
    }
    let status = storage
        .recover_if_required(trusted_keys, |checked| {
            if checked.get() % 1000 == 0 || last_progress.elapsed() >= Duration::from_secs(10) {
                eprintln!(
                    "narjar: recovery checked {checked} narinfo entries in {:.1}s",
                    started.elapsed().as_secs_f64()
                );
                last_progress = Instant::now();
            }
        })
        .map_err(|error| Error::runtime(format!("cannot recover cache before serving: {error}")))?;
    if let RecoveryStatus::Completed(checked) = status {
        eprintln!(
            "narjar: recovery checked {checked} narinfo entries and completed in {:.1}s",
            started.elapsed().as_secs_f64()
        );
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
                    low_level::exit(128 + signal);
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
    publications: Arc<PublicationQueue>,
    io_timeout: Duration,
}

fn run_accept_loop(listener: TcpListener, context: AcceptLoopContext) -> Result<(), Error> {
    run_accept_loop_with(context, || listener.accept().map(|(stream, _)| stream))
}

fn run_accept_loop_with(
    context: AcceptLoopContext,
    mut accept: impl FnMut() -> io::Result<TcpStream>,
) -> Result<(), Error> {
    std::iter::from_fn(|| (!context.stopping.load(Ordering::Acquire)).then(&mut accept))
        .try_for_each(|connection| {
            match connection {
                Ok(stream) => {
                    if context.stopping.load(Ordering::Acquire) {
                        drop(stream);
                        return Ok(());
                    }
                    configure_accepted_socket(&stream, context.io_timeout).map_err(|error| {
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
                Err(error) => continue_after_accept_error(error)?,
            }
            Ok(())
        })?;
    context.publications.begin_draining();
    Ok(())
}

fn continue_after_accept_error(error: io::Error) -> Result<(), Error> {
    let kind = error.kind();
    // Linux reports pending per-connection network failures from accept().
    // Its accept(2) contract requires treating these like an empty queue.
    #[cfg(target_os = "linux")]
    let kind = match error
        .raw_os_error()
        .map(rustix::io::Errno::from_raw_os_error)
    {
        Some(
            rustix::io::Errno::NETDOWN
            | rustix::io::Errno::PROTO
            | rustix::io::Errno::NOPROTOOPT
            | rustix::io::Errno::HOSTDOWN
            | rustix::io::Errno::NONET
            | rustix::io::Errno::HOSTUNREACH
            | rustix::io::Errno::OPNOTSUPP
            | rustix::io::Errno::NETUNREACH,
        ) => io::ErrorKind::WouldBlock,
        _ => kind,
    };
    match kind {
        io::ErrorKind::WouldBlock => {
            thread::sleep(Duration::from_millis(50));
            Ok(())
        }
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted => Ok(()),
        _ => Err(Error::runtime(format!("cannot accept connection: {error}"))),
    }
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
        "listening http://{} workers={} max_in_flight={} max_nar_bytes={} max_encoded_nar_bytes={} max_decoder_memory_bytes={} max_concurrent_decoders={} min_free_bytes={} shutdown_grace_seconds={} io_timeout_seconds={}",
        listener
            .local_addr()
            .map_err(|error| Error::runtime(format!("cannot inspect listener: {error}")))?,
        config.workers,
        config.max_in_flight,
        config.max_nar_bytes,
        config.max_encoded_nar_bytes,
        config.max_decoder_memory_bytes,
        config.workers,
        config.min_free_bytes,
        config.shutdown_grace_seconds,
        config.io_timeout_seconds
    );
    io::stdout()
        .flush()
        .map_err(|error| Error::runtime(format!("cannot report listener: {error}")))?;

    let min_free_bytes = config.min_free_bytes;
    let egress_compression = config.egress_compression();
    let upload_policy = NarUploadPolicy::with_limits(
        config.max_encoded_nar_bytes.get(),
        config.max_nar_bytes.get(),
        config.max_decoder_memory_bytes.get(),
        config.min_free_bytes,
    );
    let max_encoded_nar_bytes = config.max_encoded_nar_bytes.get();
    let max_in_flight = config.max_in_flight.get();
    metrics.configure_pressure_limits(max_in_flight as u64, config.workers.get() as u64);
    let admissions = Arc::new(Admissions::new(max_in_flight, Arc::clone(&metrics)));
    let (sender, receiver) = bounded::<AcceptedRequest>(max_in_flight);
    let (publication_sender, publication_receiver) = bounded::<QueuedPublication>(max_in_flight);
    let publications = Arc::new(PublicationQueue::new(
        publication_sender,
        Arc::clone(&metrics),
    ));
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
        metrics: Arc::clone(&metrics),
        publications: Arc::clone(&publications),
        stopping: Arc::clone(&stopping),
        min_free_bytes,
        max_encoded_nar_bytes,
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
            publications,
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

    use narjar::__private::{http_server::Request, metrics::Metrics};

    use super::{
        Admissions, ConnectionReadiness, configure_accepted_socket, request_read_failure_outcome,
        wait_for_keep_alive_request_or_shutdown,
    };
    use narjar::__private::metrics::ConnectionOutcome;

    #[test]
    fn aborted_pending_connections_do_not_stop_accepting_requests() {
        assert_accepts_after_connection_error(io::ErrorKind::ConnectionAborted.into());
    }

    #[test]
    fn permanent_listener_errors_are_not_retried() {
        use rustix::io::Errno;
        for errno in [
            Errno::BADF,
            Errno::INVAL,
            Errno::NOTSOCK,
            Errno::MFILE,
            Errno::NFILE,
        ] {
            let error = super::continue_after_accept_error(errno.into())
                .expect_err("invalid listeners and exhausted descriptors must not spin");
            assert!(
                error
                    .to_string()
                    .contains(&errno.raw_os_error().to_string())
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pending_network_errors_do_not_stop_accepting_requests() {
        use rustix::io::Errno;
        for errno in [
            Errno::NETDOWN,
            Errno::PROTO,
            Errno::NOPROTOOPT,
            Errno::HOSTDOWN,
            Errno::NONET,
            Errno::HOSTUNREACH,
            Errno::OPNOTSUPP,
            Errno::NETUNREACH,
        ] {
            assert_accepts_after_connection_error(errno.into());
        }
    }

    fn assert_accepts_after_connection_error(error: io::Error) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let metrics = Arc::new(Metrics::default());
        let admissions = Arc::new(Admissions::new(1, Arc::clone(&metrics)));
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let (publication_sender, _publication_receiver) = crossbeam_channel::bounded(1);
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let context = super::AcceptLoopContext {
            sender,
            admissions,
            metrics: Arc::clone(&metrics),
            stopping: Arc::clone(&stopping),
            publications: Arc::new(super::PublicationQueue::new(publication_sender, metrics)),
            io_timeout: Duration::from_secs(1),
        };
        let mut pending = [Err(error), Ok(stream)].into_iter();
        super::run_accept_loop_with(context, || {
            pending.next().unwrap_or_else(|| {
                stopping.store(true, std::sync::atomic::Ordering::Release);
                Err(io::ErrorKind::Interrupted.into())
            })
        })
        .expect("a failed pending connection must not stop the listener");
        let accepted = receiver
            .try_recv()
            .expect("the next connection reaches a worker");
        assert!(accepted.stream.nodelay().unwrap());
    }

    #[test]
    fn unavailable_publication_queue_rejects_without_continue_and_releases_admission() {
        use narjar::__private::{
            auth::Authorizer,
            storage::{CacheCreation, Directory, SupportedStorageBackend},
            token_file::TokenFile,
        };
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let directory = tempfile::tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .unwrap()
            .create_or_complete()
            .unwrap();
        let mut tokens = TokenFile::default();
        tokens
            .insert("test", Sha256::digest(b"test").into())
            .unwrap();
        tokens
            .store(&directory.path().join("auth/write.tokens"))
            .unwrap();
        let metrics = Arc::new(Metrics::default());
        let admissions = Arc::new(Admissions::new(1, Arc::clone(&metrics)));
        let (publication_sender, receiver) = crossbeam_channel::bounded(0);
        let context = super::RequestWorkerContext {
            storage: Arc::new(storage),
            authorizer: Arc::new(Authorizer::load(&root).unwrap()),
            metrics: Arc::clone(&metrics),
            publications: Arc::new(super::PublicationQueue::new(
                publication_sender,
                Arc::clone(&metrics),
            )),
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            min_free_bytes: 0,
            max_encoded_nar_bytes: 1024,
        };
        let mut receiver = Some(receiver);
        enum Rejection {
            Full,
            Disconnected,
            Draining,
        }
        for rejection in [
            Rejection::Full,
            Rejection::Disconnected,
            Rejection::Draining,
        ] {
            let status = match rejection {
                Rejection::Full => "429 Too Many Requests",
                Rejection::Disconnected => {
                    drop(receiver.take());
                    "429 Too Many Requests"
                }
                Rejection::Draining => {
                    context.publications.begin_draining();
                    "503 Service Unavailable"
                }
            };
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            client.write_all(
                b"PUT /nar/0000000000000000000000000000000000000000000000000000.nar HTTP/1.1\r\nContent-Length: 4\r\nAuthorization: Basic OnRlc3Q=\r\nExpect: 100-continue\r\n\r\n",
            ).unwrap();
            let (stream, _) = listener.accept().unwrap();
            let request = Request::read(stream).unwrap();
            let mut admission = admissions.try_acquire();
            super::queue_publication(request, &mut admission, &context);
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}\r\n")),
                "{response}"
            );
            assert!(!response.contains("100 Continue"), "{response}");
            assert!(
                admissions.try_acquire().is_some(),
                "rejected request released admission"
            );
        }
    }

    #[test]
    fn draining_publication_gate_releases_its_sender_without_dropping_request_contexts() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let queue = Arc::new(super::PublicationQueue::new(
            sender,
            Arc::new(Metrics::default()),
        ));
        let request_context_reference = Arc::clone(&queue);
        assert!(matches!(
            receiver.try_recv(),
            Err(crossbeam_channel::TryRecvError::Empty)
        ));
        queue.begin_draining();
        assert!(matches!(
            receiver.try_recv(),
            Err(crossbeam_channel::TryRecvError::Disconnected)
        ));
        request_context_reference.begin_draining();
    }

    #[test]
    fn keep_alive_readiness_restores_the_request_header_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let timeout = Duration::from_secs(2);
        configure_accepted_socket(&stream, timeout).unwrap();
        client.write_all(b"G").unwrap();
        assert_eq!(
            wait_for_keep_alive_request_or_shutdown(
                &stream,
                &std::sync::atomic::AtomicBool::new(false)
            )
            .unwrap(),
            ConnectionReadiness::Readable
        );
        assert_eq!(stream.read_timeout().unwrap(), Some(timeout));
    }

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
    fn accepted_socket_sends_http_headers_and_body_without_nagle_delay() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let _client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("connect test listener");
        let (stream, _) = listener.accept().expect("accept test request");

        configure_accepted_socket(&stream, Duration::from_secs(1))
            .expect("configure accepted socket");

        assert!(stream.nodelay().expect("read TCP_NODELAY"));
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
        configure_accepted_socket(&stream, Duration::from_millis(50))
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
        configure_accepted_socket(&stream, Duration::from_millis(30))
            .expect("configure socket timeout");
        assert_eq!(
            wait_for_keep_alive_request_or_shutdown(
                &stream,
                &std::sync::atomic::AtomicBool::new(false)
            )
            .expect("peek idle connection"),
            ConnectionReadiness::Closed
        );
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
        configure_accepted_socket(&stream, Duration::from_millis(100))
            .expect("configure socket timeout");
        client.join().expect("client should close cleanly");
        assert_eq!(
            wait_for_keep_alive_request_or_shutdown(
                &stream,
                &std::sync::atomic::AtomicBool::new(false)
            )
            .expect("peek closed connection"),
            ConnectionReadiness::Closed
        );
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
        configure_accepted_socket(&stream, Duration::from_millis(30))
            .expect("configure socket timeout");
        assert_eq!(
            wait_for_keep_alive_request_or_shutdown(
                &stream,
                &std::sync::atomic::AtomicBool::new(false)
            )
            .expect("peek partial request"),
            ConnectionReadiness::Readable
        );
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
