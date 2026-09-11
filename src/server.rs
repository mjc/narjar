use std::{
    fs,
    io::{self, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crossbeam_channel::{Sender, TrySendError, bounded};

use narjar::{
    auth::Authorizer,
    http::{PublicationRequest, prepare_publication, respond},
    http_server::{Method, Request, StatusCode, write_status},
    inventory::Inventory,
    narinfo::TrustedPublicKeys,
    storage::{NarUploadPolicy, Storage},
};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    low_level,
};

use crate::{config::ServeConfig, error::Error};
use narjar::metrics::Metrics;

struct Admissions {
    limit: usize,
    in_flight: AtomicUsize,
}

impl Admissions {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<Admission> {
        self.in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |in_flight| {
                (in_flight < self.limit).then_some(in_flight + 1)
            })
            .ok()?;
        Some(Admission(Arc::clone(self)))
    }
}

struct Admission(Arc<Admissions>);

impl Drop for Admission {
    fn drop(&mut self) {
        let in_flight = self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(in_flight > 0);
    }
}

struct AcceptedRequest {
    stream: TcpStream,
    _admission: Admission,
}

struct QueuedPublication {
    request: PublicationRequest,
    _admission: Admission,
    queued_at: Instant,
}

fn try_dispatch(
    sender: &Sender<AcceptedRequest>,
    admissions: &Arc<Admissions>,
    stream: TcpStream,
) -> Option<TcpStream> {
    let admission = match admissions.try_acquire() {
        Some(admission) => admission,
        None => return Some(stream),
    };
    let accepted = AcceptedRequest {
        stream,
        _admission: admission,
    };

    match sender.try_send(accepted) {
        Ok(()) => None,
        Err(TrySendError::Full(accepted) | TrySendError::Disconnected(accepted)) => {
            Some(accepted.stream)
        }
    }
}

pub(crate) fn serve(config: ServeConfig) -> Result<(), Error> {
    if !fs::symlink_metadata(&config.data_dir)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return Err(Error::runtime(format!(
            "data directory is not a directory: {}",
            config.data_dir.display()
        )));
    }
    require_initialized_data(&config.data_dir)?;

    let storage = Arc::new(Storage::initialize(&config.data_dir).map_err(|error| {
        Error::runtime(format!(
            "cannot initialize data directory {}: {error}",
            config.data_dir.display()
        ))
    })?);
    let authorizer =
        Arc::new(Authorizer::load(&config.data_dir).map_err(|error| {
            Error::runtime(format!("cannot load authorization policy: {error}"))
        })?);
    let trusted_keys_path = config.data_dir.join("trusted-public-keys");
    let trusted_keys = TrustedPublicKeys::load(&trusted_keys_path)
        .map_err(|error| Error::runtime(format!("cannot load trusted public keys: {error}")))?;
    if storage
        .recovery_required_for(&trusted_keys_path)
        .map_err(|error| Error::runtime(format!("cannot inspect cache recovery state: {error}")))?
    {
        if !Inventory::can_serve_streaming(&config.data_dir, &trusted_keys)
            .map_err(|error| Error::runtime(format!("cannot validate cache: {error}")))?
        {
            return Err(Error::runtime(
                "cannot activate trusted public keys: published narinfo is not trusted",
            ));
        }
        storage
            .finish_recovery(&trusted_keys_path)
            .map_err(|error| Error::runtime(format!("cannot complete cache recovery: {error}")))?;
    }
    let trusted_keys = Arc::new(trusted_keys);
    let metrics = Arc::new(Metrics::default());

    let listener = TcpListener::bind(config.listen)
        .map_err(|error| Error::runtime(format!("cannot listen on {}: {error}", config.listen)))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::runtime(format!("cannot configure listener: {error}")))?;
    let stopping = Arc::new(AtomicBool::new(false));
    let signal_count = Arc::new(AtomicUsize::new(0));
    for signal in [SIGINT, SIGTERM] {
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
        .map_err(|error| Error::runtime(format!("cannot install signal handler: {error}")))?;
    }

    println!(
        "listening http://{} workers={} max_in_flight={} max_nar_bytes={} min_free_bytes={} shutdown_grace_seconds={}",
        listener
            .local_addr()
            .map_err(|error| Error::runtime(format!("cannot inspect listener: {error}")))?,
        config.workers,
        config.max_in_flight,
        config.max_nar_bytes,
        config.min_free_bytes,
        config.shutdown_grace_seconds
    );
    io::stdout()
        .flush()
        .map_err(|error| Error::runtime(format!("cannot report listener: {error}")))?;

    let min_free_bytes = config.min_free_bytes;
    let upload_policy = NarUploadPolicy::new(config.max_nar_bytes.get(), config.min_free_bytes);
    let max_in_flight = config.max_in_flight.get();
    let admissions = Arc::new(Admissions::new(max_in_flight));
    let (sender, receiver) = bounded::<AcceptedRequest>(max_in_flight);
    let (publication_sender, publication_receiver) = bounded::<QueuedPublication>(max_in_flight);
    let publication_handle = {
        let storage = Arc::clone(&storage);
        let trusted_keys = Arc::clone(&trusted_keys);
        let metrics = Arc::clone(&metrics);
        thread::Builder::new()
            .name("narjar-publication".to_owned())
            .spawn(move || {
                while let Ok(publication) = publication_receiver.recv() {
                    metrics.publication_dequeued(publication.queued_at);
                    publication
                        .request
                        .respond(&storage, &trusted_keys, upload_policy, &metrics);
                }
            })
            .map_err(|error| Error::runtime(format!("cannot start publication worker: {error}")))?
    };
    let handles: Vec<_> = (0..config.workers.get())
        .map(|_| {
            let receiver = receiver.clone();
            let storage = Arc::clone(&storage);
            let authorizer = Arc::clone(&authorizer);
            let trusted_keys = Arc::clone(&trusted_keys);
            let metrics = Arc::clone(&metrics);
            let publication_sender = publication_sender.clone();
            thread::spawn(move || {
                while let Ok(accepted) = receiver.recv() {
                    let AcceptedRequest {
                        mut stream,
                        _admission,
                    } = accepted;
                    let mut admission = Some(_admission);
                    loop {
                        match Request::read(stream) {
                            Ok(request) if matches!(request.method(), Method::Put) => {
                                let Some(request) =
                                    prepare_publication(request, &authorizer, &metrics)
                                else {
                                    break;
                                };
                                let publication = QueuedPublication {
                                    request,
                                    _admission: admission
                                        .take()
                                        .expect("request admission is present"),
                                    queued_at: Instant::now(),
                                };
                                metrics.publication_enqueued();
                                match publication_sender.try_send(publication) {
                                    Ok(()) => break,
                                    Err(
                                        TrySendError::Full(publication)
                                        | TrySendError::Disconnected(publication),
                                    ) => {
                                        metrics.publication_enqueue_failed();
                                        publication.request.reject(&metrics, 429);
                                        break;
                                    }
                                }
                            }
                            Ok(request) => match respond(
                                request,
                                &storage,
                                &authorizer,
                                &trusted_keys,
                                upload_policy,
                                &metrics,
                                min_free_bytes,
                            ) {
                                Some(next_stream) => stream = next_stream,
                                None => break,
                            },
                            Err((_stream, error))
                                if error.kind() == io::ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err((mut stream, _error)) => {
                                let _ = write_status(&mut stream, StatusCode(400));
                                break;
                            }
                        }
                    }
                }
            })
        })
        .collect();
    drop(receiver);

    while !stopping.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if stopping.load(Ordering::Acquire) {
                    drop(stream);
                    break;
                }
                if let Some(mut stream) = try_dispatch(&sender, &admissions, stream) {
                    let _ = write_status(&mut stream, StatusCode(429));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::runtime(format!("cannot accept connection: {error}"))),
        }
    }
    drop(sender);

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
    while !publication_handle.is_finished() {
        if Instant::now() >= deadline {
            return Err(Error::runtime("shutdown grace period expired"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    publication_handle
        .join()
        .map_err(|_| Error::runtime("publication worker panicked"))?;

    Ok(())
}

fn require_initialized_data(root: &Path) -> Result<(), Error> {
    require_directory(root, "data directory")?;
    for directory in [
        "nar",
        "nar/.tmp",
        ".tmp",
        "realisations",
        "realisations/.tmp",
        "auth",
    ] {
        require_directory(&root.join(directory), directory)?;
    }
    for file in ["nix-cache-info", "trusted-public-keys", "auth/write.tokens"] {
        require_private_file(&root.join(file), file)?;
    }

    let clean = root.join(".narjar-clean");
    let recovery = root.join(".narjar-recovery");
    let clean_present = path_exists(&clean)?;
    let recovery_present = path_exists(&recovery)?;
    if clean_present {
        require_private_file(&clean, ".narjar-clean")?;
    }
    if recovery_present {
        require_private_file(&recovery, ".narjar-recovery")?;
    }
    if !clean_present && !recovery_present {
        return Err(Error::runtime(
            "data directory is not initialized; run `narjar init --data-dir ...`",
        ));
    }
    Ok(())
}

fn require_directory(path: &Path, name: &str) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::runtime(format!(
            "{name} is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Error::runtime(format!(
            "{name} is not a directory: {}",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::runtime(format!(
            "{name} has unsafe permissions: {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_private_file(path: &Path, name: &str) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::runtime(format!(
            "{name} is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Error::runtime(format!(
            "{name} is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(Error::runtime(format!(
            "{name} must have 0600 permissions: {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::runtime(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };

    use super::Admissions;

    #[test]
    fn admission_limit_counts_live_guards() {
        let admissions = Arc::new(Admissions::new(2));
        let first = admissions.try_acquire().expect("first admission");
        let second = admissions.try_acquire().expect("second admission");

        assert!(admissions.try_acquire().is_none());

        drop(first);
        assert!(admissions.try_acquire().is_some());
        drop(second);
    }

    #[test]
    fn admission_is_released_during_unwind() {
        let admissions = Arc::new(Admissions::new(1));

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
}
