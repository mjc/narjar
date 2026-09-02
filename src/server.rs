use std::{
    fs,
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use crossbeam_channel::{Sender, TrySendError, bounded};

use signal_hook::{
    consts::{SIGINT, SIGTERM},
    flag,
};
use tiny_http::{Request, Response, Server, StatusCode};

use narjar::{
    auth::Authorizer,
    http::respond,
    inventory::Inventory,
    narinfo::TrustedPublicKeys,
    storage::{NarUploadPolicy, Storage},
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
    request: Request,
    _admission: Admission,
}

fn try_dispatch(
    sender: &Sender<AcceptedRequest>,
    admissions: &Arc<Admissions>,
    request: Request,
) -> Option<Request> {
    let admission = match admissions.try_acquire() {
        Some(admission) => admission,
        None => return Some(request),
    };
    let accepted = AcceptedRequest {
        request,
        _admission: admission,
    };

    match sender.try_send(accepted) {
        Ok(()) => None,
        Err(TrySendError::Full(accepted) | TrySendError::Disconnected(accepted)) => {
            Some(accepted.request)
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
        let inventory = Inventory::scan(&config.data_dir, &trusted_keys, false)
            .map_err(|error| Error::runtime(format!("cannot inventory cache: {error}")))?;
        if !inventory.can_serve() {
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

    let server = Server::http(config.listen)
        .map_err(|error| Error::runtime(format!("cannot listen on {}: {error}", config.listen)))?;
    let stopping = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stopping))
        .and_then(|_| flag::register(SIGTERM, Arc::clone(&stopping)))
        .map_err(|error| Error::runtime(format!("cannot install signal handler: {error}")))?;

    println!(
        "listening http://{} workers={} max_in_flight={} max_nar_bytes={} min_free_bytes={}",
        server.server_addr(),
        config.workers,
        config.max_in_flight,
        config.max_nar_bytes,
        config.min_free_bytes
    );
    io::stdout()
        .flush()
        .map_err(|error| Error::runtime(format!("cannot report listener: {error}")))?;

    let min_free_bytes = config.min_free_bytes;
    let upload_policy = NarUploadPolicy::new(config.max_nar_bytes.get(), config.min_free_bytes);
    let max_in_flight = config.max_in_flight.get();
    let admissions = Arc::new(Admissions::new(max_in_flight));
    let (sender, receiver) = bounded::<AcceptedRequest>(max_in_flight);
    let handles: Vec<_> = (0..config.workers.get())
        .map(|_| {
            let receiver = receiver.clone();
            let storage = Arc::clone(&storage);
            let authorizer = Arc::clone(&authorizer);
            let trusted_keys = Arc::clone(&trusted_keys);
            let metrics = Arc::clone(&metrics);
            thread::spawn(move || {
                while let Ok(accepted) = receiver.recv() {
                    let AcceptedRequest {
                        request,
                        _admission,
                    } = accepted;
                    respond(
                        request,
                        &storage,
                        &authorizer,
                        &trusted_keys,
                        upload_policy,
                        &metrics,
                        min_free_bytes,
                    );
                }
            })
        })
        .collect();
    drop(receiver);

    while !stopping.load(Ordering::Acquire) {
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
            if let Some(request) = try_dispatch(&sender, &admissions, request) {
                let _ = request.respond(Response::empty(StatusCode(429)));
            }
        }
    }
    drop(sender);

    for handle in handles {
        handle
            .join()
            .map_err(|_| Error::runtime("request worker panicked"))?;
    }

    Ok(())
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
