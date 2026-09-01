use std::{
    collections::VecDeque,
    fs,
    io::{self, Write},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use signal_hook::{
    consts::{SIGINT, SIGTERM},
    flag,
};
use tiny_http::{Request, Response, Server, StatusCode};

use narjar::{
    auth::Authorizer,
    http::respond,
    storage::{NarUploadPolicy, Storage},
};

use crate::{config::ServeConfig, error::Error};

struct WorkQueue {
    limit: usize,
    state: Mutex<QueueState>,
    ready: Condvar,
}

#[derive(Default)]
struct QueueState {
    requests: VecDeque<Request>,
    in_flight: usize,
    closed: bool,
}

impl WorkQueue {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            state: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
        }
    }

    fn try_push(&self, request: Request) -> Option<Request> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.in_flight >= self.limit {
            return Some(request);
        }
        debug_assert!(!state.closed);
        state.in_flight += 1;
        state.requests.push_back(request);
        drop(state);
        self.ready.notify_one();
        None
    }

    fn pop(&self) -> Option<Request> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(request) = state.requests.pop_front() {
                return Some(request);
            }
            if state.closed {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn complete(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(state.in_flight > 0);
        state.in_flight -= 1;
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        drop(state);
        self.ready.notify_all();
    }
}

struct Admission<'a>(&'a WorkQueue);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.complete();
    }
}

pub(crate) fn serve(config: ServeConfig) -> Result<(), Error> {
    if !fs::metadata(&config.data_dir)
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

    let upload_policy = NarUploadPolicy::new(config.max_nar_bytes.get(), config.min_free_bytes);
    let queue = Arc::new(WorkQueue::new(config.max_in_flight.get()));
    let handles: Vec<_> = (0..config.workers.get())
        .map(|_| {
            let queue = Arc::clone(&queue);
            let storage = Arc::clone(&storage);
            let authorizer = Arc::clone(&authorizer);
            thread::spawn(move || {
                while let Some(request) = queue.pop() {
                    let _admission = Admission(queue.as_ref());
                    respond(request, &storage, &authorizer, upload_policy);
                }
            })
        })
        .collect();

    while !stopping.load(Ordering::Acquire) {
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
            if let Some(request) = queue.try_push(request) {
                let _ = request.respond(Response::empty(StatusCode(429)));
            }
        }
    }
    queue.close();

    for handle in handles {
        handle
            .join()
            .map_err(|_| Error::runtime("request worker panicked"))?;
    }

    Ok(())
}
