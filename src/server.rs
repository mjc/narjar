use std::{
    collections::VecDeque,
    fs,
    io::{self, Write},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    http::respond,
    storage::{NarUploadPolicy, Storage},
};

use crate::{config::ServeConfig, error::Error};

#[derive(Default)]
struct WorkQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
}

#[derive(Default)]
struct QueueState {
    requests: VecDeque<Request>,
    closed: bool,
}

impl WorkQueue {
    fn push(&self, request: Request) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(!state.closed);
        state.requests.push_back(request);
        drop(state);
        self.ready.notify_one();
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

fn try_admit(in_flight: &AtomicUsize, limit: usize) -> bool {
    in_flight
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < limit).then_some(count + 1)
        })
        .is_ok()
}

struct Admission<'a>(&'a AtomicUsize);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
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
    let max_in_flight = config.max_in_flight.get();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let queue = Arc::new(WorkQueue::default());
    let handles: Vec<_> = (0..config.workers.get())
        .map(|_| {
            let in_flight = Arc::clone(&in_flight);
            let queue = Arc::clone(&queue);
            let storage = Arc::clone(&storage);
            thread::spawn(move || {
                while let Some(request) = queue.pop() {
                    let _admission = Admission(&in_flight);
                    respond(request, &storage, upload_policy);
                }
            })
        })
        .collect();

    while !stopping.load(Ordering::Acquire) {
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
            if try_admit(&in_flight, max_in_flight) {
                queue.push(request);
            } else {
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
