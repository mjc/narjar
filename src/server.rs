use std::{
    fs,
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use signal_hook::{
    consts::{SIGINT, SIGTERM},
    flag,
};
use tiny_http::Server;

use narjar::{http::respond, storage::Storage};

use crate::{config::ServeConfig, error::Error};

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

    let server =
        Arc::new(Server::http(config.listen).map_err(|error| {
            Error::runtime(format!("cannot listen on {}: {error}", config.listen))
        })?);
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

    let max_nar_bytes = config.max_nar_bytes.get();
    let min_free_bytes = config.min_free_bytes;
    let handles: Vec<_> = (0..config.workers.get())
        .map(|_| {
            let server = Arc::clone(&server);
            let storage = Arc::clone(&storage);
            let stopping = Arc::clone(&stopping);
            thread::spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
                        respond(request, &storage, max_nar_bytes, min_free_bytes);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .map_err(|_| Error::runtime("request worker panicked"))?;
    }

    Ok(())
}
