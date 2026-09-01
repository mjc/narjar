use std::{
    fs, io,
    io::Write,
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
use tiny_http::{Header, Method, Response, Server, StatusCode};

use narjar::storage::Storage;

use crate::{config::ServeConfig, error::Error};
const NIX_CACHE_INFO: &[u8] = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";

fn respond(request: tiny_http::Request) {
    let response = if matches!(request.method(), Method::Get | Method::Head)
        && request.url() == "/nix-cache-info"
    {
        Response::from_data(NIX_CACHE_INFO)
            .with_header(
                Header::from_bytes("Content-Type", "text/x-nix-cache-info")
                    .expect("static content type is valid"),
            )
            .with_header(
                Header::from_bytes("Cache-Control", "public, max-age=3600")
                    .expect("static cache policy is valid"),
            )
    } else {
        Response::from_data(Vec::new()).with_status_code(StatusCode(404))
    };

    let _ = request.respond(response);
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

    let _storage = Storage::initialize(&config.data_dir).map_err(|error| {
        Error::runtime(format!(
            "cannot initialize data directory {}: {error}",
            config.data_dir.display()
        ))
    })?;

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

    let handles: Vec<_> = (0..config.workers.get())
        .map(|_| {
            let server = Arc::clone(&server);
            let stopping = Arc::clone(&stopping);
            thread::spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
                        respond(request);
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
