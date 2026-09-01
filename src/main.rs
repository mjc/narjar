use std::{
    env, fs, io,
    io::Write,
    path::PathBuf,
    process::ExitCode,
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
use tiny_http::{Response, Server, StatusCode};

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("narjar: {message}");
            ExitCode::from(code)
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), (u8, String)> {
    match args.next().as_deref() {
        Some("serve") => serve(args),
        Some(command) => Err((2, format!("unknown command: {command}"))),
        None => Err((2, "a command is required".into())),
    }
}

fn serve(mut args: impl Iterator<Item = String>) -> Result<(), (u8, String)> {
    let mut data_dir = None;
    let mut listen = "127.0.0.1:5000".to_owned();
    let mut workers = 8;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--data-dir" => data_dir = Some(PathBuf::from(value(&mut args, "--data-dir")?)),
            "--listen" => listen = value(&mut args, "--listen")?,
            "--workers" => {
                workers = value(&mut args, "--workers")?
                    .parse()
                    .map_err(|_| (2, "--workers must be a positive integer".into()))?;
                if workers == 0 {
                    return Err((2, "--workers must be greater than zero".into()));
                }
            }
            _ => return Err((2, format!("unexpected argument: {argument}"))),
        }
    }

    let data_dir = data_dir.ok_or_else(|| (2, "--data-dir is required".into()))?;
    if !fs::metadata(&data_dir)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return Err((
            1,
            format!("data directory is not a directory: {}", data_dir.display()),
        ));
    }

    let server = Arc::new(
        Server::http(&listen)
            .map_err(|error| (1, format!("cannot listen on {listen}: {error}")))?,
    );
    let stopping = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stopping))
        .and_then(|_| flag::register(SIGTERM, Arc::clone(&stopping)))
        .map_err(|error| (1, format!("cannot install signal handler: {error}")))?;

    println!("listening http://{}", server.server_addr());
    io::stdout()
        .flush()
        .map_err(|error| (1, format!("cannot report listener: {error}")))?;

    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let server = Arc::clone(&server);
            let stopping = Arc::clone(&stopping);
            thread::spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
                        let _ = request.respond(Response::empty(StatusCode(404)));
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .map_err(|_| (1, "request worker panicked".into()))?;
    }

    Ok(())
}

fn value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, (u8, String)> {
    args.next()
        .ok_or_else(|| (2, format!("{option} requires a value")))
}
