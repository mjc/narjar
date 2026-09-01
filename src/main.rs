mod config;
mod error;
mod server;
#[cfg(test)]
mod storage;

use std::{env, process::ExitCode};

use config::ServeConfig;
use error::Error;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("narjar: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), Error> {
    match args.next().as_deref() {
        Some("serve") => server::serve(ServeConfig::parse(args)?),
        Some(command) => Err(Error::usage(format!("unknown command: {command}"))),
        None => Err(Error::usage("a command is required")),
    }
}
