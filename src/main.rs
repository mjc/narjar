mod config;
mod error;
mod operator;
mod server;
mod token;

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
        Some("token") => token::run(args),
        Some(command) => operator::run(command, args),
        None => Err(Error::usage("a command is required")),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn command_schema_rejects_invalid_input() {
        for args in [
            ["serve", "--unknown"].as_slice(),
            ["serve", "--data-dir", "/cache", "--workers", "1", "--workers", "2"].as_slice(),
            ["serve", "--data-dir"].as_slice(),
            ["token", "revoke", "--data-dir", "/cache", "--scope", "write"].as_slice(),
            ["token", "create", "--data-dir", "/cache", "--scope", "invalid"].as_slice(),
            ["key", "generate", "--name", "bad/name", "--secret-key-file", "secret", "--public-key-file", "public"].as_slice(),
            ["serve", "--data-dir", "/cache", "--workers", "0"].as_slice(),
            ["serve", "--data-dir", "/cache", "--listen", "not-an-address"].as_slice(),
        ] {
            assert!(Cli::try_parse_from(std::iter::once("narjar").chain(args.iter().copied())).is_err());
        }
    }
}
