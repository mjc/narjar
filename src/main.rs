mod config;
mod error;
mod operator;
mod server;
mod token;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use config::{ServeArgs, ServeConfig};
use error::Error;

#[derive(Parser)]
#[command(name = "narjar")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve(ServeArgs),
    Init(operator::Init),
    Key(operator::Key),
    Reconcile(operator::Reconcile),
    Verify(operator::Verify),
    Gc(operator::Gc),
    ListOrphans(operator::ListOrphans),
    Delete(operator::Delete),
    Stats(operator::Stats),
    Token(token::Token),
}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => match run(cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("narjar: {error}");
                ExitCode::from(error.exit_code())
            }
        },
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            ExitCode::from(code as u8)
        }
    }
}

fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Command::Serve(args) => server::serve(ServeConfig::from(args)),
        Command::Init(args) => operator::init(args),
        Command::Key(args) => operator::key(args),
        Command::Reconcile(args) => operator::reconcile(args),
        Command::Verify(args) => operator::verify(args),
        Command::ListOrphans(args) => operator::list_orphans(args),
        Command::Delete(args) => operator::delete(args),
        Command::Gc(args) => operator::gc(args),
        Command::Stats(args) => operator::stats(args),
        Command::Token(args) => token::run(args),
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
            [
                "serve",
                "--data-dir",
                "/cache",
                "--workers",
                "1",
                "--workers",
                "2",
            ]
            .as_slice(),
            ["serve", "--data-dir"].as_slice(),
            [
                "token",
                "revoke",
                "--data-dir",
                "/cache",
                "--scope",
                "write",
            ]
            .as_slice(),
            [
                "token",
                "create",
                "--data-dir",
                "/cache",
                "--scope",
                "invalid",
            ]
            .as_slice(),
            [
                "key",
                "generate",
                "--name",
                "bad/name",
                "--secret-key-file",
                "secret",
                "--public-key-file",
                "public",
            ]
            .as_slice(),
            ["serve", "--data-dir", "/cache", "--workers", "0"].as_slice(),
            [
                "serve",
                "--data-dir",
                "/cache",
                "--listen",
                "not-an-address",
            ]
            .as_slice(),
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("narjar").chain(args.iter().copied())).is_err()
            );
        }
    }

    #[test]
    fn gc_command_accepts_policy() {
        let cli = Cli::try_parse_from([
            "narjar",
            "gc",
            "--data-dir",
            "/cache",
            "--max-bytes",
            "1000",
            "--target-bytes",
            "500",
            "--min-age-seconds",
            "60",
            "--dry-run",
            "--json",
        ])
        .expect("gc policy should parse");

        assert!(matches!(cli.command, super::Command::Gc(_)));
    }
}
