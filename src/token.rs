use std::{fs::File, io::Read, path::PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use data_encoding::HEXLOWER;
use narjar::token_file::{TOKEN_BYTES, TokenFile, valid_label};
use sha2::{Digest, Sha256};

use crate::error::Error;

#[derive(Args)]
pub(crate) struct Token {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Create(Create),
    Revoke(Revoke),
}

pub(crate) fn run(token: Token) -> Result<(), Error> {
    match token.command {
        Command::Create(options) => create(options),
        Command::Revoke(options) => revoke(options),
    }
}

#[derive(Args)]
struct Create {
    #[command(flatten)]
    target: Target,
    #[arg(long, value_parser = valid_token_label)]
    name: Option<String>,
}

fn create(options: Create) -> Result<(), Error> {
    let name = options.name.as_deref().unwrap_or("token");
    let path = options.target.path();
    let mut tokens = TokenFile::load(&path).map_err(runtime)?.unwrap_or_default();

    let mut random = [0; TOKEN_BYTES];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(runtime)?;
    let secret = HEXLOWER.encode(&random);
    if !tokens.insert(name, Sha256::digest(secret.as_bytes()).into()) {
        return Err(Error::runtime(format!(
            "token label already exists: {name}"
        )));
    }
    tokens.store(&path).map_err(runtime)?;
    println!("{secret}");
    Ok(())
}

#[derive(Args)]
struct Revoke {
    #[command(flatten)]
    target: Target,
    #[arg(long)]
    name: String,
}

fn revoke(options: Revoke) -> Result<(), Error> {
    let path = options.target.path();
    let mut tokens = TokenFile::load(&path).map_err(runtime)?.unwrap_or_default();
    if !tokens.remove(&options.name) {
        return Err(Error::runtime(format!(
            "unknown token label: {}",
            options.name
        )));
    }
    tokens.store(&path).map_err(runtime)
}

#[derive(Args)]
struct Target {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, value_enum)]
    scope: Scope,
}

impl Target {
    fn path(&self) -> PathBuf {
        self.data_dir.join("auth").join(self.scope.filename())
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Scope {
    Read,
    Write,
}

impl Scope {
    const fn filename(self) -> &'static str {
        match self {
            Self::Read => "read.tokens",
            Self::Write => "write.tokens",
        }
    }
}

fn valid_token_label(value: &str) -> Result<String, String> {
    valid_label(value)
        .then(|| value.to_owned())
        .ok_or_else(|| "must contain only ASCII letters, digits, '.', '_', and '-'".to_owned())
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(format!("cannot update token file: {error}"))
}
