use std::{fs::File, io::Read, path::PathBuf};

use crate::error::Error;
use data_encoding::HEXLOWER;
use narjar::token_file::{TOKEN_BYTES, TokenFile, valid_label};
use sha2::{Digest, Sha256};

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Error> {
    match args.next().as_deref() {
        Some("create") => create(parse_options(args, false)?),
        Some("revoke") => revoke(parse_options(args, true)?),
        Some(command) => Err(Error::usage(format!("unknown token command: {command}"))),
        None => Err(Error::usage("a token command is required")),
    }
}

fn create(options: Options) -> Result<(), Error> {
    let name = options.name.as_deref().unwrap_or("token");
    if !valid_label(name) {
        return Err(Error::usage(
            "token labels may contain only ASCII letters, digits, '.', '_', and '-'",
        ));
    }

    let path = options.path();
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

fn revoke(options: Options) -> Result<(), Error> {
    let name = options
        .name
        .as_deref()
        .expect("the parser requires a revoke name");
    let path = options.path();
    let mut tokens = TokenFile::load(&path).map_err(runtime)?.unwrap_or_default();
    if !tokens.remove(name) {
        return Err(Error::runtime(format!("unknown token label: {name}")));
    }
    tokens.store(&path).map_err(runtime)
}

#[derive(Clone, Copy)]
enum Scope {
    Read,
    Write,
}

impl Scope {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err(Error::usage("--scope must be read or write")),
        }
    }

    const fn filename(self) -> &'static str {
        match self {
            Self::Read => "read.tokens",
            Self::Write => "write.tokens",
        }
    }
}

struct Options {
    data_dir: PathBuf,
    scope: Scope,
    name: Option<String>,
}

impl Options {
    fn path(&self) -> PathBuf {
        self.data_dir.join("auth").join(self.scope.filename())
    }
}

fn parse_options(
    mut args: impl Iterator<Item = String>,
    name_required: bool,
) -> Result<Options, Error> {
    let mut data_dir = None;
    let mut scope = None;
    let mut name = None;

    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| Error::usage(format!("{option} requires a value")))?;
        match option.as_str() {
            "--data-dir" if data_dir.is_none() => data_dir = Some(PathBuf::from(value)),
            "--scope" if scope.is_none() => scope = Some(Scope::parse(&value)?),
            "--name" if name.is_none() => name = Some(value),
            _ if matches!(option.as_str(), "--data-dir" | "--scope" | "--name") => {
                return Err(Error::usage(format!("duplicate option: {option}")));
            }
            _ => return Err(Error::usage(format!("unknown option: {option}"))),
        }
    }

    if name_required && name.is_none() {
        return Err(Error::usage("--name is required"));
    }

    Ok(Options {
        data_dir: data_dir.ok_or_else(|| Error::usage("--data-dir is required"))?,
        scope: scope.ok_or_else(|| Error::usage("--scope is required"))?,
        name,
    })
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(format!("cannot update token file: {error}"))
}
