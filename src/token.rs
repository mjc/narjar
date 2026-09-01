use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

use crate::error::Error;

const TOKEN_BYTES: usize = 32;

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
    validate_label(name)?;

    let path = options.path();
    let mut records = load(&path)?;
    if records.iter().any(|record| record.label == name) {
        return Err(Error::runtime(format!(
            "token label already exists: {name}"
        )));
    }

    let mut random = [0; TOKEN_BYTES];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(runtime)?;
    let secret = HEXLOWER.encode(&random);
    records.push(Record {
        label: name.to_owned(),
        digest: Sha256::digest(secret.as_bytes()).into(),
    });
    store(&path, &records)?;
    println!("{secret}");
    Ok(())
}

fn revoke(options: Options) -> Result<(), Error> {
    let name = options
        .name
        .as_deref()
        .expect("the parser requires a revoke name");
    let path = options.path();
    let mut records = load(&path)?;
    let original_len = records.len();
    records.retain(|record| record.label != name);
    if records.len() == original_len {
        return Err(Error::runtime(format!("unknown token label: {name}")));
    }
    store(&path, &records)
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

struct Record {
    label: String,
    digest: [u8; TOKEN_BYTES],
}

fn load(path: &Path) -> Result<Vec<Record>, Error> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(runtime(error)),
    };
    let metadata = file.metadata().map_err(runtime)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(Error::runtime("token hash file permissions must be 0600"));
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(runtime)?;
    let mut labels = HashSet::new();
    let mut records = Vec::new();
    for line in contents.lines().filter(|line| !line.is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let (Some(label), Some(encoded), None) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::runtime("invalid token hash file"));
        };
        validate_label(label)?;
        if !labels.insert(label) {
            return Err(Error::runtime("invalid token hash file"));
        }
        let digest = HEXLOWER
            .decode(encoded.as_bytes())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::runtime("invalid token hash file"))?;
        records.push(Record {
            label: label.to_owned(),
            digest,
        });
    }
    Ok(records)
}

fn validate_label(label: &str) -> Result<(), Error> {
    if !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        Ok(())
    } else {
        Err(Error::usage(
            "token labels may contain only ASCII letters, digits, '.', '_', and '-'",
        ))
    }
}

fn store(path: &Path, records: &[Record]) -> Result<(), Error> {
    let directory = path
        .parent()
        .expect("token paths always have an auth directory");
    fs::create_dir_all(directory).map_err(runtime)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(runtime)?;

    let mut temporary = None;
    for attempt in 0..128 {
        let candidate = directory.join(format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .expect("token paths always have a file name")
                .to_string_lossy(),
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(runtime(error)),
        }
    }
    let (temporary_path, mut file) =
        temporary.ok_or_else(|| Error::runtime("cannot create temporary token hash file"))?;

    let result = (|| -> io::Result<()> {
        for record in records {
            writeln!(file, "{} {}", record.label, HEXLOWER.encode(&record.digest))?;
        }
        file.sync_all()?;
        fs::rename(&temporary_path, path)?;
        File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result.map_err(runtime)
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(format!("cannot update token file: {error}"))
}
