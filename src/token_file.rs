use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use data_encoding::HEXLOWER;

pub const TOKEN_BYTES: usize = 32;

#[derive(Debug, Default)]
pub struct TokenFile(Vec<Record>);

#[derive(Debug)]
struct Record {
    label: String,
    digest: [u8; TOKEN_BYTES],
}

impl TokenFile {
    pub fn load(path: &Path) -> Result<Option<Self>, Error> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(Error::InsecurePermissions);
        }

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let mut labels = HashSet::new();
        let mut records = Vec::new();
        for line in contents.lines().filter(|line| !line.is_empty()) {
            let mut fields = line.split_ascii_whitespace();
            let (Some(label), Some(encoded), None) = (fields.next(), fields.next(), fields.next())
            else {
                return Err(Error::Invalid);
            };
            if !valid_label(label) || !labels.insert(label) {
                return Err(Error::Invalid);
            }
            let digest = HEXLOWER
                .decode(encoded.as_bytes())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Invalid)?;
            records.push(Record {
                label: label.to_owned(),
                digest,
            });
        }
        Ok(Some(Self(records)))
    }

    pub fn hashes(&self) -> impl Iterator<Item = &[u8; TOKEN_BYTES]> {
        self.0.iter().map(|record| &record.digest)
    }

    pub fn insert(&mut self, label: &str, digest: [u8; TOKEN_BYTES]) -> bool {
        debug_assert!(valid_label(label));
        if self.0.iter().any(|record| record.label == label) {
            return false;
        }
        self.0.push(Record {
            label: label.to_owned(),
            digest,
        });
        true
    }

    pub fn remove(&mut self, label: &str) -> bool {
        let original_len = self.0.len();
        self.0.retain(|record| record.label != label);
        self.0.len() != original_len
    }

    pub fn store(&self, path: &Path) -> Result<(), Error> {
        let directory = path
            .parent()
            .expect("token paths always have an auth directory");
        fs::create_dir_all(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;

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
                Err(error) => return Err(error.into()),
            }
        }
        let (temporary_path, mut file) = temporary.ok_or(Error::TemporaryFileExhausted)?;

        let result = (|| -> io::Result<()> {
            for record in &self.0 {
                writeln!(file, "{} {}", record.label, HEXLOWER.encode(&record.digest))?;
            }
            file.sync_all()?;
            fs::rename(&temporary_path, path)?;
            File::open(directory)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result.map_err(Into::into)
    }
}

pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[derive(Debug)]
pub enum Error {
    InsecurePermissions,
    Invalid,
    TemporaryFileExhausted,
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePermissions => {
                formatter.write_str("token hash file permissions must be 0600")
            }
            Self::Invalid => formatter.write_str("invalid token hash file"),
            Self::TemporaryFileExhausted => {
                formatter.write_str("cannot create temporary token hash file")
            }
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InsecurePermissions | Self::Invalid | Self::TemporaryFileExhausted => None,
        }
    }
}
