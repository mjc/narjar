use std::{
    collections::HashSet,
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
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags((rustix::fs::OFlags::NOFOLLOW).bits() as i32)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Self::read(file).map(Some)
    }

    pub(crate) fn read(mut file: File) -> Result<Self, Error> {
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
        Ok(Self(records))
    }

    pub fn hashes(&self) -> impl Iterator<Item = &[u8; TOKEN_BYTES]> {
        self.0.iter().map(|record| &record.digest)
    }

    pub fn insert(&mut self, label: &str, digest: [u8; TOKEN_BYTES]) -> Result<bool, Error> {
        if !valid_label(label) {
            return Err(Error::InvalidLabel);
        }
        if self.0.iter().any(|record| record.label == label) {
            return Ok(false);
        }
        self.0.push(Record {
            label: label.to_owned(),
            digest,
        });
        Ok(true)
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
        let directory_file = match OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(directory)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(directory)?;
                OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits()
                            as i32,
                    )
                    .open(directory)?
            }
            Err(error) => return Err(error.into()),
        };
        directory_file.set_permissions(fs::Permissions::from_mode(0o700))?;

        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        for record in &self.0 {
            writeln!(
                temporary,
                "{} {}",
                record.label,
                HEXLOWER.encode(&record.digest)
            )?;
        }
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        directory_file.sync_all()?;
        Ok(())
    }
}

pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token hash file permissions must be 0600")]
    InsecurePermissions,
    #[error("invalid token hash file")]
    Invalid,
    #[error("invalid token label")]
    InvalidLabel,
    #[error("{0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process,
    };

    use super::{Error, TokenFile};

    #[test]
    fn insert_rejects_invalid_labels_without_mutating_the_file() {
        let mut tokens = TokenFile::default();

        assert!(matches!(
            tokens.insert("not a label", [0; super::TOKEN_BYTES]),
            Err(Error::InvalidLabel)
        ));
        assert_eq!(tokens.hashes().count(), 0);
    }

    #[test]
    fn store_uses_unpredictable_private_temporary_file() {
        let directory = tempfile::tempdir().expect("create test directory");
        let path = directory.path().join("tokens");
        fs::write(&path, b"stale").expect("create existing token file");
        for attempt in 0..128 {
            let candidate =
                directory
                    .path()
                    .join(format!(".tokens.{}.{}.tmp", process::id(), attempt));
            fs::write(candidate, []).expect("preclaim temporary name");
        }

        TokenFile::default()
            .store(&path)
            .expect("store should not depend on predictable temporary names");

        assert_eq!(fs::read(&path).expect("read token file"), b"");
        let mode = fs::metadata(path)
            .expect("read token file metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_rejects_a_symlinked_token_file() {
        let directory = tempfile::tempdir().expect("create test directory");
        let target = directory.path().join("target");
        let path = directory.path().join("tokens");
        fs::write(
            &target,
            b"token 0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .expect("write token target");
        symlink(&target, &path).expect("create token symlink");

        assert!(TokenFile::load(&path).is_err());
        assert!(target.exists());
    }

    #[test]
    fn store_rejects_a_symlinked_token_directory() {
        let directory = tempfile::tempdir().expect("create test directory");
        let target = directory.path().join("auth-real");
        let auth = directory.path().join("auth");
        fs::create_dir(&target).expect("create token target directory");
        symlink(&target, &auth).expect("create token directory symlink");

        assert!(TokenFile::default().store(&auth.join("tokens")).is_err());
        assert!(!target.join("tokens").exists());
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &Error::InsecurePermissions,
                "token hash file permissions must be 0600",
            ),
            (&Error::Invalid, "invalid token hash file"),
            (&Error::InvalidLabel, "invalid token label"),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_io_error_preserves_message_and_source() {
        use std::error::Error as _;
        let error = Error::from(io::Error::other("read failure"));
        assert_eq!(error.to_string(), "read failure");
        assert!(error.source().unwrap().is::<io::Error>());
        assert!(error.source().unwrap().source().is_none());
    }
}
