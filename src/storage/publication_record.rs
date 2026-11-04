use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{Storage, StorageError, StoreHash};
use crate::cache::{
    filesystem::{
        FilePrivacy, PreparedFile, ensure_directory_at, open_directory_at, open_regular_at,
        read_dir_names, set_file_privacy, unlink_at, validate_private_directory,
        validate_private_file,
    },
    token_file::valid_label,
};

pub(super) const DIRECTORY: &str = ".narjar-publication-records";
const MAX_RECORD_BYTES: u64 = 4096;
const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationRecord {
    pub(crate) store_path: String,
    pub(crate) published_at: SystemTime,
    pub(crate) writer: Option<String>,
    pub(crate) removed_at: Option<SystemTime>,
}

impl Storage {
    pub(super) fn remember_publication(
        &self,
        store: &StoreHash,
        store_path: &str,
        writer: Option<&str>,
        now: SystemTime,
    ) -> Result<(), StorageError> {
        if !single_line(store_path) {
            return Err(invalid("publication store path is not a single line"));
        }
        self.expire_elapsed_records(now)?;
        let writer = match writer {
            Some(label) if valid_label(label) => Some(label.to_owned()),
            Some(_) => return Err(invalid("publication writer label is invalid")),
            None => self
                .publication_record_at(store)?
                .and_then(|record| record.writer),
        };
        self.write_record(
            store,
            &PublicationRecord {
                store_path: store_path.to_owned(),
                published_at: now,
                writer,
                removed_at: None,
            },
        )
    }

    pub(super) fn note_publication_removed(
        &self,
        store: &StoreHash,
        now: SystemTime,
    ) -> Result<(), StorageError> {
        self.expire_elapsed_records(now)?;
        let Some(mut record) = self.publication_record_at(store)? else {
            return Ok(());
        };
        if record.removed_at.is_none() {
            record.removed_at = Some(now);
            self.write_record(store, &record)?;
        }
        Ok(())
    }

    pub(crate) fn publication_record(
        &self,
        store: &StoreHash,
        now: SystemTime,
    ) -> Result<Option<PublicationRecord>, StorageError> {
        let Some(record) = self.publication_record_at(store)? else {
            return Ok(None);
        };
        let expired = record
            .removed_at
            .is_some_and(|removed_at| expired(removed_at, now));
        if !expired {
            return Ok(Some(record));
        }
        if let Some(directory) = open_records_directory(&self.root_directory()?)? {
            match unlink_at(&directory, OsStr::new(store.as_str())) {
                Ok(()) => directory.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    fn expire_elapsed_records(&self, now: SystemTime) -> Result<(), StorageError> {
        let Some(directory) = open_records_directory(&self.root_directory()?)? else {
            return Ok(());
        };
        for name in read_dir_names(&directory)? {
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(store) = StoreHash::parse(name) else {
                continue;
            };
            self.publication_record(&store, now)?;
        }
        Ok(())
    }

    fn publication_record_at(
        &self,
        store: &StoreHash,
    ) -> Result<Option<PublicationRecord>, StorageError> {
        let Some(directory) = open_records_directory(&self.root_directory()?)? else {
            return Ok(None);
        };
        let file = match open_regular_at(&directory, OsStr::new(store.as_str())) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_private_file(&file)?;
        Ok(Some(parse_record(&read_limited(&file)?)?))
    }

    fn write_record(
        &self,
        store: &StoreHash,
        record: &PublicationRecord,
    ) -> Result<(), StorageError> {
        let directory = records_directory(self)?;
        let bytes = encode_record(record)?;
        let temporary = PreparedFile::write(&directory, FilePrivacy::Private, |file| {
            file.write_all(&bytes)
        })?;
        temporary.replace(OsStr::new(store.as_str()))?;
        Ok(())
    }
}

fn records_directory(storage: &Storage) -> Result<File, StorageError> {
    let root = storage.root_directory()?;
    if let Some(directory) = open_records_directory(&root)? {
        return Ok(directory);
    }
    let directory = ensure_directory_at(&root, OsStr::new(DIRECTORY), DIRECTORY)?;
    set_file_privacy(&directory, FilePrivacy::Private)?;
    validate_private_directory(&directory)?;
    root.sync_all()?;
    Ok(directory)
}

fn open_records_directory(root: &File) -> Result<Option<File>, StorageError> {
    match open_directory_at(root, OsStr::new(DIRECTORY)) {
        Ok(directory) => {
            validate_private_directory(&directory)?;
            Ok(Some(directory))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn encode_record(record: &PublicationRecord) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    writeln!(bytes, "v1")?;
    writeln!(bytes, "path {}", record.store_path)?;
    writeln!(bytes, "published {}", unix_seconds(record.published_at)?)?;
    match &record.writer {
        Some(label) => writeln!(bytes, "writer {label}")?,
        None => writeln!(bytes, "writer")?,
    }
    match record.removed_at {
        Some(removed_at) => writeln!(bytes, "removed {}", unix_seconds(removed_at)?)?,
        None => writeln!(bytes, "removed")?,
    }
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid_io("publication record exceeds its size limit"));
    }
    Ok(bytes)
}

fn parse_record(text: &str) -> io::Result<PublicationRecord> {
    let mut lines = text.lines();
    let version = lines
        .next()
        .ok_or_else(|| invalid_io("publication record is empty"))?;
    if version != "v1" {
        return Err(invalid_io("publication record version is unsupported"));
    }
    let store_path = field(lines.next(), "path")?;
    if !single_line(store_path) {
        return Err(invalid_io("publication store path is invalid"));
    }
    let published_at = system_time(field(lines.next(), "published")?)?;
    let writer = match field(lines.next(), "writer")? {
        "" => None,
        label if valid_label(label) => Some(label.to_owned()),
        _ => return Err(invalid_io("publication writer label is invalid")),
    };
    let removed_at = match field(lines.next(), "removed")? {
        "" => None,
        seconds => Some(system_time(seconds)?),
    };
    if lines.next().is_some() {
        return Err(invalid_io("publication record has trailing data"));
    }
    Ok(PublicationRecord {
        store_path: store_path.to_owned(),
        published_at,
        writer,
        removed_at,
    })
}

fn field<'a>(line: Option<&'a str>, name: &str) -> io::Result<&'a str> {
    let Some(line) = line else {
        return Err(invalid_io("publication record is incomplete"));
    };
    let Some(rest) = line.strip_prefix(name) else {
        return Err(invalid_io("publication record field is missing"));
    };
    match rest {
        "" => Ok(""),
        rest => rest
            .strip_prefix(' ')
            .ok_or_else(|| invalid_io("publication record field is malformed")),
    }
}

fn read_limited(file: &File) -> io::Result<String> {
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid_io("publication record exceeds its size limit"));
    }
    String::from_utf8(bytes).map_err(|_| invalid_io("publication record is not text"))
}

fn unix_seconds(time: SystemTime) -> io::Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_io("publication time predates the Unix epoch"))
}

fn system_time(seconds: &str) -> io::Result<SystemTime> {
    let seconds = seconds
        .parse::<u64>()
        .map_err(|_| invalid_io("publication time is invalid"))?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| invalid_io("publication time is too large"))
}

fn expired(removed_at: SystemTime, now: SystemTime) -> bool {
    match now.duration_since(removed_at) {
        Ok(age) => age > RETENTION,
        Err(_) => false,
    }
}

fn single_line(value: &str) -> bool {
    !value.is_empty() && !value.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn invalid(message: &str) -> StorageError {
    invalid_io(message).into()
}

fn invalid_io(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
