use std::{
    collections::BinaryHeap,
    ffi::OsStr,
    fs, io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::SystemTime,
};

use super::{
    Storage, StorageError, entry_identity_at, entry_is_directory_at, entry_is_regular_at,
    open_regular_at, parse_nix32, read_dir_names, unlink_at,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReconcileClass {
    NarObject,
    NarInfo,
    Realisation,
    TempYoung,
    TempStale,
    InvalidFilename,
    UnexpectedType,
    UnknownFile,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReconcileEntry {
    relative_path: PathBuf,
    class: ReconcileClass,
    identity: FileIdentity,
}

impl ReconcileEntry {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn class(&self) -> ReconcileClass {
        self.class
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReconcileReport {
    entries: Vec<ReconcileEntry>,
    truncated: bool,
}

impl ReconcileReport {
    pub fn entries(&self) -> &[ReconcileEntry] {
        &self.entries
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn scan(
    storage: &Storage,
    limit: NonZeroUsize,
    stale_before: SystemTime,
) -> Result<ReconcileReport, StorageError> {
    let mut found = BoundedEntries::new(limit);
    let root = storage.root_directory()?;

    for name in read_dir_names(&root)? {
        if let Some(class) = classify_root_entry(&root, &name)? {
            found.record(
                PathBuf::from(&name),
                class,
                entry_identity_at(&root, &name)?,
            );
        }
    }

    let nar_directory = storage.nar_directory()?;
    for name in read_dir_names(&nar_directory)? {
        let relative = PathBuf::from("nar").join(&name);
        let class = if !entry_is_regular_at(&nar_directory, &name)? {
            ReconcileClass::UnexpectedType
        } else if valid_nar_filename(&name) {
            ReconcileClass::NarObject
        } else {
            ReconcileClass::InvalidFilename
        };
        found.record(relative, class, entry_identity_at(&nar_directory, &name)?);
    }

    let temp_directory = storage.temp_directory()?;
    for name in read_dir_names(&temp_directory)? {
        let relative = PathBuf::from(".tmp").join(&name);
        let identity = entry_identity_at(&temp_directory, &name)?;
        let class = if !entry_is_regular_at(&temp_directory, &name)? {
            ReconcileClass::UnexpectedType
        } else if !valid_temp_filename(&name) {
            ReconcileClass::InvalidFilename
        } else if open_regular_at(&temp_directory, &name)?
            .metadata()?
            .modified()?
            <= stale_before
        {
            ReconcileClass::TempStale
        } else {
            ReconcileClass::TempYoung
        };
        found.record(relative, class, identity);
    }

    let realisations_directory = storage.realisations_directory()?;
    for name in read_dir_names(&realisations_directory)? {
        let relative = PathBuf::from("realisations").join(&name);
        let class = if !entry_is_regular_at(&realisations_directory, &name)? {
            ReconcileClass::UnexpectedType
        } else if valid_realisation_filename(&name) {
            ReconcileClass::Realisation
        } else {
            ReconcileClass::InvalidFilename
        };
        found.record(
            relative,
            class,
            entry_identity_at(&realisations_directory, &name)?,
        );
    }

    Ok(found.finish())
}

pub(super) fn cleanup_stale_temp(
    storage: &Storage,
    entry: &ReconcileEntry,
) -> Result<bool, StorageError> {
    if entry.class != ReconcileClass::TempStale
        || entry.relative_path.parent() != Some(Path::new(".tmp"))
    {
        return Ok(false);
    }

    let directory = storage.temp_directory()?;
    let name = entry
        .relative_path
        .file_name()
        .expect("validated temporary entry has a filename");
    let identity = match entry_identity_at(&directory, name) {
        Ok((device, inode)) => FileIdentity { device, inode },
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if identity != entry.identity {
        return Ok(false);
    }

    unlink_at(&directory, name)?;
    directory.sync_all()?;
    Ok(true)
}

#[derive(Debug)]
struct BoundedEntries {
    limit: usize,
    seen: usize,
    entries: BinaryHeap<ReconcileEntry>,
}

impl BoundedEntries {
    fn new(limit: NonZeroUsize) -> Self {
        Self {
            limit: limit.get(),
            seen: 0,
            entries: BinaryHeap::with_capacity(limit.get()),
        }
    }

    fn record(
        &mut self,
        relative_path: PathBuf,
        class: ReconcileClass,
        (device, inode): (u64, u64),
    ) {
        self.seen += 1;
        self.entries.push(ReconcileEntry {
            relative_path,
            class,
            identity: FileIdentity { device, inode },
        });
        if self.entries.len() > self.limit {
            self.entries.pop();
        }
    }

    fn finish(self) -> ReconcileReport {
        let mut entries = self.entries.into_vec();
        entries.sort_unstable();
        ReconcileReport {
            truncated: self.seen > entries.len(),
            entries,
        }
    }
}

fn classify_root_entry(
    directory: &fs::File,
    name: &OsStr,
) -> Result<Option<ReconcileClass>, StorageError> {
    let is_directory = entry_is_directory_at(directory, name)?;
    let is_regular = entry_is_regular_at(directory, name)?;
    Ok(match name.to_str() {
        Some("nar" | ".tmp" | "realisations" | "auth") => {
            (!is_directory).then_some(ReconcileClass::UnexpectedType)
        }
        Some(
            "lock"
            | "nix-cache-info"
            | "trusted-public-keys"
            | ".narjar-clean"
            | ".narjar-recovery",
        ) => (!is_regular).then_some(ReconcileClass::UnexpectedType),
        Some(name) if valid_store_hash_filename(name) => Some(if is_regular {
            ReconcileClass::NarInfo
        } else {
            ReconcileClass::UnexpectedType
        }),
        Some(_) => Some(ReconcileClass::UnknownFile),
        None => Some(ReconcileClass::InvalidFilename),
    })
}

fn valid_store_hash_filename(name: &str) -> bool {
    name.strip_suffix(".narinfo")
        .is_some_and(|hash| parse_nix32(hash, 32).is_ok())
}

fn valid_nar_filename(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".nar"))
        .is_some_and(|hash| parse_nix32(hash, 52).is_ok())
}

fn valid_temp_filename(name: &OsStr) -> bool {
    let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".part")) else {
        return false;
    };
    let Some(body) = ["nar-", "narinfo-", "realisation-"]
        .into_iter()
        .find_map(|prefix| stem.strip_prefix(prefix))
    else {
        return false;
    };
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_realisation_filename(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".doi"))
        .is_some_and(|stem| {
            !stem.is_empty()
                && stem.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_')
                })
        })
}
