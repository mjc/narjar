use std::{
    collections::BinaryHeap,
    ffi::OsStr,
    fs, io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::SystemTime,
};

use super::fs::unlink_at;
use super::{
    Storage, StorageError, StoreHash, entry_identity_at, entry_is_directory_at,
    entry_is_regular_at, open_regular_at, read_dir_names,
};
use crate::maintenance::FILE_NAMES as MAINTENANCE_FILES;

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

impl ReconcileClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NarObject => "nar_object",
            Self::NarInfo => "narinfo",
            Self::Realisation => "realisation",
            Self::TempYoung => "temp_young",
            Self::TempStale => "temp_stale",
            Self::InvalidFilename => "invalid_filename",
            Self::UnexpectedType => "unexpected_type",
            Self::UnknownFile => "unknown_file",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReconcileReport {
    entries: Vec<ReconcileEntry>,
    truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    Removed,
    Unchanged,
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
    change_time_seconds: i64,
    change_time_nanoseconds: i64,
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
    scan_named_directory(
        &mut found,
        &nar_directory,
        Path::new("nar"),
        ReconcileClass::NarObject,
        valid_nar_filename,
    )?;
    scan_temps(
        &mut found,
        &storage.nar_temp_directory()?,
        Path::new("nar/.tmp"),
        stale_before,
    )?;

    scan_temps(
        &mut found,
        &storage.temp_directory()?,
        Path::new(".tmp"),
        stale_before,
    )?;

    let realisations_directory = storage.realisations_directory()?;
    scan_named_directory(
        &mut found,
        &realisations_directory,
        Path::new("realisations"),
        ReconcileClass::Realisation,
        valid_realisation_filename,
    )?;
    scan_temps(
        &mut found,
        &storage.realisations_temp_directory()?,
        Path::new("realisations/.tmp"),
        stale_before,
    )?;

    Ok(found.finish())
}

fn scan_named_directory(
    found: &mut BoundedEntries,
    directory: &fs::File,
    relative_prefix: &Path,
    valid_class: ReconcileClass,
    is_valid_name: fn(&OsStr) -> bool,
) -> Result<(), StorageError> {
    read_dir_names(directory)?
        .into_iter()
        .filter(|name| name != OsStr::new(".tmp"))
        .try_for_each(|name| {
            let relative = relative_prefix.join(&name);
            let class = classify_named_entry(directory, &name, valid_class, is_valid_name)?;
            found.record(relative, class, entry_identity_at(directory, &name)?);
            Ok::<(), StorageError>(())
        })
}

fn classify_named_entry(
    directory: &fs::File,
    name: &OsStr,
    valid_class: ReconcileClass,
    is_valid_name: fn(&OsStr) -> bool,
) -> Result<ReconcileClass, StorageError> {
    Ok(match entry_is_regular_at(directory, name)? {
        true if is_valid_name(name) => valid_class,
        true => ReconcileClass::InvalidFilename,
        false => ReconcileClass::UnexpectedType,
    })
}

fn scan_temps(
    found: &mut BoundedEntries,
    directory: &fs::File,
    prefix: &Path,
    stale_before: SystemTime,
) -> Result<(), StorageError> {
    read_dir_names(directory)?.into_iter().try_for_each(|name| {
        let relative = prefix.join(&name);
        let identity = entry_identity_at(directory, &name)?;
        let class = classify_temp_entry(directory, &name, stale_before)?;
        found.record(relative, class, identity);
        Ok::<(), StorageError>(())
    })
}

fn classify_temp_entry(
    directory: &fs::File,
    name: &OsStr,
    stale_before: SystemTime,
) -> Result<ReconcileClass, StorageError> {
    Ok(match entry_is_regular_at(directory, name)? {
        false => ReconcileClass::UnexpectedType,
        true if !valid_temp_filename(name) => ReconcileClass::InvalidFilename,
        true => match open_regular_at(directory, name)?.metadata()?.modified()? <= stale_before {
            true => ReconcileClass::TempStale,
            false => ReconcileClass::TempYoung,
        },
    })
}

pub(super) fn cleanup_stale_temp(
    storage: &Storage,
    entry: &ReconcileEntry,
) -> Result<CleanupOutcome, StorageError> {
    if entry.class != ReconcileClass::TempStale {
        return Ok(CleanupOutcome::Unchanged);
    }

    let (directory, parent) = match entry.relative_path.parent() {
        Some(path) if path == Path::new(".tmp") => (storage.temp_directory()?, path),
        Some(path) if path == Path::new("nar/.tmp") => (storage.nar_temp_directory()?, path),
        Some(path) if path == Path::new("realisations/.tmp") => {
            (storage.realisations_temp_directory()?, path)
        }
        _ => return Ok(CleanupOutcome::Unchanged),
    };
    debug_assert_eq!(entry.relative_path.parent(), Some(parent));
    let name = entry
        .relative_path
        .file_name()
        .expect("validated temporary entry has a filename");
    let identity = match entry_identity_at(&directory, name) {
        Ok((device, inode, change_time_seconds, change_time_nanoseconds)) => FileIdentity {
            device,
            inode,
            change_time_seconds,
            change_time_nanoseconds,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CleanupOutcome::Unchanged);
        }
        Err(error) => return Err(error.into()),
    };
    if identity != entry.identity {
        return Ok(CleanupOutcome::Unchanged);
    }

    unlink_at(&directory, name)?;
    directory.sync_all()?;
    Ok(CleanupOutcome::Removed)
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
        (device, inode, change_time_seconds, change_time_nanoseconds): (u64, u64, i64, i64),
    ) {
        self.seen += 1;
        self.entries.push(ReconcileEntry {
            relative_path,
            class,
            identity: FileIdentity {
                device,
                inode,
                change_time_seconds,
                change_time_nanoseconds,
            },
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
        Some(
            "nar"
            | ".tmp"
            | ".narjar-transactions"
            | ".narjar-ingress"
            | ".narjar-egress"
            | ".narjar-validation"
            | "realisations"
            | "auth",
        ) => (!is_directory).then_some(ReconcileClass::UnexpectedType),
        Some(
            "lock"
            | "nix-cache-info"
            | "trusted-public-keys"
            | ".narjar-clean"
            | ".narjar-recovery",
        ) => (!is_regular).then_some(ReconcileClass::UnexpectedType),
        Some(name) if MAINTENANCE_FILES.contains(&name) => {
            (!is_regular).then_some(ReconcileClass::UnexpectedType)
        }
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
        .is_some_and(|hash| StoreHash::parse(hash).is_ok())
}

fn valid_nar_filename(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| crate::object::NarFileName::parse(name).is_ok())
}

fn valid_temp_filename(name: &OsStr) -> bool {
    let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".part")) else {
        return false;
    };
    let Some(body) = [
        "cache-info-",
        "nar-",
        "narinfo-",
        "realisation-",
        "validation-",
        "egress-receipt-",
    ]
    .into_iter()
    .find_map(|prefix| stem.strip_prefix(prefix)) else {
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
