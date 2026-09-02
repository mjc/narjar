use std::{
    collections::BinaryHeap,
    ffi::OsStr,
    fs, io,
    num::NonZeroUsize,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use super::{Layout, StorageError, parse_nix32, sync_dir};

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

impl From<&fs::Metadata> for FileIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

pub(super) fn scan(
    layout: &Layout,
    limit: NonZeroUsize,
    stale_before: SystemTime,
) -> Result<ReconcileReport, StorageError> {
    let mut found = BoundedEntries::new(limit);

    for entry in fs::read_dir(&layout.root)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if let Some(class) = classify_root_entry(&name, &file_type) {
            found.record(PathBuf::from(name), class, &path)?;
        }
    }

    for entry in fs::read_dir(layout.nar_dir())? {
        let entry = entry?;
        let path = entry.path();
        let relative = PathBuf::from("nar").join(entry.file_name());
        let file_type = entry.file_type()?;
        let class = if !file_type.is_file() {
            ReconcileClass::UnexpectedType
        } else if valid_nar_filename(&entry.file_name()) {
            ReconcileClass::NarObject
        } else {
            ReconcileClass::InvalidFilename
        };
        found.record(relative, class, &path)?;
    }

    for entry in fs::read_dir(layout.temp_dir())? {
        let entry = entry?;
        let path = entry.path();
        let relative = PathBuf::from(".tmp").join(entry.file_name());
        let file_type = entry.file_type()?;
        let metadata = fs::symlink_metadata(&path)?;
        let class = if !file_type.is_file() {
            ReconcileClass::UnexpectedType
        } else if !valid_temp_filename(&entry.file_name()) {
            ReconcileClass::InvalidFilename
        } else if metadata.modified()? <= stale_before {
            ReconcileClass::TempStale
        } else {
            ReconcileClass::TempYoung
        };
        found.record_with_metadata(relative, class, metadata);
    }

    for entry in fs::read_dir(layout.realisations_dir())? {
        let entry = entry?;
        let path = entry.path();
        let relative = PathBuf::from("realisations").join(entry.file_name());
        let file_type = entry.file_type()?;
        let class = if !file_type.is_file() {
            ReconcileClass::UnexpectedType
        } else if valid_realisation_filename(&entry.file_name()) {
            ReconcileClass::Realisation
        } else {
            ReconcileClass::InvalidFilename
        };
        found.record(relative, class, &path)?;
    }

    Ok(found.finish())
}

pub(super) fn cleanup_stale_temp(
    layout: &Layout,
    entry: &ReconcileEntry,
) -> Result<bool, StorageError> {
    if entry.class != ReconcileClass::TempStale
        || entry.relative_path.parent() != Some(Path::new(".tmp"))
    {
        return Ok(false);
    }

    let path = layout.root.join(&entry.relative_path);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if FileIdentity::from(&metadata) != entry.identity {
        return Ok(false);
    }

    fs::remove_file(path)?;
    sync_dir(&layout.temp_dir())?;
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
        path: &Path,
    ) -> Result<(), StorageError> {
        let metadata = fs::symlink_metadata(path)?;
        self.record_with_metadata(relative_path, class, metadata);
        Ok(())
    }

    fn record_with_metadata(
        &mut self,
        relative_path: PathBuf,
        class: ReconcileClass,
        metadata: fs::Metadata,
    ) {
        self.seen += 1;
        self.entries.push(ReconcileEntry {
            relative_path,
            class,
            identity: FileIdentity::from(&metadata),
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

fn classify_root_entry(name: &OsStr, file_type: &fs::FileType) -> Option<ReconcileClass> {
    match name.to_str() {
        Some("nar" | ".tmp" | "realisations" | "auth") => {
            (!file_type.is_dir()).then_some(ReconcileClass::UnexpectedType)
        }
        Some(
            "lock"
            | "nix-cache-info"
            | "trusted-public-keys"
            | ".narjar-clean"
            | ".narjar-recovery",
        ) => (!file_type.is_file()).then_some(ReconcileClass::UnexpectedType),
        Some(name) if valid_store_hash_filename(name) => Some(if file_type.is_file() {
            ReconcileClass::NarInfo
        } else {
            ReconcileClass::UnexpectedType
        }),
        Some(_) => Some(ReconcileClass::UnknownFile),
        None => Some(ReconcileClass::InvalidFilename),
    }
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
