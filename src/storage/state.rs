use std::{
    collections::HashMap,
    fmt,
    fs::File,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, Weak, atomic::AtomicU64},
};

use super::chunk_store::ChunkStore;
#[cfg(test)]
use super::publication::Layout;
use super::publication::{ProcessLock, StagingBudget};
use super::recovery::RecoveryState;
use crate::object::{NarFileName, NarIdentity};

#[derive(Debug)]
pub(super) enum PayloadStorage {
    Flat,
    Chunked(ChunkStore),
}

impl PayloadStorage {
    pub(super) const fn backend(&self) -> StorageBackend {
        match self {
            Self::Flat => StorageBackend::Flat,
            Self::Chunked(_) => StorageBackend::Chunked,
        }
    }

    #[cfg(test)]
    pub(super) const fn chunk_store(&self) -> Option<&ChunkStore> {
        match self {
            Self::Flat => None,
            Self::Chunked(store) => Some(store),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackend {
    Flat,
    Chunked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidStorageBackend;

impl fmt::Display for InvalidStorageBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected one of: flat, chunked")
    }
}

impl std::error::Error for InvalidStorageBackend {}

impl FromStr for StorageBackend {
    type Err = InvalidStorageBackend;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "flat" => Ok(Self::Flat),
            "chunked" => Ok(Self::Chunked),
            _ => Err(InvalidStorageBackend),
        }
    }
}

impl StorageBackend {
    pub const fn layout_descriptor(self) -> &'static [u8] {
        match self {
            Self::Flat => b"narjar-layout-v1\nbackend=flat\n",
            Self::Chunked => b"narjar-layout-v1\nbackend=chunked\nprofile=mincdc-hash4-v2\n",
        }
    }
}

#[derive(Debug)]
pub struct Storage {
    #[cfg(test)]
    pub(super) layout: Layout,
    pub(super) root: File,
    pub(super) payloads: PayloadStorage,
    pub(super) recovery: RecoveryState,
    pub(super) delivery_validation: DeliveryValidationCache,
    pub(super) publication_locks: Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>,
    pub(super) staging_budget: Arc<Mutex<StagingBudget>>,
    pub(super) temporary_objects: AtomicU64,
    #[cfg(test)]
    pub(super) egress_generations: AtomicU64,
    pub(super) _lock: ProcessLock,
}

#[derive(Debug, Default)]
pub(super) struct DeliveryValidationCache {
    proofs: Mutex<HashMap<NarFileName, DeliveryProof>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeliveryProof {
    stamp: FileStamp,
    identity: NarIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    size: u64,
    device: u64,
    inode: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileStamp {
    fn from_file(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            size: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

impl DeliveryValidationCache {
    pub(super) fn get(
        &self,
        name: NarFileName,
        file: &File,
    ) -> std::io::Result<Option<NarIdentity>> {
        let stamp = FileStamp::from_file(file)?;
        let proofs = self
            .proofs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(proofs
            .get(&name)
            .filter(|proof| proof.stamp == stamp)
            .map(|proof| proof.identity))
    }

    pub(super) fn insert(
        &self,
        name: NarFileName,
        file: &File,
        identity: NarIdentity,
    ) -> std::io::Result<()> {
        let proof = DeliveryProof {
            stamp: FileStamp::from_file(file)?,
            identity,
        };
        let mut proofs = self
            .proofs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proofs.insert(name, proof);
        Ok(())
    }
}

impl Storage {
    pub(crate) const fn backend(&self) -> StorageBackend {
        self.payloads.backend()
    }

    #[cfg(test)]
    pub(super) const fn chunk_store(&self) -> Option<&ChunkStore> {
        self.payloads.chunk_store()
    }
}
