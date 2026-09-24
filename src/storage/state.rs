use std::{
    collections::HashMap,
    fmt,
    fs::File,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, Weak, atomic::AtomicU64},
};

use serde::{Deserialize, Serialize};

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

    pub(super) const fn chunk_store(&self) -> Option<&ChunkStore> {
        match self {
            Self::Flat => None,
            Self::Chunked(store) => Some(store),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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
    pub(super) activity: Arc<StorageActivity>,
    #[cfg(test)]
    pub(super) egress_generations: AtomicU64,
    pub(super) _lock: ProcessLock,
}

#[derive(Debug, Default)]
pub(crate) struct StorageActivity {
    pub(super) upload_validated_logical_bytes: AtomicU64,
    pub(super) upload_created_logical_bytes: AtomicU64,
    pub(super) upload_identical_logical_bytes: AtomicU64,
    pub(super) egress_reuses: AtomicU64,
    pub(super) egress_generations_started: AtomicU64,
    pub(super) egress_generations_succeeded: AtomicU64,
    pub(super) egress_generations_failed: AtomicU64,
    pub(super) egress_repairs: AtomicU64,
    pub(super) egress_coalesced_waits: AtomicU64,
    pub(super) egress_coalesced_wait_nanos: AtomicU64,
    pub(super) chunks_created: AtomicU64,
    pub(super) chunks_reused: AtomicU64,
    pub(super) chunk_bytes_created: AtomicU64,
    pub(super) chunk_bytes_reused: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StorageActivitySnapshot {
    pub(crate) backend: StorageBackend,
    pub(crate) upload_validated_logical_bytes: u64,
    pub(crate) upload_created_logical_bytes: u64,
    pub(crate) upload_identical_logical_bytes: u64,
    pub(crate) egress_reuses: u64,
    pub(crate) egress_generations_started: u64,
    pub(crate) egress_generations_succeeded: u64,
    pub(crate) egress_generations_failed: u64,
    pub(crate) egress_repairs: u64,
    pub(crate) egress_coalesced_waits: u64,
    pub(crate) egress_coalesced_wait_seconds: f64,
    pub(crate) chunks_created: u64,
    pub(crate) chunks_reused: u64,
    pub(crate) chunk_bytes_created: u64,
    pub(crate) chunk_bytes_reused: u64,
}

impl StorageActivity {
    pub(super) fn record_upload_validated_logical_bytes(&self, bytes: u64) {
        increment_saturating(&self.upload_validated_logical_bytes, bytes);
    }

    pub(super) fn record_upload_publication(
        &self,
        outcome: super::publication::PublishOutcome,
        logical_bytes: u64,
    ) {
        let counter = match outcome {
            super::publication::PublishOutcome::Created => &self.upload_created_logical_bytes,
            super::publication::PublishOutcome::Identical => &self.upload_identical_logical_bytes,
        };
        increment_saturating(counter, logical_bytes);
    }

    pub(super) fn record_egress_reuse(&self) {
        increment_saturating(&self.egress_reuses, 1);
    }

    pub(super) fn record_egress_generation_started(&self) {
        increment_saturating(&self.egress_generations_started, 1);
    }

    pub(super) fn record_egress_generation_succeeded(&self) {
        increment_saturating(&self.egress_generations_succeeded, 1);
    }

    pub(super) fn record_egress_generation_failed(&self) {
        increment_saturating(&self.egress_generations_failed, 1);
    }

    pub(super) fn record_egress_repair(&self) {
        increment_saturating(&self.egress_repairs, 1);
    }

    pub(super) fn record_egress_coalesced_wait(&self, elapsed: std::time::Duration) {
        increment_saturating(&self.egress_coalesced_waits, 1);
        increment_saturating(
            &self.egress_coalesced_wait_nanos,
            elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
        );
    }

    pub(super) fn record_chunk_publication(
        &self,
        outcome: super::publication::PublishOutcome,
        bytes: u64,
    ) {
        let (count, byte_count) = match outcome {
            super::publication::PublishOutcome::Created => {
                (&self.chunks_created, &self.chunk_bytes_created)
            }
            super::publication::PublishOutcome::Identical => {
                (&self.chunks_reused, &self.chunk_bytes_reused)
            }
        };
        increment_saturating(count, 1);
        increment_saturating(byte_count, bytes);
    }

    pub(crate) fn snapshot(&self, backend: StorageBackend) -> StorageActivitySnapshot {
        use std::sync::atomic::Ordering::Relaxed;

        StorageActivitySnapshot {
            backend,
            upload_validated_logical_bytes: self.upload_validated_logical_bytes.load(Relaxed),
            upload_created_logical_bytes: self.upload_created_logical_bytes.load(Relaxed),
            upload_identical_logical_bytes: self.upload_identical_logical_bytes.load(Relaxed),
            egress_reuses: self.egress_reuses.load(Relaxed),
            egress_generations_started: self.egress_generations_started.load(Relaxed),
            egress_generations_succeeded: self.egress_generations_succeeded.load(Relaxed),
            egress_generations_failed: self.egress_generations_failed.load(Relaxed),
            egress_repairs: self.egress_repairs.load(Relaxed),
            egress_coalesced_waits: self.egress_coalesced_waits.load(Relaxed),
            egress_coalesced_wait_seconds: self.egress_coalesced_wait_nanos.load(Relaxed) as f64
                / 1_000_000_000.0,
            chunks_created: self.chunks_created.load(Relaxed),
            chunks_reused: self.chunks_reused.load(Relaxed),
            chunk_bytes_created: self.chunk_bytes_created.load(Relaxed),
            chunk_bytes_reused: self.chunk_bytes_reused.load(Relaxed),
        }
    }
}

impl Default for StorageActivitySnapshot {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Flat,
            upload_validated_logical_bytes: 0,
            upload_created_logical_bytes: 0,
            upload_identical_logical_bytes: 0,
            egress_reuses: 0,
            egress_generations_started: 0,
            egress_generations_succeeded: 0,
            egress_generations_failed: 0,
            egress_repairs: 0,
            egress_coalesced_waits: 0,
            egress_coalesced_wait_seconds: 0.0,
            chunks_created: 0,
            chunks_reused: 0,
            chunk_bytes_created: 0,
            chunk_bytes_reused: 0,
        }
    }
}

fn increment_saturating(counter: &AtomicU64, amount: u64) {
    use std::sync::atomic::Ordering::Relaxed;

    let _ = counter.fetch_update(Relaxed, Relaxed, |value| Some(value.saturating_add(amount)));
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
    pub const fn backend(&self) -> StorageBackend {
        self.payloads.backend()
    }

    pub(crate) fn activity_snapshot(&self) -> StorageActivitySnapshot {
        self.activity.snapshot(self.backend())
    }

    #[cfg(test)]
    pub(super) const fn chunk_store(&self) -> Option<&ChunkStore> {
        self.payloads.chunk_store()
    }
}
