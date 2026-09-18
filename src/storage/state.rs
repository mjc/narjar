use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, Weak, atomic::AtomicU64},
};

use super::chunk_store::ChunkStore;
#[cfg(test)]
use super::publication::Layout;
use super::publication::{ProcessLock, StagingBudget};
use super::recovery::RecoveryState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackend {
    Flat,
    Chunked,
}

impl StorageBackend {
    pub const fn layout_descriptor(self) -> &'static [u8] {
        match self {
            Self::Flat => b"narjar-layout-v1\nbackend=flat\n",
            Self::Chunked => b"narjar-layout-v1\nbackend=chunked\n",
        }
    }
}

#[derive(Debug)]
pub struct Storage {
    #[cfg(test)]
    pub(super) layout: Layout,
    pub(super) root: File,
    pub(super) chunk_store: ChunkStore,
    pub(super) backend: StorageBackend,
    pub(super) recovery: RecoveryState,
    pub(super) publication_locks: Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>,
    pub(super) staging_budget: Arc<Mutex<StagingBudget>>,
    pub(super) temporary_objects: AtomicU64,
    #[cfg(test)]
    pub(super) egress_generations: AtomicU64,
    pub(super) _lock: ProcessLock,
}

impl Storage {
    pub(crate) const fn backend(&self) -> StorageBackend {
        self.backend
    }
}
