use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, Weak, atomic::AtomicU64},
};

#[cfg(test)]
use super::publication::Layout;
use super::publication::ProcessLock;
use super::recovery::RecoveryState;

#[derive(Debug)]
pub struct Storage {
    #[cfg(test)]
    pub(super) layout: Layout,
    pub(super) root: File,
    pub(super) recovery: RecoveryState,
    pub(super) publication_locks: Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>,
    pub(super) staging_reservations: Arc<AtomicU64>,
    pub(super) temporary_objects: AtomicU64,
    pub(super) _lock: ProcessLock,
}
