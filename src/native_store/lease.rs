use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    num::{NonZeroU64, NonZeroUsize},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use data_encoding::HEXLOWER;
use narjar::__private::records::{BoundedRegularFile, decode_complete, read_bounded_regular_file};
use rustix::{fs::FlockOperation, io::Errno};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlite::{ConnectionThreadSafe, State};

const LEASE_PREFIX: &str = ".narjar-lease-";
const LEASE_TEMP_PREFIX: &str = ".narjar-lease-temp-";
const RECORD_FILE: &str = "record";
const ROOT_FILE: &str = "root";
const LOCK_FILE: &str = ".narjar-lease.lock";
const CAPACITY_FILE: &str = ".narjar-lease-capacity";
const MAX_RECORD_BYTES: u64 = 4096;
const MAX_CAPACITY_RECORD_BYTES: u64 = 4096;
const MAX_EXPIRY_CLEANUP_PER_CALL: usize = 64;
#[cfg(test)]
const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";

#[cfg(test)]
static FAIL_DIRECTORY_SYNC: Mutex<Option<(PathBuf, usize)>> = Mutex::new(None);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeStorePath {
    absolute_path: PathBuf,
    basename: String,
}

impl NativeStorePath {
    fn validate(store_dir: &Path, absolute_path: &Path) -> Result<Self, NativeStoreLeaseError> {
        let path = Self::parse(store_dir, absolute_path)?;
        let metadata = fs::symlink_metadata(absolute_path).map_err(NativeStoreLeaseError::Io)?;
        if !(metadata.file_type().is_symlink() || metadata.is_dir() || metadata.is_file()) {
            return Err(NativeStoreLeaseError::InvalidStorePath);
        }
        Ok(path)
    }

    fn parse(store_dir: &Path, absolute_path: &Path) -> Result<Self, NativeStoreLeaseError> {
        let basename = absolute_path
            .strip_prefix(store_dir)
            .ok()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .filter(|_| absolute_path.parent() == Some(store_dir))
            .ok_or(NativeStoreLeaseError::InvalidStorePath)?;
        narjar::__private::storage::validate_store_basename(basename)
            .map_err(|_| NativeStoreLeaseError::InvalidStorePath)?;
        let absolute_path = absolute_path
            .to_str()
            .ok_or(NativeStoreLeaseError::InvalidStorePath)?;
        Ok(Self {
            absolute_path: PathBuf::from(absolute_path),
            basename: basename.to_owned(),
        })
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.absolute_path
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum PersistedLeaseState {
    Pending,
    Live,
}

enum LiveRecordDisposition {
    Expired,
    Unregistered,
    Registered,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LeaseRecord {
    version: u8,
    state: PersistedLeaseState,
    store_path: String,
    expires_at: u64,
}

impl LeaseRecord {
    fn pending(path: &NativeStorePath, expires_at: u64) -> Self {
        Self {
            version: 1,
            state: PersistedLeaseState::Pending,
            store_path: path.absolute_path.to_string_lossy().into_owned(),
            expires_at,
        }
    }

    fn live(path: &NativeStorePath, expires_at: u64) -> Self {
        Self {
            state: PersistedLeaseState::Live,
            ..Self::pending(path, expires_at)
        }
    }

    fn store_path(&self, store_dir: &Path) -> Result<NativeStorePath, NativeStoreLeaseError> {
        if self.version != 1 {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        NativeStorePath::parse(store_dir, Path::new(&self.store_path))
            .map_err(|_| NativeStoreLeaseError::InvalidRecord)
    }
}

pub(crate) struct NativeStoreLease {
    path: NativeStorePath,
    expires_at: u64,
    record_path: PathBuf,
    state: Arc<Mutex<LeaseManagerState>>,
}

impl std::fmt::Debug for NativeStoreLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeStoreLease")
            .field("path", &self.path)
            .field("expires_at", &self.expires_at)
            .field("record_path", &self.record_path)
            .finish_non_exhaustive()
    }
}

impl NativeStoreLease {
    pub(crate) fn store_path(&self) -> &NativeStorePath {
        &self.path
    }

    pub(crate) const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn begin_active_delivery(
        &self,
    ) -> Result<NativeStoreActiveDelivery, NativeStoreLeaseError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeStoreLeaseError::Poisoned)?;
        if !state.record_paths.contains(&self.record_path) {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        let root = fs::read_link(self.record_path.with_file_name(ROOT_FILE))
            .map_err(NativeStoreLeaseError::Io)?;
        if root != self.path.as_path() {
            return Err(NativeStoreLeaseError::RootConflict);
        }
        state.active_delivery_started(&self.record_path);
        Ok(NativeStoreActiveDelivery {
            record_path: self.record_path.clone(),
            state: Arc::clone(&self.state),
        })
    }
}

/// Protects a root from cleanup by its serving manager. All deliveries and
/// maintenance for a live service must share that manager; this is not a
/// cross-process pin for independently opened managers.
pub(crate) struct NativeStoreActiveDelivery {
    record_path: PathBuf,
    state: Arc<Mutex<LeaseManagerState>>,
}

impl Drop for NativeStoreActiveDelivery {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active_delivery_finished(&self.record_path);
        }
    }
}

#[derive(Debug)]
pub(crate) struct NativeLeaseSnapshot {
    pub(crate) active: usize,
    pub(crate) maximum: NonZeroUsize,
    pub(crate) capacity_rejections: u64,
}

pub(crate) struct NativeStoreLeaseManager {
    store_dir: PathBuf,
    roots_dir: PathBuf,
    state_dir: PathBuf,
    minimum_lease_seconds: NonZeroU64,
    maximum_active: NonZeroUsize,
    metadata_database: std::sync::Arc<ConnectionThreadSafe>,
    state: Arc<Mutex<LeaseManagerState>>,
}

struct LeaseManagerState {
    active: usize,
    record_index: RecordPathIndex,
    record_scan: Option<RecordPathScan>,
    capacity_rejections: u64,
    record_paths: BTreeSet<PathBuf>,
    cleanup_cursor: Option<PathBuf>,
    active_deliveries: BTreeMap<PathBuf, usize>,
}

enum RecordPathIndex {
    Current(u64),
    NeedsRefresh(u64),
}

struct RecordPathScan {
    generation: u64,
    entries: fs::ReadDir,
}

impl RecordPathIndex {
    fn needs_refresh(&self) -> bool {
        match self {
            Self::Current(_) => false,
            Self::NeedsRefresh(_) => true,
        }
    }

    fn observed_generation(&self) -> u64 {
        match self {
            Self::Current(generation) | Self::NeedsRefresh(generation) => *generation,
        }
    }

    fn note_generation(&mut self, generation: u64) {
        if generation != self.observed_generation() {
            *self = Self::NeedsRefresh(self.observed_generation());
        }
    }

    fn advance_local_index(&mut self, generation: u64) {
        match self {
            Self::Current(_) => *self = Self::Current(generation),
            Self::NeedsRefresh(_) => {}
        }
    }

    fn refresh(&mut self, generation: u64) {
        *self = Self::Current(generation);
    }
}

impl LeaseManagerState {
    fn cleanup_candidates(&mut self, limit: usize) -> Vec<PathBuf> {
        let candidates: Vec<_> = match self.cleanup_cursor.as_ref() {
            Some(cursor) => self
                .record_paths
                .range::<PathBuf, _>((
                    std::ops::Bound::Excluded(cursor),
                    std::ops::Bound::Unbounded,
                ))
                .chain(self.record_paths.range::<PathBuf, _>(..=cursor))
                .take(limit)
                .cloned()
                .collect(),
            None => self.record_paths.iter().take(limit).cloned().collect(),
        };
        self.cleanup_cursor = candidates
            .last()
            .cloned()
            .or_else(|| self.cleanup_cursor.clone());
        candidates
    }

    fn record_removed(&mut self, path: &Path) {
        self.record_paths.remove(path);
    }

    fn record_added(&mut self, path: PathBuf) {
        self.record_paths.insert(path);
    }

    fn active_delivery_started(&mut self, path: &Path) {
        *self
            .active_deliveries
            .entry(path.to_path_buf())
            .or_default() += 1;
    }

    fn active_delivery_finished(&mut self, path: &Path) {
        if let Some(count) = self.active_deliveries.get_mut(path) {
            *count -= 1;
            if *count == 0 {
                self.active_deliveries.remove(path);
            }
        }
    }

    fn has_active_delivery(&self, path: &Path) -> bool {
        self.active_deliveries.contains_key(path)
    }
}

struct LeasePaths {
    directory: PathBuf,
    record: PathBuf,
    root: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum CapacityMutationKind {
    Acquire,
    ReleaseLive,
    RemovePending,
    Reconcile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CapacityMutation {
    kind: CapacityMutationKind,
    store_basename: String,
    previous_active: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct CapacityRecord {
    generation: u64,
    active: u64,
    pending: Option<CapacityMutation>,
}

impl NativeStoreLeaseManager {
    pub(crate) fn open(
        store_dir: PathBuf,
        state_dir: PathBuf,
        roots_dir: PathBuf,
        minimum_lease_seconds: NonZeroU64,
        maximum_active: NonZeroUsize,
        metadata_database: std::sync::Arc<ConnectionThreadSafe>,
    ) -> Result<Self, NativeStoreLeaseError> {
        Self::open_at(
            store_dir,
            state_dir,
            roots_dir,
            minimum_lease_seconds,
            maximum_active,
            metadata_database,
            now_unix_seconds()?,
        )
    }

    fn open_at(
        store_dir: PathBuf,
        state_dir: PathBuf,
        roots_dir: PathBuf,
        minimum_lease_seconds: NonZeroU64,
        maximum_active: NonZeroUsize,
        metadata_database: std::sync::Arc<ConnectionThreadSafe>,
        now: u64,
    ) -> Result<Self, NativeStoreLeaseError> {
        let manager = Self {
            store_dir,
            roots_dir,
            state_dir,
            minimum_lease_seconds,
            maximum_active,
            metadata_database,
            state: Arc::new(Mutex::new(LeaseManagerState {
                active: 0,
                record_index: RecordPathIndex::Current(0),
                record_scan: None,
                capacity_rejections: 0,
                record_paths: BTreeSet::new(),
                cleanup_cursor: None,
                active_deliveries: BTreeMap::new(),
            })),
        };
        manager.recover(now)?;
        Ok(manager)
    }

    pub(crate) fn validate_store_path(
        &self,
        path: &Path,
    ) -> Result<NativeStorePath, NativeStoreLeaseError> {
        NativeStorePath::validate(&self.store_dir, path)
    }

    pub(crate) fn acquire(
        &self,
        path: NativeStorePath,
        #[cfg(test)] now: u64,
    ) -> Result<NativeStoreLease, NativeStoreLeaseError> {
        #[cfg(test)]
        let mut clock = || Ok(now);
        #[cfg(not(test))]
        let mut clock = now_unix_seconds;
        self.acquire_with_clock(path, &mut clock)
    }

    fn acquire_with_clock(
        &self,
        path: NativeStorePath,
        clock: &mut impl FnMut() -> Result<u64, NativeStoreLeaseError>,
    ) -> Result<NativeStoreLease, NativeStoreLeaseError> {
        let mut state = self.lock_state()?;
        let _cross_process_lock = self.acquire_sidecar_lock()?;
        self.recover_pending_capacity_mutation(&mut state)?;
        let now = clock()?;
        self.refresh_record_paths_if_stale(&mut state)?;
        self.cleanup_expired_records(now, MAX_EXPIRY_CLEANUP_PER_CALL, &mut state)?;
        let path = self.validate_store_path(path.as_path())?;
        let paths = LeasePaths {
            directory: self.lease_directory(&path),
            record: self.record_path(&path),
            root: self.root_path(&path),
        };
        let expires_at = self.acquire_existing_or_new_lease(&path, &paths, &mut state, clock)?;

        Ok(NativeStoreLease {
            record_path: self.record_path(&path),
            path,
            expires_at,
            state: Arc::clone(&self.state),
        })
    }

    fn acquire_existing_or_new_lease(
        &self,
        path: &NativeStorePath,
        paths: &LeasePaths,
        state: &mut LeaseManagerState,
        clock: &mut impl FnMut() -> Result<u64, NativeStoreLeaseError>,
    ) -> Result<u64, NativeStoreLeaseError> {
        match read_optional_record(&paths.record, &self.store_dir)? {
            Some(record) => self.acquire_from_existing_record(path, record, paths, state, clock),
            None => self.create_first_lease(path, paths, state, clock),
        }
    }

    fn acquire_from_existing_record(
        &self,
        path: &NativeStorePath,
        record: LeaseRecord,
        paths: &LeasePaths,
        state: &mut LeaseManagerState,
        clock: &mut impl FnMut() -> Result<u64, NativeStoreLeaseError>,
    ) -> Result<u64, NativeStoreLeaseError> {
        if record.store_path(&self.store_dir)? != *path {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        match record.state {
            PersistedLeaseState::Live => {
                let requested_expiry = lease_expiry(clock()?, self.minimum_lease_seconds)?;
                let renewed_expiry = record.expires_at.max(requested_expiry);
                self.verify_root(&paths.root, path)?;
                write_record_atomically(
                    &self.roots_dir,
                    &paths.record,
                    &LeaseRecord::live(path, renewed_expiry),
                )?;
                state.record_added(paths.record.clone());
                Ok(renewed_expiry)
            }
            PersistedLeaseState::Pending => Err(NativeStoreLeaseError::InvalidRecord),
        }
    }

    fn create_first_lease(
        &self,
        path: &NativeStorePath,
        paths: &LeasePaths,
        state: &mut LeaseManagerState,
        clock: &mut impl FnMut() -> Result<u64, NativeStoreLeaseError>,
    ) -> Result<u64, NativeStoreLeaseError> {
        let _gc_read_lock = self.acquire_gc_read_lock()?;
        if !self.is_registered_store_path(path)? {
            return Err(NativeStoreLeaseError::UnregisteredStorePath);
        }
        self.ensure_capacity(path, state)?;
        self.write_pending_root_and_live_record(path, paths, state, clock)
    }

    fn ensure_capacity(
        &self,
        path: &NativeStorePath,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        let capacity = read_capacity_record(&self.roots_dir)?;
        state.record_index.note_generation(capacity.generation);
        let active = usize::try_from(capacity.active)
            .map_err(|_| NativeStoreLeaseError::InvalidCapacityRecord)?;
        if active >= self.maximum_active.get() {
            state.capacity_rejections = state.capacity_rejections.saturating_add(1);
            return Err(NativeStoreLeaseError::CapacityExceeded);
        }
        let generation = next_generation(capacity.generation)?;
        write_capacity_record(
            &self.roots_dir,
            CapacityRecord {
                generation,
                active: capacity.active,
                pending: Some(CapacityMutation {
                    kind: CapacityMutationKind::Acquire,
                    store_basename: path.basename.clone(),
                    previous_active: capacity.active,
                }),
            },
        )
    }

    fn begin_release_mutation(
        &self,
        path: &NativeStorePath,
        state: PersistedLeaseState,
    ) -> Result<(), NativeStoreLeaseError> {
        let capacity = read_capacity_record(&self.roots_dir)?;
        let generation = next_generation(capacity.generation)?;
        let kind = match state {
            PersistedLeaseState::Live => CapacityMutationKind::ReleaseLive,
            PersistedLeaseState::Pending => CapacityMutationKind::RemovePending,
        };
        write_capacity_record(
            &self.roots_dir,
            CapacityRecord {
                generation,
                active: capacity.active,
                pending: Some(CapacityMutation {
                    kind,
                    store_basename: path.basename.clone(),
                    previous_active: capacity.active,
                }),
            },
        )
    }

    fn complete_capacity_mutation(
        &self,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        let capacity = read_capacity_record(&self.roots_dir)?;
        let mutation = capacity
            .pending
            .as_ref()
            .ok_or(NativeStoreLeaseError::InvalidCapacityRecord)?;
        let active = match mutation.kind {
            CapacityMutationKind::Acquire => mutation
                .previous_active
                .checked_add(1)
                .ok_or(NativeStoreLeaseError::CapacityExceeded)?,
            CapacityMutationKind::ReleaseLive => mutation
                .previous_active
                .checked_sub(1)
                .ok_or(NativeStoreLeaseError::InvalidCapacityRecord)?,
            CapacityMutationKind::RemovePending => mutation.previous_active,
            CapacityMutationKind::Reconcile => {
                return Err(NativeStoreLeaseError::InvalidCapacityRecord);
            }
        };
        let completed = CapacityRecord {
            generation: capacity.generation,
            active,
            pending: None,
        };
        let completed_generation = completed.generation;
        write_capacity_record(&self.roots_dir, completed)?;
        state.active =
            usize::try_from(active).map_err(|_| NativeStoreLeaseError::InvalidCapacityRecord)?;
        state.record_index.advance_local_index(completed_generation);
        Ok(())
    }

    fn recover_pending_capacity_mutation(
        &self,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        let capacity = read_capacity_record(&self.roots_dir)?;
        state.record_index.note_generation(capacity.generation);
        let Some(mutation) = capacity.pending else {
            state.active = usize::try_from(capacity.active)
                .map_err(|_| NativeStoreLeaseError::InvalidCapacityRecord)?;
            return Ok(());
        };
        if mutation.kind == CapacityMutationKind::Reconcile {
            return Err(NativeStoreLeaseError::RecoveryRequired);
        }
        let _gc_read_lock = self.acquire_gc_read_lock()?;
        let path = NativeStorePath::parse(
            &self.store_dir,
            &self.store_dir.join(&mutation.store_basename),
        )?;
        let record_path = self.record_path(&path);
        let record = read_optional_record(&record_path, &self.store_dir)?;
        let active = match mutation.kind {
            CapacityMutationKind::Acquire => match record.as_ref() {
                Some(record) if record.state == PersistedLeaseState::Live => {
                    if self.is_registered_store_path_present(&path)? {
                        self.ensure_root(&self.root_path(&path), &path)?;
                        mutation
                            .previous_active
                            .checked_add(1)
                            .ok_or(NativeStoreLeaseError::CapacityExceeded)?
                    } else {
                        self.remove_incomplete_acquire(&path, Some(record))?;
                        mutation.previous_active
                    }
                }
                Some(_) | None => {
                    self.remove_incomplete_acquire(&path, record.as_ref())?;
                    mutation.previous_active
                }
            },
            CapacityMutationKind::ReleaseLive | CapacityMutationKind::RemovePending => {
                match record.as_ref() {
                    Some(record) => {
                        if mutation.kind == CapacityMutationKind::ReleaseLive
                            && self.is_registered_store_path_present(&path)?
                        {
                            self.recover_interrupted_release(&path, record)?;
                            mutation.previous_active
                        } else {
                            self.remove_recorded_root(&self.root_path(&path), record)?;
                            remove_record(&self.roots_dir, &record_path)?;
                            fs::remove_dir(self.lease_directory(&path))
                                .map_err(NativeStoreLeaseError::Io)?;
                            sync_directory(&self.roots_dir)?;
                            released_active_count(&mutation)?
                        }
                    }
                    None => {
                        self.remove_empty_lease_directory(&path)?;
                        released_active_count(&mutation)?
                    }
                }
            }
            CapacityMutationKind::Reconcile => {
                return Err(NativeStoreLeaseError::InvalidCapacityRecord);
            }
        };
        let recovered = CapacityRecord {
            generation: capacity.generation,
            active,
            pending: None,
        };
        write_capacity_record(&self.roots_dir, recovered)?;
        state.active =
            usize::try_from(active).map_err(|_| NativeStoreLeaseError::InvalidCapacityRecord)?;
        Ok(())
    }

    fn remove_incomplete_acquire(
        &self,
        path: &NativeStorePath,
        record: Option<&LeaseRecord>,
    ) -> Result<(), NativeStoreLeaseError> {
        if let Some(record) = record {
            self.remove_recorded_root(&self.root_path(path), record)?;
            remove_record(&self.roots_dir, &self.record_path(path))?;
        }
        self.remove_empty_lease_directory(path)
    }

    fn remove_empty_lease_directory(
        &self,
        path: &NativeStorePath,
    ) -> Result<(), NativeStoreLeaseError> {
        match fs::remove_dir(self.lease_directory(path)) {
            Ok(()) => sync_directory(&self.roots_dir),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(()),
            Err(error) => Err(NativeStoreLeaseError::Io(error)),
        }
    }

    fn recover_interrupted_release(
        &self,
        path: &NativeStorePath,
        record: &LeaseRecord,
    ) -> Result<(), NativeStoreLeaseError> {
        if record.state != PersistedLeaseState::Live {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        self.ensure_root(&self.root_path(path), path)
    }

    pub(crate) fn release(
        &self,
        lease: &NativeStoreLease,
        #[cfg(test)] test_now: u64,
    ) -> Result<(), NativeStoreLeaseError> {
        let mut state = self.lock_state()?;
        let _cross_process_lock = self.acquire_sidecar_lock()?;
        self.recover_pending_capacity_mutation(&mut state)?;
        #[cfg(test)]
        let now = test_now;
        #[cfg(not(test))]
        let now = now_unix_seconds()?;
        let path = &lease.path;
        let record_path = self.record_path(path);
        let root_path = self.root_path(path);
        let Some(record) = read_optional_record(&record_path, &self.store_dir)? else {
            return Ok(());
        };
        if record.store_path(&self.store_dir)? != *path {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        if state.has_active_delivery(&record_path) {
            return Err(NativeStoreLeaseError::LeaseStillLive);
        }
        if record.state == PersistedLeaseState::Live && record.expires_at > now {
            return Err(NativeStoreLeaseError::LeaseStillLive);
        }
        (|| {
            let _gc_read_lock = self.acquire_gc_read_lock()?;
            self.begin_release_mutation(path, record.state)?;
            self.remove_recorded_root(&root_path, &record)?;
            remove_record(&self.roots_dir, &record_path)?;
            fs::remove_dir(self.lease_directory(path)).map_err(NativeStoreLeaseError::Io)?;
            sync_directory(&self.roots_dir)?;
            state.record_removed(&record_path);
            self.complete_capacity_mutation(&mut state)?;
            Ok(())
        })()
    }

    pub(crate) fn snapshot(&self) -> Result<NativeLeaseSnapshot, NativeStoreLeaseError> {
        let mut state = self.lock_state()?;
        let _cross_process_lock = self.acquire_sidecar_lock()?;
        self.recover_pending_capacity_mutation(&mut state)?;
        let capacity = read_capacity_record(&self.roots_dir)?;
        state.active = usize::try_from(capacity.active)
            .map_err(|_| NativeStoreLeaseError::InvalidCapacityRecord)?;
        Ok(NativeLeaseSnapshot {
            active: state.active,
            maximum: self.maximum_active,
            capacity_rejections: state.capacity_rejections,
        })
    }

    pub(crate) fn cleanup_expired(&self) -> Result<(), NativeStoreLeaseError> {
        let mut state = self.lock_state()?;
        let _cross_process_lock = self.acquire_sidecar_lock()?;
        let now = now_unix_seconds()?;
        self.recover_interrupted_reconciliation(&mut state, now)?;
        self.refresh_record_paths_if_stale(&mut state)?;
        self.cleanup_expired_records(now, MAX_EXPIRY_CLEANUP_PER_CALL, &mut state)
    }

    fn cleanup_expired_at(&self, now: u64) -> Result<(), NativeStoreLeaseError> {
        let mut state = self.lock_state()?;
        let _cross_process_lock = self.acquire_sidecar_lock()?;
        self.recover_interrupted_reconciliation(&mut state, now)?;
        self.refresh_record_paths_if_stale(&mut state)?;
        self.cleanup_expired_records(now, MAX_EXPIRY_CLEANUP_PER_CALL, &mut state)
    }

    fn recover(&self, now: u64) -> Result<(), NativeStoreLeaseError> {
        let mut state = self.lock_state()?;
        let _cross_process_lock = self.acquire_sidecar_lock()?;
        self.recover_under_lock(now, &mut state)
    }

    fn recover_interrupted_reconciliation(
        &self,
        state: &mut LeaseManagerState,
        now: u64,
    ) -> Result<(), NativeStoreLeaseError> {
        let pending = read_capacity_record(&self.roots_dir)?.pending;
        match pending {
            Some(mutation) if mutation.kind == CapacityMutationKind::Reconcile => {
                self.recover_under_lock(now, state)
            }
            _ => self.recover_pending_capacity_mutation(state),
        }
    }

    fn recover_under_lock(
        &self,
        now: u64,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        let capacity = read_capacity_record(&self.roots_dir)?;
        if !capacity
            .pending
            .as_ref()
            .is_some_and(|mutation| mutation.kind == CapacityMutationKind::Reconcile)
        {
            if capacity.pending.is_some() {
                self.recover_pending_capacity_mutation(state)?;
            }
            self.begin_recovery_reconciliation()?;
        }
        state.active = 0;
        state.record_paths.clear();
        state.cleanup_cursor = None;
        let _gc_read_lock = self.acquire_gc_read_lock()?;
        remove_stale_temporary_records(&self.roots_dir)?;
        remove_empty_orphan_lease_directories(&self.roots_dir)?;
        let record_paths = read_record_paths(&self.roots_dir)?;
        state.record_paths = record_paths.iter().cloned().collect();
        let capacity = read_capacity_record(&self.roots_dir)?;
        state.record_index.refresh(capacity.generation);
        let mut cleanup_remaining = MAX_EXPIRY_CLEANUP_PER_CALL;
        record_paths.into_iter().try_for_each(|record_path| {
            self.recover_record_at_path(&record_path, now, &mut cleanup_remaining, state)
        })?;

        let generation = next_generation(capacity.generation)?;
        write_capacity_record(
            &self.roots_dir,
            CapacityRecord {
                generation,
                active: state.active as u64,
                pending: None,
            },
        )?;
        state.record_index.refresh(generation);
        Ok(())
    }

    fn begin_recovery_reconciliation(&self) -> Result<(), NativeStoreLeaseError> {
        let capacity = read_capacity_record(&self.roots_dir)?;
        let generation = next_generation(capacity.generation)?;
        write_capacity_record(
            &self.roots_dir,
            CapacityRecord {
                generation,
                active: capacity.active,
                pending: Some(CapacityMutation {
                    kind: CapacityMutationKind::Reconcile,
                    store_basename: String::new(),
                    previous_active: capacity.active,
                }),
            },
        )
    }

    fn recover_record_at_path(
        &self,
        record_path: &Path,
        now: u64,
        cleanup_remaining: &mut usize,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        let record = read_required_record(record_path, &self.store_dir)?;
        let store_path = record.store_path(&self.store_dir)?;
        match record.state {
            PersistedLeaseState::Pending => self.remove_pending_record_if_budget_allows(
                record_path,
                &store_path,
                &record,
                cleanup_remaining,
                state,
            ),
            PersistedLeaseState::Live => self.recover_live_record(
                record_path,
                &store_path,
                &record,
                now,
                cleanup_remaining,
                state,
            ),
        }
    }

    fn remove_pending_record_if_budget_allows(
        &self,
        record_path: &Path,
        store_path: &NativeStorePath,
        record: &LeaseRecord,
        cleanup_remaining: &mut usize,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        match cleanup_remaining.checked_sub(1) {
            Some(remaining) => {
                self.remove_recovered_lease_files(record_path, store_path, record, state)?;
                *cleanup_remaining = remaining;
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn recover_live_record(
        &self,
        record_path: &Path,
        store_path: &NativeStorePath,
        record: &LeaseRecord,
        now: u64,
        cleanup_remaining: &mut usize,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        state.active += 1;
        let disposition = match (
            record.expires_at <= now,
            self.is_registered_store_path(store_path)?,
        ) {
            (true, _) => LiveRecordDisposition::Expired,
            (false, false) => LiveRecordDisposition::Unregistered,
            (false, true) => LiveRecordDisposition::Registered,
        };
        match disposition {
            LiveRecordDisposition::Expired | LiveRecordDisposition::Unregistered => self
                .remove_live_record_if_budget_allows(
                    record_path,
                    store_path,
                    record,
                    cleanup_remaining,
                    state,
                ),
            LiveRecordDisposition::Registered => self.restore_registered_live_root(
                record_path,
                store_path,
                record,
                cleanup_remaining,
                state,
            ),
        }
    }

    fn restore_registered_live_root(
        &self,
        record_path: &Path,
        store_path: &NativeStorePath,
        record: &LeaseRecord,
        cleanup_remaining: &mut usize,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        match NativeStorePath::validate(&self.store_dir, store_path.as_path()) {
            Ok(valid_path) if valid_path == *store_path => {
                self.ensure_root(&self.root_path(store_path), store_path)
            }
            Ok(_) => Err(NativeStoreLeaseError::InvalidRecord),
            Err(NativeStoreLeaseError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                self.remove_live_record_if_budget_allows(
                    record_path,
                    store_path,
                    record,
                    cleanup_remaining,
                    state,
                )
            }
            Err(error) => Err(error),
        }
    }

    fn remove_live_record_if_budget_allows(
        &self,
        record_path: &Path,
        store_path: &NativeStorePath,
        record: &LeaseRecord,
        cleanup_remaining: &mut usize,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        if state.has_active_delivery(record_path) {
            return Ok(());
        }
        match cleanup_remaining.checked_sub(1) {
            Some(remaining) => {
                self.remove_recovered_lease_files(record_path, store_path, record, state)?;
                *cleanup_remaining = remaining;
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn remove_recorded_lease_files(
        &self,
        record_path: &Path,
        store_path: &NativeStorePath,
        record: &LeaseRecord,
    ) -> Result<(), NativeStoreLeaseError> {
        self.remove_recorded_root(&self.root_path(store_path), record)?;
        remove_record(&self.roots_dir, record_path)?;
        fs::remove_dir(self.lease_directory(store_path)).map_err(NativeStoreLeaseError::Io)?;
        sync_directory(&self.roots_dir)
    }

    fn remove_recovered_lease_files(
        &self,
        record_path: &Path,
        store_path: &NativeStorePath,
        record: &LeaseRecord,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        self.remove_recorded_lease_files(record_path, store_path, record)?;
        state.record_removed(record_path);
        if record.state == PersistedLeaseState::Live {
            state.active -= 1;
        }
        Ok(())
    }

    fn refresh_record_paths_if_stale(
        &self,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        let generation = read_capacity_record(&self.roots_dir)?.generation;
        state.record_index.note_generation(generation);
        if state.record_index.needs_refresh() && state.record_scan.is_none() {
            state.record_scan = Some(RecordPathScan {
                generation,
                entries: fs::read_dir(&self.roots_dir).map_err(NativeStoreLeaseError::Io)?,
            });
        }
        let batch = state
            .record_scan
            .as_mut()
            .map(|scan| {
                read_record_path_batch(&mut scan.entries, MAX_EXPIRY_CLEANUP_PER_CALL)
                    .map(|batch| (scan.generation, batch))
            })
            .transpose();
        match batch {
            Err(error) => {
                state.record_scan = None;
                return Err(error);
            }
            Ok(Some((scanned_generation, (paths, complete)))) => {
                state.record_paths.extend(paths);
                if complete {
                    state.record_scan = None;
                    state.record_index.refresh(scanned_generation);
                    state
                        .record_index
                        .note_generation(read_capacity_record(&self.roots_dir)?.generation);
                }
            }
            Ok(None) => {}
        }
        Ok(())
    }

    fn write_pending_root_and_live_record(
        &self,
        path: &NativeStorePath,
        paths: &LeasePaths,
        state: &mut LeaseManagerState,
        clock: &mut impl FnMut() -> Result<u64, NativeStoreLeaseError>,
    ) -> Result<u64, NativeStoreLeaseError> {
        fs::create_dir(&paths.directory).map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => NativeStoreLeaseError::RootConflict,
            _ => NativeStoreLeaseError::Io(error),
        })?;
        sync_directory(&self.roots_dir)?;
        let pending_expiry = lease_expiry(clock()?, self.minimum_lease_seconds)?;
        write_record_atomically(
            &self.roots_dir,
            &paths.record,
            &LeaseRecord::pending(path, pending_expiry),
        )?;
        state.record_added(paths.record.clone());
        let current_path = NativeStorePath::validate(&self.store_dir, &path.absolute_path)?;
        if current_path != *path {
            return Err(NativeStoreLeaseError::InvalidStorePath);
        }
        let expires_at = lease_expiry(clock()?, self.minimum_lease_seconds)?;
        self.create_root(&paths.root, path)?;
        write_record_atomically(
            &self.roots_dir,
            &paths.record,
            &LeaseRecord::live(path, expires_at),
        )?;
        self.complete_capacity_mutation(state)?;
        Ok(expires_at)
    }

    fn ensure_root(
        &self,
        root_path: &Path,
        store_path: &NativeStorePath,
    ) -> Result<(), NativeStoreLeaseError> {
        let current_path = NativeStorePath::validate(&self.store_dir, &store_path.absolute_path)?;
        if current_path != *store_path {
            return Err(NativeStoreLeaseError::InvalidStorePath);
        }
        match fs::symlink_metadata(root_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                self.verify_root(root_path, store_path)?;
                sync_root_parent_directory(root_path)
            }
            Ok(_) => Err(NativeStoreLeaseError::RootConflict),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::os::unix::fs::symlink(&store_path.absolute_path, root_path)
                    .map_err(NativeStoreLeaseError::Io)?;
                sync_root_parent_directory(root_path)
            }
            Err(error) => Err(NativeStoreLeaseError::Io(error)),
        }
    }

    fn create_root(
        &self,
        root_path: &Path,
        store_path: &NativeStorePath,
    ) -> Result<(), NativeStoreLeaseError> {
        std::os::unix::fs::symlink(&store_path.absolute_path, root_path).map_err(|error| {
            match error.kind() {
                io::ErrorKind::AlreadyExists => NativeStoreLeaseError::RootConflict,
                _ => NativeStoreLeaseError::Io(error),
            }
        })?;
        sync_directory(
            root_path
                .parent()
                .ok_or(NativeStoreLeaseError::InvalidRecord)?,
        )
    }

    fn verify_root(
        &self,
        root_path: &Path,
        store_path: &NativeStorePath,
    ) -> Result<(), NativeStoreLeaseError> {
        let metadata = fs::symlink_metadata(root_path).map_err(NativeStoreLeaseError::Io)?;
        let target = fs::read_link(root_path).map_err(NativeStoreLeaseError::Io)?;
        if metadata.file_type().is_symlink() && target == store_path.absolute_path {
            Ok(())
        } else {
            Err(NativeStoreLeaseError::RootConflict)
        }
    }

    fn remove_recorded_root(
        &self,
        root_path: &Path,
        record: &LeaseRecord,
    ) -> Result<(), NativeStoreLeaseError> {
        let store_path = record.store_path(&self.store_dir)?;
        match fs::symlink_metadata(root_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                self.verify_root(root_path, &store_path)?;
                fs::remove_file(root_path).map_err(NativeStoreLeaseError::Io)?;
                sync_directory(
                    root_path
                        .parent()
                        .ok_or(NativeStoreLeaseError::InvalidRecord)?,
                )
            }
            Ok(_) => Err(NativeStoreLeaseError::RootConflict),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(NativeStoreLeaseError::Io(error)),
        }
    }

    fn cleanup_expired_records(
        &self,
        now: u64,
        maximum_to_remove: usize,
        state: &mut LeaseManagerState,
    ) -> Result<(), NativeStoreLeaseError> {
        (|| {
            let _gc_read_lock = self.acquire_gc_read_lock()?;
            state
                .cleanup_candidates(maximum_to_remove)
                .into_iter()
                .try_for_each(|record_path| {
                    let Some(record) = read_optional_record(&record_path, &self.store_dir)? else {
                        state.record_removed(&record_path);
                        return Ok(());
                    };
                    if record.state != PersistedLeaseState::Pending && record.expires_at > now {
                        return Ok(());
                    }
                    if state.has_active_delivery(&record_path) {
                        return Ok(());
                    }
                    let store_path = record.store_path(&self.store_dir)?;
                    self.begin_release_mutation(&store_path, record.state)?;
                    self.remove_recorded_root(&self.root_path(&store_path), &record)?;
                    remove_record(&self.roots_dir, &record_path)?;
                    fs::remove_dir(self.lease_directory(&store_path))
                        .map_err(NativeStoreLeaseError::Io)?;
                    sync_directory(&self.roots_dir)?;
                    state.record_removed(&record_path);
                    self.complete_capacity_mutation(state)?;
                    Ok(())
                })
        })()
    }

    fn lease_directory(&self, path: &NativeStorePath) -> PathBuf {
        self.roots_dir.join(lease_directory_name(path))
    }

    fn record_path(&self, path: &NativeStorePath) -> PathBuf {
        self.lease_directory(path).join(RECORD_FILE)
    }

    fn root_path(&self, path: &NativeStorePath) -> PathBuf {
        self.lease_directory(path).join(ROOT_FILE)
    }

    fn acquire_sidecar_lock(&self) -> Result<SidecarLock, NativeStoreLeaseError> {
        let path = self.roots_dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(path)
            .map_err(NativeStoreLeaseError::Io)?;
        set_flock_lock(&file)?;
        Ok(SidecarLock { _file: file })
    }

    fn acquire_gc_read_lock(&self) -> Result<GcReadLock, NativeStoreLeaseError> {
        let path = self.state_dir.join("gc.lock");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(path)
            .map_err(NativeStoreLeaseError::Io)?;
        set_flock_lock_with_mode(&file, FlockOperation::LockShared)?;
        Ok(GcReadLock { _file: file })
    }

    fn is_registered_store_path(
        &self,
        path: &NativeStorePath,
    ) -> Result<bool, NativeStoreLeaseError> {
        let mut statement = self
            .metadata_database
            .prepare("SELECT 1 FROM ValidPaths WHERE path = ? LIMIT 1")
            .map_err(|error| NativeStoreLeaseError::Database(error.to_string()))?;
        statement
            .bind((1, path.absolute_path.to_string_lossy().as_ref()))
            .map_err(|error| NativeStoreLeaseError::Database(error.to_string()))?;
        statement
            .next()
            .map(|state| state == State::Row)
            .map_err(|error| NativeStoreLeaseError::Database(error.to_string()))
    }

    fn is_registered_store_path_present(
        &self,
        path: &NativeStorePath,
    ) -> Result<bool, NativeStoreLeaseError> {
        if !self.is_registered_store_path(path)? {
            return Ok(false);
        }
        match NativeStorePath::validate(&self.store_dir, path.as_path()) {
            Ok(current_path) if current_path == *path => Ok(true),
            Ok(_) => Err(NativeStoreLeaseError::InvalidStorePath),
            Err(NativeStoreLeaseError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, LeaseManagerState>, NativeStoreLeaseError> {
        self.state
            .lock()
            .map_err(|_| NativeStoreLeaseError::Poisoned)
    }
}

struct SidecarLock {
    _file: File,
}

struct GcReadLock {
    _file: File,
}

fn set_flock_lock(file: &File) -> Result<(), NativeStoreLeaseError> {
    set_flock_lock_with_mode(file, FlockOperation::LockExclusive)
}

fn set_flock_lock_with_mode(
    file: &File,
    lock_mode: FlockOperation,
) -> Result<(), NativeStoreLeaseError> {
    std::iter::repeat_with(|| rustix::fs::flock(file, lock_mode))
        .find(|result| *result != Err(Errno::INTR))
        .unwrap_or(Err(Errno::INTR))
        .map_err(|error| NativeStoreLeaseError::Io(error.into()))
}

fn read_record_paths(roots_dir: &Path) -> Result<Vec<PathBuf>, NativeStoreLeaseError> {
    fs::read_dir(roots_dir)
        .map_err(NativeStoreLeaseError::Io)?
        .try_fold(Vec::new(), |mut paths, entry| {
            let entry = entry.map_err(NativeStoreLeaseError::Io)?;
            if let Some(path) = record_path_from_directory_entry(entry)? {
                paths.push(path);
            }
            Ok(paths)
        })
}

fn read_record_path_batch(
    entries: &mut fs::ReadDir,
    maximum_entries: usize,
) -> Result<(Vec<PathBuf>, bool), NativeStoreLeaseError> {
    let (paths, entries_read) = std::iter::from_fn(|| entries.next())
        .take(maximum_entries)
        .try_fold((Vec::new(), 0), |(mut paths, entries_read), entry| {
            let entry = entry.map_err(NativeStoreLeaseError::Io)?;
            if let Some(path) = record_path_from_directory_entry(entry)? {
                paths.push(path);
            }
            Ok::<_, NativeStoreLeaseError>((paths, entries_read + 1))
        })?;
    Ok((paths, entries_read < maximum_entries))
}

fn record_path_from_directory_entry(
    entry: fs::DirEntry,
) -> Result<Option<PathBuf>, NativeStoreLeaseError> {
    if !is_lease_directory_name(&entry.file_name()) {
        return Ok(None);
    }
    let directory = entry.path();
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() => {
            let record = directory.join(RECORD_FILE);
            match fs::symlink_metadata(&record) {
                Ok(_) => Ok(Some(record)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(NativeStoreLeaseError::Io(error)),
            }
        }
        Ok(_) => Err(NativeStoreLeaseError::InvalidRecord),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(NativeStoreLeaseError::Io(error)),
    }
}

fn remove_empty_orphan_lease_directories(roots_dir: &Path) -> Result<(), NativeStoreLeaseError> {
    let orphan_directories = fs::read_dir(roots_dir)
        .map_err(NativeStoreLeaseError::Io)?
        .filter_map(|entry| match entry {
            Ok(entry) if is_lease_directory_name(&entry.file_name()) => {
                let directory = entry.path();
                match fs::symlink_metadata(&directory) {
                    Ok(metadata) if metadata.is_dir() => {}
                    Ok(_) => return Some(Err(NativeStoreLeaseError::InvalidRecord)),
                    Err(error) => return Some(Err(NativeStoreLeaseError::Io(error))),
                }
                let record = directory.join(RECORD_FILE);
                match fs::symlink_metadata(&record) {
                    Ok(_) => None,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        let root = directory.join(ROOT_FILE);
                        match fs::symlink_metadata(&root) {
                            Ok(_) => None,
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                Some(Ok(directory))
                            }
                            Err(error) => Some(Err(NativeStoreLeaseError::Io(error))),
                        }
                    }
                    Err(error) => Some(Err(NativeStoreLeaseError::Io(error))),
                }
            }
            Ok(_) => None,
            Err(error) => Some(Err(NativeStoreLeaseError::Io(error))),
        })
        .take(MAX_EXPIRY_CLEANUP_PER_CALL)
        .collect::<Result<Vec<_>, _>>()?;
    orphan_directories
        .iter()
        .try_for_each(|directory| fs::remove_dir(directory).map_err(NativeStoreLeaseError::Io))?;
    if !orphan_directories.is_empty() {
        sync_directory(roots_dir)?;
    }
    Ok(())
}

fn is_lease_directory_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.strip_prefix(LEASE_PREFIX).is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    })
}

fn read_optional_record(
    path: &Path,
    store_dir: &Path,
) -> Result<Option<LeaseRecord>, NativeStoreLeaseError> {
    let record = match read_bounded_regular_file(rustix::fs::CWD, path, MAX_RECORD_BYTES)
        .map_err(NativeStoreLeaseError::Io)?
        .parse(|bytes| decode_complete::<LeaseRecord>(bytes).ok())
    {
        BoundedRegularFile::Missing => return Ok(None),
        BoundedRegularFile::Invalid => return Err(NativeStoreLeaseError::InvalidRecord),
        BoundedRegularFile::Valid(record) => record,
    };
    let store_path = record.store_path(store_dir)?;
    if path.file_name() != Some(std::ffi::OsStr::new(RECORD_FILE))
        || path.parent().and_then(Path::file_name)
            != Some(lease_directory_name(&store_path).as_ref())
    {
        return Err(NativeStoreLeaseError::InvalidRecord);
    }
    Ok(Some(record))
}

fn read_required_record(
    path: &Path,
    store_dir: &Path,
) -> Result<LeaseRecord, NativeStoreLeaseError> {
    read_optional_record(path, store_dir)?.ok_or(NativeStoreLeaseError::InvalidRecord)
}

fn write_record_atomically(
    roots_dir: &Path,
    path: &Path,
    record: &LeaseRecord,
) -> Result<(), NativeStoreLeaseError> {
    let bytes = postcard::to_allocvec(record).map_err(|_| NativeStoreLeaseError::InvalidRecord)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(NativeStoreLeaseError::RecordTooLarge);
    }
    write_bytes_atomically(roots_dir, path, &bytes)
}

fn read_capacity_record(roots_dir: &Path) -> Result<CapacityRecord, NativeStoreLeaseError> {
    let path = roots_dir.join(CAPACITY_FILE);
    match read_bounded_regular_file(rustix::fs::CWD, &path, MAX_CAPACITY_RECORD_BYTES)
        .map_err(NativeStoreLeaseError::Io)?
        .parse(|bytes| decode_complete(bytes).ok())
    {
        BoundedRegularFile::Missing => Ok(CapacityRecord::default()),
        BoundedRegularFile::Invalid => Err(NativeStoreLeaseError::InvalidCapacityRecord),
        BoundedRegularFile::Valid(record) => Ok(record),
    }
}

fn write_capacity_record(
    roots_dir: &Path,
    record: CapacityRecord,
) -> Result<(), NativeStoreLeaseError> {
    let bytes =
        postcard::to_allocvec(&record).map_err(|_| NativeStoreLeaseError::InvalidCapacityRecord)?;
    if bytes.len() as u64 > MAX_CAPACITY_RECORD_BYTES {
        return Err(NativeStoreLeaseError::InvalidCapacityRecord);
    }
    write_bytes_atomically(roots_dir, &roots_dir.join(CAPACITY_FILE), &bytes)
}

fn next_generation(generation: u64) -> Result<u64, NativeStoreLeaseError> {
    generation
        .checked_add(1)
        .ok_or(NativeStoreLeaseError::CapacityExceeded)
}

fn released_active_count(mutation: &CapacityMutation) -> Result<u64, NativeStoreLeaseError> {
    match mutation.kind {
        CapacityMutationKind::ReleaseLive => mutation
            .previous_active
            .checked_sub(1)
            .ok_or(NativeStoreLeaseError::InvalidCapacityRecord),
        CapacityMutationKind::RemovePending => Ok(mutation.previous_active),
        CapacityMutationKind::Acquire | CapacityMutationKind::Reconcile => {
            Err(NativeStoreLeaseError::InvalidCapacityRecord)
        }
    }
}

fn write_bytes_atomically(
    roots_dir: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), NativeStoreLeaseError> {
    let mut temporary = tempfile::Builder::new()
        .prefix(LEASE_TEMP_PREFIX)
        .tempfile_in(roots_dir)
        .map_err(NativeStoreLeaseError::Io)?;
    temporary
        .write_all(bytes)
        .map_err(NativeStoreLeaseError::Io)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(NativeStoreLeaseError::Io)?;
    temporary
        .persist(path)
        .map_err(|error| NativeStoreLeaseError::Io(error.error))?;
    let destination_directory = path.parent().unwrap_or(roots_dir);
    sync_directory(destination_directory)?;
    if destination_directory != roots_dir {
        sync_directory(roots_dir)?;
    }
    Ok(())
}

fn remove_record(roots_dir: &Path, path: &Path) -> Result<(), NativeStoreLeaseError> {
    fs::remove_file(path).map_err(NativeStoreLeaseError::Io)?;
    sync_directory(path.parent().unwrap_or(roots_dir))
}

fn sync_root_parent_directory(root_path: &Path) -> Result<(), NativeStoreLeaseError> {
    sync_directory(
        root_path
            .parent()
            .ok_or(NativeStoreLeaseError::InvalidRecord)?,
    )
}

fn sync_directory(path: &Path) -> Result<(), NativeStoreLeaseError> {
    #[cfg(test)]
    if let Ok(mut failure) = FAIL_DIRECTORY_SYNC.lock()
        && let Some((directory, remaining_syncs)) = failure.as_mut()
        && directory == path
    {
        *remaining_syncs -= 1;
        if *remaining_syncs == 0 {
            failure.take();
            return Err(NativeStoreLeaseError::Io(io::Error::other(
                "injected directory synchronization failure",
            )));
        }
    }
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(NativeStoreLeaseError::Io)
}

#[cfg(test)]
fn fail_nth_directory_sync(path: &Path, nth_sync: usize) {
    *FAIL_DIRECTORY_SYNC
        .lock()
        .expect("directory-sync failpoint lock should be available") =
        Some((path.to_owned(), nth_sync));
}

fn remove_stale_temporary_records(roots_dir: &Path) -> Result<(), NativeStoreLeaseError> {
    let stale_paths = fs::read_dir(roots_dir)
        .map_err(NativeStoreLeaseError::Io)?
        .filter_map(|entry| match entry {
            Ok(entry) if is_temporary_record_name(&entry.file_name()) => Some(Ok(entry.path())),
            Ok(_) => None,
            Err(error) => Some(Err(NativeStoreLeaseError::Io(error))),
        })
        .take(MAX_EXPIRY_CLEANUP_PER_CALL)
        .collect::<Result<Vec<_>, _>>()?;
    stale_paths.iter().try_for_each(|path| {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(path).map_err(NativeStoreLeaseError::Io)?;
            }
            Ok(_) => return Err(NativeStoreLeaseError::InvalidRecord),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(NativeStoreLeaseError::Io(error)),
        }
        Ok(())
    })?;
    if !stale_paths.is_empty() {
        sync_directory(roots_dir)?;
    }
    Ok(())
}

fn is_temporary_record_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix(LEASE_TEMP_PREFIX))
        .is_some_and(|suffix| {
            suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn lease_directory_name(path: &NativeStorePath) -> std::ffi::OsString {
    let digest = Sha256::digest(path.basename.as_bytes());
    format!("{LEASE_PREFIX}{}", HEXLOWER.encode(&digest)).into()
}

fn lease_expiry(now: u64, minimum_lease_seconds: NonZeroU64) -> Result<u64, NativeStoreLeaseError> {
    now.checked_add(minimum_lease_seconds.get())
        .ok_or(NativeStoreLeaseError::ClockOverflow)
}

fn now_unix_seconds() -> Result<u64, NativeStoreLeaseError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NativeStoreLeaseError::ClockBeforeEpoch)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeStoreLeaseError {
    #[error("native-store lease capacity is full")]
    CapacityExceeded,
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
    #[error("native-store lease expiry overflows")]
    ClockOverflow,
    #[error("querying the Nix store database: {0}")]
    Database(String),
    #[error("native-store lease record is invalid")]
    InvalidRecord,
    #[error("native-store lease capacity record is invalid")]
    InvalidCapacityRecord,
    #[error("native-store path is invalid")]
    InvalidStorePath,
    #[error("native-store lease I/O: {0}")]
    Io(#[source] io::Error),
    #[error("native-store lease has not expired")]
    LeaseStillLive,
    #[error("native-store lease state is poisoned")]
    Poisoned,
    #[error("native-store GC root conflicts with its lease")]
    RootConflict,
    #[error("native-store lease record exceeds its limit")]
    RecordTooLarge,
    #[error("native-store lease recovery must finish before admission")]
    RecoveryRequired,
    #[error("native-store path is not registered in the Nix store")]
    UnregisteredStorePath,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlite::Connection;
    use std::{
        num::NonZeroUsize,
        process::{Command, Output},
        sync::{Arc, Barrier},
        thread,
    };

    #[test]
    fn lease_and_capacity_readers_keep_absence_invalid_records_and_io_distinct() {
        let directory = tempfile::tempdir().unwrap();
        let capacity = directory.path().join(CAPACITY_FILE);
        assert_eq!(
            read_capacity_record(directory.path()).unwrap(),
            CapacityRecord::default()
        );
        assert!(
            read_optional_record(&capacity, directory.path())
                .unwrap()
                .is_none()
        );

        for bytes in [vec![], vec![0; MAX_RECORD_BYTES as usize + 1]] {
            fs::write(&capacity, bytes).unwrap();
            assert!(matches!(
                read_capacity_record(directory.path()),
                Err(NativeStoreLeaseError::InvalidCapacityRecord)
            ));
            assert!(matches!(
                read_optional_record(&capacity, directory.path()),
                Err(NativeStoreLeaseError::InvalidRecord)
            ));
        }

        fs::remove_file(&capacity).unwrap();
        fs::create_dir(&capacity).unwrap();
        assert!(matches!(
            read_capacity_record(directory.path()),
            Err(NativeStoreLeaseError::InvalidCapacityRecord)
        ));
        assert!(matches!(
            read_optional_record(&capacity, directory.path()),
            Err(NativeStoreLeaseError::InvalidRecord)
        ));
        fs::remove_dir(&capacity).unwrap();
        #[cfg(target_os = "linux")]
        {
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                &capacity,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .unwrap();
            assert!(matches!(
                read_capacity_record(directory.path()),
                Err(NativeStoreLeaseError::InvalidCapacityRecord)
            ));
            assert!(matches!(
                read_optional_record(&capacity, directory.path()),
                Err(NativeStoreLeaseError::InvalidRecord)
            ));
            fs::remove_file(&capacity).unwrap();
        }
        let target = directory.path().join("target");
        fs::write(
            &target,
            postcard::to_allocvec(&CapacityRecord::default()).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, &capacity).unwrap();
        assert!(matches!(
            read_capacity_record(directory.path()),
            Err(NativeStoreLeaseError::InvalidCapacityRecord)
        ));
        assert!(matches!(
            read_optional_record(&capacity, directory.path()),
            Err(NativeStoreLeaseError::InvalidRecord)
        ));

        for result in [
            read_capacity_record(&target).map(|_| ()),
            read_optional_record(&target.join(RECORD_FILE), directory.path()).map(|_| ()),
        ] {
            match result {
                Err(NativeStoreLeaseError::Io(error)) => {
                    assert_eq!(error.raw_os_error(), Some(Errno::NOTDIR.raw_os_error()))
                }
                result => panic!("non-directory parent must retain its I/O error: {result:?}"),
            }
        }
    }

    #[test]
    fn lease_and_capacity_reads_reject_trailing_bytes() {
        let fixture = LeaseFixture::new(1);
        let _lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), 2)
            .unwrap();
        let path = fixture
            .roots_dir
            .join(lease_directory_name(&fixture.store_path))
            .join(RECORD_FILE);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(matches!(
            read_optional_record(&path, &fixture.store_dir),
            Err(NativeStoreLeaseError::InvalidRecord)
        ));
        let capacity = fixture.roots_dir.join(CAPACITY_FILE);
        OpenOptions::new()
            .append(true)
            .open(capacity)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(matches!(
            read_capacity_record(&fixture.roots_dir),
            Err(NativeStoreLeaseError::InvalidCapacityRecord)
        ));
    }

    #[test]
    fn failed_record_persistence_cleans_the_owned_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            write_bytes_atomically(
                directory.path(),
                &directory.path().join("missing/record"),
                b"record"
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    struct LeaseFixture {
        _directory: tempfile::TempDir,
        store_dir: PathBuf,
        state_dir: PathBuf,
        roots_dir: PathBuf,
        database_path: PathBuf,
        metadata_database: Arc<ConnectionThreadSafe>,
        manager: NativeStoreLeaseManager,
        store_path: NativeStorePath,
    }

    impl LeaseFixture {
        fn new(maximum_active: usize) -> Self {
            let directory = tempfile::tempdir().expect("lease test root should be created");
            let store_dir = directory.path().join("store");
            let state_dir = directory.path().join("state");
            let roots_dir = state_dir.join("gcroots/auto/narjar");
            fs::create_dir_all(&store_dir).expect("store directory should be created");
            fs::create_dir_all(&state_dir).expect("state directory should be created");
            fs::create_dir_all(&roots_dir).expect("roots directory should be created");
            File::create(state_dir.join("gc.lock")).expect("Nix GC lock should be created");
            let database_directory = state_dir.join("db");
            fs::create_dir_all(&database_directory).expect("Nix database directory should exist");
            let database_path = database_directory.join("db.sqlite");
            let setup_database =
                Connection::open(&database_path).expect("fixture Nix database should open");
            setup_database
                .execute("CREATE TABLE ValidPaths (path TEXT PRIMARY KEY)")
                .expect("ValidPaths fixture table should be created");
            let store_path = store_dir.join(format!("{}-test-package", "0".repeat(32)));
            fs::create_dir(&store_path).expect("store object should be created");
            setup_database
                .prepare("INSERT INTO ValidPaths (path) VALUES (?)")
                .and_then(|mut statement| {
                    statement.bind((1, store_path.to_string_lossy().as_ref()))?;
                    statement.next().map(|_| ())
                })
                .expect("fixture store path should be registered");
            drop(setup_database);
            let metadata_database = Arc::new(
                Connection::open_thread_safe_with_flags(
                    &database_path,
                    sqlite::OpenFlags::new().with_read_only(),
                )
                .expect("read-only fixture database should open"),
            );
            let manager = NativeStoreLeaseManager::open(
                store_dir.clone(),
                state_dir.clone(),
                roots_dir.clone(),
                NonZeroU64::new(3_600).expect("lease period should be nonzero"),
                NonZeroUsize::new(maximum_active).expect("capacity should be nonzero"),
                Arc::clone(&metadata_database),
            )
            .expect("lease manager should open");
            let store_path = manager
                .validate_store_path(&store_path)
                .expect("fixture store path should validate");
            Self {
                _directory: directory,
                store_dir,
                state_dir,
                roots_dir,
                database_path,
                metadata_database,
                manager,
                store_path,
            }
        }

        fn reopen(&self, maximum_active: usize) -> NativeStoreLeaseManager {
            NativeStoreLeaseManager::open(
                self.store_dir.clone(),
                self.state_dir.clone(),
                self.roots_dir.clone(),
                NonZeroU64::new(3_600).expect("lease period should be nonzero"),
                NonZeroUsize::new(maximum_active).expect("capacity should be nonzero"),
                Arc::clone(&self.metadata_database),
            )
            .expect("lease manager should recover")
        }

        fn reopen_at(&self, maximum_active: usize, now: u64) -> NativeStoreLeaseManager {
            NativeStoreLeaseManager::open_at(
                self.store_dir.clone(),
                self.state_dir.clone(),
                self.roots_dir.clone(),
                NonZeroU64::new(3_600).expect("lease period should be nonzero"),
                NonZeroUsize::new(maximum_active).expect("capacity should be nonzero"),
                Arc::clone(&self.metadata_database),
                now,
            )
            .expect("lease manager should recover at the supplied time")
        }

        fn owned_records(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.roots_dir)
                .expect("roots should be readable")
                .filter_map(Result::ok)
                .map(|entry| entry.path().join(RECORD_FILE))
                .filter(|path| path.exists())
                .collect()
        }

        fn write_record(&self, path: &Path, record: &LeaseRecord) {
            fs::create_dir_all(path.parent().expect("record has lease directory"))
                .expect("lease directory should be created");
            write_record_atomically(&self.roots_dir, path, record)
                .expect("test lease record should be durable");
        }

        fn register_path(&self, path: &Path) {
            let database = Connection::open(&self.database_path)
                .expect("writable fixture database should open");
            let mut statement = database
                .prepare("INSERT INTO ValidPaths (path) VALUES (?)")
                .expect("ValidPaths insert should prepare");
            statement
                .bind((1, path.to_string_lossy().as_ref()))
                .expect("store path should bind");
            assert_eq!(
                statement.next().expect("store path should insert"),
                State::Done
            );
        }
    }

    #[test]
    fn acquisition_publishes_owned_root_and_renewal_keeps_one_record() {
        let fixture = LeaseFixture::new(2);
        let now = now_unix_seconds().expect("clock should be available");
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");
        let root = fixture.manager.root_path(&fixture.store_path);
        let first_expiry = lease.expires_at_unix_seconds();

        assert_eq!(
            fs::read_link(&root).expect("root should be a symlink"),
            fixture.store_path.as_path()
        );
        assert_eq!(fixture.owned_records().len(), 1);
        assert_eq!(fixture.manager.snapshot().expect("snapshot").active, 1);

        let renewed = fixture
            .manager
            .acquire(fixture.store_path.clone(), now + 10)
            .expect("existing lease should renew");
        assert!(renewed.expires_at_unix_seconds() > first_expiry);
        assert_eq!(fixture.owned_records().len(), 1);
        assert_eq!(fixture.manager.snapshot().expect("snapshot").active, 1);
    }

    #[test]
    fn renewal_never_shortens_a_live_lease_when_the_clock_moves_backward() {
        let fixture = LeaseFixture::new(1);
        let now = now_unix_seconds().expect("clock should be available");
        let first_lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");
        let previous_expiry = first_lease.expires_at_unix_seconds();

        let renewed_lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now - 1)
            .expect("lease should renew despite a backward clock step");

        assert_eq!(renewed_lease.expires_at_unix_seconds(), previous_expiry);
    }

    #[test]
    fn restart_recovers_live_root_and_rejects_release_before_expiry() {
        let fixture = LeaseFixture::new(2);
        let now = now_unix_seconds().expect("clock should be available");
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");
        let manager = fixture.reopen(2);

        assert_eq!(manager.snapshot().expect("snapshot").active, 1);
        assert!(matches!(
            manager.release(&lease, now + 1),
            Err(NativeStoreLeaseError::LeaseStillLive)
        ));
        manager
            .release(&lease, lease.expires_at_unix_seconds())
            .expect("expired lease should release");
        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert!(fixture.owned_records().is_empty());
        assert_eq!(manager.snapshot().expect("snapshot").active, 0);
    }

    #[test]
    fn concurrent_acquisitions_coalesce_one_path_without_shortening_expiry() {
        let fixture = LeaseFixture::new(2);
        let manager = Arc::new(fixture.manager);
        let path = Arc::new(fixture.store_path);
        let barrier = Arc::new(Barrier::new(8));
        let now = now_unix_seconds().expect("clock should be available");
        let leases = thread::scope(|scope| {
            (0..8)
                .map(|_| {
                    let manager = Arc::clone(&manager);
                    let path = Arc::clone(&path);
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        manager
                            .acquire((*path).clone(), now)
                            .expect("same-path lease")
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|worker| worker.join().expect("lease worker should finish"))
                .collect::<Vec<_>>()
        });

        assert!(leases.iter().all(|lease| lease.expires_at_unix_seconds() == leases[0].expires_at_unix_seconds()));
        assert_eq!(manager.snapshot().expect("snapshot").active, 1);
    }

    #[test]
    fn capacity_rejection_does_not_create_root_or_record() {
        let fixture = LeaseFixture::new(1);
        let second_path = fixture.store_dir.join(format!("{}-second", "1".repeat(32)));
        fs::create_dir(&second_path).expect("second object should be created");
        fixture.register_path(&second_path);
        let second_path = fixture
            .manager
            .validate_store_path(&second_path)
            .expect("second store path should validate");
        let now = now_unix_seconds().expect("clock should be available");
        fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("first lease should be acquired");

        assert!(matches!(
            fixture.manager.acquire(second_path.clone(), now),
            Err(NativeStoreLeaseError::CapacityExceeded)
        ));
        assert!(!fixture.manager.root_path(&second_path).exists());
        assert_eq!(fixture.owned_records().len(), 1);
        let snapshot = fixture.manager.snapshot().expect("snapshot");
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.capacity_rejections, 1);
    }

    #[test]
    fn separate_managers_share_the_durable_capacity_limit() {
        let fixture = LeaseFixture::new(1);
        let other_manager = fixture.reopen(1);
        let second_path = fixture.store_dir.join(format!("{}-second", "1".repeat(32)));
        fs::create_dir(&second_path).expect("second store object should be created");
        fixture.register_path(&second_path);
        let second_path = other_manager
            .validate_store_path(&second_path)
            .expect("second store path should validate");
        let now = now_unix_seconds().expect("clock should be available");

        fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("first manager should consume the only slot");
        assert!(matches!(
            other_manager.acquire(second_path.clone(), now),
            Err(NativeStoreLeaseError::CapacityExceeded)
        ));
        assert_eq!(other_manager.snapshot().expect("shared snapshot").active, 1);
        assert!(!other_manager.root_path(&second_path).exists());
    }

    #[test]
    fn already_open_manager_discovers_leases_created_by_another_manager() {
        let fixture = LeaseFixture::new(2);
        let other_manager = fixture.reopen(2);
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), 10)
            .expect("first manager creates the lease after the second opens");
        assert_eq!(
            other_manager.snapshot().expect("read-only snapshot").active,
            1
        );

        other_manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("other manager refreshes paths after the durable generation changes");

        assert!(fixture.owned_records().is_empty());
        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert_eq!(other_manager.snapshot().expect("shared capacity").active, 0);
    }

    #[test]
    fn acquisition_rejects_an_existing_store_object_absent_from_valid_paths() {
        let fixture = LeaseFixture::new(1);
        let unregistered_path = fixture
            .store_dir
            .join(format!("{}-unregistered", "1".repeat(32)));
        fs::create_dir(&unregistered_path).expect("unregistered store object should exist");
        let unregistered_path = fixture
            .manager
            .validate_store_path(&unregistered_path)
            .expect("filesystem path syntax should be valid");

        assert!(matches!(
            fixture.manager.acquire(unregistered_path.clone(), 1),
            Err(NativeStoreLeaseError::UnregisteredStorePath)
        ));
        assert_eq!(fixture.manager.snapshot().expect("snapshot").active, 0);
        assert!(!fixture.manager.root_path(&unregistered_path).exists());
        assert!(fixture.owned_records().is_empty());
    }

    #[test]
    fn already_open_manager_recovers_capacity_crashes_before_and_after_pending_record() {
        [false, true].into_iter().for_each(|pending_sidecar| {
            let fixture = LeaseFixture::new(1);
            let surviving_manager = fixture.reopen(1);
            let reservation_path = &fixture.store_path;
            let mutation = CapacityMutation {
                kind: CapacityMutationKind::Acquire,
                store_basename: reservation_path
                    .as_path()
                    .file_name()
                    .expect("store basename")
                    .to_string_lossy()
                    .into_owned(),
                previous_active: 0,
            };
            if pending_sidecar {
                let paths = LeasePaths {
                    directory: fixture.manager.lease_directory(reservation_path),
                    record: fixture.manager.record_path(reservation_path),
                    root: fixture.manager.root_path(reservation_path),
                };
                fs::create_dir(&paths.directory).expect("pending lease directory should exist");
                write_record_atomically(
                    &fixture.roots_dir,
                    &paths.record,
                    &LeaseRecord::pending(reservation_path, 10),
                )
                .expect("pending lease record should be durable");
            }
            write_capacity_record(
                &fixture.roots_dir,
                CapacityRecord {
                    generation: 1,
                    active: 0,
                    pending: Some(mutation),
                },
            )
            .expect("interrupted reservation should be durable");

            let next_path = fixture.store_dir.join(format!("{}-next", "1".repeat(32)));
            fs::create_dir(&next_path).expect("next registered store object should exist");
            fixture.register_path(&next_path);
            let next_path = surviving_manager
                .validate_store_path(&next_path)
                .expect("next path should validate");

            surviving_manager
                .acquire(next_path, 20)
                .expect("surviving manager should repair interrupted capacity first");

            assert_eq!(surviving_manager.snapshot().expect("snapshot").active, 1);
            assert!(!fixture.manager.root_path(reservation_path).exists());
            assert_eq!(fixture.owned_records().len(), 1);
        });
    }

    #[test]
    fn recovery_deletion_is_journaled_for_already_open_managers() {
        let fixture = LeaseFixture::new(1);
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), 1)
            .expect("initial lease should be acquired");
        let surviving_manager = fixture.reopen_at(1, 2);
        let record_path = fixture.manager.record_path(&fixture.store_path);
        let lease_directory = fixture.manager.lease_directory(&fixture.store_path);
        fail_nth_directory_sync(&fixture.roots_dir, 2);

        assert!(
            NativeStoreLeaseManager::open_at(
                fixture.store_dir.clone(),
                fixture.state_dir.clone(),
                fixture.roots_dir.clone(),
                NonZeroU64::new(3_600).expect("lease period should be nonzero"),
                NonZeroUsize::new(1).expect("capacity should be nonzero"),
                Arc::clone(&fixture.metadata_database),
                lease.expires_at_unix_seconds() + 1,
            )
            .is_err()
        );
        assert!(!record_path.exists());

        assert!(matches!(
            surviving_manager.acquire(
                fixture.store_path.clone(),
                lease.expires_at_unix_seconds() + 1
            ),
            Err(NativeStoreLeaseError::RecoveryRequired)
        ));
        surviving_manager
            .recover(lease.expires_at_unix_seconds() + 1)
            .expect("explicit recovery should finish the interrupted reconciliation");
        assert_eq!(
            surviving_manager
                .snapshot()
                .expect("surviving manager should report reconciled capacity")
                .active,
            0
        );
        assert!(!record_path.exists());
        assert!(!lease_directory.exists());
    }

    #[test]
    fn interrupted_root_recovery_syncs_an_already_existing_root_before_clearing_capacity() {
        assert_interrupted_root_recovery_retries_directory_sync(CapacityMutationKind::Acquire, 0);
    }

    #[test]
    fn interrupted_release_recovery_syncs_an_existing_root_before_clearing_capacity() {
        assert_interrupted_root_recovery_retries_directory_sync(
            CapacityMutationKind::ReleaseLive,
            1,
        );
    }

    #[test]
    fn pending_acquisition_for_a_missing_registered_store_object_is_recovered() {
        assert_missing_registered_store_object_releases_pending_lease(
            CapacityMutationKind::Acquire,
            0,
        );
    }

    #[test]
    fn pending_release_for_a_missing_registered_store_object_is_recovered() {
        assert_missing_registered_store_object_releases_pending_lease(
            CapacityMutationKind::ReleaseLive,
            1,
        );
    }

    fn assert_missing_registered_store_object_releases_pending_lease(
        mutation_kind: CapacityMutationKind,
        previous_active: u64,
    ) {
        let fixture = LeaseFixture::new(1);
        let root_path = fixture.manager.root_path(&fixture.store_path);
        let record_path = fixture.manager.record_path(&fixture.store_path);
        let lease_directory = fixture.manager.lease_directory(&fixture.store_path);
        fixture.write_record(
            &record_path,
            &LeaseRecord::live(&fixture.store_path, u64::MAX),
        );
        std::os::unix::fs::symlink(fixture.store_path.as_path(), &root_path)
            .expect("owned root should be created before the store object disappears");
        write_capacity_record(
            &fixture.roots_dir,
            CapacityRecord {
                generation: 1,
                active: previous_active,
                pending: Some(CapacityMutation {
                    kind: mutation_kind,
                    store_basename: fixture.store_path.basename.clone(),
                    previous_active,
                }),
            },
        )
        .expect("interrupted capacity mutation should be durable");
        fs::remove_dir(fixture.store_path.as_path())
            .expect("store object should disappear while still registered");

        let recovered_manager = fixture.reopen_at(1, 1);

        assert_eq!(
            recovered_manager
                .snapshot()
                .expect("recovered capacity")
                .active,
            0
        );
        assert!(!root_path.is_symlink());
        assert!(!record_path.exists());
        assert!(!lease_directory.exists());
    }

    fn assert_interrupted_root_recovery_retries_directory_sync(
        mutation_kind: CapacityMutationKind,
        previous_active: u64,
    ) {
        let fixture = LeaseFixture::new(1);
        let record_path = fixture.manager.record_path(&fixture.store_path);
        let lease_directory = fixture.manager.lease_directory(&fixture.store_path);
        fixture.write_record(
            &record_path,
            &LeaseRecord::live(&fixture.store_path, u64::MAX),
        );
        write_capacity_record(
            &fixture.roots_dir,
            CapacityRecord {
                generation: 1,
                active: previous_active,
                pending: Some(CapacityMutation {
                    kind: mutation_kind,
                    store_basename: fixture.store_path.basename.clone(),
                    previous_active,
                }),
            },
        )
        .expect("interrupted capacity mutation should be durable");
        fail_nth_directory_sync(&lease_directory, 1);

        assert!(matches!(
            fixture.manager.snapshot(),
            Err(NativeStoreLeaseError::Io(_))
        ));
        assert!(fixture.manager.root_path(&fixture.store_path).is_symlink());

        fail_nth_directory_sync(&lease_directory, 1);
        assert!(matches!(
            fixture.manager.snapshot(),
            Err(NativeStoreLeaseError::Io(_))
        ));
        assert!(
            read_capacity_record(&fixture.roots_dir)
                .expect("pending capacity should remain readable")
                .pending
                .is_some(),
            "recovery must not clear the mutation before syncing the existing root"
        );

        assert_eq!(
            fixture.manager.snapshot().expect("recovery retry").active,
            1
        );
    }

    #[test]
    fn clock_failure_during_acquire_recovery_preserves_unrelated_live_roots() {
        let fixture = LeaseFixture::new(2);
        fixture
            .manager
            .acquire(fixture.store_path.clone(), 10)
            .expect("unrelated live lease should be acquired");
        let other_path = fixture.store_dir.join(format!("{}-other", "1".repeat(32)));
        fs::create_dir(&other_path).expect("second store object should exist");
        fixture.register_path(&other_path);
        let other_path = fixture
            .manager
            .validate_store_path(&other_path)
            .expect("second store path should validate");
        let mut clock_calls = 0;
        let mut clock = || {
            clock_calls += 1;
            match clock_calls {
                1 | 2 => Ok(10),
                _ => Err(NativeStoreLeaseError::ClockBeforeEpoch),
            }
        };

        assert!(matches!(
            fixture.manager.acquire_with_clock(other_path, &mut clock),
            Err(NativeStoreLeaseError::ClockBeforeEpoch)
        ));
        assert!(fixture.manager.root_path(&fixture.store_path).is_symlink());
        assert_eq!(
            read_required_record(
                &fixture.manager.record_path(&fixture.store_path),
                &fixture.store_dir
            )
            .expect("unrelated live lease should remain valid")
            .state,
            PersistedLeaseState::Live
        );
    }

    #[test]
    fn acquire_reclaims_an_expired_lease_created_by_another_manager() {
        let fixture = LeaseFixture::new(1);
        let next_path = fixture.store_dir.join(format!("{}-next", "1".repeat(32)));
        fs::create_dir(&next_path).expect("next store object should exist");
        fixture.register_path(&next_path);
        let next_path = fixture
            .manager
            .validate_store_path(&next_path)
            .expect("next store path should validate");
        let stale_manager = fixture.reopen_at(1, 1);

        fixture
            .manager
            .acquire(fixture.store_path.clone(), 1)
            .expect("first manager should create the expiring lease");
        stale_manager
            .acquire(next_path, 4_000)
            .expect("acquisition should scan stale paths and reclaim the expired lease");

        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert_eq!(
            stale_manager.snapshot().expect("one active lease").active,
            1
        );
    }

    #[test]
    fn incremental_scan_skips_a_lease_deleted_by_another_manager() {
        let fixture = LeaseFixture::new(100);
        let seeded_paths = (0..MAX_EXPIRY_CLEANUP_PER_CALL + 6)
            .map(|index| {
                let hash_digit = NIX32
                    .chars()
                    .nth(index % NIX32.len())
                    .expect("hash digit should be in the Nix32 alphabet");
                let path = fixture.store_dir.join(format!(
                    "{}{}-seed-{index}",
                    "0".repeat(31),
                    hash_digit
                ));
                fs::create_dir(&path).expect("seeded store path should exist");
                fixture.register_path(&path);
                let path = NativeStorePath::parse(&fixture.store_dir, &path)
                    .expect("seeded store path should parse");
                let record_path = fixture.manager.record_path(&path);
                fixture.write_record(&record_path, &LeaseRecord::live(&path, 10));
                std::os::unix::fs::symlink(path.as_path(), fixture.manager.root_path(&path))
                    .expect("seeded lease root should exist");
                path
            })
            .collect::<Vec<_>>();
        write_capacity_record(
            &fixture.roots_dir,
            CapacityRecord {
                generation: 1,
                active: seeded_paths.len() as u64,
                pending: None,
            },
        )
        .expect("seeded leases should be reflected in capacity");
        let scanning_manager = fixture.reopen_at(100, 1);
        let deleting_manager = fixture.reopen_at(100, 1);
        let retry_path = fixture.store_dir.join(format!("{}-retry", "2".repeat(32)));
        fs::create_dir(&retry_path).expect("retry store path should exist");
        fixture.register_path(&retry_path);
        let retry_path = scanning_manager
            .validate_store_path(&retry_path)
            .expect("retry store path should validate");

        deleting_manager
            .acquire(fixture.store_path.clone(), 1)
            .expect("second manager should advance the record generation");
        let record_to_delete = fs::read_dir(&fixture.roots_dir)
            .expect("roots should be readable")
            .enumerate()
            .skip(MAX_EXPIRY_CLEANUP_PER_CALL)
            .filter_map(|(_, entry)| entry.ok())
            .filter_map(|entry| record_path_from_directory_entry(entry).ok().flatten())
            .find(|record_path| {
                seeded_paths
                    .iter()
                    .any(|path| deleting_manager.record_path(path) == *record_path)
            })
            .expect("a seeded record should be beyond the first bounded directory batch");
        let path_to_delete = seeded_paths
            .iter()
            .find(|path| deleting_manager.record_path(path) == record_to_delete)
            .expect("selected record should correspond to a seeded path")
            .clone();

        scanning_manager
            .acquire(retry_path.clone(), 2)
            .expect("first scan batch should finish acquisition");
        let lease_to_delete = NativeStoreLease {
            record_path: deleting_manager.record_path(&path_to_delete),
            path: path_to_delete,
            expires_at: 10,
            state: Arc::clone(&deleting_manager.state),
        };
        deleting_manager
            .release(&lease_to_delete, 20)
            .expect("second manager should delete the expired record");
        scanning_manager
            .acquire(retry_path, 21)
            .expect("stale directory entries should be skipped rather than failing admission");
    }

    #[test]
    fn stale_record_index_scans_at_most_one_bounded_batch_per_refresh() {
        let fixture = LeaseFixture::new(1);
        (0..3).for_each(|index| {
            let directory = fixture
                .roots_dir
                .join(format!("{LEASE_PREFIX}{index:064x}"));
            fs::create_dir(&directory).expect("lease directory should be created");
            File::create(directory.join(RECORD_FILE)).expect("lease record should be created");
        });
        let mut entries = fs::read_dir(&fixture.roots_dir).expect("roots directory should open");
        let batches = (0..8)
            .map(|_| read_record_path_batch(&mut entries, 1).expect("one batch should read"))
            .collect::<Vec<_>>();

        assert!(batches.iter().all(|(paths, _)| paths.len() <= 1));
        assert_eq!(
            batches.iter().map(|(paths, _)| paths.len()).sum::<usize>(),
            3
        );
        assert!(batches.iter().any(|(_, complete)| *complete));
    }

    #[test]
    fn manager_churn_does_not_restart_expiry_cleanup_before_its_cursor() {
        let fixture = LeaseFixture::new(200);
        let paths = (0..MAX_EXPIRY_CLEANUP_PER_CALL * 2 + 2)
            .map(|index| {
                let path = fixture
                    .store_dir
                    .join(format!("{}-expired-{index}", "0".repeat(32)));
                fs::create_dir(&path).expect("registered store object should exist");
                fixture.register_path(&path);
                let path = NativeStorePath::parse(&fixture.store_dir, &path)
                    .expect("store path should parse");
                let record_path = fixture.manager.record_path(&path);
                fixture.write_record(&record_path, &LeaseRecord::live(&path, 10_000));
                std::os::unix::fs::symlink(path.as_path(), fixture.manager.root_path(&path))
                    .expect("live GC root should exist");
                path
            })
            .collect::<Vec<_>>();
        write_capacity_record(
            &fixture.roots_dir,
            CapacityRecord {
                generation: 1,
                active: paths.len() as u64,
                pending: None,
            },
        )
        .expect("seeded leases should be reflected in capacity");
        let other_manager = fixture.reopen_at(200, 1);
        let mut ordered_record_paths = paths
            .iter()
            .map(|path| other_manager.record_path(path))
            .collect::<Vec<_>>();
        ordered_record_paths.sort();
        let later_expired_record = ordered_record_paths[MAX_EXPIRY_CLEANUP_PER_CALL + 6].clone();

        other_manager
            .cleanup_expired_at(10_001)
            .expect("first bounded expiry batch should advance the cursor");
        assert!(later_expired_record.exists());

        let externally_added_path = fixture
            .store_dir
            .join(format!("{}-external", "1".repeat(32)));
        fs::create_dir(&externally_added_path).expect("external store object should exist");
        fixture.register_path(&externally_added_path);
        let externally_added_path = fixture
            .manager
            .validate_store_path(&externally_added_path)
            .expect("external path should validate");
        fixture
            .manager
            .acquire(externally_added_path, 10_001)
            .expect("other manager should advance the durable generation");

        other_manager
            .cleanup_expired_at(10_001)
            .expect("refresh after manager churn should continue from the old cursor");

        assert!(
            !later_expired_record.exists(),
            "the next expired batch should not restart at the first record"
        );
    }

    #[test]
    fn lease_expiry_uses_the_clock_after_waiting_for_the_nix_gc_lock() {
        let fixture = LeaseFixture::new(1);
        let mut times = [5, 10, 100].into_iter();
        let mut clock = || Ok(times.next().expect("each lease phase reads the clock"));

        let lease = fixture
            .manager
            .acquire_with_clock(fixture.store_path.clone(), &mut clock)
            .expect("lease should be acquired");

        assert_eq!(lease.expires_at_unix_seconds(), 100 + 3_600);
    }

    #[test]
    fn post_rename_sync_failure_rebuilds_capacity_from_the_committed_live_record() {
        let fixture = LeaseFixture::new(1);
        let lease_directory = fixture.manager.lease_directory(&fixture.store_path);
        fail_nth_directory_sync(&lease_directory, 3);
        let now = now_unix_seconds().expect("clock should be available");

        let error = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect_err("sync failure after committed record must be reported");

        assert!(matches!(error, NativeStoreLeaseError::Io(_)));
        assert!(fixture.manager.root_path(&fixture.store_path).is_symlink());
        assert_eq!(
            fixture.manager.snapshot().expect("recovered count").active,
            1
        );
    }

    #[test]
    fn capacity_write_sync_failure_is_reconciled_before_returning() {
        let fixture = LeaseFixture::new(1);
        fail_nth_directory_sync(&fixture.roots_dir, 1);

        let error = fixture
            .manager
            .acquire(fixture.store_path.clone(), 10)
            .expect_err("capacity metadata sync failure should abort acquisition");

        assert!(matches!(error, NativeStoreLeaseError::Io(_)));
        assert_eq!(
            fixture
                .manager
                .snapshot()
                .expect("reconciled capacity")
                .active,
            0
        );
        assert!(fixture.owned_records().is_empty());
        fixture
            .manager
            .acquire(fixture.store_path.clone(), 10)
            .expect("a failed reservation must not strand a capacity slot");
    }

    #[test]
    fn recovery_preserves_foreign_root_and_discards_its_pending_record() {
        let fixture = LeaseFixture::new(2);
        let foreign_path = fixture
            .store_dir
            .join(format!("{}-foreign", "1".repeat(32)));
        fs::create_dir(&foreign_path).expect("foreign fixture object should be created");
        let root = fixture.manager.root_path(&fixture.store_path);
        fs::create_dir_all(root.parent().expect("root lease directory"))
            .expect("lease directory should be created");
        std::os::unix::fs::symlink(&foreign_path, &root).expect("foreign root should be installed");
        let now = now_unix_seconds().expect("clock should be available");

        assert!(matches!(
            fixture.manager.acquire(fixture.store_path.clone(), now),
            Err(NativeStoreLeaseError::RootConflict)
        ));
        fixture
            .manager
            .recover(now)
            .expect("pending recovery should be safe");

        assert_eq!(
            fs::read_link(&root).expect("foreign root remains"),
            foreign_path
        );
        assert!(fixture.owned_records().is_empty());
    }

    #[test]
    fn initial_acquisition_never_adopts_a_matching_foreign_root() {
        let fixture = LeaseFixture::new(1);
        let root = fixture.manager.root_path(&fixture.store_path);
        fs::create_dir_all(root.parent().expect("root lease directory"))
            .expect("foreign lease directory should be created");
        std::os::unix::fs::symlink(fixture.store_path.as_path(), &root)
            .expect("foreign matching root should be installed");
        let now = now_unix_seconds().expect("clock should be available");

        assert!(matches!(
            fixture.manager.acquire(fixture.store_path.clone(), now),
            Err(NativeStoreLeaseError::RootConflict)
        ));
        fixture
            .manager
            .recover(now)
            .expect("pending record can be removed without claiming the root");

        assert_eq!(
            fs::read_link(&root).expect("foreign root remains"),
            fixture.store_path.as_path()
        );
        assert!(fixture.owned_records().is_empty());
        assert_eq!(
            fixture
                .manager
                .snapshot()
                .expect("capacity snapshot")
                .active,
            0
        );
    }

    #[test]
    fn malformed_or_symlinked_sidecars_fail_closed() {
        let fixture = LeaseFixture::new(1);
        let record_path = fixture.manager.record_path(&fixture.store_path);
        let target = fixture.roots_dir.join("not-a-record");
        fs::write(&target, b"not a lease record").expect("sidecar target should be written");
        fs::create_dir_all(record_path.parent().expect("record lease directory"))
            .expect("lease directory should be created");
        std::os::unix::fs::symlink(&target, &record_path)
            .expect("sidecar symlink should be created");

        assert!(matches!(
            NativeStoreLeaseManager::open(
                fixture.store_dir.clone(),
                fixture.state_dir.clone(),
                fixture.roots_dir.clone(),
                NonZeroU64::new(3_600).expect("lease period should be nonzero"),
                NonZeroUsize::new(1).expect("capacity should be nonzero"),
                Arc::clone(&fixture.metadata_database),
            ),
            Err(NativeStoreLeaseError::InvalidRecord)
        ));
    }

    #[test]
    fn recovery_rejects_a_record_stored_under_another_paths_filename() {
        let fixture = LeaseFixture::new(1);
        let wrong_record_path = fixture
            .roots_dir
            .join(format!("{LEASE_PREFIX}{}", "f".repeat(64)))
            .join(RECORD_FILE);
        fixture.write_record(
            &wrong_record_path,
            &LeaseRecord::pending(&fixture.store_path, u64::MAX),
        );

        assert!(matches!(
            NativeStoreLeaseManager::open_at(
                fixture.store_dir.clone(),
                fixture.state_dir.clone(),
                fixture.roots_dir.clone(),
                NonZeroU64::new(3_600).expect("lease period should be nonzero"),
                NonZeroUsize::new(1).expect("capacity should be nonzero"),
                Arc::clone(&fixture.metadata_database),
                1,
            ),
            Err(NativeStoreLeaseError::InvalidRecord)
        ));
        assert!(wrong_record_path.exists());
    }

    #[test]
    fn root_and_record_names_remain_bounded_for_long_store_names() {
        let fixture = LeaseFixture::new(1);
        let store_path = fixture
            .store_dir
            .join(format!("{}-{}", "2".repeat(32), "n".repeat(200)));
        fs::create_dir(&store_path).expect("long-named object should be created");
        fixture.register_path(&store_path);
        let store_path = fixture
            .manager
            .validate_store_path(&store_path)
            .expect("long store path should validate");

        fixture
            .manager
            .acquire(
                store_path.clone(),
                now_unix_seconds().expect("clock should be available"),
            )
            .expect("bounded root filename should be created");

        assert!(fixture.manager.root_path(&store_path).is_symlink());
        assert_eq!(
            fixture
                .manager
                .root_path(&store_path)
                .file_name()
                .unwrap()
                .len(),
            ROOT_FILE.len()
        );
    }

    #[test]
    fn lease_accepts_a_store_path_whose_nix_object_is_a_symlink() {
        let fixture = LeaseFixture::new(1);
        let target = fixture.store_dir.join(format!("{}-target", "1".repeat(32)));
        fs::create_dir(&target).expect("symlink target object should be created");
        let store_path = fixture
            .store_dir
            .join(format!("{}-symlink", "2".repeat(32)));
        std::os::unix::fs::symlink(&target, &store_path)
            .expect("store path symlink should be created");
        fixture.register_path(&store_path);
        let store_path = fixture
            .manager
            .validate_store_path(&store_path)
            .expect("Nix store symlink should be a valid object path");

        fixture
            .manager
            .acquire(
                store_path.clone(),
                now_unix_seconds().expect("clock should be available"),
            )
            .expect("symlink object should be rooted");

        assert_eq!(
            fs::read_link(fixture.manager.root_path(&store_path)).expect("GC root target"),
            store_path.as_path()
        );
    }

    #[test]
    fn recovery_removes_at_most_one_bounded_batch_of_pending_records() {
        let fixture = LeaseFixture::new(65);
        (0..MAX_EXPIRY_CLEANUP_PER_CALL + 1).for_each(|index| {
            let hash_character = NIX32
                .chars()
                .nth(index % NIX32.len())
                .expect("index is limited to the Nix32 alphabet");
            let path = fixture.store_dir.join(format!(
                "{}{}-pending-{index}",
                "0".repeat(31),
                hash_character
            ));
            fs::create_dir(&path).expect("pending object should be created");
            let path = fixture
                .manager
                .validate_store_path(&path)
                .expect("pending path should validate");
            fixture.write_record(
                &fixture.manager.record_path(&path),
                &LeaseRecord::pending(&path, u64::MAX),
            );
        });

        let manager = fixture.reopen_at(65, 1);

        assert_eq!(fixture.owned_records().len(), 1);
        manager
            .recover(1)
            .expect("next bounded cleanup batch should run");
        assert!(fixture.owned_records().is_empty());
    }

    #[test]
    fn recovery_does_not_remove_missing_store_objects_past_its_cleanup_budget() {
        let fixture = LeaseFixture::new(65);
        (0..MAX_EXPIRY_CLEANUP_PER_CALL + 1).for_each(|index| {
            let hash_character = NIX32
                .chars()
                .nth(index % NIX32.len())
                .expect("index is limited to the Nix32 alphabet");
            let path = fixture.store_dir.join(format!(
                "{}{}-missing-{index}",
                "0".repeat(31),
                hash_character
            ));
            let path = NativeStorePath::parse(&fixture.store_dir, &path)
                .expect("missing store path still has valid Nix identity");
            fixture.register_path(path.as_path());
            let record_path = fixture.manager.record_path(&path);
            fixture.write_record(&record_path, &LeaseRecord::live(&path, 100));
            std::os::unix::fs::symlink(path.as_path(), fixture.manager.root_path(&path))
                .expect("dangling GC root should model a collected store object");
        });

        let manager = fixture.reopen_at(65, 1);

        assert_eq!(fixture.owned_records().len(), 1);
        assert_eq!(manager.snapshot().expect("one deferred record").active, 1);
        manager
            .recover(1)
            .expect("next batch removes the remaining record");
        assert!(fixture.owned_records().is_empty());
        assert_eq!(manager.snapshot().expect("all records removed").active, 0);
    }

    #[test]
    fn bounded_expiry_cleanup_does_not_release_slots_twice() {
        let fixture = LeaseFixture::new(1);
        let live_paths = (0..MAX_EXPIRY_CLEANUP_PER_CALL * 3 + 1)
            .map(|index| {
                let path = fixture.store_dir.join(format!(
                    "{}{}-expired-{index}",
                    "0".repeat(31),
                    NIX32.chars().nth(index % NIX32.len()).expect("hash digit")
                ));
                fs::create_dir(&path).expect("expired store object should be created");
                fixture.register_path(&path);
                let path = fixture
                    .manager
                    .validate_store_path(&path)
                    .expect("store path");
                let record_path = fixture.manager.record_path(&path);
                let root_path = fixture.manager.root_path(&path);
                let expired = LeaseRecord::live(&path, 2);
                fixture.write_record(&record_path, &expired);
                std::os::unix::fs::symlink(path.as_path(), root_path)
                    .expect("expired root should be installed");
                path
            })
            .collect::<Vec<_>>();
        let manager = fixture.reopen_at(1, 3);

        assert_eq!(manager.snapshot().expect("recovered count").active, 129);
        manager
            .cleanup_expired_at(3)
            .expect("first bounded cleanup should finish");
        assert_eq!(manager.snapshot().expect("remaining count").active, 65);
        let new_path = fixture.store_dir.join(format!("{}-new", "3".repeat(32)));
        fs::create_dir(&new_path).expect("new store object should be created");
        fixture.register_path(&new_path);
        let new_path = manager
            .validate_store_path(&new_path)
            .expect("new store path");
        assert!(matches!(
            manager.acquire(new_path.clone(), 3),
            Err(NativeStoreLeaseError::CapacityExceeded)
        ));
        manager
            .acquire(new_path.clone(), 3)
            .expect("bounded cleanup frees the remaining expired batch before admission");
        let second_path = fixture.store_dir.join(format!("{}-second", "4".repeat(32)));
        fs::create_dir(&second_path).expect("second store object should be created");
        fixture.register_path(&second_path);
        let second_path = manager
            .validate_store_path(&second_path)
            .expect("second path");
        assert!(matches!(
            manager.acquire(second_path, 3),
            Err(NativeStoreLeaseError::CapacityExceeded)
        ));
        assert_eq!(manager.snapshot().expect("new active lease").active, 1);
        assert_eq!(live_paths.len(), MAX_EXPIRY_CLEANUP_PER_CALL * 3 + 1);
    }

    #[test]
    fn recovery_removes_leftover_temporary_records() {
        let fixture = LeaseFixture::new(1);
        let temporary = tempfile::Builder::new()
            .prefix(LEASE_TEMP_PREFIX)
            .tempfile_in(&fixture.roots_dir)
            .unwrap();
        let (_, path) = temporary.keep().unwrap();
        fs::write(&path, b"incomplete sidecar").expect("interrupted temp should be written");

        fixture.reopen(1);

        assert!(!path.exists());
    }

    #[test]
    fn recovery_removes_expired_root_and_sidecar() {
        let fixture = LeaseFixture::new(1);
        let now = now_unix_seconds().expect("clock should be available");
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");

        let manager = fixture.reopen_at(1, lease.expires_at_unix_seconds());

        assert_eq!(manager.snapshot().expect("snapshot").active, 0);
        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert!(fixture.owned_records().is_empty());
    }

    #[test]
    fn cleanup_expired_releases_the_root_without_waiting_for_restart() {
        let fixture = LeaseFixture::new(1);
        let now = now_unix_seconds().expect("clock should be available");
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");
        fixture
            .manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("expiration cleanup should release it");

        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert!(fixture.owned_records().is_empty());
    }

    #[test]
    fn cleanup_expired_keeps_a_root_with_an_active_native_delivery() {
        let fixture = LeaseFixture::new(1);
        let now = now_unix_seconds().expect("clock should be available");
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");
        let active_delivery = lease
            .begin_active_delivery()
            .expect("active delivery should be recorded");

        fixture
            .manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("expiration cleanup should skip active delivery");

        assert!(fixture.manager.root_path(&fixture.store_path).exists());
        assert_eq!(fixture.owned_records().len(), 1);
        drop(active_delivery);
        fixture
            .manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("expiration cleanup should release inactive delivery");
        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert!(fixture.owned_records().is_empty());
    }

    #[test]
    fn cleaned_up_lease_cannot_start_an_unrooted_delivery() {
        let fixture = LeaseFixture::new(1);
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), 1)
            .expect("lease should be acquired");
        fixture
            .manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("expire the root before delivery starts");
        assert!(!fixture.manager.root_path(&fixture.store_path).exists());

        assert!(lease.begin_active_delivery().is_err());
        let state = fixture.manager.lock_state().expect("lease state");
        assert!(!state.has_active_delivery(&lease.record_path));
        assert_eq!(state.active, 0);
    }

    #[test]
    fn renewing_a_live_lease_not_yet_scanned_registers_it_for_delivery() {
        let fixture = LeaseFixture::new(1);
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), 1)
            .expect("durable live lease");
        let paths = LeasePaths {
            directory: fixture.manager.lease_directory(&fixture.store_path),
            record: fixture.manager.record_path(&fixture.store_path),
            root: fixture.manager.root_path(&fixture.store_path),
        };
        {
            let mut state = fixture.manager.lock_state().expect("lease state");
            // A bounded cross-manager refresh has not reached this live record.
            state.record_paths.remove(&paths.record);
            state.record_index = RecordPathIndex::NeedsRefresh(0);
            fixture
                .manager
                .acquire_existing_or_new_lease(&fixture.store_path, &paths, &mut state, &mut || {
                    Ok(2)
                })
                .expect("renewal does not need the scan to reach the record first");
        }

        let _delivery = lease
            .begin_active_delivery()
            .expect("successful renewal must make the live lease usable for delivery");
    }

    #[test]
    fn activation_rejects_a_missing_or_retargeted_root_without_recording_delivery() {
        for replacement in [None, Some("wrong-store-object")] {
            let fixture = LeaseFixture::new(1);
            let lease = fixture
                .manager
                .acquire(fixture.store_path.clone(), 1)
                .expect("lease should be acquired");
            let root = fixture.manager.root_path(&fixture.store_path);
            fs::remove_file(&root).expect("simulate a missing root");
            if let Some(target) = replacement {
                std::os::unix::fs::symlink(target, &root).expect("simulate a retargeted root");
            }

            let error = lease
                .begin_active_delivery()
                .err()
                .expect("invalid root must reject delivery");
            match replacement {
                None => assert!(matches!(
                    error,
                    NativeStoreLeaseError::Io(ref error) if error.kind() == io::ErrorKind::NotFound
                )),
                Some(_) => assert!(matches!(error, NativeStoreLeaseError::RootConflict)),
            }
            let state = fixture.manager.lock_state().expect("lease state");
            assert!(!state.has_active_delivery(&lease.record_path));
            assert_eq!(
                state.active, 1,
                "rejection must not change lease accounting"
            );
        }
    }

    #[test]
    fn interrupted_reconciliation_keeps_expired_roots_until_active_delivery_finishes() {
        let fixture = LeaseFixture::new(1);
        let lease = fixture
            .manager
            .acquire(fixture.store_path.clone(), 1)
            .expect("lease should be acquired");
        let active_delivery = lease
            .begin_active_delivery()
            .expect("delivery should protect its root");
        fixture
            .manager
            .begin_recovery_reconciliation()
            .expect("simulate an interrupted recovery journal");

        fixture
            .manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("cleanup should finish recovery without removing active delivery");

        assert!(fixture.manager.root_path(&fixture.store_path).exists());
        assert_eq!(fixture.owned_records().len(), 1);
        assert_eq!(
            fixture.manager.snapshot().expect("live root count").active,
            1
        );
        assert!(
            read_capacity_record(&fixture.roots_dir)
                .expect("completed recovery journal")
                .pending
                .is_none()
        );

        drop(active_delivery);
        fixture
            .manager
            .cleanup_expired_at(lease.expires_at_unix_seconds())
            .expect("completed delivery should permit expiry cleanup");
        assert!(!fixture.manager.root_path(&fixture.store_path).exists());
        assert!(fixture.owned_records().is_empty());
        assert_eq!(
            fixture
                .manager
                .snapshot()
                .expect("released root count")
                .active,
            0
        );
    }

    #[test]
    fn recovery_recreates_a_missing_live_root_for_an_existing_store_path() {
        let fixture = LeaseFixture::new(1);
        let now = now_unix_seconds().expect("clock should be available");
        fixture
            .manager
            .acquire(fixture.store_path.clone(), now)
            .expect("lease should be acquired");
        let root = fixture.manager.root_path(&fixture.store_path);
        fs::remove_file(&root).expect("root should be removed to simulate interruption");

        let manager = fixture.reopen(1);

        assert_eq!(
            fs::read_link(&root).expect("root should be recovered"),
            fixture.store_path.as_path()
        );
        assert_eq!(manager.snapshot().expect("snapshot").active, 1);
    }

    #[test]
    fn recovery_removes_expired_record_after_nix_collected_its_store_object() {
        let fixture = LeaseFixture::new(1);
        let record_path = fixture.manager.record_path(&fixture.store_path);
        let root_path = fixture.manager.root_path(&fixture.store_path);
        fixture.write_record(&record_path, &LeaseRecord::live(&fixture.store_path, 2));
        std::os::unix::fs::symlink(fixture.store_path.as_path(), &root_path)
            .expect("GC root should exist before collection");
        fs::remove_dir(fixture.store_path.as_path()).expect("simulate collection of the object");

        let manager = fixture.reopen_at(1, 3);

        assert!(fixture.owned_records().is_empty());
        assert!(!root_path.exists());
        assert_eq!(manager.snapshot().expect("no active leases").active, 0);
    }

    #[test]
    fn nix_gc_lock_uses_a_shared_flock_compatible_with_nix_exclusive_flock() {
        let fixture = LeaseFixture::new(1);
        let gc_lock_path = fixture.state_dir.join("gc.lock");
        let nix_gc_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&gc_lock_path)
            .expect("Nix GC lock should open");
        let narjar_gc_lock = OpenOptions::new()
            .read(true)
            .open(&gc_lock_path)
            .expect("Narjar GC lock should open");
        set_flock_lock(&nix_gc_lock).expect("exclusive Nix-style flock should succeed");
        let blocked = rustix::fs::flock(&narjar_gc_lock, FlockOperation::NonBlockingLockShared)
            .expect_err("exclusive Nix lock must block shared Narjar lock");
        assert_eq!(io::Error::from(blocked).kind(), io::ErrorKind::WouldBlock);
        rustix::fs::flock(&nix_gc_lock, FlockOperation::Unlock)
            .expect("exclusive Nix-style flock should unlock");
        set_flock_lock_with_mode(&narjar_gc_lock, FlockOperation::LockShared)
            .expect("shared Narjar-style flock should succeed after GC unlocks");
    }

    #[test]
    fn startup_rejects_a_nix_state_directory_without_an_openable_gc_lock() {
        let fixture = LeaseFixture::new(1);
        fs::remove_file(fixture.state_dir.join("gc.lock"))
            .expect("GC lock should be removed to simulate bad deployment permissions");

        let error = match NativeStoreLeaseManager::open(
            fixture.store_dir.clone(),
            fixture.state_dir.clone(),
            fixture.roots_dir.clone(),
            NonZeroU64::new(3_600).expect("lease period should be nonzero"),
            NonZeroUsize::new(1).expect("capacity should be nonzero"),
            Arc::clone(&fixture.metadata_database),
        ) {
            Err(error) => error,
            Ok(_) => panic!("startup must validate the lock needed for safe root mutation"),
        };

        assert!(
            matches!(error, NativeStoreLeaseError::Io(ref error) if error.kind() == io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn real_nix_gc_preserves_a_leased_path_then_collects_it_after_release() {
        let Ok(version) = Command::new("nix-store").arg("--version").output() else {
            eprintln!("skipping real Nix GC integration: nix-store is not installed");
            return;
        };
        assert!(version.status.success(), "nix-store must be runnable");

        let directory = tempfile::tempdir().expect("isolated Nix store should be created");
        let source = directory.path().join("store-input");
        fs::write(&source, b"narjar isolated Nix GC integration")
            .expect("store input should be written");
        let store_dir = directory.path().join("nix/store");
        let state_dir = directory.path().join("nix/var/nix");
        let store_url = format!(
            "local?store={}&real={}&state={}",
            store_dir.display(),
            store_dir.display(),
            state_dir.display()
        );
        let added = run_nix_store(
            &store_url,
            &["--add", source.to_str().expect("UTF-8 fixture path")],
        );
        assert!(
            added.status.success(),
            "adding isolated object failed: {}",
            command_stderr(&added)
        );
        let logical_store_path = String::from_utf8(added.stdout)
            .expect("Nix store path should be UTF-8")
            .trim()
            .to_owned();
        let store_path = PathBuf::from(&logical_store_path);
        assert!(
            store_path.starts_with(&store_dir),
            "Nix returned {logical_store_path}, expected under {}",
            store_dir.display()
        );
        assert!(
            store_path.exists(),
            "Nix should create the isolated physical path"
        );

        let roots_dir = state_dir.join("gcroots/auto/narjar");
        fs::create_dir_all(&roots_dir).expect("Narjar GC roots should be created");
        let metadata_database = Arc::new(
            crate::native_store::open_supported_metadata_database(&state_dir)
                .expect("isolated Nix metadata database should validate"),
        );
        let manager = NativeStoreLeaseManager::open(
            store_dir,
            state_dir,
            roots_dir,
            NonZeroU64::new(3_600).expect("lease period should be nonzero"),
            NonZeroUsize::new(1).expect("lease capacity should be nonzero"),
            Arc::clone(&metadata_database),
        )
        .expect("manager should open against isolated Nix store");
        let store_path = manager
            .validate_store_path(Path::new(&store_path))
            .expect("Nix-added store path should validate");
        let now = now_unix_seconds().expect("clock should be available");
        let lease = manager
            .acquire(store_path, now)
            .expect("lease should protect the Nix store path");

        let roots = run_nix_store(&store_url, &["--gc", "--print-roots"]);
        assert!(
            roots.status.success(),
            "listing isolated GC roots failed: {}",
            command_stderr(&roots)
        );
        let roots = String::from_utf8_lossy(&roots.stdout);
        assert!(
            roots.contains(&logical_store_path),
            "Nix did not discover the Narjar root for {logical_store_path}: {roots}"
        );
        let first_gc = run_nix_store(&store_url, &["--gc"]);
        assert!(
            first_gc.status.success(),
            "GC with lease failed: {}",
            command_stderr(&first_gc)
        );
        assert!(
            lease.store_path().as_path().exists(),
            "Nix GC collected a leased path"
        );

        manager
            .release(&lease, lease.expires_at_unix_seconds())
            .expect("expired lease should be released");
        let second_gc = run_nix_store(&store_url, &["--gc"]);
        assert!(
            second_gc.status.success(),
            "GC after release failed: {}",
            command_stderr(&second_gc)
        );
        assert!(
            !lease.store_path().as_path().exists(),
            "Nix GC retained a released path"
        );
    }

    fn run_nix_store(store_url: &str, arguments: &[&str]) -> Output {
        Command::new("nix-store")
            .arg("--store")
            .arg(store_url)
            .args(arguments)
            .output()
            .expect("nix-store command should start")
    }

    fn command_stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn recovery_removes_a_root_created_before_pending_record_was_committed() {
        let fixture = LeaseFixture::new(1);
        let foreign_path = fixture
            .store_dir
            .join(format!("{}-foreign", "1".repeat(32)));
        fs::create_dir(&foreign_path).expect("foreign fixture object should be created");
        let root = fixture.manager.root_path(&fixture.store_path);
        fs::create_dir_all(root.parent().expect("root lease directory"))
            .expect("lease directory should be created");
        std::os::unix::fs::symlink(fixture.store_path.as_path(), &root)
            .expect("interrupted owned root should be installed");
        let record_path = fixture.manager.record_path(&fixture.store_path);
        fixture.write_record(
            &record_path,
            &LeaseRecord::pending(&fixture.store_path, u64::MAX),
        );

        let manager = fixture.reopen_at(1, 1);

        assert_eq!(manager.snapshot().expect("snapshot").active, 0);
        assert!(!root.exists());
        assert!(foreign_path.exists());
        assert!(fixture.owned_records().is_empty());
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &NativeStoreLeaseError::CapacityExceeded,
                "native-store lease capacity is full",
            ),
            (
                &NativeStoreLeaseError::ClockBeforeEpoch,
                "system clock is before the Unix epoch",
            ),
            (
                &NativeStoreLeaseError::ClockOverflow,
                "native-store lease expiry overflows",
            ),
            (
                &NativeStoreLeaseError::Database("detail".into()),
                "querying the Nix store database: detail",
            ),
            (
                &NativeStoreLeaseError::InvalidRecord,
                "native-store lease record is invalid",
            ),
            (
                &NativeStoreLeaseError::InvalidCapacityRecord,
                "native-store lease capacity record is invalid",
            ),
            (
                &NativeStoreLeaseError::InvalidStorePath,
                "native-store path is invalid",
            ),
            (
                &NativeStoreLeaseError::LeaseStillLive,
                "native-store lease has not expired",
            ),
            (
                &NativeStoreLeaseError::Poisoned,
                "native-store lease state is poisoned",
            ),
            (
                &NativeStoreLeaseError::RootConflict,
                "native-store GC root conflicts with its lease",
            ),
            (
                &NativeStoreLeaseError::RecordTooLarge,
                "native-store lease record exceeds its limit",
            ),
            (
                &NativeStoreLeaseError::RecoveryRequired,
                "native-store lease recovery must finish before admission",
            ),
            (
                &NativeStoreLeaseError::UnregisteredStorePath,
                "native-store path is not registered in the Nix store",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_io_error_preserves_message_and_source() {
        use std::error::Error as _;
        let error = NativeStoreLeaseError::Io(io::Error::other("read failure"));
        assert_eq!(error.to_string(), "native-store lease I/O: read failure");
        assert!(error.source().unwrap().is::<io::Error>());
        assert!(error.source().unwrap().source().is_none());
    }
}
