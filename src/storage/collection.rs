use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use super::{NarFileName, NarHash, StorageError, StoreHash};

pub const ONLINE_GC_GRACE: Duration = Duration::from_secs(600);
const RECENT_OBJECT_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ProtectedObject {
    Publication(StoreHash),
    CanonicalNar(NarHash),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum CollectionPhase {
    #[default]
    Idle,
    Scanning,
    Deleting(ObjectSelection),
}

#[derive(Debug)]
struct Activity {
    generation: u64,
    active: usize,
    phase: CollectionPhase,
    protect_all_until: Instant,
    recent: BTreeMap<ProtectedObject, Instant>,
}

impl Activity {
    fn invalidate_snapshot(&mut self) -> Result<(), StorageError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("collection mutation generation exhausted"))?;
        Ok(())
    }
    fn protect(&mut self, object: ProtectedObject, now: Instant) {
        self.recent.retain(|_, until| *until > now);
        let until = now + ONLINE_GC_GRACE;
        let has_room = self.recent.len() < RECENT_OBJECT_LIMIT;
        match self.recent.get_mut(&object) {
            Some(existing) => *existing = (*existing).max(until),
            None if has_room => {
                self.recent.insert(object, until);
            }
            None => self.protect_all_until = self.protect_all_until.max(until),
        }
    }
}

#[derive(Debug)]
pub(super) struct CollectionCoordinator {
    activity: Mutex<Activity>,
    released: Condvar,
}

impl Default for CollectionCoordinator {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

impl CollectionCoordinator {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            activity: Mutex::new(Activity {
                generation: 0,
                active: 0,
                phase: CollectionPhase::Idle,
                protect_all_until: now + ONLINE_GC_GRACE,
                recent: BTreeMap::new(),
            }),
            released: Condvar::new(),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Activity>, StorageError> {
        self.activity
            .lock()
            .map_err(|_| io::Error::other("collection coordination lock poisoned").into())
    }

    pub(super) fn mutation(&self) -> Result<ActivityLease<'_>, StorageError> {
        let mut activity = self.wait_until_not_deleting()?;
        activity.invalidate_snapshot()?;
        self.admit_activity(activity)
    }

    pub(super) fn reader(
        &self,
        object: ProtectedObject,
    ) -> Result<Option<ActivityLease<'_>>, StorageError> {
        let activity = self.lock()?;
        let retiring = match &activity.phase {
            CollectionPhase::Deleting(retiring) => retiring.contains(object),
            CollectionPhase::Idle | CollectionPhase::Scanning => false,
        };
        if retiring {
            return Ok(None);
        }
        self.admit_activity(activity).map(Some)
    }

    fn wait_until_not_deleting(&self) -> Result<MutexGuard<'_, Activity>, StorageError> {
        self.released
            .wait_while(self.lock()?, |activity| match activity.phase {
                CollectionPhase::Deleting(_) => true,
                CollectionPhase::Idle | CollectionPhase::Scanning => false,
            })
            .map_err(|_| io::Error::other("collection coordination lock poisoned").into())
    }

    fn admit_activity(
        &self,
        mut activity: MutexGuard<'_, Activity>,
    ) -> Result<ActivityLease<'_>, StorageError> {
        activity.active = activity
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::other("collection activity count exhausted"))?;
        Ok(ActivityLease {
            coordinator: self,
            advertisement: None,
        })
    }

    pub(super) fn snapshot(&self) -> Result<CollectionSnapshot<'_>, StorageError> {
        self.snapshot_at(Instant::now())
    }

    fn snapshot_at(&self, now: Instant) -> Result<CollectionSnapshot<'_>, StorageError> {
        let mut activity = self.lock()?;
        if activity.phase != CollectionPhase::Idle || activity.active != 0 {
            return Err(StorageError::CollectionBusy);
        }
        activity.phase = CollectionPhase::Scanning;
        let protection = if activity.protect_all_until > now {
            ObjectSelection::All
        } else {
            ObjectSelection::Objects(
                activity
                    .recent
                    .iter()
                    .filter(|(_, until)| **until > now)
                    .map(|(object, _)| *object)
                    .collect(),
            )
        };
        Ok(CollectionSnapshot {
            lease: CollectionLease { coordinator: self },
            generation: activity.generation,
            protection,
        })
    }
}

pub(crate) struct ActivityLease<'coordinator> {
    coordinator: &'coordinator CollectionCoordinator,
    advertisement: Option<ProtectedObject>,
}

impl ActivityLease<'_> {
    pub(super) fn advertise(mut self, store: StoreHash) -> Result<Self, StorageError> {
        let object = ProtectedObject::Publication(store);
        let mut activity = self.coordinator.lock()?;
        activity.invalidate_snapshot()?;
        activity.protect(object, Instant::now());
        drop(activity);
        self.advertisement = Some(object);
        Ok(self)
    }
    pub(super) fn protect(&self, object: ProtectedObject) -> Result<(), StorageError> {
        self.protect_at(object, Instant::now())
    }

    fn protect_at(&self, object: ProtectedObject, now: Instant) -> Result<(), StorageError> {
        let mut activity = self.coordinator.lock()?;
        activity.protect(object, now);
        Ok(())
    }
}

impl Drop for ActivityLease<'_> {
    fn drop(&mut self) {
        let mut activity = self
            .coordinator
            .activity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(object) = self.advertisement {
            activity.protect(object, Instant::now());
        }
        activity.active -= 1;
    }
}

pub(super) struct CollectionSnapshot<'coordinator> {
    lease: CollectionLease<'coordinator>,
    generation: u64,
    pub(super) protection: ObjectSelection,
}

impl<'coordinator> CollectionSnapshot<'coordinator> {
    pub(super) fn authorize_deletion(self) -> Result<CollectionLease<'coordinator>, StorageError> {
        self.authorize_retirement(ObjectSelection::All)
    }

    pub(super) fn authorize_retirement(
        self,
        retiring: ObjectSelection,
    ) -> Result<CollectionLease<'coordinator>, StorageError> {
        let mut activity = self.lease.coordinator.lock()?;
        if activity.active != 0 {
            return Err(StorageError::CollectionBusy);
        }
        if activity.generation != self.generation {
            return Err(StorageError::CollectionChanged);
        }
        activity.phase = CollectionPhase::Deleting(retiring);
        drop(activity);
        Ok(self.lease)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ObjectSelection {
    All,
    Objects(BTreeSet<ProtectedObject>),
}

impl ObjectSelection {
    pub(super) fn contains_nar_name(&self, name: &std::ffi::OsStr) -> bool {
        match self {
            Self::All => true,
            Self::Objects(_) => name
                .to_str()
                .and_then(|name| NarFileName::parse(name).ok())
                .and_then(NarFileName::raw_hash)
                .is_some_and(|hash| self.contains(ProtectedObject::CanonicalNar(hash))),
        }
    }
    pub(super) fn contains(&self, object: ProtectedObject) -> bool {
        match self {
            Self::All => true,
            Self::Objects(objects) => objects.contains(&object),
        }
    }
}

pub(super) struct CollectionLease<'coordinator> {
    coordinator: &'coordinator CollectionCoordinator,
}

impl Drop for CollectionLease<'_> {
    fn drop(&mut self) {
        self.coordinator
            .activity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .phase = CollectionPhase::Idle;
        self.coordinator.released.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_completed_mutation_invalidates_an_unlocked_inventory_snapshot() {
        let now = Instant::now();
        let coordinator = CollectionCoordinator::new(now);
        let snapshot = coordinator.snapshot().unwrap();
        drop(coordinator.mutation().unwrap());
        assert!(matches!(
            snapshot.authorize_deletion(),
            Err(StorageError::CollectionChanged)
        ));
        assert!(
            coordinator.snapshot().is_ok(),
            "a rejected scan releases its lease"
        );
    }

    #[test]
    fn an_active_operation_defers_collection_without_holding_a_mutex() {
        let coordinator = CollectionCoordinator::default();
        let object = ProtectedObject::CanonicalNar(NarHash::from_digest([42; 32]));
        let operation = coordinator.reader(object).unwrap().unwrap();
        assert!(matches!(
            coordinator.snapshot(),
            Err(StorageError::CollectionBusy)
        ));
        drop(operation);
        assert!(coordinator.snapshot().is_ok());
    }

    #[test]
    fn deletion_exclusion_releases_on_unwind_without_holding_the_coordination_mutex() {
        let coordinator = CollectionCoordinator::default();
        let failure = std::panic::catch_unwind(|| {
            let _deletion = coordinator
                .snapshot()
                .unwrap()
                .authorize_deletion()
                .unwrap();
            let activity = coordinator.activity.try_lock().unwrap();
            assert_eq!(
                activity.phase,
                CollectionPhase::Deleting(ObjectSelection::All)
            );
            assert_eq!(activity.active, 0);
            drop(activity);
            assert!(matches!(
                coordinator.snapshot(),
                Err(StorageError::CollectionBusy)
            ));
            panic!("injected deletion failure");
        });
        assert!(failure.is_err());
        assert!(
            coordinator
                .reader(ProtectedObject::CanonicalNar(NarHash::from_digest(
                    [42; 32]
                )))
                .unwrap()
                .is_some()
        );
        assert!(coordinator.mutation().is_ok());
        assert!(coordinator.snapshot().is_ok());
    }

    #[test]
    fn retained_readers_are_admitted_before_retirement_finishes_and_victims_return_a_miss() {
        let coordinator = CollectionCoordinator::default();
        let retired = ProtectedObject::CanonicalNar(NarHash::from_digest([1; 32]));
        let retained = ProtectedObject::CanonicalNar(NarHash::from_digest([2; 32]));
        let permit = coordinator
            .snapshot()
            .unwrap()
            .authorize_retirement(ObjectSelection::Objects([retired].into_iter().collect()))
            .unwrap();
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let _read = coordinator.reader(retained).unwrap().unwrap();
                assert!(coordinator.reader(retired).unwrap().is_none());
            });
            // The reader must finish while the collector still owns retirement.
            reader.join().unwrap();
            assert!(matches!(
                coordinator.lock().unwrap().phase,
                CollectionPhase::Deleting(_)
            ));
        });
        drop(permit);
        assert!(coordinator.reader(retired).unwrap().is_some());
    }

    #[test]
    fn recent_protection_expires_and_overflow_fails_closed_with_bounded_memory() {
        let now = Instant::now();
        let coordinator = CollectionCoordinator::new(now - ONLINE_GC_GRACE);
        let object = ProtectedObject::CanonicalNar(NarHash::from_digest([42; 32]));
        let operation = coordinator.reader(object).unwrap().unwrap();
        operation.protect_at(object, now).unwrap();
        drop(operation);
        let snapshot = coordinator.snapshot().unwrap();
        assert!(snapshot.protection.contains(object));
        drop(snapshot.authorize_deletion().unwrap());
        let snapshot = coordinator.snapshot_at(now + ONLINE_GC_GRACE).unwrap();
        assert!(!snapshot.protection.contains(object));
        drop(snapshot);

        let operation = coordinator.reader(object).unwrap().unwrap();
        for index in 0..=RECENT_OBJECT_LIMIT {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            operation
                .protect_at(
                    ProtectedObject::CanonicalNar(NarHash::from_digest(digest)),
                    now,
                )
                .unwrap();
        }
        drop(operation);
        assert_eq!(
            coordinator.lock().unwrap().recent.len(),
            RECENT_OBJECT_LIMIT
        );
        let snapshot = coordinator.snapshot().unwrap();
        assert!(
            snapshot
                .protection
                .contains(ProtectedObject::CanonicalNar(NarHash::from_digest(
                    [255; 32]
                )))
        );
    }
}
