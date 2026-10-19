use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Cursor},
    num::NonZeroU64,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{
    Storage, StorageError, StoreHash,
    collection::{ActivityLease, AdvertisementRenewal, CollectionLease, ProtectedObject},
    fs::{ensure_directory_at, read_dir_names, require_directory_at, unlink_at},
    publication::PublishTarget,
};
use crate::cache::{
    object::NarIdentity,
    records::{BoundedRegularFile, decode_complete, read_bounded_regular_file},
};

pub(super) const DIRECTORY: &str = ".narjar-advertisements";
const POLICY: &str = "policy";
const MAX_RECORD_BYTES: u64 = 256;
const LEASE_VERSION: u8 = 2;

#[derive(Clone, Copy)]
pub(super) enum AdvertisementRemovalContext<'operation> {
    Standalone,
    Collection(&'operation CollectionLease<'operation>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct LeasePolicy {
    version: u8,
    lifetime_seconds: NonZeroU64,
    min_free_bytes: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct AdvertisementLease {
    version: u8,
    identity: NarIdentity,
    retention: AdvertisementRetention,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum AdvertisementRetention {
    Until(u64),
    RemovalPending,
}

impl AdvertisementRetention {
    fn expires_at(self) -> u64 {
        match self {
            Self::Until(expiry) => expiry,
            Self::RemovalPending => 0,
        }
    }
}

#[derive(Debug)]
pub(super) enum AdvertisementLeases {
    Absent,
    Incomplete,
    Active {
        directory: File,
        policy: LeasePolicy,
    },
}

pub(super) enum AdvertisementProtection {
    Absent,
    All,
    Recorded {
        publications: BTreeMap<StoreHash, u64>,
        nars: BTreeSet<crate::cache::object::NarHash>,
        now: u64,
    },
}

impl AdvertisementProtection {
    pub(super) fn protects_nar_name(&self, name: &OsStr) -> bool {
        match self {
            Self::All => true,
            Self::Absent | Self::Recorded { .. } => name
                .to_str()
                .and_then(|name| crate::cache::object::NarFileName::parse(name).ok())
                .and_then(crate::cache::object::NarFileName::raw_hash)
                .is_some_and(|hash| self.protects(ProtectedObject::CanonicalNar(hash))),
        }
    }

    pub(super) fn protects(&self, object: ProtectedObject) -> bool {
        match self {
            Self::Absent => false,
            Self::All => true,
            Self::Recorded {
                publications,
                nars,
                now,
            } => match object {
                ProtectedObject::Publication(store) => {
                    publications.get(&store).is_none_or(|expiry| expiry > now)
                }
                ProtectedObject::CanonicalNar(hash) => nars.contains(&hash),
            },
        }
    }
}

impl AdvertisementLeases {
    pub(super) fn open(root: &File) -> Result<Self, StorageError> {
        let directory = match require_directory_at(root, DIRECTORY) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(error) => return Err(error.into()),
        };
        match read_record::<LeasePolicy>(&directory, POLICY.as_ref())? {
            None => Ok(Self::Incomplete),
            Some(policy) if policy.version == 1 => Ok(Self::Active { directory, policy }),
            Some(_) => Err(invalid("unsupported advertisement policy")),
        }
    }
}

#[derive(Clone, Copy)]
enum LeasePurpose<'reader> {
    Publication(NarIdentity),
    Advertisement(&'reader AdvertisementRenewal<'reader>, &'reader [u8]),
}

pub(crate) enum AdvertisementEvidence {
    Recorded,
    Missing,
}

impl Storage {
    pub(crate) fn advertisement_evidence(
        &self,
        store: StoreHash,
    ) -> Result<AdvertisementEvidence, StorageError> {
        match &self.advertisements {
            AdvertisementLeases::Absent => {
                Err(invalid("advertisement retention is not configured"))
            }
            AdvertisementLeases::Incomplete => Err(invalid("advertisement policy is missing")),
            AdvertisementLeases::Active { directory, .. } => {
                match read_record::<AdvertisementLease>(directory, &lease_name(store))? {
                    Some(record) if record.version == LEASE_VERSION => match record.retention {
                        AdvertisementRetention::Until(_) => Ok(AdvertisementEvidence::Recorded),
                        AdvertisementRetention::RemovalPending => {
                            Ok(AdvertisementEvidence::Missing)
                        }
                    },
                    Some(_) => Err(invalid("unsupported advertisement lease")),
                    None => Ok(AdvertisementEvidence::Missing),
                }
            }
        }
    }

    /// Set how long GC must retain served metadata and NARs before starting workers.
    pub(crate) fn configure_advertisement_leases(
        &mut self,
        lifetime: NonZeroU64,
        min_free_bytes: u64,
    ) -> Result<(), StorageError> {
        let policy = LeasePolicy {
            version: 1,
            lifetime_seconds: lifetime,
            min_free_bytes,
        };
        if let AdvertisementLeases::Active {
            policy: existing, ..
        } = self.advertisements
            && existing == policy
        {
            return Ok(());
        }
        let bytes = postcard::to_allocvec(&policy).map_err(|error| invalid(error.to_string()))?;
        let _reservation = self.reserve_staging(bytes.len() as u64, min_free_bytes)?;
        let directory =
            ensure_directory_at(&self.root, DIRECTORY.as_ref(), "advertisement directory")?;
        directory.sync_all()?;
        self.root.sync_all()?;
        self.publish(
            PublishTarget::AdvertisementRecord(POLICY.as_ref()),
            Cursor::new(bytes),
        )?;
        self.advertisements = AdvertisementLeases::Active { directory, policy };
        Ok(())
    }

    pub(super) fn record_publication_lease(
        &self,
        store: StoreHash,
        identity: NarIdentity,
    ) -> Result<(), StorageError> {
        self.update_advertisement_lease(
            store,
            LeasePurpose::Publication(identity),
            unix_seconds()?,
            File::sync_all,
        )
    }

    pub(super) fn renew_advertisement_lease(
        &self,
        activity: &ActivityLease<'_>,
        metadata: &[u8],
    ) -> Result<(), StorageError> {
        let renewal = activity.advertisement_renewal()?;
        self.update_advertisement_lease(
            renewal.store(),
            LeasePurpose::Advertisement(&renewal, metadata),
            unix_seconds()?,
            File::sync_all,
        )
    }

    fn update_advertisement_lease(
        &self,
        store: StoreHash,
        purpose: LeasePurpose<'_>,
        now: u64,
        synchronize_reused: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), StorageError> {
        match &self.advertisements {
            AdvertisementLeases::Absent => Ok(()),
            AdvertisementLeases::Incomplete => Err(invalid("advertisement policy is missing")),
            AdvertisementLeases::Active { directory, policy } => {
                let lock = self.destination_lock(
                    PathBuf::from(DIRECTORY).join(format!("{}.renew", store.as_str())),
                );
                let _guard = lock
                    .lock()
                    .map_err(|_| invalid("advertisement renewal lock poisoned"))?;
                let name = lease_name(store);
                let existing = read_record::<AdvertisementLease>(directory, &name)?;
                let identity = match (purpose, existing) {
                    (_, Some(record)) if record.version != LEASE_VERSION => {
                        return Err(invalid("unsupported advertisement lease"));
                    }
                    (LeasePurpose::Publication(identity), Some(record)) => match record.retention {
                        AdvertisementRetention::Until(_) if identity != record.identity => {
                            return Err(StorageError::NarMismatch);
                        }
                        AdvertisementRetention::Until(_)
                        | AdvertisementRetention::RemovalPending => identity,
                    },
                    (LeasePurpose::Advertisement(renewal, metadata), Some(record)) => {
                        match record.retention {
                            AdvertisementRetention::Until(_) => record.identity,
                            AdvertisementRetention::RemovalPending => {
                                identity_from_pending_metadata(renewal.store(), metadata)?
                            }
                        }
                    }
                    (LeasePurpose::Publication(identity), None) => identity,
                    // GC keeps publications with missing retention records. Read-through
                    // requests recreate them from verified metadata and NARs before success.
                    (LeasePurpose::Advertisement(_, _), None) => return Ok(()),
                };
                let required_expiry = now
                    .checked_add(policy.lifetime_seconds.get())
                    .ok_or_else(|| invalid("advertisement expiry overflow"))?;
                match existing {
                    Some(record) if record.retention.expires_at() >= required_expiry => {
                        synchronize_reused(directory).map_err(Into::into)
                    }
                    Some(_) | None => {
                        let headroom = policy.lifetime_seconds.get().div_ceil(10).min(3600);
                        let lease = AdvertisementLease {
                            version: LEASE_VERSION,
                            identity,
                            retention: AdvertisementRetention::Until(
                                required_expiry
                                    .checked_add(headroom)
                                    .ok_or_else(|| invalid("advertisement expiry overflow"))?,
                            ),
                        };
                        match purpose {
                            LeasePurpose::Publication(_) => self.publish_advertisement_record(
                                name,
                                &lease,
                                policy.min_free_bytes,
                            ),
                            LeasePurpose::Advertisement(renewal, _) => self
                                .publish_advertisement_target(
                                    PublishTarget::AdvertisementRenewal(renewal),
                                    &lease,
                                    policy.min_free_bytes,
                                ),
                        }
                    }
                }
            }
        }
    }

    fn publish_advertisement_record(
        &self,
        name: OsString,
        record: &impl Serialize,
        min_free_bytes: u64,
    ) -> Result<(), StorageError> {
        self.publish_advertisement_target(
            PublishTarget::AdvertisementRecord(&name),
            record,
            min_free_bytes,
        )
    }

    fn publish_advertisement_target(
        &self,
        target: PublishTarget<'_>,
        record: &impl Serialize,
        min_free_bytes: u64,
    ) -> Result<(), StorageError> {
        let bytes = postcard::to_allocvec(record).map_err(|error| invalid(error.to_string()))?;
        let _reservation = self.reserve_staging(bytes.len() as u64, min_free_bytes)?;
        self.publish(target, Cursor::new(bytes)).map(|_| ())
    }

    #[cfg(test)]
    pub(super) fn expire_advertisement_lease_for_test(
        &self,
        store: StoreHash,
    ) -> Result<(), StorageError> {
        let AdvertisementLeases::Active { directory, .. } = &self.advertisements else {
            return Err(invalid("test requires configured advertisement retention"));
        };
        let name = lease_name(store);
        let mut record: AdvertisementLease = read_record(directory, &name)?
            .ok_or_else(|| invalid("test requires an existing advertisement"))?;
        record.retention = AdvertisementRetention::Until(0);
        self.publish_advertisement_record(name, &record, 0)
    }

    #[cfg(test)]
    pub(crate) fn force_advertisement_renewal_with_unavailable_reserve_for_test(
        &mut self,
        store: StoreHash,
    ) -> Result<(), StorageError> {
        let AdvertisementLeases::Active { directory, policy } = &self.advertisements else {
            return Err(invalid("test requires configured advertisement retention"));
        };
        let directory = directory.try_clone()?;
        let mut policy = *policy;
        policy.min_free_bytes = u64::MAX;
        let name = lease_name(store);
        let mut record: AdvertisementLease = read_record(&directory, &name)?
            .ok_or_else(|| invalid("test requires an existing advertisement"))?;
        record.retention = AdvertisementRetention::Until(
            unix_seconds()? + (policy.lifetime_seconds.get() / 2).max(1),
        );
        // Set the test's space limit without filling the filesystem.
        self.publish_advertisement_record(POLICY.into(), &policy, 0)?;
        self.publish_advertisement_record(name, &record, 0)?;
        self.advertisements = AdvertisementLeases::Active { directory, policy };
        Ok(())
    }

    pub(super) fn advertisement_protection(
        &self,
        time: SystemTime,
    ) -> Result<AdvertisementProtection, StorageError> {
        match &self.advertisements {
            AdvertisementLeases::Absent => Ok(AdvertisementProtection::Absent),
            AdvertisementLeases::Incomplete => Ok(AdvertisementProtection::All),
            AdvertisementLeases::Active { directory, .. } => {
                let now = time
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| invalid("system clock predates advertisement records"))?
                    .as_secs();
                let mut publications = BTreeMap::new();
                let mut nars = BTreeSet::new();
                for name in read_dir_names(directory)? {
                    if name == POLICY {
                        continue;
                    }
                    let store = name
                        .to_str()
                        .and_then(|name| name.strip_suffix(".lease"))
                        .and_then(|name| StoreHash::parse(name).ok())
                        .ok_or_else(|| invalid("invalid advertisement lease filename"))?;
                    let lease =
                        read_record::<AdvertisementLease>(directory, &name)?.ok_or_else(|| {
                            invalid("advertisement lease disappeared during collection")
                        })?;
                    if lease.version != LEASE_VERSION {
                        return Err(invalid("unsupported advertisement lease"));
                    }
                    let expires_at = lease.retention.expires_at();
                    publications.insert(store, expires_at);
                    if expires_at > now {
                        nars.insert(lease.identity.hash());
                    }
                }
                Ok(AdvertisementProtection::Recorded {
                    publications,
                    nars,
                    now,
                })
            }
        }
    }

    pub(super) fn mark_advertisement_removal_pending(
        &self,
        store: StoreHash,
        context: AdvertisementRemovalContext<'_>,
    ) -> Result<(), StorageError> {
        match &self.advertisements {
            AdvertisementLeases::Absent => Ok(()),
            AdvertisementLeases::Incomplete => Err(invalid("advertisement policy is missing")),
            AdvertisementLeases::Active { directory, .. } => {
                let lock = self.destination_lock(
                    PathBuf::from(DIRECTORY).join(format!("{}.renew", store.as_str())),
                );
                let _guard = lock
                    .lock()
                    .map_err(|_| invalid("advertisement renewal lock poisoned"))?;
                let name = lease_name(store);
                match read_record::<AdvertisementLease>(directory, &name)? {
                    None => Ok(()),
                    Some(record) if record.version != LEASE_VERSION => {
                        Err(invalid("unsupported advertisement lease"))
                    }
                    Some(mut record) => match record.retention {
                        AdvertisementRetention::RemovalPending => {
                            directory.sync_all().map_err(Into::into)
                        }
                        AdvertisementRetention::Until(_) => {
                            record.retention = AdvertisementRetention::RemovalPending;
                            match context {
                                AdvertisementRemovalContext::Standalone => {
                                    self.publish_advertisement_record(name, &record, 0)
                                }
                                AdvertisementRemovalContext::Collection(lease) => self
                                    .publish_advertisement_removal_during_collection(
                                        store,
                                        postcard::to_allocvec(&record)
                                            .map_err(|error| invalid(error.to_string()))?,
                                        lease,
                                    ),
                            }
                        }
                    },
                }
            }
        }
    }

    pub(super) fn remove_advertisement_record(&self, store: StoreHash) -> Result<(), StorageError> {
        match &self.advertisements {
            AdvertisementLeases::Absent => Ok(()),
            AdvertisementLeases::Incomplete => Err(invalid("advertisement policy is missing")),
            AdvertisementLeases::Active { directory, .. } => {
                let lock = self.destination_lock(
                    PathBuf::from(DIRECTORY).join(format!("{}.renew", store.as_str())),
                );
                let _guard = lock
                    .lock()
                    .map_err(|_| invalid("advertisement renewal lock poisoned"))?;
                // Keep the pending record until the metadata unlink is durable.
                self.root.sync_all()?;
                match unlink_at(directory, &lease_name(store)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                directory.sync_all().map_err(Into::into)
            }
        }
    }
}

fn read_record<T: for<'de> Deserialize<'de>>(
    directory: &File,
    name: &OsStr,
) -> Result<Option<T>, StorageError> {
    match read_bounded_regular_file(directory, name, MAX_RECORD_BYTES)? {
        BoundedRegularFile::Missing => Ok(None),
        BoundedRegularFile::Invalid => Err(invalid("invalid advertisement record file")),
        BoundedRegularFile::Valid(bytes) => decode_complete(&bytes)
            .map(Some)
            .map_err(|error| invalid(error.to_string())),
    }
}

fn identity_from_pending_metadata(
    store: StoreHash,
    metadata: &[u8],
) -> Result<NarIdentity, StorageError> {
    crate::cache::narinfo::NarInfoClaims::parse_external_narinfo(&store, metadata.to_vec())
        .map(|claims| claims.identity())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error).into())
}

pub(super) fn lease_name(store: StoreHash) -> OsString {
    format!("{}.lease", store.as_str()).into()
}

fn unix_seconds() -> Result<u64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| invalid("system clock predates advertisement records"))
}

fn invalid(message: impl Into<String>) -> StorageError {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::super::{
        CacheCreation, Directory, SupportedStorageBackend, publication::PublishBoundary,
    };
    use super::*;
    use crate::cache::object::NarHash;

    fn unconfigured_fixture() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = CacheCreation::prepare(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap()
        .create_or_complete()
        .unwrap();
        (directory, storage)
    }

    fn advertised_fixture() -> (tempfile::TempDir, Storage, StoreHash, NarIdentity) {
        let (directory, mut storage) = unconfigured_fixture();
        storage
            .configure_advertisement_leases(NonZeroU64::new(3600).unwrap(), 0)
            .unwrap();
        let store = StoreHash::parse("00000000000000000000000000000000").unwrap();
        let identity = NarIdentity::new(NarHash::from_digest([42; 32]), 3.into());
        storage.record_publication_lease(store, identity).unwrap();
        (directory, storage, store, identity)
    }

    fn raw_metadata(store: StoreHash, identity: NarIdentity) -> Vec<u8> {
        crate::cache::narinfo::NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{}-fixture", store.as_str()),
            None,
            None,
            identity,
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
        .serialize(crate::cache::object::NarRepresentation::Raw(identity))
        .unwrap()
    }

    #[test]
    fn rejected_initial_retention_policy_does_not_disable_the_cache_after_restart() {
        let (directory, mut storage) = unconfigured_fixture();
        let store = StoreHash::parse("00000000000000000000000000000000").unwrap();
        let metadata = directory.path().join(format!("{}.narinfo", store.as_str()));
        std::fs::write(&metadata, b"existing cached metadata").unwrap();
        assert!(matches!(
            storage.configure_advertisement_leases(NonZeroU64::new(60).unwrap(), u64::MAX),
            Err(StorageError::InsufficientSpace)
        ));
        assert!(
            !directory.path().join(DIRECTORY).exists(),
            "failed admission must not leave an incomplete retention directory"
        );
        drop(storage);
        let mut storage = Storage::open(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        assert_eq!(
            storage
                .read_advertised_narinfo(&store)
                .unwrap()
                .unwrap()
                .bytes,
            b"existing cached metadata"
        );
        assert!(
            !storage
                .advertisement_protection(SystemTime::now())
                .unwrap()
                .protects(ProtectedObject::Publication(store))
        );
        storage.delete_narinfo(&store).unwrap();
        assert!(!metadata.exists());
        storage
            .configure_advertisement_leases(NonZeroU64::new(60).unwrap(), 0)
            .unwrap();
        assert!(matches!(
            storage.advertisements,
            AdvertisementLeases::Active { .. }
        ));
    }

    #[test]
    fn rejected_retention_policy_update_preserves_existing_promises_after_restart() {
        let (directory, mut storage, store, identity) = advertised_fixture();
        let policy_path = directory.path().join(DIRECTORY).join(POLICY);
        let previous_policy = std::fs::read(&policy_path).unwrap();
        assert!(matches!(
            storage.configure_advertisement_leases(NonZeroU64::new(60).unwrap(), u64::MAX),
            Err(StorageError::InsufficientSpace)
        ));
        assert_eq!(std::fs::read(&policy_path).unwrap(), previous_policy);
        drop(storage);
        let storage = Storage::open(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        let protection = storage.advertisement_protection(SystemTime::now()).unwrap();
        assert!(protection.protects(ProtectedObject::Publication(store)));
        assert!(protection.protects(ProtectedObject::CanonicalNar(identity.hash())));
    }

    #[test]
    fn concurrent_cached_readers_do_not_turn_each_other_into_cache_misses() {
        use std::{
            sync::{Arc, mpsc},
            time::{Duration, Instant},
        };

        let (directory, storage, store, _) = advertised_fixture();
        std::fs::write(
            directory.path().join(format!("{}.narinfo", store.as_str())),
            b"cached metadata",
        )
        .unwrap();
        let renewal = storage
            .destination_lock(PathBuf::from(DIRECTORY).join(format!("{}.renew", store.as_str())));
        std::thread::scope(|scope| {
            let storage = &storage;
            let paused = renewal.lock().unwrap();
            let first = scope.spawn(move || {
                storage
                    .read_advertised_narinfo(&store)
                    .map(|metadata| metadata.map(|metadata| metadata.bytes))
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            while Arc::strong_count(&renewal) < 2 {
                assert!(Instant::now() < deadline, "first reader must reach renewal");
                std::thread::yield_now();
            }
            let (completed, response) = mpsc::channel();
            let second = scope.spawn(move || {
                let result = storage
                    .read_advertised_narinfo(&store)
                    .map(|metadata| metadata.map(|metadata| metadata.bytes));
                completed.send(result).unwrap();
            });
            let early_response = loop {
                match response.try_recv() {
                    Ok(result) => break Some(result),
                    Err(mpsc::TryRecvError::Empty) if Arc::strong_count(&renewal) >= 3 => {
                        break None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        assert!(
                            Instant::now() < deadline,
                            "second reader must reach renewal"
                        );
                        std::thread::yield_now();
                    }
                    Err(mpsc::TryRecvError::Disconnected) => panic!("reader must send its result"),
                }
            };
            drop(paused);
            let second_result = early_response
                .unwrap_or_else(|| response.recv_timeout(Duration::from_secs(5)).unwrap());
            second.join().unwrap();
            assert!(first.join().unwrap().unwrap().is_some());
            assert!(
                second_result.unwrap().is_some(),
                "another reader is not a pending publisher"
            );
        });
    }

    #[test]
    fn pending_publication_reads_return_a_miss_without_waiting_for_rollback() {
        use std::{sync::mpsc, time::Duration};

        let (directory, storage, store, _) = advertised_fixture();
        std::fs::write(
            directory.path().join(format!("{}.narinfo", store.as_str())),
            b"metadata visible before publication completion",
        )
        .unwrap();
        let publication = storage.narinfo_publication_lock(&store);
        let pending = publication.write().unwrap();
        let (completed, response) = mpsc::channel();
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let result = storage
                    .read_advertised_narinfo(&store)
                    .map(|metadata| metadata.map(|metadata| metadata.bytes));
                completed.send(result).unwrap();
            });
            let before_rollback = response.recv_timeout(Duration::from_secs(5));
            storage.remove_narinfo_with_retention(&store).unwrap();
            storage.root.sync_all().unwrap();
            drop(pending);
            reader.join().unwrap();
            assert!(
                before_rollback
                    .expect("a reader must return without waiting for publication")
                    .unwrap()
                    .is_none(),
                "a reader must not acknowledge metadata that can still be rolled back"
            );
        });
        assert!(
            !directory
                .path()
                .join(format!("{}.narinfo", store.as_str()))
                .exists()
        );
        assert!(matches!(
            storage.advertisement_evidence(store).unwrap(),
            AdvertisementEvidence::Missing
        ));
    }

    #[test]
    fn initial_lease_capacity_failure_does_not_leave_unreclaimable_metadata() {
        use crate::cache::{narinfo::NarInfoMetadata, object::NarRepresentation};
        use sha2::Digest;

        let (directory, mut storage, store, _) = advertised_fixture();
        storage.remove_advertisement_record(store).unwrap();
        let bytes = b"raw NAR";
        let identity = NarIdentity::new(
            NarHash::from_digest(sha2::Sha256::digest(bytes).into()),
            (bytes.len() as u64).into(),
        );
        storage
            .publish_nar(
                crate::cache::object::NarFileName::raw(identity.hash()),
                bytes.as_slice(),
                bytes.len() as u64,
                super::super::NarUploadPolicy::new(1024, 0),
            )
            .unwrap();
        let metadata = NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{}-fixture", store.as_str()),
            None,
            None,
            identity,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let encoded = metadata
            .serialize(NarRepresentation::Raw(identity))
            .unwrap();
        let AdvertisementLeases::Active { policy, .. } = &mut storage.advertisements else {
            panic!("fixture configures retention");
        };
        policy.min_free_bytes = u64::MAX;
        assert!(matches!(
            storage.publish_narinfo_with_claims(metadata.claims(), encoded.clone()),
            Err(StorageError::InsufficientSpace)
        ));
        assert!(storage.open_narinfo(&store).unwrap().is_none());
        assert!(
            directory
                .path()
                .join("nar")
                .join(crate::cache::object::NarFileName::raw(identity.hash()).to_string())
                .is_file(),
            "the raw NAR remains an orphan that GC can reclaim"
        );

        let AdvertisementLeases::Active { policy, .. } = &mut storage.advertisements else {
            panic!("fixture configures retention");
        };
        policy.min_free_bytes = 0;
        storage
            .publish_narinfo_with_claims(metadata.claims(), encoded.clone())
            .unwrap();
        storage
            .force_advertisement_renewal_with_unavailable_reserve_for_test(store)
            .unwrap();
        assert!(matches!(
            storage.publish_narinfo_with_claims(metadata.claims(), encoded.clone()),
            Err(StorageError::InsufficientSpace)
        ));
        assert_eq!(
            std::fs::read(directory.path().join(format!("{}.narinfo", store.as_str()))).unwrap(),
            encoded,
            "a failed retry must not delete metadata already accepted by clients"
        );
        assert!(matches!(
            storage.advertisement_evidence(store).unwrap(),
            AdvertisementEvidence::Recorded
        ));
    }

    #[test]
    fn reading_metadata_after_failed_removal_restores_its_retention() {
        let (directory, storage, store, identity) = advertised_fixture();
        std::fs::write(
            directory.path().join(format!("{}.narinfo", store.as_str())),
            raw_metadata(store, identity),
        )
        .unwrap();
        assert!(
            storage
                .remove_narinfo_with_retention_and_unlink(
                    &store,
                    AdvertisementRemovalContext::Standalone,
                    |_, _| Err(io::Error::other("injected unlink failure"))
                )
                .is_err()
        );
        assert!(matches!(
            storage.advertisement_evidence(store).unwrap(),
            AdvertisementEvidence::Missing
        ));
        assert!(storage.read_advertised_narinfo(&store).unwrap().is_some());
        let protection = storage.advertisement_protection(SystemTime::now()).unwrap();
        assert!(protection.protects(ProtectedObject::Publication(store)));
        assert!(protection.protects(ProtectedObject::CanonicalNar(identity.hash())));
        assert!(matches!(
            storage.advertisement_evidence(store).unwrap(),
            AdvertisementEvidence::Recorded
        ));
    }

    #[test]
    fn pending_removal_does_not_bind_a_later_publication_to_the_deleted_identity() {
        let (directory, storage, store, original) = advertised_fixture();
        std::fs::write(
            directory.path().join(format!("{}.narinfo", store.as_str())),
            raw_metadata(store, original),
        )
        .unwrap();
        storage
            .mark_advertisement_removal_pending(store, AdvertisementRemovalContext::Standalone)
            .unwrap();
        unlink_at(
            &storage.root,
            OsStr::new(&format!("{}.narinfo", store.as_str())),
        )
        .unwrap();
        storage.root.sync_all().unwrap();
        drop(storage);
        let storage = Storage::open(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        let replacement = NarIdentity::new(NarHash::from_digest([99; 32]), 4.into());
        let metadata_path = directory.path().join(format!("{}.narinfo", store.as_str()));
        std::fs::write(&metadata_path, raw_metadata(store, replacement)).unwrap();
        File::open(&metadata_path).unwrap().sync_all().unwrap();
        storage.root.sync_all().unwrap();
        assert!(storage.read_advertised_narinfo(&store).unwrap().is_some());
        storage
            .record_publication_lease(store, replacement)
            .unwrap();
        let protection = storage.advertisement_protection(SystemTime::now()).unwrap();
        assert!(protection.protects(ProtectedObject::CanonicalNar(replacement.hash())));
        assert!(!protection.protects(ProtectedObject::CanonicalNar(original.hash())));
    }

    #[test]
    fn explicit_metadata_deletion_removes_its_lease_before_identity_replacement() {
        let (directory, storage, store, _) = advertised_fixture();
        std::fs::write(
            directory.path().join(format!("{}.narinfo", store.as_str())),
            b"metadata",
        )
        .unwrap();
        storage.delete_narinfo(&store).unwrap();
        assert!(matches!(
            storage.advertisement_evidence(store).unwrap(),
            AdvertisementEvidence::Missing
        ));
        let replacement = NarIdentity::new(NarHash::from_digest([99; 32]), 4.into());
        storage
            .record_publication_lease(store, replacement)
            .unwrap();
    }

    #[test]
    fn failed_renewal_keeps_the_previous_durable_promise_intact() {
        let (_directory, mut storage, store, identity) = advertised_fixture();
        storage
            .force_advertisement_renewal_with_unavailable_reserve_for_test(store)
            .unwrap();
        let AdvertisementLeases::Active { directory, .. } = &storage.advertisements else {
            panic!("configured policy")
        };
        let before: AdvertisementLease =
            read_record(directory, &lease_name(store)).unwrap().unwrap();
        let reader = storage
            .collection
            .reader(ProtectedObject::Publication(store))
            .unwrap()
            .unwrap();
        assert!(matches!(
            storage.renew_advertisement_lease(&reader, &[]),
            Err(StorageError::InsufficientSpace)
        ));
        let after: AdvertisementLease =
            read_record(directory, &lease_name(store)).unwrap().unwrap();
        assert_eq!(after.retention.expires_at(), before.retention.expires_at());
        assert_eq!(after.identity, identity);
        let protection = storage.advertisement_protection(SystemTime::now()).unwrap();
        assert!(protection.protects(ProtectedObject::Publication(store)));
        assert!(protection.protects(ProtectedObject::CanonicalNar(identity.hash())));
    }

    #[test]
    fn retry_of_an_unacknowledged_lease_replacement_must_complete_directory_sync() {
        let (directory, storage, store, identity) = advertised_fixture();
        let now = unix_seconds().unwrap();
        let record = AdvertisementLease {
            version: LEASE_VERSION,
            identity,
            retention: AdvertisementRetention::Until(now + 7200),
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let reader = storage
            .collection
            .reader(ProtectedObject::Publication(store))
            .unwrap()
            .unwrap();
        let renewal = reader.advertisement_renewal().unwrap();
        let failure = storage.publish_with(
            PublishTarget::AdvertisementRenewal(&renewal),
            Cursor::new(bytes),
            |boundary| match boundary {
                PublishBoundary::BeforeParentSync => {
                    Err(io::Error::other("injected lease directory sync failure").into())
                }
                _ => Ok(()),
            },
        );
        assert!(
            failure.is_err(),
            "rename is visible but not acknowledged as durable"
        );
        let failure = storage.update_advertisement_lease(
            store,
            LeasePurpose::Advertisement(&renewal, &[]),
            now,
            |_| Err(io::Error::other("directory synchronization still fails")),
        );
        assert!(
            failure.is_err(),
            "a visible future expiry cannot bypass the missing durability barrier"
        );
        storage
            .update_advertisement_lease(
                store,
                LeasePurpose::Advertisement(&renewal, &[]),
                now,
                File::sync_all,
            )
            .unwrap();
        drop(reader);
        drop(storage);
        let storage = Storage::open(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        let protection = storage.advertisement_protection(SystemTime::now()).unwrap();
        assert!(protection.protects(ProtectedObject::Publication(store)));
        assert!(protection.protects(ProtectedObject::CanonicalNar(identity.hash())));
    }

    #[test]
    fn missing_publication_evidence_is_conservative_but_expired_leases_release_both_identities() {
        let store = StoreHash::parse("00000000000000000000000000000000").unwrap();
        let hash = NarHash::from_digest([42; 32]);
        let protection = AdvertisementProtection::Recorded {
            publications: BTreeMap::new(),
            nars: BTreeSet::new(),
            now: 10,
        };
        assert!(protection.protects(ProtectedObject::Publication(store)));
        let protection = AdvertisementProtection::Recorded {
            publications: BTreeMap::from([(store, 9)]),
            nars: BTreeSet::new(),
            now: 10,
        };
        assert!(!protection.protects(ProtectedObject::Publication(store)));
        assert!(!protection.protects(ProtectedObject::CanonicalNar(hash)));
        assert!(AdvertisementProtection::All.protects(ProtectedObject::CanonicalNar(hash)));
    }
}
