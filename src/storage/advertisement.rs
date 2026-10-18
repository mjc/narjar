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
    collection::{ActivityLease, AdvertisementRenewal, ProtectedObject},
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
    expires_at: u64,
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
    Advertisement(&'reader AdvertisementRenewal<'reader>),
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
                    Some(record) if record.version == 1 => Ok(AdvertisementEvidence::Recorded),
                    Some(_) => Err(invalid("unsupported advertisement lease")),
                    None => Ok(AdvertisementEvidence::Missing),
                }
            }
        }
    }

    /// Configure durable advertisement retention before sharing storage with workers.
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
        let directory =
            ensure_directory_at(&self.root, DIRECTORY.as_ref(), "advertisement directory")?;
        directory.sync_all()?;
        self.root.sync_all()?;
        self.publish_advertisement_record(POLICY.into(), &policy, min_free_bytes)?;
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
    ) -> Result<(), StorageError> {
        let renewal = activity.advertisement_renewal()?;
        self.update_advertisement_lease(
            renewal.store(),
            LeasePurpose::Advertisement(&renewal),
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
                    (_, Some(record)) if record.version != 1 => {
                        return Err(invalid("unsupported advertisement lease"));
                    }
                    (LeasePurpose::Publication(identity), Some(record))
                        if identity != record.identity =>
                    {
                        return Err(StorageError::NarMismatch);
                    }
                    (_, Some(record)) => record.identity,
                    (LeasePurpose::Publication(identity), None) => identity,
                    // Collection retains missing evidence conservatively. Edge reads repair it
                    // from trusted metadata and canonical bytes before advertising success.
                    (LeasePurpose::Advertisement(_), None) => return Ok(()),
                };
                let required_expiry = now
                    .checked_add(policy.lifetime_seconds.get())
                    .ok_or_else(|| invalid("advertisement expiry overflow"))?;
                match existing {
                    Some(record) if record.expires_at >= required_expiry => {
                        synchronize_reused(directory).map_err(Into::into)
                    }
                    Some(_) | None => {
                        let headroom = policy.lifetime_seconds.get().div_ceil(10).min(3600);
                        let lease = AdvertisementLease {
                            version: 1,
                            identity,
                            expires_at: required_expiry
                                .checked_add(headroom)
                                .ok_or_else(|| invalid("advertisement expiry overflow"))?,
                        };
                        match purpose {
                            LeasePurpose::Publication(_) => self.publish_advertisement_record(
                                name,
                                &lease,
                                policy.min_free_bytes,
                            ),
                            LeasePurpose::Advertisement(renewal) => self
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
        record.expires_at = 0;
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
        record.expires_at = unix_seconds()? + (policy.lifetime_seconds.get() / 2).max(1);
        // Set controlled admission policy without consuming real filesystem capacity.
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
                    if lease.version != 1 {
                        return Err(invalid("unsupported advertisement lease"));
                    }
                    publications.insert(store, lease.expires_at);
                    if lease.expires_at > now {
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

    pub(super) fn forget_advertisement(&self, store: StoreHash) {
        if let AdvertisementLeases::Active { directory, .. } = &self.advertisements {
            let removed =
                unlink_at(directory, &lease_name(store)).and_then(|()| directory.sync_all());
            if let Err(error) = removed {
                eprintln!("narjar: remove expired advertisement record: {error}");
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

    fn advertised_fixture() -> (tempfile::TempDir, Storage, StoreHash, NarIdentity) {
        let directory = tempfile::tempdir().unwrap();
        let mut storage = CacheCreation::prepare(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap()
        .create_or_complete()
        .unwrap();
        storage
            .configure_advertisement_leases(NonZeroU64::new(3600).unwrap(), 0)
            .unwrap();
        let store = StoreHash::parse("00000000000000000000000000000000").unwrap();
        let identity = NarIdentity::new(NarHash::from_digest([42; 32]), 3.into());
        storage.record_publication_lease(store, identity).unwrap();
        (directory, storage, store, identity)
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
            storage.renew_advertisement_lease(&reader),
            Err(StorageError::InsufficientSpace)
        ));
        let after: AdvertisementLease =
            read_record(directory, &lease_name(store)).unwrap().unwrap();
        assert_eq!(after.expires_at, before.expires_at);
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
            version: 1,
            identity,
            expires_at: now + 7200,
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
            LeasePurpose::Advertisement(&renewal),
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
                LeasePurpose::Advertisement(&renewal),
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
