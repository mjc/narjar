use narjar::object::{NarHash, NarIdentity};
use serde::{Deserialize, Serialize};

use super::{
    MAX_RECORD_BYTES, NativeStoreLease, NativeStoreLeaseError, NativeStoreLeaseManager,
    NativeStorePath, read_required_record, remove_record, write_bytes_atomically,
};
use crate::{
    cache::records::{BoundedRegularFile, decode_complete, read_bounded_regular_file},
    native_store::metadata::SignedNativeNarInfo,
};

const INDEX_PREFIX: &str = ".narjar-native-nar-";
const ASSOCIATION: &str = "advertised";

#[derive(Serialize, Deserialize)]
struct AdvertisementRecord {
    version: u8,
    store_path: String,
    identity: NarIdentity,
    expires_at: u64,
}

/// Private durable evidence created only after a trusted native advertisement.
pub(crate) struct AdvertisedNativeNar(AdvertisementRecord);

impl AdvertisedNativeNar {
    pub(crate) fn store_path(&self) -> &str {
        &self.0.store_path
    }
    pub(crate) fn identity(&self) -> NarIdentity {
        self.0.identity
    }
}

impl NativeStoreLeaseManager {
    pub(crate) fn record_advertisement(
        &self,
        lease: &NativeStoreLease,
        signed: &SignedNativeNarInfo,
    ) -> Result<(), NativeStoreLeaseError> {
        if lease.store_path().as_path().to_str() != Some(signed.claims().store_path()) {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        self.publish_advertisement(lease, signed.claims().identity())
    }

    pub(crate) fn renew_advertisement(
        &self,
        lease: &NativeStoreLease,
        advertised: &AdvertisedNativeNar,
    ) -> Result<(), NativeStoreLeaseError> {
        if lease.store_path().as_path().to_str() != Some(advertised.store_path()) {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        self.publish_advertisement(lease, advertised.identity())
    }

    pub(crate) fn lookup_advertisement(
        &self,
        hash: NarHash,
    ) -> Result<Option<AdvertisedNativeNar>, NativeStoreLeaseError> {
        self.lookup_advertisement_at(hash, super::now_unix_seconds()?)
    }

    pub(super) fn lookup_advertisement_at(
        &self,
        hash: NarHash,
        now: u64,
    ) -> Result<Option<AdvertisedNativeNar>, NativeStoreLeaseError> {
        let record = self.read_advertisement(&self.advertisement_path(hash))?;
        match record {
            Some(record) if record.expires_at <= now => Ok(None),
            Some(record) if record.identity.hash() == hash => Ok(Some(AdvertisedNativeNar(record))),
            Some(_) => Err(NativeStoreLeaseError::InvalidRecord),
            None => Ok(None),
        }
    }

    pub(super) fn publish_advertisement(
        &self,
        lease: &NativeStoreLease,
        identity: NarIdentity,
    ) -> Result<(), NativeStoreLeaseError> {
        if lease.record_path != self.record_path(lease.store_path()) {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        let _state = self.lock_state()?;
        let _lock = self.acquire_sidecar_lock()?;
        let lease_record = read_required_record(&lease.record_path, &self.store_dir)?;
        let association_path = lease.record_path.with_file_name(ASSOCIATION);
        let existing_association = self.read_advertisement(&association_path)?;
        if let Some(existing) = &existing_association
            && existing.identity != identity
        {
            return Err(NativeStoreLeaseError::RootConflict);
        }
        let record = AdvertisementRecord {
            version: 1,
            store_path: lease
                .store_path()
                .as_path()
                .to_str()
                .ok_or(NativeStoreLeaseError::InvalidRecord)?
                .to_owned(),
            identity,
            expires_at: lease_record.expires_at,
        };
        let bytes =
            postcard::to_allocvec(&record).map_err(|_| NativeStoreLeaseError::InvalidRecord)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(NativeStoreLeaseError::RecordTooLarge);
        }
        match existing_association {
            Some(existing) if existing.expires_at >= record.expires_at => {
                super::sync_directory(&self.lease_directory(lease.store_path()))?
            }
            Some(_) | None => write_bytes_atomically(&self.roots_dir, &association_path, &bytes)?,
        }
        let index_path = self.advertisement_path(identity.hash());
        match self.read_advertisement(&index_path)? {
            Some(existing) if existing.expires_at >= record.expires_at => {
                super::sync_directory(&self.roots_dir)
            }
            Some(_) | None => write_bytes_atomically(&self.roots_dir, &index_path, &bytes),
        }
    }

    pub(super) fn remove_advertisement_for_lease(
        &self,
        path: &NativeStorePath,
    ) -> Result<(), NativeStoreLeaseError> {
        let association_path = self.record_path(path).with_file_name(ASSOCIATION);
        match self.read_advertisement(&association_path)? {
            None => Ok(()),
            Some(association) => {
                let index_path = self.advertisement_path(association.identity.hash());
                if let Some(index) = self.read_advertisement(&index_path)?
                    && index.store_path == association.store_path
                {
                    remove_record(&self.roots_dir, &index_path)?;
                }
                remove_record(&self.roots_dir, &association_path)
            }
        }
    }

    fn advertisement_path(&self, hash: NarHash) -> std::path::PathBuf {
        self.roots_dir.join(format!("{INDEX_PREFIX}{hash}"))
    }

    fn read_advertisement(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<AdvertisementRecord>, NativeStoreLeaseError> {
        let record = match read_bounded_regular_file(rustix::fs::CWD, path, MAX_RECORD_BYTES)
            .map_err(NativeStoreLeaseError::Io)?
        {
            BoundedRegularFile::Missing => return Ok(None),
            BoundedRegularFile::Invalid => return Err(NativeStoreLeaseError::InvalidRecord),
            BoundedRegularFile::Valid(bytes) => decode_complete::<AdvertisementRecord>(&bytes)
                .map_err(|_| NativeStoreLeaseError::InvalidRecord)?,
        };
        if record.version != 1 || record.identity.size().get() == 0 {
            return Err(NativeStoreLeaseError::InvalidRecord);
        }
        NativeStorePath::parse(&self.store_dir, std::path::Path::new(&record.store_path))?;
        Ok(Some(record))
    }
}
