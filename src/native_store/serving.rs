use std::{
    cell::OnceCell,
    fmt::Write as _,
    io::{self, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use enum_map::{Enum, EnumMap};
use narjar::object::{NarHash, NarIdentity};

use super::{
    ValidatedNativeStore,
    delivery::NativeNarDelivery,
    lease::{NativeStoreActiveDelivery, NativeStoreLease, NativeStoreLeaseError},
    metadata::{NativeMetadataError, ValidatedNativeClaims},
};
use crate::cache::{
    narinfo::TrustedPublicKeys,
    storage::{StorageReadiness, StoreHash, filesystem_space},
};

pub(crate) struct NativeStoreSource {
    store: ValidatedNativeStore,
    trusted: Arc<TrustedPublicKeys>,
    failures: EnumMap<NativeFailure, AtomicU64>,
}

#[derive(Clone, Copy, Enum)]
enum NativeFailure {
    Metadata,
    Signature,
    Lease,
    Delivery,
    Cleanup,
}

impl NativeFailure {
    fn label(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Signature => "signature",
            Self::Lease => "lease",
            Self::Delivery => "delivery",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeReadError {
    #[error("native object is unavailable")]
    Missing,
    #[error("native metadata: {0}")]
    Metadata(NativeMetadataError),
    #[error("native lease: {0}")]
    Lease(#[from] NativeStoreLeaseError),
    #[error("no trusted signature is available")]
    Signature,
    #[error("native delivery: {0}")]
    Delivery(#[from] io::Error),
}

impl From<NativeMetadataError> for NativeReadError {
    fn from(error: NativeMetadataError) -> Self {
        match error {
            NativeMetadataError::MissingStorePath(_) => Self::Missing,
            NativeMetadataError::Database(_) | NativeMetadataError::InvalidMetadata(_) => {
                Self::Metadata(error)
            }
        }
    }
}

/// Claims are re-read after rooting the exact path; the lease owns availability.
pub(crate) struct LeasedNativeNar {
    claims: ValidatedNativeClaims,
    lease: NativeStoreLease,
    _activity: NativeStoreActiveDelivery,
}

impl LeasedNativeNar {
    pub(crate) fn identity(&self) -> NarIdentity {
        self.claims.claims().identity()
    }

    pub(crate) fn into_delivery(self) -> Result<NativeNarDelivery, NativeReadError> {
        NativeNarDelivery::new(self.lease, self.claims.claims().identity()).map_err(Into::into)
    }
}

pub(crate) struct NativeAdvertisement {
    pub(crate) bytes: Vec<u8>,
    pub(crate) _activity: NativeStoreActiveDelivery,
}

struct FailureObservedDelivery<'source, R> {
    reader: R,
    source: &'source NativeStoreSource,
    reported: OnceCell<()>,
}

impl<R: Read> Read for FailureObservedDelivery<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer).inspect_err(|_| {
            self.reported
                .get_or_init(|| self.source.record_failure(NativeFailure::Delivery));
        })
    }
}

impl NativeStoreSource {
    pub(crate) fn observe_delivery_reader<'source, R: Read + 'source>(
        &'source self,
        reader: R,
    ) -> impl Read + 'source {
        FailureObservedDelivery {
            reader,
            source: self,
            reported: OnceCell::new(),
        }
    }

    pub(crate) fn new(store: ValidatedNativeStore, trusted: Arc<TrustedPublicKeys>) -> Self {
        Self {
            store,
            trusted,
            failures: EnumMap::default(),
        }
    }

    pub(crate) fn advertise(
        &self,
        hash: StoreHash,
    ) -> Result<NativeAdvertisement, NativeReadError> {
        self.observe_read((|| {
            let snapshot = self.store.metadata_snapshot()?;
            let path = snapshot
                .path_for_store(hash)?
                .ok_or(NativeReadError::Missing)?;
            let signed = snapshot
                .validated_claims_for(&path)?
                .sign_for_trusted_cache(&self.trusted, self.store.signing_key.as_ref())
                .map_err(|_| NativeReadError::Signature)?;
            drop(snapshot);
            let object = self.lease_and_read_current_claims(&path)?;
            signed
                .claims()
                .compare_logical_claims(object.claims.claims())
                .map_err(|_| NativeReadError::Missing)?;
            let bytes = signed.serialize_raw().map_err(|_| {
                NativeReadError::Metadata(NativeMetadataError::InvalidMetadata(
                    "native narinfo exceeds the protocol limit or has invalid fields".into(),
                ))
            })?;
            self.store
                .leases()
                .record_advertisement(&object.lease, &signed)?;
            Ok(NativeAdvertisement {
                bytes,
                _activity: object._activity,
            })
        })())
    }

    pub(crate) fn resolve_nar(&self, hash: NarHash) -> Result<LeasedNativeNar, NativeReadError> {
        self.observe_read((|| {
            let advertised: super::lease::AdvertisedNativeNar = self
                .store
                .leases()
                .lookup_advertisement(hash)?
                .ok_or(NativeReadError::Missing)?;
            let object = self.lease_and_read_current_claims(advertised.store_path())?;
            match object.identity() == advertised.identity() {
                true => {
                    self.store
                        .leases()
                        .renew_advertisement(&object.lease, &advertised)?;
                    Ok(object)
                }
                false => Err(NativeReadError::Missing),
            }
        })())
    }

    pub(crate) fn open_delivery(
        &self,
        object: LeasedNativeNar,
    ) -> Result<NativeNarDelivery, NativeReadError> {
        self.observe_read(object.into_delivery())
    }

    fn lease_and_read_current_claims(
        &self,
        path: &str,
    ) -> Result<LeasedNativeNar, NativeReadError> {
        let path = self.store.leases().validate_store_path(Path::new(path))?;
        let lease = self.store.leases().acquire(
            path,
            #[cfg(test)]
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs(),
        )?;
        let activity = lease.begin_active_delivery()?;
        let claims = self.store.metadata_snapshot()?.validated_claims_for(
            lease
                .store_path()
                .as_path()
                .to_str()
                .ok_or(NativeReadError::Missing)?,
        )?;
        Ok(LeasedNativeNar {
            claims,
            lease,
            _activity: activity,
        })
    }

    fn observe_read<T>(&self, result: Result<T, NativeReadError>) -> Result<T, NativeReadError> {
        let failure = match &result {
            Ok(_) | Err(NativeReadError::Missing) => None,
            Err(NativeReadError::Metadata(_)) => Some(NativeFailure::Metadata),
            Err(NativeReadError::Signature) => Some(NativeFailure::Signature),
            Err(NativeReadError::Lease(_)) => Some(NativeFailure::Lease),
            Err(NativeReadError::Delivery(_)) => Some(NativeFailure::Delivery),
        };
        if let Some(failure) = failure {
            self.record_failure(failure);
        }
        result
    }

    fn record_failure(&self, failure: NativeFailure) {
        let _ =
            self.failures[failure].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
    }

    pub(crate) fn readiness(
        &self,
        min_free_bytes: u64,
    ) -> Result<StorageReadiness, NativeReadError> {
        self.store.metadata_snapshot()?;
        self.store.leases().probe()?;
        let space = filesystem_space(&self.store._roots_directory)?;
        Ok(StorageReadiness::from_capacity(space, min_free_bytes))
    }

    pub(crate) fn maintain(&self) {
        if let Err(error) = self.store.leases().cleanup_expired() {
            self.record_failure(NativeFailure::Cleanup);
            eprintln!("narjar: native lease cleanup: {error}");
        }
    }

    pub(crate) fn append_metrics(&self, output: &mut String) {
        if let Ok(space) = filesystem_space(&self.store._roots_directory) {
            let _ = writeln!(
                output,
                "# TYPE narjar_native_roots_available_bytes gauge\nnarjar_native_roots_available_bytes {}",
                space.available_bytes
            );
        }
        if let Ok(leases) = self.store.leases().snapshot() {
            let _ = writeln!(
                output,
                "# TYPE narjar_native_expired_leases_released_total counter\nnarjar_native_expired_leases_released_total {}",
                leases.expired_released
            );
            let _ = writeln!(
                output,
                "# TYPE narjar_native_leases gauge\nnarjar_native_leases {}\n# TYPE narjar_native_lease_limit gauge\nnarjar_native_lease_limit {}\n# TYPE narjar_native_lease_capacity_rejections_total counter\nnarjar_native_lease_capacity_rejections_total {}",
                leases.active, leases.maximum, leases.capacity_rejections
            );
        }
        output.push_str("# TYPE narjar_native_failures_total counter\n");
        self.failures.iter().for_each(|(failure, counter)| {
            let _ = writeln!(
                output,
                "narjar_native_failures_total{{phase=\"{}\"}} {}",
                failure.label(),
                counter.load(Ordering::Relaxed)
            );
        });
    }
}
