#[cfg(test)]
use std::path::PathBuf;
use std::{ffi::OsString, io};

use super::super::{
    advertisement::lease_name, collection::AdvertisementRenewal, compression::IngestionReceipt,
    egress::EgressReceipt, ids::StoreHash, location::StorePath,
};
use crate::cache::object::{EncodedIdentity, NarFileName};

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Layout {
    root: PathBuf,
}

#[cfg(test)]
impl Layout {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn nar_dir(&self) -> PathBuf {
        self.root.join("nar")
    }

    pub(crate) fn nar_path(&self, hash: crate::cache::object::NarHash) -> PathBuf {
        self.nar_dir().join(NarFileName::raw(hash).to_string())
    }

    pub(crate) fn nar_path_encoded(&self, name: NarFileName) -> PathBuf {
        self.nar_dir().join(name.to_string())
    }

    pub(crate) fn nar_temp_dir(&self) -> PathBuf {
        self.nar_dir().join(".tmp")
    }

    pub(crate) fn narinfo_path(&self, hash: &StoreHash) -> PathBuf {
        self.root.join(format!("{}.narinfo", hash.as_str()))
    }

    pub(crate) fn temp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }

    pub(crate) fn transaction_dir(&self) -> PathBuf {
        self.root.join(".narjar-transactions")
    }

    pub(crate) fn ingestion_receipt_dir(&self) -> PathBuf {
        self.root.join(".narjar-ingress")
    }

    pub(crate) fn egress_receipt_dir(&self) -> PathBuf {
        self.root.join(".narjar-egress")
    }
}

pub(crate) enum PublishTarget<'a> {
    CacheInfo,
    Nar(NarFileName),
    NarInfo(&'a StoreHash),
    IngestionReceipt(&'a IngestionReceipt),
    EgressReceipt(&'a EgressReceipt),
    RepairEgressNar(EncodedIdentity),
    AdvertisementRecord(&'a std::ffi::OsStr),
    AdvertisementRenewal(&'a AdvertisementRenewal<'a>),
}

#[derive(Clone, Copy)]
pub(crate) enum TemporaryDirectory {
    Root,
    Nar,
}

pub(crate) struct PublicationDestination {
    pub(crate) path: StorePath,
    pub(crate) temporary_directory: TemporaryDirectory,
    pub(crate) publication: DestinationPublication,
    pub(crate) temp_prefix: &'static str,
}

impl PublicationDestination {
    pub(crate) fn validate_path(&self) -> io::Result<()> {
        if let DestinationPublication::RenewAdvertisement(store) = self.publication
            && self.path != StorePath::Advertisement(lease_name(store))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "advertisement renewal destination does not match its reader",
            ));
        }
        let path = self.path.relative_path();
        path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "transaction destination is not UTF-8",
            )
        })?;
        StorePath::parse(&path).map(|_| ())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum DestinationPublication {
    Link,
    Replace,
    Repair(EncodedIdentity),
    RenewAdvertisement(StoreHash),
}

impl PublishTarget<'_> {
    pub(crate) fn destination(&self) -> PublicationDestination {
        match self {
            Self::AdvertisementRenewal(renewal) => PublicationDestination {
                path: StorePath::Advertisement(lease_name(renewal.store())),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::RenewAdvertisement(renewal.store()),
                temp_prefix: "advertisement",
            },
            Self::AdvertisementRecord(name) => PublicationDestination {
                path: StorePath::Advertisement(name.to_os_string()),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::Replace,
                temp_prefix: "advertisement",
            },
            Self::CacheInfo => PublicationDestination {
                path: StorePath::Root(OsString::from("nix-cache-info")),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::Link,
                temp_prefix: "cache-info",
            },
            Self::Nar(name) => PublicationDestination {
                path: StorePath::Nar(name.to_string().into()),
                temporary_directory: TemporaryDirectory::Nar,
                publication: DestinationPublication::Link,
                temp_prefix: "nar",
            },
            Self::NarInfo(store) => PublicationDestination {
                path: StorePath::Root(OsString::from(format!("{}.narinfo", store.as_str()))),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::Link,
                temp_prefix: "narinfo",
            },
            Self::IngestionReceipt(receipt) => PublicationDestination {
                path: StorePath::IngestionReceipt(receipt.file_name()),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::Replace,
                temp_prefix: "receipt",
            },
            Self::EgressReceipt(receipt) => PublicationDestination {
                path: StorePath::EgressReceipt(receipt.file_name()),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::Replace,
                temp_prefix: "egress-receipt",
            },
            Self::RepairEgressNar(output) => PublicationDestination {
                path: StorePath::Nar(output.file_name().to_string().into()),
                temporary_directory: TemporaryDirectory::Nar,
                publication: DestinationPublication::Repair(*output),
                temp_prefix: "nar",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::collection::{CollectionCoordinator, ProtectedObject};
    use super::*;

    #[test]
    fn renewal_destination_cannot_redirect_its_reader_permission_to_payload_or_other_metadata() {
        let coordinator = CollectionCoordinator::without_startup_grace();
        let store = StoreHash::parse("00000000000000000000000000000000").unwrap();
        let reader = coordinator
            .reader(ProtectedObject::Publication(store))
            .unwrap()
            .unwrap();
        let renewal = reader.advertisement_renewal().unwrap();
        let mut destination = PublishTarget::AdvertisementRenewal(&renewal).destination();
        destination.validate_path().unwrap();
        for path in [
            StorePath::Root("nix-cache-info".into()),
            StorePath::Nar("payload.nar".into()),
            StorePath::Advertisement("11111111111111111111111111111111.lease".into()),
        ] {
            destination.path = path;
            assert_eq!(
                destination.validate_path().unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
