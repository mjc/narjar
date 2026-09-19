use std::ffi::OsString;

#[cfg(test)]
use std::path::PathBuf;

use super::super::{compression::IngestionReceipt, egress::EgressReceipt, ids::StoreHash};
use crate::object::{EncodedIdentity, NarFileName};

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

    pub(crate) fn nar_path(&self, hash: crate::object::NarHash) -> PathBuf {
        self.nar_dir().join(NarFileName::raw(hash).to_string())
    }

    pub(crate) fn nar_path_encoded(&self, name: NarFileName) -> PathBuf {
        self.nar_dir().join(name.to_string())
    }

    pub(crate) fn nar_temp_dir(&self) -> PathBuf {
        self.nar_dir().join(".tmp")
    }

    pub(crate) fn narinfo_path(&self, hash: &StoreHash) -> PathBuf {
        self.root.join(format!("{}.narinfo", hash.0))
    }

    pub(crate) fn temp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
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
}

#[derive(Clone, Copy)]
pub(crate) enum PublicationDirectory {
    Root,
    Nar,
    IngestionReceipts,
    EgressReceipts,
}

#[derive(Clone, Copy)]
pub(crate) enum TemporaryDirectory {
    Root,
    Nar,
}

pub(crate) struct PublicationDestination {
    pub(crate) directory: PublicationDirectory,
    pub(crate) temporary_directory: TemporaryDirectory,
    pub(crate) name: OsString,
    pub(crate) publication: DestinationPublication,
    pub(crate) temp_prefix: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) enum DestinationPublication {
    Link,
    Replace,
    Repair(EncodedIdentity),
}

impl PublishTarget<'_> {
    pub(crate) fn destination(&self) -> PublicationDestination {
        match self {
            Self::CacheInfo => PublicationDestination {
                directory: PublicationDirectory::Root,
                temporary_directory: TemporaryDirectory::Root,
                name: OsString::from("nix-cache-info"),
                publication: DestinationPublication::Link,
                temp_prefix: "cache-info",
            },
            Self::Nar(name) => PublicationDestination {
                directory: PublicationDirectory::Nar,
                temporary_directory: TemporaryDirectory::Nar,
                name: name.os_string(),
                publication: DestinationPublication::Link,
                temp_prefix: "nar",
            },
            Self::NarInfo(store) => PublicationDestination {
                directory: PublicationDirectory::Root,
                temporary_directory: TemporaryDirectory::Root,
                name: OsString::from(format!("{}.narinfo", store.as_str())),
                publication: DestinationPublication::Link,
                temp_prefix: "narinfo",
            },
            Self::IngestionReceipt(receipt) => PublicationDestination {
                directory: PublicationDirectory::IngestionReceipts,
                temporary_directory: TemporaryDirectory::Root,
                name: receipt.file_name(),
                publication: DestinationPublication::Replace,
                temp_prefix: "receipt",
            },
            Self::EgressReceipt(receipt) => PublicationDestination {
                directory: PublicationDirectory::EgressReceipts,
                temporary_directory: TemporaryDirectory::Root,
                name: receipt.file_name(),
                publication: DestinationPublication::Replace,
                temp_prefix: "egress-receipt",
            },
            Self::RepairEgressNar(output) => PublicationDestination {
                directory: PublicationDirectory::Nar,
                temporary_directory: TemporaryDirectory::Nar,
                name: output.file_name().os_string(),
                publication: DestinationPublication::Repair(*output),
                temp_prefix: "nar",
            },
        }
    }
}
