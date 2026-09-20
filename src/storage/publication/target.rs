use std::ffi::OsString;
#[cfg(test)]
use std::path::PathBuf;

use super::super::{
    compression::IngestionReceipt, egress::EgressReceipt, ids::StoreHash, location::StorePath,
};
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
        self.root.join(format!("{}.narinfo", hash.as_str()))
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
    pub(crate) fn relative_path(&self) -> std::path::PathBuf {
        self.path.relative_path()
    }
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
                path: StorePath::Root(OsString::from("nix-cache-info")),
                temporary_directory: TemporaryDirectory::Root,
                publication: DestinationPublication::Link,
                temp_prefix: "cache-info",
            },
            Self::Nar(name) => PublicationDestination {
                path: StorePath::Nar(name.os_string()),
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
                path: StorePath::Nar(output.file_name().os_string()),
                temporary_directory: TemporaryDirectory::Nar,
                publication: DestinationPublication::Repair(*output),
                temp_prefix: "nar",
            },
        }
    }
}
