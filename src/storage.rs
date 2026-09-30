#[path = "storage/cache_info.rs"]
mod cache_info;
#[allow(dead_code)]
#[path = "storage/chunk_store.rs"]
pub(crate) mod chunk_store;
#[allow(dead_code)]
#[path = "storage/chunked.rs"]
pub(crate) mod chunked;
#[path = "storage/compression.rs"]
mod compression;
#[path = "storage/directory.rs"]
mod directory;
#[path = "storage/egress.rs"]
mod egress;
#[path = "storage/fs.rs"]
mod fs;
#[path = "storage/gc.rs"]
pub mod gc;
#[path = "storage/ids.rs"]
mod ids;
#[path = "storage/ingest.rs"]
mod ingest;
#[path = "storage/initialization.rs"]
mod initialization;
#[path = "storage/inspection.rs"]
pub(crate) mod inspection;
#[path = "storage/location.rs"]
mod location;
#[path = "storage/operations.rs"]
mod operations;
#[path = "storage/population.rs"]
mod population;
#[path = "storage/publication/mod.rs"]
mod publication;
#[path = "storage/receipt.rs"]
mod receipt;
#[path = "storage/reconcile.rs"]
mod reconcile;
#[path = "storage/recovery.rs"]
mod recovery;
#[path = "storage/state.rs"]
mod state;
#[path = "storage/typestate.rs"]
mod typestate;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CleanupAction {
    Keep,
    Remove,
}

impl CleanupAction {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Remove, _) | (_, Self::Remove) => Self::Remove,
            (Self::Keep, Self::Keep) => Self::Keep,
        }
    }
}

pub(crate) use fs::{
    CapacityErrorKind, DirectoryEntryAction, DirectoryScanOutcome, StorageCapacity,
    capacity_error_kind, entry_identity_at, entry_is_directory_at, entry_is_regular_at,
    for_each_dir_name, open_directory_at, open_regular_at, read_dir_names,
};

pub use crate::object::{
    EncodedSize, FileHash, NarFileName, NarHash, NarIdentity, NarSize, WireEncoding,
};
pub use directory::Directory;
pub(crate) use egress::{NarReadBody, VerifiedCanonicalNar};
pub use ids::{InvalidObjectId, StoreHash};
pub use publication::{NarUploadPolicy, PublishOutcome, StagingReservation, StorageError};
pub(crate) use state::StorageActivitySnapshot;
pub use state::{InvalidStorageBackend, Storage, StorageBackend};

pub use operations::{NarInfoDeletion, NarMatch, StorageReadiness};
pub use population::PopulationCounts;
pub use reconcile::{CleanupOutcome, ReconcileClass, ReconcileEntry, ReconcileReport};

pub const NAR_DIRECTORY: &str = "nar";
pub const TEMPORARY_DIRECTORY: &str = ".tmp";
pub const REALISATIONS_DIRECTORY: &str = "realisations";
pub const VALIDATION_DIRECTORY: &str = ".narjar-validation";
pub const INGESTION_RECEIPT_DIRECTORY: &str = ".narjar-ingress";
pub const EGRESS_RECEIPT_DIRECTORY: &str = ".narjar-egress";
pub const CHUNK_DIRECTORY: &str = ".narjar-chunks";
pub const MANIFEST_DIRECTORY: &str = ".narjar-manifests";
pub const LAYOUT_DESCRIPTOR: &str = ".narjar-layout";

#[cfg(test)]
#[path = "storage/tests.rs"]
mod tests;
