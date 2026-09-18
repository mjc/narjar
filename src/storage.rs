#[allow(dead_code)]
pub(crate) mod chunk_store;
#[allow(dead_code)]
pub(crate) mod chunked;
mod compression;
mod directory;
mod egress;
mod fs;
pub mod gc;
mod ids;
mod ingest;
pub(crate) mod inspection;
mod operations;
mod publication;
mod reconcile;
mod recovery;
mod state;

pub(crate) use fs::{
    CapacityErrorKind, StorageCapacity, capacity_error_kind, entry_identity_at,
    entry_is_directory_at, entry_is_regular_at, for_each_dir_name, open_directory_at,
    open_regular_at, read_dir_names,
};

pub use crate::object::{
    EncodedSize, FileHash, NarFileName, NarHash, NarIdentity, NarSize, WireEncoding,
};
pub use directory::Directory;
pub(crate) use egress::StoredNar;
pub use ids::{InvalidObjectId, StoreHash};
pub use publication::{
    NarUploadPolicy, PublishOutcome, PublishedPair, StagingReservation, StorageError,
};
pub use state::{Storage, StorageBackend};

pub(crate) use operations::NarReadBody;
pub use operations::{NarInfoDeletion, NarMatch, StorageReadiness};
pub use reconcile::{CleanupOutcome, ReconcileClass, ReconcileEntry, ReconcileReport};

pub const NAR_DIRECTORY: &str = "nar";
pub const TEMPORARY_DIRECTORY: &str = ".tmp";
pub const REALISATIONS_DIRECTORY: &str = "realisations";
pub const VALIDATION_DIRECTORY: &str = ".narjar-validation";
pub const INGESTION_RECEIPT_DIRECTORY: &str = ".narjar-ingress";
pub const EGRESS_RECEIPT_DIRECTORY: &str = ".narjar-egress";
pub const CHUNK_DIRECTORY: &str = ".narjar-chunks";
pub const MANIFEST_DIRECTORY: &str = ".narjar-manifests";

#[cfg(test)]
mod tests;
