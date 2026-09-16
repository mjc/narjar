mod compression;
mod directory;
mod fs;
pub mod gc;
mod ids;
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

pub use directory::Directory;
pub use ids::{InvalidObjectId, NarObjectId, StoreHash};
pub use publication::{
    NarUploadPolicy, PublishOutcome, PublishedPair, StagingReservation, StorageError,
};
pub use state::Storage;

pub use reconcile::{ReconcileClass, ReconcileEntry, ReconcileReport};

#[cfg(test)]
mod tests;
