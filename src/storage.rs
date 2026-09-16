use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::{File, Permissions},
    io::{self, Cursor, Read},
    num::NonZeroUsize,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

#[cfg(test)]
use crate::narinfo::CompressedEncoding;
use crate::narinfo::{CompressedNarExpectation, NarEncoding, NarExpectation, ValidatedNarInfo};

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

use compression::{
    CheckedUploadReader, ValidationEvidence, nar_encoding, nar_file_matches, nar_file_size_matches,
    validate_compressed_nar, validate_xz, validate_zstd, validation_file_name,
};
#[cfg(test)]
use compression::{
    DecodedValidation, verify_decoded_compressed_file, verify_encoded_compressed_file,
};
pub(crate) use fs::{
    CapacityErrorKind, StorageCapacity, capacity_error_kind, entry_identity_at,
    entry_is_directory_at, entry_is_regular_at, for_each_dir_name, open_directory_at,
    open_regular_at, read_dir_names,
};
#[cfg(test)]
use fs::{FilesystemSpace, sync_dir};
use fs::{
    directory_is_empty, ensure_directory_at, files_equal_at, filesystem_space, hard_link_at,
    open_at, open_optional_at, remove_temp, rename_at, reserve_staging_bytes, rollback_link_at,
    unlink_at,
};

pub use directory::Directory;
pub use ids::{InvalidObjectId, NarObjectId, StoreHash};
pub(crate) use ids::{nix32_sha256, nix32_sha256_matches, parse_nix32};
#[cfg(test)]
pub(crate) use operations::{MAX_VALIDATION_EVIDENCE_BYTES, VALIDATION_DIRECTORY};
#[cfg(test)]
pub(crate) use publication::Layout;
#[cfg(test)]
pub(crate) use publication::injected_fault;
pub(crate) use publication::{
    NEXT_TEMP, ProcessLock, PublishBoundary, PublishTarget, TemporaryFile,
};
pub use publication::{
    NarUploadPolicy, PublishOutcome, PublishedPair, StagingReservation, StorageError,
};
pub use state::Storage;

pub use reconcile::{ReconcileClass, ReconcileEntry, ReconcileReport};
use recovery::{PublicationState, RecoveryState};

#[cfg(test)]
mod tests;
