use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, Permissions},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, atomic::AtomicU64},
};

use super::{
    EGRESS_RECEIPT_DIRECTORY, INGESTION_RECEIPT_DIRECTORY, LAYOUT_DESCRIPTOR, NAR_DIRECTORY,
    REALISATIONS_DIRECTORY, TEMPORARY_DIRECTORY, VALIDATION_DIRECTORY,
    chunk_store::ChunkStore,
    directory::Directory,
    fs::{directory_is_empty, ensure_directory_at, open_at, open_optional_at},
    publication::{ProcessLock, StorageError},
    recovery::RecoveryState,
    state::{DeliveryValidationCache, PayloadStorage, Storage, StorageBackend},
};

#[cfg(test)]
use super::publication::Layout;

impl Storage {
    pub fn initialize(root: &Directory, backend: StorageBackend) -> Result<Self, StorageError> {
        #[cfg(test)]
        let layout = Layout::new(root.path.clone());
        let root_directory = root.file.try_clone()?;
        let root_is_empty = directory_is_empty(&root_directory)?;
        let lock = ProcessLock::acquire(open_at(
            &root_directory,
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?)?;
        ProcessLock::validate_lock_file(&root_directory)?;
        let nar_directory =
            ensure_directory_at(&root_directory, OsStr::new(NAR_DIRECTORY), "nar directory")?;
        ensure_directory_at(
            &nar_directory,
            OsStr::new(TEMPORARY_DIRECTORY),
            "NAR temporary directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(TEMPORARY_DIRECTORY),
            "temporary directory",
        )?;
        let transactions = ensure_directory_at(
            &root_directory,
            OsStr::new(".narjar-transactions"),
            "publication transaction directory",
        )?;
        transactions.set_permissions(Permissions::from_mode(0o700))?;
        let realisations_directory = ensure_directory_at(
            &root_directory,
            OsStr::new(REALISATIONS_DIRECTORY),
            "realisations directory",
        )?;
        ensure_directory_at(
            &realisations_directory,
            OsStr::new(".tmp"),
            "realisation temporary directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(VALIDATION_DIRECTORY),
            "validation evidence directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(INGESTION_RECEIPT_DIRECTORY),
            "compressed ingestion receipt directory",
        )?;
        ensure_directory_at(
            &root_directory,
            OsStr::new(EGRESS_RECEIPT_DIRECTORY),
            "compressed egress receipt directory",
        )?;
        ensure_backend_layout(&root_directory, backend, root_is_empty)?;
        let payloads = match backend {
            StorageBackend::Flat => PayloadStorage::Flat,
            StorageBackend::Chunked => {
                PayloadStorage::Chunked(ChunkStore::initialize(&root_directory)?)
            }
        };

        root_directory.sync_all()?;

        let recovery = RecoveryState::new(&root_directory)?;
        let storage = Self {
            #[cfg(test)]
            layout,
            root: root_directory,
            payloads,
            recovery,
            delivery_validation: DeliveryValidationCache::default(),
            publication_locks: Mutex::new(HashMap::new()),
            staging_budget: Arc::new(Mutex::new(Default::default())),
            temporary_objects: AtomicU64::new(0),
            #[cfg(test)]
            egress_generations: AtomicU64::new(0),
            _lock: lock,
        };
        if root_is_empty {
            storage.recovery.initialize_clean()?;
        }
        Ok(storage)
    }

    #[cfg(test)]
    pub(super) fn layout(&self) -> &Layout {
        &self.layout
    }
}

fn ensure_backend_layout(
    root: &File,
    backend: StorageBackend,
    root_is_empty: bool,
) -> io::Result<()> {
    let name = OsStr::new(LAYOUT_DESCRIPTOR);
    match open_optional_at(root, name).map_err(storage_error_as_io)? {
        Some(descriptor) => {
            let mut bytes = Vec::new();
            descriptor.take(64).read_to_end(&mut bytes)?;
            match bytes == backend.layout_descriptor() {
                true => Ok(()),
                false => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data directory uses a different storage backend",
                )),
            }
        }
        None if !root_is_empty => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "initialized data directory is missing its storage-layout descriptor",
        )),
        None => {
            let mut descriptor = open_at(
                root,
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )?;
            descriptor.write_all(backend.layout_descriptor())?;
            descriptor.sync_all()?;
            root.sync_all()
        }
    }
}

fn storage_error_as_io(error: StorageError) -> io::Error {
    match error {
        StorageError::Io(error) => error,
        error => io::Error::new(io::ErrorKind::InvalidData, error.to_string()),
    }
}
