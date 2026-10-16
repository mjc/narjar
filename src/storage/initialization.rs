use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, Permissions},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, atomic::AtomicU64},
};

use rustix::fs::OFlags;

use super::{
    LAYOUT_DESCRIPTOR, SupportedStorageBackend,
    backend::BackendSupport,
    chunk_store::ChunkStore,
    directory::Directory,
    fs::{
        ensure_directory_at, hard_link_at, open_at, open_optional_at, require_directory_at,
        require_private_file_at, unlink_at,
    },
    publication::{ProcessLock, StorageError},
    recovery::RecoveryState,
    state::{DeliveryValidationCache, PayloadStorage, Storage, StorageActivity},
};
use crate::{auth::Authorizer, narinfo::TrustedPublicKeys};

#[cfg(test)]
use super::publication::Layout;

const COMMON_DIRECTORIES: &[&str] = &[
    "nar",
    "nar/.tmp",
    ".tmp",
    "realisations",
    "realisations/.tmp",
    ".narjar-transactions",
    ".narjar-validation",
    ".narjar-ingress",
    ".narjar-egress",
];
const CHUNK_DIRECTORIES: &[&str] = &[".narjar-chunks", ".narjar-manifests"];
const DESCRIPTOR_DRAFT: &str = ".narjar-layout.next";
pub const CACHE_POLICY_DIRECTORIES: &[&str] = &["auth"];
pub const CACHE_POLICY_FILES: &[&str] =
    &["nix-cache-info", "trusted-public-keys", "auth/write.tokens"];
pub const CACHE_RECOVERY_MARKERS: [&str; 2] = [".narjar-clean", ".narjar-recovery"];

pub fn storage_directories(backend: SupportedStorageBackend) -> impl Iterator<Item = &'static str> {
    let backend_directories = match backend.0 {
        BackendSupport::Flat => &[][..],
        BackendSupport::Chunked(_) => CHUNK_DIRECTORIES,
    };
    COMMON_DIRECTORIES
        .iter()
        .chain(backend_directories)
        .copied()
}

pub fn storage_root_entries() -> impl Iterator<Item = &'static str> {
    storage_root_directories().chain(storage_root_files())
}

pub(super) fn storage_root_files() -> impl Iterator<Item = &'static str> {
    [LAYOUT_DESCRIPTOR, DESCRIPTOR_DRAFT, "lock"]
        .into_iter()
        .chain(CACHE_RECOVERY_MARKERS)
}

pub(super) fn storage_root_directories() -> impl Iterator<Item = &'static str> {
    COMMON_DIRECTORIES
        .iter()
        .copied()
        .chain(CHUNK_DIRECTORIES.iter().copied())
        .chain([".narjar-control"])
        .filter(|name| !name.contains('/'))
}

/// Startup policies loaded only from a complete, private policy layout.
pub struct CachePolicies {
    authorizer: Authorizer,
    trusted_keys: TrustedPublicKeys,
}

impl CachePolicies {
    pub fn load(root: &Directory) -> Result<Self, StorageError> {
        CACHE_POLICY_DIRECTORIES
            .iter()
            .try_for_each(|name| require_directory_at(&root.file, name).map(drop))?;
        CACHE_POLICY_FILES.iter().try_for_each(|name| {
            let (parent, leaf) = directory_parent(&root.file, name)?;
            require_private_file_at(&parent, leaf, true).map(|_| ())
        })?;
        let invalid_policy = |error| io::Error::new(io::ErrorKind::InvalidData, error);
        Ok(Self {
            authorizer: Authorizer::load(root).map_err(invalid_policy)?,
            trusted_keys: TrustedPublicKeys::load(root)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        })
    }

    pub fn into_parts(self) -> (Authorizer, TrustedPublicKeys) {
        (self.authorizer, self.trusted_keys)
    }
}

/// Owns the exclusive directory lease while completing an initialization.
/// A prepared creation cannot be reused after transferring its lease to storage.
/// ```compile_fail
/// use narjar::__private::storage::{CacheCreation, Directory, SupportedStorageBackend};
/// fn initialize_twice(root: &Directory) {
///     let creation = CacheCreation::prepare(root, SupportedStorageBackend::FLAT).unwrap();
///     let _ = creation.create_or_complete();
///     let _ = creation.create_or_complete();
/// }
/// ```
pub struct CacheCreation {
    layout: CacheLayout,
    descriptor: DescriptorInstallation,
}

impl CacheCreation {
    pub fn prepare(
        root: &Directory,
        backend: SupportedStorageBackend,
    ) -> Result<Self, StorageError> {
        let layout = CacheLayout::lock(root, backend)?;
        let descriptor = layout.prepare_descriptor()?;
        Ok(Self { layout, descriptor })
    }

    pub fn create_or_complete(self) -> Result<Storage, StorageError> {
        self.descriptor.install(&self.layout)?;
        self.layout.create_directories()?;
        ProcessLock::validate_lock_file(&self.layout.root)?;
        let storage = self.layout.into_storage()?;
        storage.recovery.initialize_clean()?;
        Ok(storage)
    }
}

enum DescriptorInstallation {
    Existing(File),
    Create,
}

impl DescriptorInstallation {
    fn install(self, layout: &CacheLayout) -> Result<(), StorageError> {
        remove_descriptor_draft(&layout.root)?;
        match self {
            Self::Existing(file) => file.sync_all().map_err(Into::into),
            Self::Create => install_complete_descriptor(&layout.root, layout.backend),
        }
    }
}

fn remove_descriptor_draft(root: &File) -> Result<(), StorageError> {
    match open_optional_at(root, OsStr::new(DESCRIPTOR_DRAFT))? {
        None => Ok(()),
        Some(_) => {
            require_private_file_at(root, DESCRIPTOR_DRAFT, true)?;
            unlink_at(root, OsStr::new(DESCRIPTOR_DRAFT))?;
            root.sync_all()?;
            Ok(())
        }
    }
}

fn install_complete_descriptor(
    root: &File,
    backend: SupportedStorageBackend,
) -> Result<(), StorageError> {
    let draft = OsStr::new(DESCRIPTOR_DRAFT);
    let result = (|| -> Result<(), StorageError> {
        let mut file = open_at(
            root,
            draft,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            0o600,
        )?;
        file.write_all(backend.backend().layout_descriptor())?;
        file.sync_all()?;
        hard_link_at(root, draft, root, OsStr::new(LAYOUT_DESCRIPTOR))?;
        root.sync_all()?;
        Ok(())
    })();
    let cleanup = remove_descriptor_draft(root);
    result.and(cleanup)
}

struct CacheLayout {
    root: File,
    backend: SupportedStorageBackend,
    lock: ProcessLock,
    #[cfg(test)]
    test_layout: Layout,
}

impl CacheLayout {
    fn lock(root: &Directory, backend: SupportedStorageBackend) -> Result<Self, StorageError> {
        let directory = root.file.try_clone()?;
        let lock = ProcessLock::acquire(open_at(
            &directory,
            OsStr::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            0,
        )?)?;
        Ok(Self {
            root: directory,
            backend,
            lock,
            #[cfg(test)]
            test_layout: Layout::new(root.path.clone()),
        })
    }

    fn prepare_descriptor(&self) -> Result<DescriptorInstallation, StorageError> {
        match open_optional_at(&self.root, OsStr::new(LAYOUT_DESCRIPTOR))? {
            None => Ok(DescriptorInstallation::Create),
            Some(mut descriptor) => {
                let mut bytes = Vec::new();
                (&mut descriptor).take(64).read_to_end(&mut bytes)?;
                self.check_descriptor(&bytes)?;
                require_private_file_at(&self.root, LAYOUT_DESCRIPTOR, true)?;
                Ok(DescriptorInstallation::Existing(descriptor))
            }
        }
    }

    fn check_descriptor(&self, bytes: &[u8]) -> Result<(), StorageError> {
        match bytes == self.backend.backend().layout_descriptor() {
            true => Ok(()),
            false => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data directory uses a different storage backend",
            )
            .into()),
        }
    }

    fn require_descriptor(&self) -> Result<(), StorageError> {
        match self.prepare_descriptor()? {
            DescriptorInstallation::Existing(_) => Ok(()),
            DescriptorInstallation::Create => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "initialized data directory is missing its storage-layout descriptor",
            )
            .into()),
        }
    }

    fn create_directories(&self) -> io::Result<()> {
        storage_directories(self.backend).try_for_each(|name| {
            let (parent, leaf) = directory_parent(&self.root, name)?;
            let directory =
                ensure_directory_at(&parent, OsStr::new(leaf), &format!("{name} directory"))?;
            directory.set_permissions(Permissions::from_mode(0o700))?;
            directory.sync_all()?;
            parent.sync_all()
        })
    }

    fn validate_existing(&self) -> Result<(), StorageError> {
        self.require_descriptor()?;
        storage_directories(self.backend).try_for_each(|name| {
            let (parent, leaf) = directory_parent(&self.root, name)?;
            require_directory_at(&parent, leaf).map(drop)
        })?;
        require_private_file_at(&self.root, "lock", true)?;
        let [clean, recovery] = CACHE_RECOVERY_MARKERS;
        match (
            require_private_file_at(&self.root, clean, false)?,
            require_private_file_at(&self.root, recovery, false)?,
        ) {
            (false, false) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "data directory is not initialized",
            )
            .into()),
            _ => Ok(()),
        }
    }

    fn into_storage(self) -> Result<Storage, StorageError> {
        let activity = Arc::new(StorageActivity::default());
        let payloads = match self.backend.0 {
            BackendSupport::Flat => PayloadStorage::Flat,
            BackendSupport::Chunked(durability) => PayloadStorage::Chunked(ChunkStore::open(
                &self.root,
                durability,
                Arc::clone(&activity),
            )?),
        };
        let recovery = RecoveryState::new(&self.root)?;
        Ok(Storage {
            #[cfg(test)]
            layout: self.test_layout,
            root: self.root,
            payloads,
            recovery,
            collection: Default::default(),
            delivery_validation: DeliveryValidationCache::default(),
            publication_locks: Mutex::new(HashMap::new()),
            staging_budget: Arc::new(Mutex::new(Default::default())),
            temporary_objects: AtomicU64::new(0),
            activity,
            #[cfg(test)]
            egress_generations: AtomicU64::new(0),
            _lock: self.lock,
        })
    }
}

fn directory_parent<'name>(root: &File, name: &'name str) -> io::Result<(File, &'name str)> {
    match name.split_once('/') {
        Some((parent, leaf)) => Ok((require_directory_at(root, parent)?, leaf)),
        None => Ok((root.try_clone()?, name)),
    }
}

impl Storage {
    pub fn open(root: &Directory, backend: SupportedStorageBackend) -> Result<Self, StorageError> {
        let layout = CacheLayout::lock(root, backend)?;
        layout.validate_existing()?;
        layout.into_storage()
    }

    #[cfg(test)]
    pub(super) fn layout(&self) -> &Layout {
        &self.layout
    }
}
