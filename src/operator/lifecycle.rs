use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use crate::cache::filesystem::{
    FileAccess, FileCreation, FilePrivacy, create_private_directory_tree, open_directory,
    open_writable_at, set_file_privacy, validate_private_file,
};
use crate::cache::maintenance::FILE_NAMES as MAINTENANCE_FILES;
use crate::cache::storage::{
    CacheCreation, Directory, StorageBackend, SupportedStorageBackend, storage_root_entries,
};
use clap::{Args, Subcommand};
use data_encoding::BASE64;
use ed25519_dalek::SigningKey;

use crate::error::Error;

use super::{create_file, runtime, valid_key_name};

#[derive(Args)]
pub(crate) struct Init {
    #[arg(long)]
    pub(crate) data_dir: PathBuf,
    #[arg(long, default_value_t = 30)]
    pub(crate) priority: u32,
    #[arg(long)]
    pub(crate) private_read: bool,
    #[arg(long, default_value = "flat")]
    pub(crate) storage_backend: StorageBackend,
}

pub(crate) fn init(options: Init) -> Result<(), Error> {
    let Init {
        data_dir: root,
        priority,
        private_read,
        storage_backend,
    } = options;
    let backend = SupportedStorageBackend::try_from(storage_backend)
        .map_err(|error| Error::usage(error.to_string()))?;
    initialize_cache(root, priority, private_read, backend)
}

pub(crate) fn initialize_cache(
    root: PathBuf,
    priority: u32,
    private_read: bool,
    backend: SupportedStorageBackend,
) -> Result<(), Error> {
    if root.exists() {
        reject_unexpected_init_entries(&root)?;
        reject_unexpected_auth_entries(&root)?;
    } else {
        create_private_directory_tree(&root).map_err(runtime)?;
    }

    let directory = Directory::open(&root).map_err(runtime)?;
    let creation = CacheCreation::prepare(&directory, backend).map_err(runtime)?;
    set_file_privacy(directory.file(), FilePrivacy::Private).map_err(runtime)?;
    create_recovery_marker(&root)?;
    let storage = creation.create_or_complete().map_err(runtime)?;
    ensure_directory(&root.join("auth"))?;
    create_file(
        &root.join("nix-cache-info"),
        format!("StoreDir: /nix/store\nWantMassQuery: 0\nPriority: {priority}\n").as_bytes(),
        FilePrivacy::Private,
        false,
    )?;
    create_file(
        &root.join("trusted-public-keys"),
        b"",
        FilePrivacy::Private,
        true,
    )?;
    create_file(
        &root.join("auth/write.tokens"),
        b"",
        FilePrivacy::Private,
        true,
    )?;
    if private_read || path_exists(&root.join("auth/read.tokens"))? {
        create_file(
            &root.join("auth/read.tokens"),
            b"",
            FilePrivacy::Private,
            true,
        )?;
    }
    storage.finish_recovery().map_err(runtime)?;
    drop(storage);
    Ok(())
}

const INIT_ROOT_ENTRIES: &[&str] = &["auth", "nix-cache-info", "trusted-public-keys"];

fn reject_unexpected_init_entries(root: &Path) -> Result<(), Error> {
    let mut unexpected = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(runtime)? {
        let entry = entry.map_err(runtime)?;
        let name = entry.file_name();
        let allowed = INIT_ROOT_ENTRIES
            .iter()
            .copied()
            .chain(storage_root_entries())
            .any(|allowed| name == std::ffi::OsStr::new(allowed))
            || MAINTENANCE_FILES
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed));
        if !allowed {
            unexpected.insert(name.to_string_lossy().into_owned());
        }
    }
    if unexpected.is_empty() {
        return Ok(());
    }
    Err(Error::runtime(format!(
        "data directory has unexpected entries: {}",
        unexpected.into_iter().collect::<Vec<_>>().join(", ")
    )))
}

fn reject_unexpected_auth_entries(root: &Path) -> Result<(), Error> {
    let auth = root.join("auth");
    let metadata = match fs::symlink_metadata(&auth) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(runtime(error)),
    };
    if !metadata.file_type().is_dir() {
        return Err(Error::runtime(format!(
            "initialization entry is not a directory: {}",
            auth.display()
        )));
    }
    let mut unexpected = BTreeSet::new();
    for entry in fs::read_dir(&auth).map_err(runtime)? {
        let name = entry.map_err(runtime)?.file_name();
        if !matches!(name.to_str(), Some("read.tokens" | "write.tokens")) {
            unexpected.insert(name.to_string_lossy().into_owned());
        }
    }
    if unexpected.is_empty() {
        return Ok(());
    }
    Err(Error::runtime(format!(
        "auth directory has unexpected entries: {}",
        unexpected.into_iter().collect::<Vec<_>>().join(", ")
    )))
}

fn path_exists(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(runtime(error)),
    }
}

fn create_recovery_marker(root: &Path) -> Result<(), Error> {
    let directory = open_directory(root).map_err(runtime)?;
    let marker = open_writable_at(
        &directory,
        std::ffi::OsStr::new(".narjar-recovery"),
        FileAccess::ReadWrite,
        FileCreation::OpenOrCreate,
        FilePrivacy::Private,
    )
    .map_err(runtime)?;
    validate_private_file(&marker).map_err(runtime)?;
    marker
        .sync_all()
        .and_then(|()| directory.sync_all())
        .map_err(runtime)
}

fn ensure_directory(path: &Path) -> Result<(), Error> {
    let directory = create_private_directory_tree(path).map_err(runtime)?;
    directory.sync_all().map_err(runtime)?;
    if let Some(parent) = path.parent() {
        open_directory(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(runtime)?;
    }
    Ok(())
}

#[derive(Args)]
pub(crate) struct Key {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Subcommand)]
enum KeyCommand {
    Generate(GenerateKey),
}

pub(crate) fn key(key: Key) -> Result<(), Error> {
    match key.command {
        KeyCommand::Generate(options) => generate_key(options),
    }
}

#[derive(Args)]
struct GenerateKey {
    #[arg(long, value_parser = valid_key_name)]
    name: String,
    #[arg(long)]
    secret_key_file: PathBuf,
    #[arg(long)]
    public_key_file: PathBuf,
}

fn generate_key(options: GenerateKey) -> Result<(), Error> {
    let GenerateKey {
        name,
        secret_key_file: secret_path,
        public_key_file: public_path,
    } = options;

    generate_key_pair(&name, &secret_path, &public_path)
}

pub(crate) fn generate_key_pair(
    name: &str,
    secret_path: &Path,
    public_path: &Path,
) -> Result<(), Error> {
    let mut seed = [0; 32];
    getrandom::getrandom(&mut seed).map_err(runtime)?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();
    let secret = signing.to_keypair_bytes();

    create_file(
        secret_path,
        format!("{name}:{}\n", BASE64.encode(&secret)).as_bytes(),
        FilePrivacy::Private,
        false,
    )?;
    if let Err(error) = create_file(
        public_path,
        format!("{name}:{}\n", BASE64.encode(public.as_bytes())).as_bytes(),
        FilePrivacy::Public,
        false,
    ) {
        let _ = fs::remove_file(secret_path);
        return Err(error);
    }
    Ok(())
}
