use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand};
use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use narjar::maintenance::FILE_NAMES as MAINTENANCE_FILES;
use narjar::storage::{
    CHUNK_DIRECTORY, Directory, EGRESS_RECEIPT_DIRECTORY, INGESTION_RECEIPT_DIRECTORY,
    LAYOUT_DESCRIPTOR, MANIFEST_DIRECTORY, NAR_DIRECTORY, REALISATIONS_DIRECTORY, Storage,
    StorageBackend, TEMPORARY_DIRECTORY, VALIDATION_DIRECTORY,
};

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

    if root.exists() {
        reject_unexpected_init_entries(&root)?;
        reject_unexpected_auth_entries(&root)?;
    } else {
        fs::create_dir_all(&root).map_err(runtime)?;
    }

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(runtime)?;
    create_recovery_marker(&root)?;
    create_file(
        &root.join(LAYOUT_DESCRIPTOR),
        storage_backend.layout_descriptor(),
        0o600,
        true,
    )?;
    let directory = Directory::open(&root).map_err(runtime)?;
    let storage = Storage::initialize(&directory, storage_backend).map_err(runtime)?;
    for directory in [
        NAR_DIRECTORY,
        TEMPORARY_DIRECTORY,
        REALISATIONS_DIRECTORY,
        VALIDATION_DIRECTORY,
        INGESTION_RECEIPT_DIRECTORY,
        EGRESS_RECEIPT_DIRECTORY,
        CHUNK_DIRECTORY,
        MANIFEST_DIRECTORY,
    ] {
        ensure_directory(&root.join(directory), 0o700)?;
    }
    ensure_directory(&root.join("auth"), 0o700)?;
    create_file(
        &root.join("nix-cache-info"),
        format!("StoreDir: /nix/store\nWantMassQuery: 0\nPriority: {priority}\n").as_bytes(),
        0o600,
        false,
    )?;
    create_file(&root.join("trusted-public-keys"), b"", 0o600, true)?;
    create_file(&root.join("auth/write.tokens"), b"", 0o600, true)?;
    if private_read || path_exists(&root.join("auth/read.tokens"))? {
        create_file(&root.join("auth/read.tokens"), b"", 0o600, true)?;
    }
    storage.finish_recovery().map_err(runtime)?;
    drop(storage);
    Ok(())
}

const INIT_ROOT_ENTRIES: &[&str] = &[
    ".narjar-clean",
    INGESTION_RECEIPT_DIRECTORY,
    EGRESS_RECEIPT_DIRECTORY,
    CHUNK_DIRECTORY,
    MANIFEST_DIRECTORY,
    ".narjar-recovery",
    LAYOUT_DESCRIPTOR,
    ".narjar-transactions",
    VALIDATION_DIRECTORY,
    TEMPORARY_DIRECTORY,
    "auth",
    NAR_DIRECTORY,
    "nix-cache-info",
    "lock",
    REALISATIONS_DIRECTORY,
    "trusted-public-keys",
];

fn reject_unexpected_init_entries(root: &Path) -> Result<(), Error> {
    let mut unexpected = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(runtime)? {
        let entry = entry.map_err(runtime)?;
        let name = entry.file_name();
        let allowed = INIT_ROOT_ENTRIES
            .iter()
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
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(".narjar-recovery"))
    {
        Ok(file) => file.sync_all().map_err(runtime)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(root.join(".narjar-recovery")).map_err(runtime)?;
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(Error::runtime(
                    "initialization recovery marker is not a regular 0600 file",
                ));
            }
        }
        Err(error) => return Err(runtime(error)),
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(runtime)
}

fn ensure_directory(path: &Path, mode: u32) -> Result<(), Error> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(runtime)?;
            if !metadata.file_type().is_dir() {
                return Err(Error::runtime(format!(
                    "initialization entry is not a directory: {}",
                    path.display()
                )));
            }
        }
        Err(error) => return Err(runtime(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(runtime)?;
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(runtime)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
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

    let mut seed = [0; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut seed))
        .map_err(runtime)?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();
    let mut secret = [0; 64];
    secret[..32].copy_from_slice(&seed);
    secret[32..].copy_from_slice(public.as_bytes());

    create_file(
        &secret_path,
        format!("{name}:{}\n", BASE64.encode(&secret)).as_bytes(),
        0o600,
        false,
    )?;
    if let Err(error) = create_file(
        &public_path,
        format!("{name}:{}\n", BASE64.encode(public.as_bytes())).as_bytes(),
        0o644,
        false,
    ) {
        let _ = fs::remove_file(&secret_path);
        return Err(error);
    }
    Ok(())
}
