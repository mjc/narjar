use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    mem::MaybeUninit,
    net::TcpStream,
    num::NonZeroUsize,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use clap::{Args, Subcommand};
use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use narjar::{
    inventory::{Inventory, InventoryClass, MAX_NARINFO_BYTES, narinfo_is_valid},
    narinfo::TrustedPublicKeys,
    storage::{
        ReconcileClass, Storage, StoreHash,
        gc::{self, GcOptions},
    },
};

use crate::error::Error;

#[derive(Args)]
pub(crate) struct Init {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value_t = 30)]
    priority: u32,
    #[arg(long)]
    private_read: bool,
}

pub(crate) fn init(options: Init) -> Result<(), Error> {
    let Init {
        data_dir: root,
        priority,
        private_read,
    } = options;

    if root.exists() {
        reject_unexpected_init_entries(&root)?;
        reject_unexpected_auth_entries(&root)?;
    } else {
        fs::create_dir_all(&root).map_err(runtime)?;
    }

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(runtime)?;
    create_recovery_marker(&root)?;
    let storage = Storage::initialize(&root).map_err(runtime)?;
    for directory in ["nar", ".tmp", "realisations"] {
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
    storage
        .finish_recovery(&root.join("trusted-public-keys"))
        .map_err(runtime)?;
    drop(storage);
    Ok(())
}

const INIT_ROOT_ENTRIES: &[&str] = &[
    ".narjar-clean",
    ".narjar-recovery",
    ".narjar-transactions",
    ".tmp",
    "auth",
    "nar",
    "nix-cache-info",
    "lock",
    "realisations",
    "trusted-public-keys",
];

fn reject_unexpected_init_entries(root: &Path) -> Result<(), Error> {
    let mut unexpected = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(runtime)? {
        let entry = entry.map_err(runtime)?;
        let name = entry.file_name();
        if !INIT_ROOT_ENTRIES
            .iter()
            .any(|allowed| name == std::ffi::OsStr::new(allowed))
        {
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
        Ok(file) => {
            file.sync_all().map_err(runtime)?;
        }
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

#[derive(Args)]
pub(crate) struct Reconcile {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    verify_hashes: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    structural: bool,
    #[arg(long, default_value_t = 10_000)]
    limit: usize,
    #[arg(long, default_value_t = 3_600)]
    min_age_seconds: u64,
}

pub(crate) fn reconcile(options: Reconcile) -> Result<(), Error> {
    if options.structural {
        return structural_report(
            options.data_dir,
            options.limit,
            options.min_age_seconds,
            options.json,
        );
    }
    report(
        options.data_dir,
        ReportMode::Reconcile,
        options.verify_hashes,
        options.json,
    )
}

#[derive(Args)]
pub(crate) struct Cleanup {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value_t = 3_600)]
    min_age_seconds: u64,
    #[arg(long, default_value_t = 10_000)]
    limit: usize,
    #[arg(long)]
    json: bool,
}

pub(crate) fn cleanup(options: Cleanup) -> Result<(), Error> {
    structural_scan(
        options.data_dir,
        options.limit,
        options.min_age_seconds,
        options.json,
        true,
    )
}

#[derive(Args)]
pub(crate) struct Verify {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    json: bool,
}

pub(crate) fn verify(options: Verify) -> Result<(), Error> {
    report(options.data_dir, ReportMode::Verify, false, options.json)
}

#[derive(Args)]
pub(crate) struct ListOrphans {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    verify_hashes: bool,
    #[arg(long)]
    json: bool,
}

pub(crate) fn list_orphans(options: ListOrphans) -> Result<(), Error> {
    report(
        options.data_dir,
        ReportMode::Orphans,
        options.verify_hashes,
        options.json,
    )
}

#[derive(Clone, Copy)]
enum ReportMode {
    Reconcile,
    Verify,
    Orphans,
}

impl ReportMode {
    const fn scans_content(self) -> bool {
        matches!(self, Self::Verify)
    }

    const fn only_orphans(self) -> bool {
        matches!(self, Self::Orphans)
    }
}

fn report(root: PathBuf, mode: ReportMode, verify_hashes: bool, json: bool) -> Result<(), Error> {
    let trusted = TrustedPublicKeys::load(&root.join("trusted-public-keys")).map_err(runtime)?;
    let inventory =
        Inventory::scan(&root, &trusted, mode.scans_content() || verify_hashes).map_err(runtime)?;

    for finding in inventory
        .entries()
        .iter()
        .filter(|finding| !mode.only_orphans() || finding.class() == InventoryClass::OrphanNar)
    {
        if json {
            println!(
                "{{\"class\":\"{}\",\"identifier\":\"{}\",\"action\":\"{}\"}}",
                finding.class(),
                json_escape(finding.identifier()),
                finding.class().action()
            );
        } else {
            println!(
                "{}\t{}\t{}",
                finding.class(),
                finding.identifier(),
                finding.class().action()
            );
        }
    }

    if mode.scans_content()
        && inventory
            .entries()
            .iter()
            .any(|finding| finding.class().invalid_published_pair())
    {
        return Err(Error::runtime("verification found invalid published pairs"));
    }
    Ok(())
}

fn structural_report(
    root: PathBuf,
    limit: usize,
    min_age_seconds: u64,
    json: bool,
) -> Result<(), Error> {
    structural_scan(root, limit, min_age_seconds, json, false)
}

fn structural_scan(
    root: PathBuf,
    limit: usize,
    min_age_seconds: u64,
    json: bool,
    cleanup: bool,
) -> Result<(), Error> {
    let limit =
        NonZeroUsize::new(limit).ok_or_else(|| Error::usage("limit must be greater than zero"))?;
    let stale_before = SystemTime::now()
        .checked_sub(Duration::from_secs(min_age_seconds))
        .ok_or_else(|| Error::usage("minimum age is out of range"))?;
    let storage = Storage::initialize(&root).map_err(runtime)?;
    let report = storage.reconcile(limit, stale_before).map_err(runtime)?;

    for entry in report.entries() {
        let action = if cleanup && entry.class() == ReconcileClass::TempStale {
            if storage.cleanup_stale_temp(entry).map_err(runtime)? {
                "deleted"
            } else {
                "kept_replaced"
            }
        } else if cleanup {
            "kept"
        } else {
            "inspect"
        };
        print_structural_entry(entry.class(), entry.relative_path(), action, json);
    }

    if report.truncated() {
        return Err(Error::runtime(format!(
            "structural reconciliation reached the --limit of {limit} entries"
        )));
    }
    Ok(())
}

fn print_structural_entry(class: ReconcileClass, path: &Path, action: &str, json: bool) {
    if json {
        println!(
            "{{\"class\":\"{}\",\"path\":\"{}\",\"action\":\"{}\"}}",
            class.as_str(),
            json_escape(&path.to_string_lossy()),
            action
        );
    } else {
        println!("{}\t{}\t{}", class.as_str(), path.display(), action);
    }
}

#[derive(Args)]
pub(crate) struct Gc {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    max_bytes: Option<u64>,
    #[arg(long)]
    target_bytes: Option<u64>,
    #[arg(long)]
    max_age_seconds: Option<u64>,
    #[arg(long, default_value_t = 0)]
    min_age_seconds: u64,
    #[arg(long)]
    protected_roots: Option<PathBuf>,
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
    #[arg(long)]
    json: bool,
}

pub(crate) fn gc(options: Gc) -> Result<(), Error> {
    let Gc {
        data_dir,
        max_bytes,
        target_bytes,
        max_age_seconds,
        min_age_seconds,
        protected_roots,
        dry_run: _,
        apply,
        json,
    } = options;
    let report = gc::run(GcOptions {
        data_dir,
        max_bytes,
        target_bytes,
        max_age: max_age_seconds.map(std::time::Duration::from_secs),
        min_age: std::time::Duration::from_secs(min_age_seconds),
        protected_roots,
        apply,
    })
    .map_err(runtime)?;

    if json {
        println!(
            "{{\"accounting_basis\":\"{}\",\"dry_run\":{},\"before_bytes\":{},\"after_bytes\":{},\"target_met\":{},\"candidates\":{},\"protected\":{},\"eligible\":{},\"evicted\":{},\"shared\":{},\"orphaned\":{},\"temporary\":{},\"malformed\":{},\"missing_roots\":{},\"missing_references\":{},\"protected_bytes\":{},\"eligible_bytes\":{},\"evicted_bytes\":{},\"shared_bytes\":{},\"orphaned_bytes\":{},\"temporary_bytes\":{},\"malformed_bytes\":{},\"deleted_narinfos\":{},\"deleted_nars\":{},\"deleted_orphans\":{}}}",
            report.accounting_basis,
            report.dry_run,
            report.before_bytes,
            report.after_bytes,
            report.target_met,
            report.candidates,
            report.protected,
            report.eligible,
            report.evicted,
            report.shared,
            report.orphaned,
            report.temporary,
            report.malformed,
            report.missing_roots,
            report.missing_references,
            report.protected_bytes,
            report.eligible_bytes,
            report.evicted_bytes,
            report.shared_bytes,
            report.orphaned_bytes,
            report.temporary_bytes,
            report.malformed_bytes,
            report.deleted_narinfos,
            report.deleted_nars,
            report.deleted_orphans,
        );
    } else {
        println!(
            "accounting_basis={} dry_run={} before_bytes={} after_bytes={} target_met={} candidates={} protected={} eligible={} evicted={} shared={} orphaned={} temporary={} malformed={} missing_roots={} missing_references={} protected_bytes={} eligible_bytes={} evicted_bytes={} shared_bytes={} orphaned_bytes={} temporary_bytes={} malformed_bytes={} deleted_narinfos={} deleted_nars={} deleted_orphans={}",
            report.accounting_basis,
            report.dry_run,
            report.before_bytes,
            report.after_bytes,
            report.target_met,
            report.candidates,
            report.protected,
            report.eligible,
            report.evicted,
            report.shared,
            report.orphaned,
            report.temporary,
            report.malformed,
            report.missing_roots,
            report.missing_references,
            report.protected_bytes,
            report.eligible_bytes,
            report.evicted_bytes,
            report.shared_bytes,
            report.orphaned_bytes,
            report.temporary_bytes,
            report.malformed_bytes,
            report.deleted_narinfos,
            report.deleted_nars,
            report.deleted_orphans,
        );
    }
    Ok(())
}

#[derive(Args)]
pub(crate) struct Delete {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    store_hash: String,
    #[arg(long)]
    json: bool,
}

pub(crate) fn delete(options: Delete) -> Result<(), Error> {
    let Delete {
        data_dir: root,
        store_hash: route,
        json,
    } = options;
    let store = StoreHash::parse(&route).map_err(|_| Error::usage("--store-hash is invalid"))?;
    let storage = Storage::initialize(&root).map_err(runtime)?;
    let trusted = TrustedPublicKeys::load(&root.join("trusted-public-keys")).map_err(runtime)?;
    let file = storage
        .open_narinfo(&store)
        .map_err(runtime)?
        .ok_or_else(|| Error::runtime("narinfo is not published"))?;
    let mut bytes = Vec::new();
    file.take(MAX_NARINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(runtime)?;
    if !narinfo_is_valid(&trusted, &store, bytes) {
        return Err(Error::runtime("narinfo is malformed or untrusted"));
    }
    storage.delete_narinfo(&store).map_err(runtime)?;

    if json {
        println!(
            "{{\"class\":\"deleted\",\"identifier\":\"{}\",\"action\":\"narinfo removed; NAR retained\"}}",
            json_escape(&route)
        );
    } else {
        println!("deleted\t{route}");
    }
    Ok(())
}

#[derive(Args)]
pub(crate) struct Doctor {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy)]
enum DoctorSeverity {
    Ok,
    Warning,
    Error,
    Unavailable,
}

impl DoctorSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Unavailable => "unavailable",
        }
    }
}

struct DoctorPath {
    path: &'static str,
    required: bool,
    kind: &'static str,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    severity: DoctorSeverity,
    detail: String,
}

struct DoctorCapacity {
    path: &'static str,
    total_bytes: u64,
    available_bytes: u64,
    total_inodes: u64,
    available_inodes: u64,
    read_only: bool,
    device: u64,
}

struct DoctorReport {
    root: PathBuf,
    paths: Vec<DoctorPath>,
    capacities: Vec<DoctorCapacity>,
    mount: DoctorSeverity,
    mount_detail: String,
    lease: DoctorSeverity,
    lease_detail: String,
}

const DOCTOR_DIRECTORIES: &[&str] = &[
    "",
    "nar",
    "nar/.tmp",
    ".tmp",
    "realisations",
    "realisations/.tmp",
    "auth",
];
const DOCTOR_FILES: &[&str] = &[
    "lock",
    "nix-cache-info",
    "trusted-public-keys",
    "auth/write.tokens",
];

pub(crate) fn doctor(options: Doctor) -> Result<(), Error> {
    let report = inspect_doctor(&options.data_dir)?;
    if options.json {
        println!("{}", doctor_json(&report));
    } else {
        print_doctor(&report);
    }
    Ok(())
}

fn inspect_doctor(root: &Path) -> Result<DoctorReport, Error> {
    let mut paths = Vec::new();
    for path in DOCTOR_DIRECTORIES {
        paths.push(inspect_doctor_path(root, path, true, true));
    }
    for path in DOCTOR_FILES {
        paths.push(inspect_doctor_path(root, path, true, false));
    }
    paths.push(inspect_doctor_path(root, "auth/read.tokens", false, false));

    let mut capacities = Vec::new();
    for (path, relative) in [("root", Path::new("")), ("nar", Path::new("nar"))] {
        if let Ok(capacity) = doctor_capacity(&root.join(relative)) {
            capacities.push(DoctorCapacity { path, ..capacity });
        }
    }
    let mount = match capacities.as_slice() {
        [root_capacity, nar_capacity] if root_capacity.device == nar_capacity.device => (
            DoctorSeverity::Ok,
            "root and NAR destination report the same device".to_owned(),
        ),
        [root_capacity, nar_capacity] => (
            DoctorSeverity::Warning,
            format!(
                "root device {} differs from NAR destination device {}",
                root_capacity.device, nar_capacity.device
            ),
        ),
        _ => (
            DoctorSeverity::Unavailable,
            "mount identity is unavailable".to_owned(),
        ),
    };

    let lease = match File::open(root) {
        Ok(file) => match doctor_try_lease(&file) {
            Ok(()) => (DoctorSeverity::Ok, "lease is available".to_owned()),
            Err(error)
                if error.raw_os_error() == Some(libc::EWOULDBLOCK)
                    || error.raw_os_error() == Some(libc::EAGAIN) =>
            {
                (
                    DoctorSeverity::Warning,
                    "lease is held by another process".to_owned(),
                )
            }
            Err(error) => (DoctorSeverity::Unavailable, error.to_string()),
        },
        Err(error) => (DoctorSeverity::Unavailable, error.to_string()),
    };

    Ok(DoctorReport {
        root: root.to_owned(),
        paths,
        capacities,
        mount: mount.0,
        mount_detail: mount.1,
        lease: lease.0,
        lease_detail: lease.1,
    })
}

fn inspect_doctor_path(
    root: &Path,
    relative: &'static str,
    required: bool,
    directory: bool,
) -> DoctorPath {
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return DoctorPath {
                path: relative,
                required,
                kind: "missing",
                mode: None,
                uid: None,
                gid: None,
                severity: DoctorSeverity::Ok,
                detail: "optional".to_owned(),
            };
        }
        Err(error) => {
            return DoctorPath {
                path: relative,
                required,
                kind: "missing",
                mode: None,
                uid: None,
                gid: None,
                severity: if required {
                    DoctorSeverity::Error
                } else {
                    DoctorSeverity::Unavailable
                },
                detail: error.to_string(),
            };
        }
    };
    let kind = if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    };
    let mode = metadata.mode() & 0o7777;
    let wrong_type = (directory && kind != "directory") || (!directory && kind != "file");
    let unsafe_mode = if directory {
        mode & 0o022 != 0
    } else {
        mode & 0o133 != 0
    };
    let severity = if wrong_type || unsafe_mode {
        DoctorSeverity::Error
    } else {
        DoctorSeverity::Ok
    };
    let detail = if wrong_type {
        format!(
            "expected {}, found {kind}",
            if directory {
                "directory"
            } else {
                "regular file"
            }
        )
    } else if unsafe_mode {
        format!("unsafe permissions {mode:04o}")
    } else {
        "matches portable layout contract".to_owned()
    };
    DoctorPath {
        path: relative,
        required,
        kind,
        mode: Some(mode),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        severity,
        detail,
    }
}

fn doctor_capacity(path: &Path) -> Result<DoctorCapacity, std::io::Error> {
    let file = File::open(path)?;
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(file.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let statistics = unsafe { statistics.assume_init() };
    let scale = statistics.f_frsize as u128;
    let bytes = |blocks: libc::fsblkcnt_t| {
        (blocks as u128)
            .saturating_mul(scale)
            .min(u128::from(u64::MAX)) as u64
    };
    Ok(DoctorCapacity {
        path: "",
        total_bytes: bytes(statistics.f_blocks),
        available_bytes: bytes(statistics.f_bavail),
        total_inodes: (statistics.f_files as u128).min(u128::from(u64::MAX)) as u64,
        available_inodes: (statistics.f_favail as u128).min(u128::from(u64::MAX)) as u64,
        read_only: statistics.f_flag & libc::ST_RDONLY != 0,
        device: file.metadata()?.dev(),
    })
}

fn doctor_try_lease(file: &File) -> Result<(), std::io::Error> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn doctor_json(report: &DoctorReport) -> String {
    let paths = report.paths.iter().map(|path| format!("{{\"path\":\"{}\",\"required\":{},\"kind\":\"{}\",\"mode\":{},\"uid\":{},\"gid\":{},\"severity\":\"{}\",\"detail\":\"{}\"}}", json_escape(path.path), path.required, json_escape(path.kind), path.mode.map_or_else(|| "null".to_owned(), |value| value.to_string()), path.uid.map_or_else(|| "null".to_owned(), |value| value.to_string()), path.gid.map_or_else(|| "null".to_owned(), |value| value.to_string()), path.severity.as_str(), json_escape(&path.detail))).collect::<Vec<_>>().join(",");
    let capacities = report.capacities.iter().map(|capacity| format!("{{\"path\":\"{}\",\"total_bytes\":{},\"available_bytes\":{},\"total_inodes\":{},\"available_inodes\":{},\"read_only\":{},\"device\":{}}}", capacity.path, capacity.total_bytes, capacity.available_bytes, capacity.total_inodes, capacity.available_inodes, capacity.read_only, capacity.device)).collect::<Vec<_>>().join(",");
    format!(
        "{{\"schema\":1,\"data_dir\":\"{}\",\"mount\":{{\"severity\":\"{}\",\"detail\":\"{}\"}},\"lease\":{{\"severity\":\"{}\",\"detail\":\"{}\"}},\"paths\":[{}],\"capacity\":[{}]}}",
        json_escape(&report.root.to_string_lossy()),
        report.mount.as_str(),
        json_escape(&report.mount_detail),
        report.lease.as_str(),
        json_escape(&report.lease_detail),
        paths,
        capacities
    )
}

fn print_doctor(report: &DoctorReport) {
    println!("data_dir\t{}", report.root.display());
    println!("mount\t{}\t{}", report.mount.as_str(), report.mount_detail);
    println!("lease\t{}\t{}", report.lease.as_str(), report.lease_detail);
    for capacity in &report.capacities {
        println!(
            "capacity\t{}\t{} bytes available / {} total\t{} inodes available / {} total\tread_only={}",
            capacity.path,
            capacity.available_bytes,
            capacity.total_bytes,
            capacity.available_inodes,
            capacity.total_inodes,
            capacity.read_only
        );
    }
    for path in &report.paths {
        println!(
            "path\t{}\t{}\t{}\t{}",
            path.path,
            path.severity.as_str(),
            path.kind,
            path.detail
        );
    }
}

#[derive(Args)]
pub(crate) struct Stats {
    #[arg(long)]
    url: String,
    #[arg(long)]
    netrc_file: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

pub(crate) fn stats(options: Stats) -> Result<(), Error> {
    let authority = options
        .url
        .strip_prefix("http://")
        .and_then(|url| url.split('/').next())
        .filter(|authority| !authority.is_empty())
        .ok_or_else(|| Error::usage("--url must be an http:// URL"))?;
    let authorization = options
        .netrc_file
        .as_deref()
        .map(|path| netrc_authorization(path, authority))
        .transpose()?;

    let mut stream = TcpStream::connect(authority).map_err(runtime)?;
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
    )
    .map_err(runtime)?;
    if let Some(authorization) = authorization {
        write!(stream, "Authorization: Basic {authorization}\r\n").map_err(runtime)?;
    }
    write!(stream, "\r\n").map_err(runtime)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(runtime)?;
    let split = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| Error::runtime("stats endpoint returned an invalid HTTP response"))?;
    let headers = String::from_utf8_lossy(&response[..split]);
    if !headers.starts_with("HTTP/1.1 200") {
        return Err(Error::runtime(format!(
            "stats endpoint failed: {}",
            headers.lines().next().unwrap_or("unknown status")
        )));
    }
    let body = String::from_utf8(response[split + 4..].to_vec())
        .map_err(|_| Error::runtime("stats endpoint returned non-UTF-8 metrics"))?;
    if options.json {
        println!("{{\"metrics\":\"{}\"}}", json_escape(&body));
    } else {
        print!("{body}");
    }
    Ok(())
}

pub(crate) fn netrc_authorization(path: &Path, authority: &str) -> Result<String, Error> {
    let text = fs::read_to_string(path).map_err(runtime)?;
    netrc_authorization_from_str(&text, authority)
}

fn netrc_authorization_from_str(text: &str, authority: &str) -> Result<String, Error> {
    let host = match authority
        .strip_prefix('[')
        .and_then(|authority| authority.split_once(']'))
    {
        Some((host, _)) => host,
        None => authority
            .split_once(':')
            .map_or(authority, |(host, _)| host),
    };
    let words: Vec<_> = text.split_whitespace().collect();
    let machine = words
        .windows(2)
        .position(|pair| pair == ["machine", host])
        .ok_or_else(|| Error::runtime("netrc has no matching machine"))?;
    let remaining = &words[machine + 2..];
    let entry_end = remaining
        .iter()
        .position(|word| *word == "machine")
        .unwrap_or(remaining.len());
    let fields = &remaining[..entry_end];
    let login = fields
        .windows(2)
        .find(|pair| pair[0] == "login")
        .map(|pair| pair[1])
        .ok_or_else(|| Error::runtime("netrc entry has no login"))?;
    let password = fields
        .windows(2)
        .find(|pair| pair[0] == "password")
        .map(|pair| pair[1])
        .ok_or_else(|| Error::runtime("netrc entry has no password"))?;
    Ok(BASE64.encode(format!("{login}:{password}").as_bytes()))
}

fn create_file(path: &Path, bytes: &[u8], mode: u32, preserve_existing: bool) -> Result<(), Error> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes).map_err(runtime)?;
            file.sync_all().map_err(runtime)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(runtime)?;
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != mode {
                return Err(Error::runtime(format!(
                    "initialization entry is not a regular {:o} file: {}",
                    mode,
                    path.display()
                )));
            }
            if !preserve_existing {
                let existing = fs::read(path).map_err(runtime)?;
                if existing != bytes {
                    return Err(Error::runtime(format!(
                        "initialization file differs from requested configuration: {}",
                        path.display()
                    )));
                }
            }
            File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(runtime)?;
        }
        Err(error) => return Err(runtime(error)),
    }
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(runtime)?;
    }
    Ok(())
}

fn valid_key_name(value: &str) -> Result<String, String> {
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then(|| value.to_owned())
    .ok_or_else(|| "must be 1-64 ASCII letters, digits, '.', '_' or '-'".to_owned())
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(error.to_string())
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netrc_entry_does_not_borrow_password_from_next_machine() {
        let error = netrc_authorization_from_str(
            "machine cache.example login cache-user
machine other.example password other-secret
",
            "cache.example:5000",
        )
        .expect_err("the matching machine has no password");

        assert_eq!(error.to_string(), "netrc entry has no password");
    }

    #[test]
    fn netrc_matches_a_bracketed_ipv6_authority() {
        let authorization = netrc_authorization_from_str(
            "machine ::1 login cache-user password cache-secret
",
            "[::1]:5000",
        )
        .expect("IPv6 machine should match");

        assert_eq!(authorization, BASE64.encode(b"cache-user:cache-secret"));
    }

    #[test]
    fn init_resumes_partial_layout_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        fs::create_dir(directory.path().join("nar")).expect("partial layout should be created");

        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
        })
        .expect("partial initialization should resume");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
        })
        .expect("completed initialization should be idempotent");

        assert!(directory.path().join(".narjar-clean").is_file());
        assert!(!directory.path().join(".narjar-recovery").exists());
        assert!(directory.path().join("auth/read.tokens").is_file());
    }

    #[test]
    fn init_preserves_existing_trust_and_token_material() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
        })
        .expect("initialization should succeed");

        fs::write(
            directory.path().join("trusted-public-keys"),
            b"cache.example-1:public-key",
        )
        .expect("trust material should be writable");
        fs::write(directory.path().join("auth/write.tokens"), b"write-secret")
            .expect("write token should be writable");
        fs::write(directory.path().join("auth/read.tokens"), b"read-secret")
            .expect("read token should be writable");

        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
        })
        .expect("retry should preserve existing material");

        assert_eq!(
            fs::read(directory.path().join("trusted-public-keys")).unwrap(),
            b"cache.example-1:public-key"
        );
        assert_eq!(
            fs::read(directory.path().join("auth/write.tokens")).unwrap(),
            b"write-secret"
        );
        assert_eq!(
            fs::read(directory.path().join("auth/read.tokens")).unwrap(),
            b"read-secret"
        );
    }

    #[test]
    fn init_rejects_unknown_entries_before_creating_recovery_state() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        fs::write(directory.path().join("unexpected"), b"do not touch")
            .expect("unexpected entry should be created");

        let error = init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
        })
        .expect_err("unknown entries should fail closed");

        assert!(error.to_string().contains("unexpected"));
        assert!(!directory.path().join(".narjar-recovery").exists());
    }

    #[test]
    fn doctor_json_reports_layout_and_capacity_without_inventory() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
        })
        .expect("cache should initialize");

        let report = inspect_doctor(directory.path()).expect("doctor should inspect cache");
        let json = doctor_json(&report);
        assert!(json.contains("\"schema\":1"));
        assert!(json.contains("\"mount\":{\"severity\":\"ok\""));
        assert!(json.contains("\"path\":\"nar\""));
        assert!(json.contains("\"total_bytes\":"));
        assert!(json.contains("\"lease\":{\"severity\":\"ok\""));
    }

    #[test]
    fn doctor_marks_wrong_fixed_path_type_as_error() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
        })
        .expect("cache should initialize");
        fs::remove_dir_all(directory.path().join("nar"))
            .expect("nar directory should be removable");
        fs::write(directory.path().join("nar"), b"wrong type")
            .expect("replacement should be writable");

        let report = inspect_doctor(directory.path()).expect("doctor should inspect cache");
        let nar = report
            .paths
            .iter()
            .find(|path| path.path == "nar")
            .expect("nar path should be reported");
        assert!(matches!(nar.severity, DoctorSeverity::Error));
        assert_eq!(nar.kind, "file");
    }

    #[test]
    fn doctor_detects_a_held_data_lease() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
        })
        .expect("cache should initialize");
        let held = File::open(directory.path()).expect("data directory should open");
        doctor_try_lease(&held).expect("test should hold the lease");

        let report = inspect_doctor(directory.path()).expect("doctor should inspect cache");
        assert!(matches!(report.lease, DoctorSeverity::Warning));
        assert!(report.lease_detail.contains("held"));
    }
}
