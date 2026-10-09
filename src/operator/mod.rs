use std::{
    fs::{self, File},
    io::Write,
    num::{NonZeroU64, NonZeroUsize},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use clap::{Args, builder::TypedValueParser};
use data_encoding::BASE64;
use narjar::__private::{
    inventory::{Inventory, InventoryClass, InventoryEntry, VerificationMode},
    maintenance::{
        Mode as MaintenanceMode, Operation as MaintenanceOperation, Outcome as MaintenanceOutcome,
        RunValues as MaintenanceValues,
    },
    narinfo::{TrustedPublicKeys, read_narinfo_file},
    storage::{
        CACHE_POLICY_DIRECTORIES, CACHE_POLICY_FILES, CACHE_RECOVERY_MARKERS, CachePolicies,
        CleanupOutcome, Directory, LAYOUT_DESCRIPTOR, ReconcileClass, Storage, StorageBackend,
        StorageCapacity, StoreHash, SupportedStorageBackend, capacity_from_statvfs,
        gc::{self, GcMode, GcOptions, GcReport},
        private_file_mode_is_valid, storage_directories,
    },
};
use narjar::object::WireEncoding;
use serde::Serialize;
use ureq::Agent;

use crate::{
    config::{ServeSource, ServeSourceChoice, SourcePreparationError},
    error::Error,
    http_url::HttpUrl,
    native_store::{NativeStoreOptions, NativeStoreSettings},
};

mod lifecycle;
mod maintenance_session;
pub(crate) use lifecycle::{Init, Key, generate_key_pair, init, initialize_cache, key};
use maintenance_session::{MaintenanceRecord, MaintenanceSession, record_maintenance_result};

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
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
}

pub(crate) fn reconcile(options: Reconcile) -> Result<(), Error> {
    if options.structural {
        return structural_report(
            options.data_dir,
            options.limit,
            options.min_age_seconds,
            options.json,
            options.storage_backend,
        );
    }
    report(
        options.data_dir,
        ReportMode::Reconcile,
        options.verify_hashes,
        options.json,
        options.storage_backend,
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
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
}

pub(crate) fn cleanup(options: Cleanup) -> Result<(), Error> {
    structural_scan(
        options.data_dir,
        options.limit,
        options.min_age_seconds,
        options.json,
        options.storage_backend,
        StructuralAction::Cleanup,
    )
}

#[derive(Args)]
pub(crate) struct Verify {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
}

pub(crate) fn verify(options: Verify) -> Result<(), Error> {
    report(
        options.data_dir,
        ReportMode::Verify,
        false,
        options.json,
        options.storage_backend,
    )
}

#[derive(Args)]
pub(crate) struct ListOrphans {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    verify_hashes: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
}

pub(crate) fn list_orphans(options: ListOrphans) -> Result<(), Error> {
    report(
        options.data_dir,
        ReportMode::Orphans,
        options.verify_hashes,
        options.json,
        options.storage_backend,
    )
}

#[derive(Clone, Copy)]
enum ReportMode {
    Reconcile,
    Verify,
    Orphans,
}

impl ReportMode {
    const fn verification_mode(self, verify_hashes: bool) -> VerificationMode {
        match self {
            Self::Verify => VerificationMode::Content,
            Self::Reconcile | Self::Orphans if verify_hashes => VerificationMode::Content,
            Self::Reconcile | Self::Orphans => VerificationMode::Availability,
        }
    }

    fn includes_finding(self, class: InventoryClass) -> bool {
        match self {
            Self::Reconcile | Self::Verify => true,
            Self::Orphans => class == InventoryClass::OrphanNar,
        }
    }

    fn maintenance_record(self) -> Option<MaintenanceRecord> {
        match self {
            Self::Reconcile => Some(MaintenanceRecord::new(
                MaintenanceOperation::Reconcile,
                MaintenanceMode::Reconcile,
            )),
            Self::Verify => Some(MaintenanceRecord::new(
                MaintenanceOperation::Verify,
                MaintenanceMode::Verify,
            )),
            Self::Orphans => None,
        }
    }

    const fn verification_failed(self, invalid_pairs: u64) -> bool {
        match self {
            Self::Verify => invalid_pairs != 0,
            Self::Reconcile | Self::Orphans => false,
        }
    }
}

fn report(
    root: PathBuf,
    mode: ReportMode,
    verify_hashes: bool,
    json: bool,
    backend: narjar::__private::storage::StorageBackend,
) -> Result<(), Error> {
    let session = MaintenanceSession::open(&root, backend, mode.maintenance_record())?;
    session.run_inspection(|storage, trusted| {
        let inventory = scan_inventory(storage, trusted, mode.verification_mode(verify_hashes))?;
        let inventory_class_counts = inventory_class_counts(&inventory);
        let invalid_pairs = invalid_published_pair_count(&inventory);
        print_inventory_findings(&inventory, mode, json)?;

        let failed_verification = mode.verification_failed(invalid_pairs);
        Ok((
            if failed_verification {
                Err(Error::runtime("verification found invalid published pairs"))
            } else {
                Ok(())
            },
            if failed_verification {
                MaintenanceOutcome::Failure
            } else {
                MaintenanceOutcome::Success
            },
            MaintenanceValues {
                objects_examined: Some(inventory.entries().len() as u64),
                inventory_class_counts: Some(inventory_class_counts),
                ..MaintenanceValues::default()
            },
        ))
    })?
}

fn scan_inventory(
    storage: &Storage,
    trusted: &TrustedPublicKeys,
    verification: VerificationMode,
) -> Result<Inventory, Error> {
    Inventory::scan_storage(storage, trusted, verification).map_err(runtime)
}

fn inventory_class_counts(inventory: &Inventory) -> [u64; InventoryClass::ALL.len()] {
    std::array::from_fn(|index| {
        let class = InventoryClass::ALL[index];
        inventory
            .entries()
            .iter()
            .filter(|finding| finding.class() == class)
            .count() as u64
    })
}

fn invalid_published_pair_count(inventory: &Inventory) -> u64 {
    inventory
        .entries()
        .iter()
        .filter(|finding| finding.class().invalid_published_pair())
        .count() as u64
}

fn print_inventory_findings(
    inventory: &Inventory,
    mode: ReportMode,
    json: bool,
) -> Result<(), Error> {
    inventory
        .entries()
        .iter()
        .filter(|finding| mode.includes_finding(finding.class()))
        .try_for_each(|finding| print_inventory_finding(finding, json))
}

#[derive(Serialize)]
struct FindingRecord<'a> {
    class: &'a str,
    identifier: &'a str,
    action: &'a str,
}

fn print_inventory_finding(finding: &InventoryEntry, json: bool) -> Result<(), Error> {
    if json {
        write_json_line(
            std::io::stdout().lock(),
            &FindingRecord {
                class: finding.class().as_str(),
                identifier: finding.identifier(),
                action: finding.class().action(),
            },
        )?;
    } else {
        println!(
            "{}\t{}\t{}",
            finding.class(),
            finding.identifier(),
            finding.class().action()
        );
    }
    Ok(())
}

fn structural_report(
    root: PathBuf,
    limit: usize,
    min_age_seconds: u64,
    json: bool,
    backend: narjar::__private::storage::StorageBackend,
) -> Result<(), Error> {
    structural_scan(
        root,
        limit,
        min_age_seconds,
        json,
        backend,
        StructuralAction::Inspect,
    )
}

#[derive(Clone, Copy)]
enum StructuralAction {
    Inspect,
    Cleanup,
}

fn structural_scan(
    root: PathBuf,
    limit: usize,
    min_age_seconds: u64,
    json: bool,
    backend: narjar::__private::storage::StorageBackend,
    action: StructuralAction,
) -> Result<(), Error> {
    let options = StructuralScanOptions::new(limit, min_age_seconds)?;
    let record = MaintenanceRecord::new(MaintenanceOperation::Reconcile, action.maintenance_mode());
    let session = MaintenanceSession::open(&root, backend, Some(record))?;
    match action {
        StructuralAction::Inspect => session.run_inspection(|storage, _| {
            run_structural_scan(storage, options, json, action)
                .map(|values| ((), MaintenanceOutcome::Success, values))
        }),
        StructuralAction::Cleanup => session.run_mutation(|recovered, _| {
            run_structural_scan(recovered.storage(), options, json, action)
                .map(|values| ((), MaintenanceOutcome::Success, values))
        }),
    }
}

struct StructuralScanOptions {
    limit: NonZeroUsize,
    stale_before: SystemTime,
}

impl StructuralScanOptions {
    fn new(limit: usize, min_age_seconds: u64) -> Result<Self, Error> {
        let limit = NonZeroUsize::new(limit)
            .ok_or_else(|| Error::usage("limit must be greater than zero"))?;
        let stale_before = SystemTime::now()
            .checked_sub(Duration::from_secs(min_age_seconds))
            .ok_or_else(|| Error::usage("minimum age is out of range"))?;
        Ok(Self {
            limit,
            stale_before,
        })
    }
}

impl StructuralAction {
    const fn maintenance_mode(self) -> MaintenanceMode {
        match self {
            Self::Inspect => MaintenanceMode::Structural,
            Self::Cleanup => MaintenanceMode::Cleanup,
        }
    }
}

fn run_structural_scan(
    storage: &Storage,
    options: StructuralScanOptions,
    json: bool,
    action: StructuralAction,
) -> Result<MaintenanceValues, Error> {
    let report = storage
        .reconcile(options.limit, options.stale_before)
        .map_err(runtime)?;
    let removed_entries = report.entries().iter().try_fold(0_u64, |removed, entry| {
        process_structural_entry(storage, entry, action, json)
            .map(|result| removed.saturating_add(result.removed_count()))
    })?;

    if report.truncated() {
        return Err(Error::runtime(format!(
            "structural reconciliation reached the --limit of {} entries",
            options.limit
        )));
    }
    Ok(MaintenanceValues {
        objects_examined: Some(report.entries().len() as u64),
        objects_reclaimed: action.reclaimed_entries(removed_entries),
        ..MaintenanceValues::default()
    })
}

#[derive(Clone, Copy)]
enum StructuralEntryResult {
    Kept,
    Removed,
}

impl StructuralEntryResult {
    const fn removed_count(self) -> u64 {
        match self {
            Self::Kept => 0,
            Self::Removed => 1,
        }
    }
}

impl StructuralAction {
    const fn reclaimed_entries(self, removed: u64) -> Option<u64> {
        match self {
            Self::Inspect => None,
            Self::Cleanup => Some(removed),
        }
    }
}

fn process_structural_entry(
    storage: &Storage,
    entry: &narjar::__private::storage::ReconcileEntry,
    action: StructuralAction,
    json: bool,
) -> Result<StructuralEntryResult, Error> {
    let (output_action, result) = structural_entry_action(storage, entry, action)?;
    print_structural_entry(entry.class(), entry.relative_path(), output_action, json)?;
    Ok(result)
}

fn structural_entry_action(
    storage: &Storage,
    entry: &narjar::__private::storage::ReconcileEntry,
    action: StructuralAction,
) -> Result<(&'static str, StructuralEntryResult), Error> {
    match action {
        StructuralAction::Inspect => Ok(("inspect", StructuralEntryResult::Kept)),
        StructuralAction::Cleanup => cleanup_structural_entry(storage, entry),
    }
}

fn cleanup_structural_entry(
    storage: &Storage,
    entry: &narjar::__private::storage::ReconcileEntry,
) -> Result<(&'static str, StructuralEntryResult), Error> {
    match entry.class() {
        ReconcileClass::TempStale => match storage.cleanup_stale_temp(entry).map_err(runtime)? {
            CleanupOutcome::Removed => Ok(("deleted", StructuralEntryResult::Removed)),
            CleanupOutcome::Unchanged => Ok(("kept_replaced", StructuralEntryResult::Kept)),
        },
        _ => Ok(("kept", StructuralEntryResult::Kept)),
    }
}

fn print_structural_entry(
    class: ReconcileClass,
    path: &Path,
    action: &str,
    json: bool,
) -> Result<(), Error> {
    if json {
        #[derive(Serialize)]
        struct StructuralRecord<'a> {
            class: &'a str,
            path: std::borrow::Cow<'a, str>,
            action: &'a str,
        }
        write_json_line(
            std::io::stdout().lock(),
            &StructuralRecord {
                class: class.as_str(),
                path: path.to_string_lossy(),
                action,
            },
        )?;
    } else {
        println!("{}\t{}\t{}", class.as_str(), path.display(), action);
    }
    Ok(())
}

#[derive(Args)]
pub(crate) struct Gc {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    max_bytes: Option<u64>,
    #[arg(long)]
    target_bytes: Option<u64>,
    /// Collect eligible publications and orphan payloads at least this many seconds old.
    #[arg(long)]
    max_age_seconds: Option<u64>,
    /// Collect eligible publications and orphan payloads older than PERIOD, e.g. 7d (24 hours per day).
    #[arg(long, value_name = "PERIOD", value_parser = parse_gc_retention_period, allow_hyphen_values = true, conflicts_with = "max_age_seconds")]
    delete_older_than: Option<Duration>,
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
    /// Request collection from the running daemon; never stop it or fall back.
    #[arg(long = "online", action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolValueParser::new().map(CollectionExecution::from_online_flag))]
    execution: CollectionExecution,
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollectionExecution {
    Offline,
    Online,
}

impl CollectionExecution {
    fn from_online_flag(online: bool) -> Self {
        match online {
            false => Self::Offline,
            true => Self::Online,
        }
    }
}

fn parse_gc_retention_period(value: &str) -> Result<Duration, String> {
    let days = value
        .strip_suffix('d')
        .ok_or_else(|| "expected a whole number of days followed by 'd', e.g. 7d".to_owned())?
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    let seconds = days
        .checked_mul(24 * 60 * 60)
        .ok_or_else(|| "day count exceeds the supported age limit".to_owned())?;
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn gc(options: Gc) -> Result<(), Error> {
    let Gc {
        data_dir,
        max_bytes,
        target_bytes,
        max_age_seconds,
        delete_older_than,
        min_age_seconds,
        protected_roots,
        dry_run: _,
        apply,
        json,
        execution,
        storage_backend,
    } = options;
    let maintenance_record = if apply {
        MaintenanceRecord::new(MaintenanceOperation::Gc, MaintenanceMode::GcApply)
    } else {
        MaintenanceRecord::new(MaintenanceOperation::Gc, MaintenanceMode::GcDryRun)
    };
    let options = GcOptions {
        data_dir,
        max_bytes,
        target_bytes,
        max_age: delete_older_than.or_else(|| max_age_seconds.map(Duration::from_secs)),
        min_age: std::time::Duration::from_secs(min_age_seconds),
        protected_roots,
        mode: if apply { GcMode::Apply } else { GcMode::DryRun },
        backend: storage_backend,
    };
    let report = match execution {
        CollectionExecution::Online => crate::control::collect(options).map_err(runtime)?,
        CollectionExecution::Offline => {
            let session = MaintenanceSession::open(
                &options.data_dir,
                storage_backend,
                Some(maintenance_record),
            )?;
            match apply {
                true => session.run_mutation(|recovered, trusted| {
                    gc::run_apply(options, recovered, trusted)
                        .map_err(runtime)
                        .map(gc_successful_maintenance_result)
                })?,
                false => session.run_inspection(|storage, trusted| {
                    gc::run_dry_run(options, storage, trusted)
                        .map_err(runtime)
                        .map(gc_successful_maintenance_result)
                })?,
            }
        }
    };

    if json {
        write_json_line(std::io::stdout().lock(), &report)?;
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

pub(crate) fn collect_online(
    options: GcOptions,
    storage: &Storage,
    trusted: &TrustedPublicKeys,
) -> Result<GcReport, narjar::__private::storage::StorageError> {
    let mode = match options.mode {
        GcMode::Apply => MaintenanceMode::GcApply,
        GcMode::DryRun => MaintenanceMode::GcDryRun,
    };
    let recorder = MaintenanceRecord::new(MaintenanceOperation::Gc, mode).start(&options.data_dir);
    record_maintenance_result(
        recorder,
        gc::run_online(options, storage, trusted).map(gc_successful_maintenance_result),
    )
}

fn gc_successful_maintenance_result(
    report: GcReport,
) -> (GcReport, MaintenanceOutcome, MaintenanceValues) {
    let reclaimed = !report.dry_run;
    let values = MaintenanceValues {
        objects_selected: Some(report.candidates as u64),
        objects_reclaimed: reclaimed.then_some(report.evicted as u64),
        bytes_reclaimed: reclaimed.then_some(report.evicted_bytes),
        ..MaintenanceValues::default()
    };
    (report, MaintenanceOutcome::Success, values)
}

#[derive(Args)]
pub(crate) struct Delete {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    store_hash: String,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
}

pub(crate) fn delete(options: Delete) -> Result<(), Error> {
    let Delete {
        data_dir: root,
        store_hash: route,
        json,
        storage_backend,
    } = options;
    let store = StoreHash::parse(&route).map_err(|_| Error::usage("--store-hash is invalid"))?;
    let session = MaintenanceSession::open(&root, storage_backend, None)?;
    session.run_mutation(|recovered, trusted| {
        let storage = recovered.storage();
        let file = storage
            .open_narinfo(&store)
            .map_err(runtime)?
            .ok_or_else(|| Error::runtime("narinfo is not published"))?;
        let bytes = read_narinfo_file(file).map_err(runtime)?;
        if trusted.validate(&store, bytes).is_err() {
            return Err(Error::runtime("narinfo is malformed or untrusted"));
        }
        storage.delete_narinfo(&store).map_err(runtime)?;
        Ok((
            (),
            MaintenanceOutcome::Success,
            MaintenanceValues::default(),
        ))
    })?;

    if json {
        write_json_line(
            std::io::stdout().lock(),
            &FindingRecord {
                class: "deleted",
                identifier: &route,
                action: "narinfo removed; NAR retained",
            },
        )?;
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
    #[arg(
        long,
        env = "NARJAR_SERVE_SOURCE",
        value_enum,
        default_value = "flat-cache"
    )]
    serve_source: ServeSourceChoice,
    #[arg(long, env = "NARJAR_NATIVE_STORE_DIR")]
    native_store_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_STATE_DIR")]
    native_state_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_ROOTS_DIR")]
    native_roots_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_MIN_LEASE_SECONDS")]
    native_min_lease_seconds: Option<NonZeroU64>,
    #[arg(long, env = "NARJAR_EGRESS_COMPRESSION", default_value = "none")]
    egress_compression: WireEncoding,
    #[arg(long, env = "NARJAR_STORAGE_BACKEND", default_value = "flat")]
    storage_backend: StorageBackend,
}

impl Doctor {
    fn prepare_source(&self) -> Result<ServeSource, SourcePreparationError> {
        ServeSource::prepare(
            self.serve_source,
            self.storage_backend,
            self.egress_compression,
            NativeStoreOptions {
                store_dir: self.native_store_dir.as_deref(),
                state_dir: self.native_state_dir.as_deref(),
                roots_dir: self.native_roots_dir.as_deref(),
                min_lease_seconds: self.native_min_lease_seconds,
            },
        )
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
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

    const fn is_failure(self) -> bool {
        match self {
            Self::Ok | Self::Warning => false,
            Self::Error | Self::Unavailable => true,
        }
    }
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct DoctorCapacity {
    path: &'static str,
    #[serde(flatten)]
    capacity: StorageCapacity,
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
    source: DoctorSource,
}

#[derive(Serialize)]
struct DoctorSource {
    name: &'static str,
    severity: DoctorSeverity,
    detail: &'static str,
}

impl DoctorReport {
    fn has_failures(&self) -> bool {
        self.mount.is_failure()
            || self.lease.is_failure()
            || self.source.severity.is_failure()
            || self.paths.iter().any(|path| path.severity.is_failure())
    }
}

pub(crate) fn doctor(options: Doctor) -> Result<(), Error> {
    let source = options.prepare_source();
    let backend = match &source {
        Err(SourcePreparationError::UnsupportedBackend(error)) => {
            return Err(Error::usage(error.to_string()));
        }
        Err(
            SourcePreparationError::NativeOptionsForCache
            | SourcePreparationError::MissingNativeOptions
            | SourcePreparationError::NativeCompressedOutput
            | SourcePreparationError::NativeChunkedBackend,
        ) => SupportedStorageBackend::try_from(options.storage_backend)
            .map_err(|error| Error::usage(error.to_string()))?,
        Ok(source) => source.storage_backend(),
    };
    let mut report = inspect_doctor(&options.data_dir, backend)?;
    report.source = inspect_doctor_source(&options, source);
    let failed = report.has_failures();
    if options.json {
        write_json_line(std::io::stdout().lock(), &doctor_json(&report))?;
    } else {
        print_doctor(&report);
    }
    if failed {
        return Err(Error::runtime("doctor found errors"));
    }
    Ok(())
}

fn inspect_doctor(root: &Path, backend: SupportedStorageBackend) -> Result<DoctorReport, Error> {
    let mut paths = Vec::new();
    for path in std::iter::once("")
        .chain(storage_directories(backend))
        .chain(CACHE_POLICY_DIRECTORIES.iter().copied())
    {
        paths.push(inspect_doctor_path(root, path, true, true));
    }
    for path in ["lock", LAYOUT_DESCRIPTOR]
        .into_iter()
        .chain(CACHE_POLICY_FILES.iter().copied())
    {
        paths.push(inspect_doctor_path(root, path, true, false));
    }
    paths.push(inspect_doctor_path(root, "auth/read.tokens", false, false));
    paths.extend(inspect_doctor_recovery_markers(root));

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
                if error.raw_os_error() == Some(rustix::io::Errno::WOULDBLOCK.raw_os_error())
                    || error.raw_os_error() == Some(rustix::io::Errno::AGAIN.raw_os_error()) =>
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
        source: DoctorSource {
            name: "flat-cache",
            severity: DoctorSeverity::Ok,
            detail: "selected",
        },
    })
}

fn inspect_doctor_source(
    options: &Doctor,
    source: Result<ServeSource, SourcePreparationError>,
) -> DoctorSource {
    let (name, validation) = match source {
        Ok(ServeSource::FlatCache { .. }) => ("flat-cache", Ok("selected")),
        Err(error) => (options.serve_source.name(), Err(error.doctor_detail())),
        Ok(ServeSource::NativeStore(settings)) => (
            "native-store",
            validate_doctor_native_store(&options.data_dir, &settings)
                .map(|()| "source configuration is valid"),
        ),
    };
    let (severity, detail) = match validation {
        Ok(detail) => (DoctorSeverity::Ok, detail),
        Err(detail) => (DoctorSeverity::Error, detail),
    };
    DoctorSource {
        name,
        severity,
        detail,
    }
}

fn validate_doctor_native_store(
    data_dir: &Path,
    settings: &NativeStoreSettings,
) -> Result<(), &'static str> {
    let data_directory =
        Directory::open(data_dir).map_err(|_| "Narjar data directory is unavailable")?;
    let (_, trusted_keys) = CachePolicies::load(&data_directory)
        .map_err(|_| "cache policy is invalid")?
        .into_parts();
    settings
        .validate(data_dir, &trusted_keys)
        .map(drop)
        .map_err(|error| error.doctor_detail())
}

fn inspect_doctor_recovery_markers(root: &Path) -> [DoctorPath; 2] {
    let markers = CACHE_RECOVERY_MARKERS.map(|name| inspect_doctor_path(root, name, false, false));
    match markers.each_ref().map(|marker| marker.mode) {
        [None, None] => markers.map(|mut marker| {
            marker.severity = DoctorSeverity::Error;
            marker.detail = "cache requires a clean or recovery marker".to_owned();
            marker
        }),
        [Some(_), _] | [None, Some(_)] => markers,
    }
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
        !private_file_mode_is_valid(mode)
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
    let statistics = rustix::fs::fstatvfs(&file)?;
    let capacity = capacity_from_statvfs(&statistics);
    Ok(DoctorCapacity {
        path: "",
        capacity,
        device: file.metadata()?.dev(),
    })
}

fn doctor_try_lease(file: &File) -> Result<(), std::io::Error> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(Into::into)
}

fn doctor_json(report: &DoctorReport) -> impl Serialize + '_ {
    #[derive(Serialize)]
    struct Check<'a> {
        severity: DoctorSeverity,
        detail: &'a str,
    }
    #[derive(Serialize)]
    struct Report<'a> {
        schema: u8,
        data_dir: std::borrow::Cow<'a, str>,
        source: &'a DoctorSource,
        mount: Check<'a>,
        lease: Check<'a>,
        paths: &'a [DoctorPath],
        capacity: &'a [DoctorCapacity],
    }
    Report {
        schema: 1,
        data_dir: report.root.to_string_lossy(),
        source: &report.source,
        mount: Check {
            severity: report.mount,
            detail: &report.mount_detail,
        },
        lease: Check {
            severity: report.lease,
            detail: &report.lease_detail,
        },
        paths: &report.paths,
        capacity: &report.capacities,
    }
}

fn print_doctor(report: &DoctorReport) {
    println!("data_dir\t{}", report.root.display());
    println!(
        "source\t{}\t{}\t{}",
        report.source.name,
        report.source.severity.as_str(),
        report.source.detail
    );
    println!("mount\t{}\t{}", report.mount.as_str(), report.mount_detail);
    println!("lease\t{}\t{}", report.lease.as_str(), report.lease_detail);
    for capacity in &report.capacities {
        println!(
            "capacity\t{}\t{} bytes available / {} total\t{} inodes available / {} total\tread_only={}",
            capacity.path,
            capacity.capacity.available_bytes,
            capacity.capacity.total_bytes,
            capacity.capacity.available_inodes,
            capacity.capacity.total_inodes,
            capacity.capacity.read_only
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
    url: HttpUrl,
    #[arg(long)]
    netrc_file: Option<PathBuf>,
}

pub(crate) fn stats(options: Stats) -> Result<(), Error> {
    let authorization = options
        .netrc_file
        .as_deref()
        .map(|path| netrc_authorization(path, &options.url, false))
        .transpose()?
        .flatten();
    let stats_url = options.url.endpoint(&["metrics"]);
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_recv_body(Some(Duration::from_secs(10)))
        .build()
        .into();
    let mut request = agent
        .get(stats_url.as_str())
        .config()
        .max_redirects(0)
        .build()
        .header("Accept", "text/plain; version=0.0.4");
    if let Some(authorization) = authorization {
        request = request.header("Authorization", format!("Basic {authorization}"));
    }
    let mut response = request.call().map_err(runtime)?;
    if response.status() != 200 {
        return Err(Error::runtime(format!(
            "stats endpoint failed: HTTP {}",
            response.status()
        )));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(256 * 1024)
        .read_to_vec()
        .map_err(runtime)?;
    let exposition = String::from_utf8(body).map_err(runtime)?;
    print!("{exposition}");
    Ok(())
}

pub(crate) fn netrc_authorization(
    path: &Path,
    url: &HttpUrl,
    allow_insecure_http: bool,
) -> Result<Option<String>, Error> {
    if !url.is_https() && !allow_insecure_http {
        return Ok(None);
    }

    let text = fs::read_to_string(path).map_err(runtime)?;
    netrc_authorization_from_str(&text, url.host()).map(Some)
}

fn netrc_authorization_from_str(text: &str, host: &str) -> Result<String, Error> {
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

pub(crate) fn create_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    preserve_existing: bool,
) -> Result<(), Error> {
    let mut temporary = tempfile::NamedTempFile::new_in(
        path.parent()
            .expect("Narjar managed files always have a parent directory"),
    )
    .map_err(runtime)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(runtime)?;
    temporary.write_all(bytes).map_err(runtime)?;
    temporary.as_file().sync_all().map_err(runtime)?;

    match temporary.persist_noclobber(path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_existing_managed_file(path, bytes, mode, preserve_existing)?;
        }
        Err(error) => return Err(runtime(error.error)),
    }
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(runtime)?;
    }
    Ok(())
}

fn validate_existing_managed_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    preserve_existing: bool,
) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(runtime)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != mode {
        return Err(Error::runtime(format!(
            "initialization entry is not a regular {:o} file: {}",
            mode,
            path.display()
        )));
    }
    if !preserve_existing && fs::read(path).map_err(runtime)? != bytes {
        return Err(Error::runtime(format!(
            "initialization file differs from requested configuration: {}",
            path.display()
        )));
    }
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(runtime)
}

pub(crate) fn valid_key_name(value: &str) -> Result<String, String> {
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

fn write_json_line(mut writer: impl Write, value: &impl Serialize) -> Result<(), Error> {
    serde_json::to_writer(&mut writer, value).map_err(runtime)?;
    writer.write_all(b"\n").map_err(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use narjar::__private::maintenance::{Operation, Outcome};
    use narjar::__private::storage::{CacheCreation, Directory, SupportedStorageBackend};

    #[test]
    fn gc_day_periods_have_exact_checked_duration_values() {
        for days in [0, 7, u64::MAX / 86_400] {
            assert_eq!(
                parse_gc_retention_period(&format!("{days}d")).unwrap(),
                Duration::from_secs(days * 86_400)
            );
        }
        assert!(parse_gc_retention_period(&format!("{}d", u64::MAX / 86_400 + 1)).is_err());
    }

    #[test]
    fn the_online_flag_is_parsed_into_an_explicit_collection_execution_mode() {
        use clap::Parser;
        for (extra_args, expected) in [
            (vec![], CollectionExecution::Offline),
            (vec!["--online"], CollectionExecution::Online),
        ] {
            let cli = crate::Cli::try_parse_from(
                [vec!["narjar", "gc", "--data-dir", "/cache"], extra_args].concat(),
            )
            .unwrap();
            let crate::Command::Gc(options) = cli.command else {
                panic!("GC command")
            };
            assert_eq!(options.execution, expected);
        }
    }

    #[test]
    fn json_lines_preserve_strings_and_end_with_one_newline() {
        let record = FindingRecord {
            class: "invalid",
            identifier: "quotes\" backslash\\ newline\n tab\t nul\0 café",
            action: "inspect",
        };
        let mut output = Vec::new();
        write_json_line(&mut output, &record).unwrap();
        assert_eq!(output.last(), Some(&b'\n'));
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["identifier"], record.identifier);
        assert_eq!(value["class"], record.class);
        assert_eq!(value["action"], record.action);
    }

    #[test]
    fn json_lines_propagate_body_and_newline_write_failures() {
        struct FailsAfter(usize);
        impl Write for FailsAfter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "report sink closed",
                    ));
                }
                let length = bytes.len().min(self.0);
                self.0 -= length;
                Ok(length)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for remaining in [0, 4] {
            let error = write_json_line(FailsAfter(remaining), &true).unwrap_err();
            assert!(error.to_string().contains("report sink closed"));
        }
    }

    #[test]
    fn doctor_json_preserves_lossy_paths_nulls_and_flat_capacity_fields() {
        use std::os::unix::ffi::OsStringExt;
        let directory = initialized_doctor_cache();
        let mut report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT).unwrap();
        report.root = PathBuf::from(std::ffi::OsString::from_vec(b"cache-\xff".to_vec()));
        report.mount_detail = "quote\" slash\\\n\0".into();
        report.paths[0].mode = None;
        let value = serde_json::to_value(doctor_json(&report)).unwrap();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["data_dir"], "cache-�");
        assert_eq!(value["mount"]["detail"], report.mount_detail);
        assert!(value["paths"][0]["mode"].is_null());
        assert!(value["capacity"][0]["available_bytes"].is_u64());
        assert!(value["capacity"][0]["read_only"].is_boolean());
        assert!(value["capacity"][0].get("capacity").is_none());
    }

    #[test]
    fn managed_file_conflict_never_replaces_existing_contents_or_leaves_temps() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("credential");
        create_file(&path, b"original", 0o600, false).expect("initial file should be created");

        assert!(create_file(&path, b"replacement", 0o600, false).is_err());

        assert_eq!(
            fs::read(path).expect("original file should remain"),
            b"original"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("directory should be readable")
                .count(),
            1,
            "the abandoned atomic-write temporary should be removed"
        );
    }

    #[test]
    fn netrc_entry_does_not_borrow_password_from_next_machine() {
        let error = netrc_authorization_from_str(
            "machine cache.example login cache-user
machine other.example password other-secret
",
            "cache.example",
        )
        .expect_err("the matching machine has no password");

        assert_eq!(error.to_string(), "netrc entry has no password");
    }

    #[test]
    fn gc_records_a_completed_operation_for_metrics() {
        let directory = tempfile::tempdir().expect("cache directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");

        gc(Gc {
            data_dir: directory.path().to_owned(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age_seconds: None,
            delete_older_than: None,
            min_age_seconds: 0,
            protected_roots: None,
            dry_run: false,
            apply: false,
            json: false,
            execution: CollectionExecution::Offline,
            storage_backend: StorageBackend::Flat,
        })
        .expect("dry-run GC should complete");

        let history = narjar::__private::maintenance::read_snapshot(directory.path())
            .expect("maintenance history should be readable");
        let run = history.last_runs[Operation::Gc].expect("GC result should be recorded");
        assert_eq!(run.outcome, Outcome::Success);
        assert_eq!(run.objects_selected, Some(0));
        assert_eq!(run.objects_reclaimed, None);
        assert_eq!(history.started[Operation::Gc], None);

        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("maintenance records should be accepted by repeated initialization");
        let root = Directory::open(directory.path()).expect("cache root should open");
        let storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .and_then(|creation| creation.create_or_complete())
            .expect("cache storage should initialize");
        let report = storage
            .reconcile(
                NonZeroUsize::new(32).expect("reconcile limit is nonzero"),
                SystemTime::now(),
            )
            .expect("maintenance records should be recognized by reconciliation");
        assert!(report.entries().iter().all(|entry| {
            !entry
                .relative_path()
                .to_string_lossy()
                .starts_with(".narjar-maintenance-")
        }));
    }

    #[test]
    fn gc_lock_conflict_does_not_overwrite_an_active_maintenance_record() {
        let directory = tempfile::tempdir().expect("cache directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        let before = narjar::__private::maintenance::read_snapshot(directory.path())
            .expect("maintenance history should be readable");
        let root = Directory::open(directory.path()).expect("cache root should open");
        let _active_storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .and_then(|creation| creation.create_or_complete())
            .expect("first operation should hold the cache lock");

        let result = gc(Gc {
            data_dir: directory.path().to_owned(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age_seconds: None,
            delete_older_than: None,
            min_age_seconds: 0,
            protected_roots: None,
            dry_run: false,
            apply: false,
            json: false,
            execution: CollectionExecution::Offline,
            storage_backend: StorageBackend::Flat,
        });
        assert!(
            result.is_err(),
            "a concurrent GC must fail to acquire the lock"
        );

        let after = narjar::__private::maintenance::read_snapshot(directory.path())
            .expect("maintenance history should remain readable");
        assert_eq!(after.started[Operation::Gc], before.started[Operation::Gc]);
        assert_eq!(
            after.last_runs[Operation::Gc],
            before.last_runs[Operation::Gc]
        );
    }

    #[test]
    fn verify_lock_conflict_does_not_write_maintenance_history() {
        let directory = tempfile::tempdir().expect("cache directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        let before = narjar::__private::maintenance::read_snapshot(directory.path())
            .expect("maintenance history should be readable");
        let root = Directory::open(directory.path()).expect("cache root should open");
        let _active_storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .and_then(|creation| creation.create_or_complete())
            .expect("first operation should hold the cache lock");

        let result = verify(Verify {
            data_dir: directory.path().to_owned(),
            json: false,
            storage_backend: StorageBackend::Flat,
        });
        assert!(
            result.is_err(),
            "concurrent verify must fail to acquire the lock"
        );

        let after = narjar::__private::maintenance::read_snapshot(directory.path())
            .expect("maintenance history should remain readable");
        assert_eq!(
            after, before,
            "failed lock acquisition must not write history"
        );
    }

    #[test]
    fn delete_lock_conflict_preserves_published_metadata() {
        let directory = tempfile::tempdir().expect("cache directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        let store_hash = "1".repeat(32);
        let narinfo = directory.path().join(format!("{store_hash}.narinfo"));
        fs::write(&narinfo, b"published metadata fixture").expect("fixture should be written");
        let root = Directory::open(directory.path()).expect("cache root should open");
        let _active_storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .and_then(|creation| creation.create_or_complete())
            .expect("first operation should hold the cache lock");

        let result = delete(Delete {
            data_dir: directory.path().to_owned(),
            store_hash,
            json: false,
            storage_backend: StorageBackend::Flat,
        });
        assert!(
            result.is_err(),
            "concurrent delete must fail to acquire the lock"
        );
        assert_eq!(
            fs::read(narinfo).expect("published metadata must remain readable"),
            b"published metadata fixture",
            "failed lock acquisition must not reach the deletion"
        );
    }

    #[test]
    fn maintenance_session_finishes_published_recovery_before_mutation() {
        let directory = tempfile::tempdir().expect("cache directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        let staging_path = directory.path().join(".tmp/recovered-publication.part");
        fs::write(&staging_path, b"published transaction staging")
            .expect("staged publication should exist");
        let transaction_path = directory
            .path()
            .join(".narjar-transactions/publish-maintenance.txn");
        fs::write(
            &transaction_path,
            // Postcard enum discriminants: TransactionRecord::V1 = 0, Published = 4.
            postcard::to_allocvec(&(
                0_u32,
                ".tmp/recovered-publication.part",
                4_u32,
                "nix-cache-info",
            ))
            .expect("published recovery fixture should encode"),
        )
        .expect("published transaction should be durable on disk");
        fs::set_permissions(&transaction_path, fs::Permissions::from_mode(0o600))
            .expect("transaction should have private permissions");
        let recovery_marker = directory.path().join(".narjar-recovery");
        fs::write(&recovery_marker, b"interrupted\n").expect("recovery marker should be present");
        fs::set_permissions(&recovery_marker, fs::Permissions::from_mode(0o600))
            .expect("recovery marker should have private permissions");

        let published_destination = directory.path().join("nix-cache-info");

        gc(Gc {
            data_dir: directory.path().to_owned(),
            max_bytes: None,
            target_bytes: Some(u64::MAX),
            max_age_seconds: None,
            delete_older_than: None,
            min_age_seconds: 0,
            protected_roots: None,
            dry_run: false,
            apply: true,
            json: false,
            execution: CollectionExecution::Offline,
            storage_backend: StorageBackend::Flat,
        })
        .expect("GC must recover before applying maintenance");
        assert!(
            published_destination.exists(),
            "recovery keeps its published destination before the GC pass"
        );
        assert!(
            !transaction_path.exists(),
            "recovery removes its completed journal"
        );
        assert!(
            !staging_path.exists(),
            "recovery removes abandoned staging bytes"
        );

        let root = Directory::open(directory.path()).expect("cache root should reopen");
        let storage = CacheCreation::prepare(&root, SupportedStorageBackend::FLAT)
            .and_then(|creation| creation.create_or_complete())
            .expect("cache storage should reopen");
        assert!(
            !storage
                .recovery_required()
                .expect("recovery state should be readable"),
            "restart must not encounter a journal whose destination maintenance removed"
        );
    }

    #[test]
    fn verify_records_completed_status_and_each_inventory_class() {
        let directory = tempfile::tempdir().expect("cache directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        let malformed_metadata = directory.path().join(format!("{}.narinfo", "1".repeat(32)));
        fs::write(malformed_metadata, b"not narinfo").expect("fixture should be written");

        let error = report(
            directory.path().to_owned(),
            ReportMode::Verify,
            false,
            false,
            StorageBackend::Flat,
        )
        .expect_err("malformed metadata should fail verification");
        assert!(error.to_string().contains("invalid published pairs"));

        let history = narjar::__private::maintenance::read_snapshot(directory.path())
            .expect("maintenance history should be readable");
        let run =
            history.last_runs[Operation::Verify].expect("verification result should be recorded");
        assert_eq!(run.outcome, Outcome::Failure);
        assert_eq!(run.objects_examined, Some(2));
        assert_eq!(run.inventory_class_counts, Some([0, 0, 0, 1, 0, 0, 1]));
        assert_eq!(history.started[Operation::Verify], None);
    }

    #[test]
    fn netrc_matches_an_ipv6_host() {
        let authorization = netrc_authorization_from_str(
            "machine ::1 login cache-user password cache-secret
",
            "::1",
        )
        .expect("IPv6 machine should match");

        assert_eq!(authorization, BASE64.encode(b"cache-user:cache-secret"));
    }

    #[test]
    fn netrc_credentials_are_not_available_to_plain_http() {
        let file = tempfile::NamedTempFile::new().expect("temporary netrc should be created");
        fs::write(
            file.path(),
            "machine cache.example login cache-user password cache-secret\n",
        )
        .expect("temporary netrc should be written");
        let http: HttpUrl = "http://cache.example"
            .parse()
            .expect("HTTP URL should parse");
        let https: HttpUrl = "https://cache.example"
            .parse()
            .expect("HTTPS URL should parse");

        assert_eq!(
            netrc_authorization(file.path(), &http, false).unwrap(),
            None
        );
        assert_eq!(
            netrc_authorization(file.path(), &https, false).unwrap(),
            Some(BASE64.encode(b"cache-user:cache-secret"))
        );
        assert_eq!(
            netrc_authorization(file.path(), &http, true).unwrap(),
            Some(BASE64.encode(b"cache-user:cache-secret"))
        );
    }

    #[test]
    fn init_resumes_partial_layout_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        fs::create_dir(directory.path().join("nar")).expect("partial layout should be created");

        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
            storage_backend: StorageBackend::Flat,
        })
        .expect("partial initialization should resume");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
            storage_backend: StorageBackend::Flat,
        })
        .expect("completed initialization should be idempotent");

        assert!(directory.path().join(".narjar-clean").is_file());
        assert!(!directory.path().join(".narjar-recovery").exists());
        assert!(directory.path().join("auth/read.tokens").is_file());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn init_can_select_the_chunked_storage_backend() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Chunked,
        })
        .expect("chunked cache should initialize");

        assert_eq!(
            fs::read(directory.path().join(".narjar-layout")).unwrap(),
            b"narjar-layout-v1\nbackend=chunked\nprofile=mincdc-hash4-v2\n"
        );
        assert!(directory.path().join(".narjar-chunks").is_dir());
        assert!(directory.path().join(".narjar-manifests").is_dir());
    }

    #[test]
    fn init_preserves_existing_trust_and_token_material() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: true,
            storage_backend: StorageBackend::Flat,
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
            storage_backend: StorageBackend::Flat,
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
    fn doctor_rejects_private_file_modes_that_startup_rejects() {
        let directory = initialized_doctor_cache();
        for name in ["lock", LAYOUT_DESCRIPTOR]
            .into_iter()
            .chain(CACHE_POLICY_FILES.iter().copied())
        {
            let path = directory.path().join(name);
            for mode in [0o400, 0o644, 0o660] {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                let report =
                    inspect_doctor(directory.path(), SupportedStorageBackend::FLAT).unwrap();
                let entry = report
                    .paths
                    .iter()
                    .find(|entry| entry.path == name)
                    .unwrap();
                assert!(
                    entry.severity.is_failure(),
                    "doctor accepted {name} with mode {mode:04o}"
                );
                assert!(report.has_failures());
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(
            !inspect_doctor(directory.path(), SupportedStorageBackend::FLAT)
                .unwrap()
                .has_failures()
        );
    }

    #[test]
    fn doctor_requires_one_private_recovery_marker_and_checks_both_when_present() {
        let directory = initialized_doctor_cache();
        let clean = directory.path().join(".narjar-clean");
        let recovery = directory.path().join(".narjar-recovery");
        let report = || inspect_doctor(directory.path(), SupportedStorageBackend::FLAT).unwrap();
        assert!(!report().has_failures(), "a clean cache is complete");
        fs::remove_file(&clean).unwrap();
        assert!(
            report().has_failures(),
            "neither marker is not an initialized cache"
        );
        fs::write(&recovery, b"interrupted\n").unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!report().has_failures(), "a recovery marker is sufficient");
        fs::write(&clean, b"").unwrap();
        fs::set_permissions(&clean, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            report().has_failures(),
            "a valid recovery marker cannot hide an unsafe clean marker"
        );
        fs::set_permissions(&clean, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            !report().has_failures(),
            "both private markers are permitted"
        );
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            report().has_failures(),
            "a valid clean marker cannot hide an unsafe recovery marker"
        );
    }

    #[test]
    fn native_doctor_loads_the_same_required_policies_as_startup() {
        let directory = initialized_doctor_cache();
        let settings = NativeStoreSettings::new(
            directory.path().join("missing-store"),
            directory.path().join("native-state"),
            directory.path().join("native-roots"),
            NonZeroU64::new(60).unwrap(),
        );
        for name in CACHE_POLICY_FILES {
            let path = directory.path().join(name);
            let original = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert_eq!(
                validate_doctor_native_store(directory.path(), &settings),
                Err("cache policy is invalid")
            );
            assert!(!path.exists(), "doctor must not recreate {name}");
            fs::write(&path, original).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(
            directory.path().join("auth/write.tokens"),
            b"invalid token record\n",
        )
        .unwrap();
        assert_eq!(
            validate_doctor_native_store(directory.path(), &settings),
            Err("cache policy is invalid")
        );
    }

    fn initialized_doctor_cache() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .unwrap();
        directory
    }

    #[test]
    fn doctor_requires_the_same_receipt_and_transaction_directories_as_storage_open() {
        let directory = tempfile::tempdir().unwrap();
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .unwrap();
        for missing in [".narjar-transactions", ".narjar-ingress", ".narjar-egress"] {
            let path = directory.path().join(missing);
            fs::remove_dir(&path).unwrap();
            let report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT).unwrap();
            let entry = report
                .paths
                .iter()
                .find(|entry| entry.path == missing)
                .unwrap();
            assert!(entry.required);
            assert!(
                entry.severity.is_failure(),
                "doctor cannot approve a layout Storage::open refuses: {missing}"
            );
            assert!(report.has_failures());
            fs::create_dir(path).unwrap();
        }
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
            storage_backend: StorageBackend::Flat,
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
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");

        let report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT)
            .expect("doctor should inspect cache");
        let json = serde_json::to_string(&doctor_json(&report)).unwrap();
        assert!(json.contains("\"schema\":1"));
        assert!(json.contains("\"mount\":{\"severity\":\"ok\""));
        assert!(json.contains("\"path\":\"nar\""));
        assert!(json.contains("\"total_bytes\":"));
        assert!(json.contains("\"lease\":{\"severity\":\"ok\""));
        assert!(json.contains("\"source\":{\"name\":\"flat-cache\""));
    }

    #[test]
    fn doctor_source_policy_errors_keep_the_existing_static_details() {
        use narjar::object::CompressionCodec;

        let complete = NativeStoreOptions {
            store_dir: Some(Path::new("/private/store-path")),
            state_dir: Some(Path::new("/private/state-path")),
            roots_dir: Some(Path::new("/private/roots-path")),
            min_lease_seconds: NonZeroU64::new(60),
        };
        for (choice, native, encoding, backend, expected_error, detail) in [
            (
                ServeSourceChoice::FlatCache,
                complete,
                WireEncoding::Raw,
                StorageBackend::Flat,
                SourcePreparationError::NativeOptionsForCache,
                "native source options require native-store selection",
            ),
            (
                ServeSourceChoice::NativeStore,
                NativeStoreOptions {
                    state_dir: None,
                    ..complete
                },
                WireEncoding::Raw,
                StorageBackend::Flat,
                SourcePreparationError::MissingNativeOptions,
                "required native source options are missing",
            ),
            (
                ServeSourceChoice::NativeStore,
                complete,
                WireEncoding::Compressed(CompressionCodec::Xz),
                StorageBackend::Flat,
                SourcePreparationError::NativeCompressedOutput,
                "native source requires raw output and flat storage",
            ),
            (
                ServeSourceChoice::NativeStore,
                complete,
                WireEncoding::Compressed(CompressionCodec::Zstd),
                StorageBackend::Flat,
                SourcePreparationError::NativeCompressedOutput,
                "native source requires raw output and flat storage",
            ),
            (
                ServeSourceChoice::NativeStore,
                complete,
                WireEncoding::Raw,
                StorageBackend::Chunked,
                SourcePreparationError::NativeChunkedBackend,
                "native source requires raw output and flat storage",
            ),
        ] {
            let options = Doctor {
                data_dir: PathBuf::from("/unavailable/narjar-cache"),
                json: true,
                serve_source: choice,
                native_store_dir: native.store_dir.map(Path::to_owned),
                native_state_dir: native.state_dir.map(Path::to_owned),
                native_roots_dir: native.roots_dir.map(Path::to_owned),
                native_min_lease_seconds: native.min_lease_seconds,
                egress_compression: encoding,
                storage_backend: backend,
            };
            let source = options.prepare_source();
            assert_eq!(
                source.as_ref().unwrap_err(),
                &expected_error,
                "doctor must use the same source policy as serve"
            );
            let diagnostic = inspect_doctor_source(&options, source);
            assert_eq!(diagnostic.name, choice.name());
            assert!(matches!(diagnostic.severity, DoctorSeverity::Error));
            assert_eq!(
                diagnostic.detail, detail,
                "policy errors must retain static details instead of inspecting unavailable paths"
            );
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn doctor_rejects_unsupported_backend_before_reporting_other_source_errors() {
        use narjar::object::CompressionCodec;

        let directory = tempfile::tempdir().expect("temporary directory should be created");
        for (choice, complete, encoding) in [
            (ServeSourceChoice::FlatCache, true, WireEncoding::Raw),
            (ServeSourceChoice::NativeStore, false, WireEncoding::Raw),
            (ServeSourceChoice::NativeStore, true, WireEncoding::Raw),
            (
                ServeSourceChoice::NativeStore,
                true,
                WireEncoding::Compressed(CompressionCodec::Xz),
            ),
            (
                ServeSourceChoice::NativeStore,
                true,
                WireEncoding::Compressed(CompressionCodec::Zstd),
            ),
        ] {
            let options = Doctor {
                data_dir: directory.path().to_owned(),
                json: true,
                serve_source: choice,
                native_store_dir: Some(directory.path().join("private-store")),
                native_state_dir: complete.then(|| directory.path().join("private-state")),
                native_roots_dir: Some(directory.path().join("private-roots")),
                native_min_lease_seconds: NonZeroU64::new(60),
                egress_compression: encoding,
                storage_backend: StorageBackend::Chunked,
            };
            let error = doctor(options).expect_err("unsupported backend must be a usage error");
            assert_eq!(error.exit_code(), 2);
            assert_eq!(
                error.to_string(),
                "chunked storage is not supported on macOS; choose flat"
            );
        }
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("cache should remain readable")
                .count(),
            0,
            "failed source preparation must not create cache or native directories"
        );
    }

    #[test]
    fn native_source_doctor_reports_validation_without_echoing_configured_paths() {
        let directory = initialized_doctor_cache();
        let options = Doctor {
            data_dir: directory.path().to_owned(),
            json: true,
            serve_source: ServeSourceChoice::NativeStore,
            native_store_dir: Some(PathBuf::from("/private/store-path")),
            native_state_dir: Some(PathBuf::from("/private/state-path")),
            native_roots_dir: Some(PathBuf::from("/private/roots-path")),
            native_min_lease_seconds: NonZeroU64::new(60),
            egress_compression: WireEncoding::Raw,
            storage_backend: StorageBackend::Flat,
        };
        let mut report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT)
            .expect("doctor should inspect cache");
        report.source = inspect_doctor_source(&options, options.prepare_source());
        let json = serde_json::to_string(&doctor_json(&report)).unwrap();

        assert!(json.contains("\"name\":\"native-store\""));
        assert!(json.contains("\"detail\":\"Nix store path is unavailable or unsafe\""));
        assert!(!json.contains("/private/store-path"));
        assert!(!json.contains("/private/state-path"));
        assert!(!json.contains("/private/roots-path"));
    }

    #[test]
    fn doctor_marks_wrong_fixed_path_type_as_error() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        init(Init {
            data_dir: directory.path().to_owned(),
            priority: 30,
            private_read: false,
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        fs::remove_dir_all(directory.path().join("nar"))
            .expect("nar directory should be removable");
        fs::write(directory.path().join("nar"), b"wrong type")
            .expect("replacement should be writable");

        let report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT)
            .expect("doctor should inspect cache");
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
            storage_backend: StorageBackend::Flat,
        })
        .expect("cache should initialize");
        let held = File::open(directory.path()).expect("data directory should open");
        doctor_try_lease(&held).expect("test should hold the lease");

        let report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT)
            .expect("doctor should inspect cache");
        assert!(matches!(report.lease, DoctorSeverity::Warning));
        assert!(report.lease_detail.contains("held"));
    }
}
