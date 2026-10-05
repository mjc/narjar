use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use super::{
    chunk_store::{ChunkManifestFile, ChunkStore},
    fs::unlink_at,
    state::PayloadStorage,
};
use crate::{
    narinfo::{PublishedNarInfoError, TrustedPublicKeys, read_narinfo_file},
    object::{NarHash, NarRepresentation},
    storage::{
        Directory, NarFileName, RecoveredStorage, Storage, StorageBackend, StorageError, StoreHash,
        SupportedStorageBackend, open_regular_at, read_dir_names,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcMode {
    DryRun,
    Apply,
}

pub struct GcOptions {
    pub data_dir: PathBuf,
    pub max_bytes: Option<u64>,
    pub target_bytes: Option<u64>,
    pub max_age: Option<Duration>,
    pub min_age: Duration,
    pub protected_roots: Option<PathBuf>,
    pub mode: GcMode,
    pub backend: StorageBackend,
}

#[derive(serde::Serialize)]
pub struct GcReport {
    pub accounting_basis: &'static str,
    pub dry_run: bool,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub target_met: bool,
    pub candidates: usize,
    pub protected: usize,
    pub eligible: usize,
    pub evicted: usize,
    pub shared: usize,
    pub orphaned: usize,
    pub temporary: usize,
    pub malformed: usize,
    pub missing_roots: usize,
    pub missing_references: usize,
    pub protected_bytes: u64,
    pub eligible_bytes: u64,
    pub evicted_bytes: u64,
    pub shared_bytes: u64,
    pub orphaned_bytes: u64,
    pub temporary_bytes: u64,
    pub malformed_bytes: u64,
    pub deleted_narinfos: usize,
    pub deleted_nars: usize,
    pub deleted_orphans: usize,
}

struct ProtectionReport {
    protected: usize,
    missing_roots: usize,
    missing_references: usize,
}

struct Entry {
    store: StoreHash,
    store_path: String,
    references: Vec<String>,
    narinfo_name: OsString,
    nar_name: OsString,
    narinfo_bytes: u64,
    nar_bytes: u64,
    raw_nar_name: OsString,
    raw_nar_bytes: u64,
    modified: SystemTime,
    protected: bool,
}

struct TrustedGcPublication {
    store: StoreHash,
    store_path: String,
    references: Vec<String>,
    narinfo_name: OsString,
    narinfo_bytes: u64,
    modified: SystemTime,
    representation: NarRepresentation,
}

fn scan_trusted_gc_publications<'a>(
    root: &'a File,
    trusted: &'a TrustedPublicKeys,
    names: Vec<OsString>,
) -> impl Iterator<Item = Result<TrustedGcPublication, StorageError>> + 'a {
    names.into_iter().filter_map(move |name| {
        let route = name.to_str()?.strip_suffix(".narinfo")?;
        Some(
            StoreHash::parse(route)
                .map_err(|_| {
                    invalid(format!(
                        "invalid narinfo filename: {}",
                        name.to_string_lossy()
                    ))
                })
                .and_then(|store| inspect_trusted_gc_publication(root, trusted, store, name)),
        )
    })
}

fn inspect_trusted_gc_publication(
    root: &File,
    trusted: &TrustedPublicKeys,
    store: StoreHash,
    name: OsString,
) -> Result<TrustedGcPublication, StorageError> {
    let name_str = name.to_string_lossy();
    let file = open_regular_at(root, &name).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => invalid(format!("narinfo disappeared during scan: {name_str}")),
        io::ErrorKind::InvalidData => invalid(format!("narinfo is not a regular file: {name_str}")),
        _ if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            invalid(format!("narinfo is not a regular file: {name_str}"))
        }
        _ => error.into(),
    })?;
    let metadata = file.metadata()?;
    let validated =
        trusted
            .inspect(&store, read_narinfo_file(file)?)
            .map_err(|error| match error {
                PublishedNarInfoError::Malformed => {
                    invalid(format!("malformed narinfo: {name_str}"))
                }
                PublishedNarInfoError::UntrustedSignature => {
                    invalid(format!("untrusted narinfo: {name_str}"))
                }
            })?;
    Ok(TrustedGcPublication {
        store,
        store_path: validated.claims().store_path().to_owned(),
        references: validated
            .claims()
            .reference_paths()
            .map(str::to_owned)
            .collect(),
        narinfo_name: name,
        narinfo_bytes: metadata.len(),
        modified: metadata.modified()?,
        representation: validated.payload(),
    })
}

struct ChunkedEntry {
    store: StoreHash,
    store_path: String,
    references: Vec<String>,
    narinfo_name: OsString,
    output_name: Option<OsString>,
    output_bytes: u64,
    raw_hash: NarHash,
    manifest_bytes: u64,
    narinfo_bytes: u64,
    modified: SystemTime,
    protected: bool,
}

struct ChunkedGcReportInput<'a> {
    before_entries: &'a [ChunkedEntry],
    before_bytes: u64,
    after_bytes: u64,
    target_bytes: Option<u64>,
    dry_run: bool,
    protection: ProtectionReport,
    protected_bytes: u64,
    eligible: usize,
    eligible_bytes: u64,
    evicted: usize,
    orphaned: usize,
    orphaned_bytes: u64,
    deleted: (usize, usize, usize),
}

#[derive(Default)]
struct ChunkedOrphans {
    manifests: Vec<ChunkManifestFile>,
    outputs: Vec<Orphan>,
}

#[derive(Default)]
struct ChunkedSelection {
    entries: Vec<usize>,
    manifests: Vec<usize>,
    outputs: Vec<usize>,
}

impl ChunkedSelection {
    fn include(&mut self, candidate: ChunkedCandidate) {
        match candidate {
            ChunkedCandidate::Entry(index) => self.entries.push(index),
            ChunkedCandidate::Manifest(index) => self.manifests.push(index),
            ChunkedCandidate::Output(index) => self.outputs.push(index),
        }
    }
}

#[derive(Clone, Copy)]
enum ChunkedCandidate {
    Entry(usize),
    Manifest(usize),
    Output(usize),
}
struct Orphan {
    name: OsString,
    bytes: u64,
    modified: SystemTime,
}

#[derive(Clone, Copy)]
struct RetentionPolicy {
    pressure_target: Option<u64>,
    max_age: Option<Duration>,
    min_age: Duration,
    now: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollectionReason {
    MaximumAge,
    SizePressure,
}

impl RetentionPolicy {
    fn new(
        options: &GcOptions,
        current_bytes: u64,
        target_bytes: Option<u64>,
        now: SystemTime,
    ) -> Self {
        Self::for_limits(
            current_bytes,
            target_bytes,
            options.max_bytes,
            options.max_age,
            options.min_age,
            now,
        )
    }

    fn for_limits(
        current_bytes: u64,
        target_bytes: Option<u64>,
        max_bytes: Option<u64>,
        max_age: Option<Duration>,
        min_age: Duration,
        now: SystemTime,
    ) -> Self {
        Self {
            pressure_target: pressure_target(current_bytes, target_bytes, max_bytes),
            max_age,
            min_age,
            now,
        }
    }

    fn reason(
        self,
        modified: SystemTime,
        protected: bool,
        remaining_bytes: u64,
    ) -> Option<CollectionReason> {
        let age = self.now.duration_since(modified).unwrap_or_default();
        if protected || age < self.min_age {
            return None;
        }
        if self.max_age.is_some_and(|max_age| age >= max_age) {
            return Some(CollectionReason::MaximumAge);
        }
        self.pressure_target
            .is_some_and(|target| remaining_bytes > target)
            .then_some(CollectionReason::SizePressure)
    }
}

pub fn run(options: GcOptions) -> Result<GcReport, StorageError> {
    let backend = SupportedStorageBackend::try_from(options.backend)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    let root = Directory::open(&options.data_dir)?;
    let storage = Storage::open(&root, backend)?;
    let (_, trusted) = super::CachePolicies::load(&root)?.into_parts();
    match options.mode {
        GcMode::DryRun => run_dry_run(options, &storage, &trusted),
        GcMode::Apply => {
            let recovered = storage.recover_for_mutation(&trusted)?;
            run_apply(options, &recovered, &trusted)
        }
    }
}

/// Inspect GC candidates without recovering or mutating cache state.
pub fn run_dry_run(
    options: GcOptions,
    storage: &Storage,
    trusted: &TrustedPublicKeys,
) -> Result<GcReport, StorageError> {
    run_with_mode(options, storage, trusted, GcMode::DryRun)
}

/// Apply garbage collection only with storage whose recovery has completed.
pub fn run_apply(
    options: GcOptions,
    recovered: &RecoveredStorage<'_>,
    trusted: &TrustedPublicKeys,
) -> Result<GcReport, StorageError> {
    run_with_mode(options, recovered.storage(), trusted, GcMode::Apply)
}

fn run_with_mode(
    mut options: GcOptions,
    storage: &Storage,
    trusted: &TrustedPublicKeys,
    mode: GcMode,
) -> Result<GcReport, StorageError> {
    options.mode = mode;
    let target_bytes = gc_target_bytes(&options)?;
    if let PayloadStorage::Chunked(chunk_store) = &storage.payloads {
        return run_chunked(options, storage, chunk_store, trusted, target_bytes);
    }
    run_flat_gc(options, storage, trusted, target_bytes, scan)
}

fn gc_target_bytes(options: &GcOptions) -> Result<Option<u64>, StorageError> {
    if options.max_bytes.is_none() && options.target_bytes.is_none() && options.max_age.is_none() {
        return Err(invalid("at least one retention policy is required"));
    }
    if options
        .target_bytes
        .zip(options.max_bytes)
        .is_some_and(|(target, maximum)| target > maximum)
    {
        return Err(invalid("--target-bytes cannot exceed --max-bytes"));
    }
    Ok(options.target_bytes.or(options.max_bytes))
}

fn pressure_target(
    current_bytes: u64,
    target_bytes: Option<u64>,
    max_bytes: Option<u64>,
) -> Option<u64> {
    let target = target_bytes?;
    (current_bytes > max_bytes.unwrap_or(target)).then_some(target)
}

fn run_flat_gc(
    options: GcOptions,
    storage: &Storage,
    trusted: &TrustedPublicKeys,
    target_bytes: Option<u64>,
    mut scan_entries: impl FnMut(&Storage, &TrustedPublicKeys) -> Result<Vec<Entry>, StorageError>,
) -> Result<GcReport, StorageError> {
    let mut entries = scan_entries(storage, trusted)?;
    let protection = protect(&mut entries, options.protected_roots.as_deref(), |entry| {
        ProtectionNode {
            store: &entry.store,
            store_path: &entry.store_path,
            references: &entry.references,
            protected: &mut entry.protected,
        }
    })?;
    let orphans = scan_orphans(storage, &entries)?;
    let protected_bytes = category_bytes(&entries, |entry| entry.protected);

    let before_bytes = total_bytes(&entries) + orphan_bytes(&orphans);
    let now = SystemTime::now();
    let policy = RetentionPolicy::new(&options, before_bytes, target_bytes, now);
    let eligible = eligible_count(&entries, &orphans, now, options.min_age);
    let eligible_bytes_total = eligible_bytes(&entries, &orphans, now, options.min_age);
    let shared = shared_count(&entries);
    let shared_bytes_total = shared_bytes(&entries);
    let (temporary, temporary_bytes) = temporary_inventory(storage)?;
    let selected = select(&entries, before_bytes, policy);
    let after_publications = projected_published_bytes(&entries, &selected);
    let selected_orphans = select_orphans(
        &orphans,
        after_publications + orphan_bytes(&orphans),
        policy,
    );
    let projected_after_bytes =
        logical_after_bytes(&entries, &selected, &orphans, &selected_orphans);
    let mut after_bytes = projected_after_bytes;
    let dry_run = options.mode == GcMode::DryRun;
    let (deleted_narinfos, deleted_nars, deleted_orphans) = if dry_run {
        (0, 0, 0)
    } else {
        let result: Result<(usize, usize, usize), StorageError> = (|| {
            let (deleted_narinfos, deleted_nars) = apply(storage, &entries, &selected)?;
            let deleted_orphans = apply_orphans(storage, &orphans, &selected_orphans)?;
            Ok((deleted_narinfos, deleted_nars, deleted_orphans))
        })();
        let deleted = result?;
        let remaining_entries = scan_entries(storage, trusted)?;
        let remaining_orphans = scan_orphans(storage, &remaining_entries)?;
        after_bytes = total_bytes(&remaining_entries) + orphan_bytes(&remaining_orphans);
        storage.finish_recovery()?;
        deleted
    };
    let evicted_bytes = before_bytes.saturating_sub(after_bytes);

    Ok(GcReport {
        accounting_basis: "logical",
        dry_run,
        before_bytes,
        after_bytes,
        target_met: target_bytes.is_none_or(|target| after_bytes <= target),
        candidates: selected.len() + selected_orphans.len(),
        protected: protection.protected,
        eligible,
        evicted: selected.len() + selected_orphans.len(),
        shared,
        orphaned: orphans.len(),
        temporary,
        malformed: 0,
        missing_roots: protection.missing_roots,
        missing_references: protection.missing_references,
        protected_bytes,
        eligible_bytes: eligible_bytes_total,
        evicted_bytes,
        shared_bytes: shared_bytes_total,
        orphaned_bytes: orphan_bytes(&orphans),
        temporary_bytes,
        malformed_bytes: 0,
        deleted_narinfos,
        deleted_nars,
        deleted_orphans,
    })
}

fn scan(storage: &Storage, trusted: &TrustedPublicKeys) -> Result<Vec<Entry>, StorageError> {
    scan_with_directory_names(storage, trusted, read_dir_names)
}

fn scan_with_directory_names(
    storage: &Storage,
    trusted: &TrustedPublicKeys,
    read_names: impl FnOnce(&File) -> io::Result<Vec<OsString>>,
) -> Result<Vec<Entry>, StorageError> {
    let mut entries = Vec::new();
    let root = storage.root_directory()?;
    let nar_directory = storage.nar_directory()?;
    for publication in scan_trusted_gc_publications(&root, trusted, read_names(&root)?) {
        let TrustedGcPublication {
            store,
            store_path,
            references,
            narinfo_name: name,
            narinfo_bytes,
            modified,
            representation,
        } = publication?;
        let name_str = name.to_string_lossy();
        let nar_name = OsString::from(representation.file_name().to_string());
        let nar_metadata = open_regular_at(&nar_directory, &nar_name)
            .and_then(|file| file.metadata())
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => invalid(format!("missing NAR for narinfo: {name_str}")),
                _ => error.into(),
            })?;
        if nar_metadata.len() != representation.encoded_size().get() {
            return Err(invalid(format!(
                "NAR size mismatch for narinfo: {name_str}"
            )));
        }

        let canonical_raw_name =
            OsString::from(super::NarFileName::raw(representation.identity().hash()).to_string());
        let (raw_nar_name, raw_nar_bytes) =
            match open_regular_at(&nar_directory, &canonical_raw_name) {
                Ok(file) => (canonical_raw_name, file.metadata()?.len()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    (nar_name.clone(), nar_metadata.len())
                }
                Err(error) => return Err(error.into()),
            };

        entries.push(Entry {
            store,
            store_path,
            references,
            narinfo_name: name,
            nar_name,
            narinfo_bytes,
            nar_bytes: nar_metadata.len(),
            raw_nar_name,
            raw_nar_bytes,
            modified,
            protected: false,
        });
    }
    Ok(entries)
}

fn run_chunked(
    options: GcOptions,
    storage: &Storage,
    chunk_store: &ChunkStore,
    trusted: &TrustedPublicKeys,
    target_bytes: Option<u64>,
) -> Result<GcReport, StorageError> {
    let mut entries = scan_chunked(storage, chunk_store, trusted)?;
    let protection = protect(&mut entries, options.protected_roots.as_deref(), |entry| {
        ProtectionNode {
            store: &entry.store,
            store_path: &entry.store_path,
            references: &entry.references,
            protected: &mut entry.protected,
        }
    })?;
    let now = SystemTime::now();
    let orphans = scan_chunked_orphans(storage, chunk_store, &entries)?;
    let before_bytes = chunked_before_bytes(storage, chunk_store, &entries)?;
    let eligible_entries = entries
        .iter()
        .filter(|entry| is_chunked_eligible(entry, now, options.min_age))
        .count();
    let eligible_orphans = orphans
        .manifests
        .iter()
        .filter(|manifest| age_reached(manifest.modified, now, options.min_age))
        .count()
        + orphans
            .outputs
            .iter()
            .filter(|orphan| age_reached(orphan.modified, now, options.min_age))
            .count();
    let eligible = eligible_entries + eligible_orphans;
    let eligible_bytes =
        chunked_eligible_bytes(chunk_store, &entries, &orphans, now, options.min_age)?;
    let orphaned = orphans.manifests.len() + orphans.outputs.len();
    let orphaned_bytes = chunked_orphan_bytes(chunk_store, &entries, &orphans)?;
    let protected_bytes =
        chunked_bytes_for_entries(chunk_store, entries.iter().filter(|entry| entry.protected))?;
    let selected = select_chunked(
        chunk_store,
        &entries,
        &orphans,
        before_bytes,
        RetentionPolicy::new(&options, before_bytes, target_bytes, now),
    )?;
    let after_bytes = chunked_projected_bytes(chunk_store, &entries, &orphans, &selected)?;
    let evicted = selected.entries.len() + selected.manifests.len() + selected.outputs.len();
    let dry_run = options.mode == GcMode::DryRun;
    let (deleted_narinfos, deleted_nars, deleted_orphans) = if dry_run {
        (0, 0, 0)
    } else {
        let deleted = apply_chunked(storage, chunk_store, &entries, &orphans, &selected)?;
        let remaining = scan_chunked(storage, chunk_store, trusted)?;
        storage.finish_recovery()?;
        let actual_after = chunked_before_bytes(storage, chunk_store, &remaining)?;
        return Ok(chunked_report(ChunkedGcReportInput {
            before_entries: &entries,
            before_bytes,
            after_bytes: actual_after,
            target_bytes,
            dry_run,
            protection,
            protected_bytes,
            eligible,
            eligible_bytes,
            evicted,
            orphaned,
            orphaned_bytes,
            deleted,
        }));
    };

    Ok(chunked_report(ChunkedGcReportInput {
        before_entries: &entries,
        before_bytes,
        after_bytes,
        target_bytes,
        dry_run,
        protection,
        protected_bytes,
        eligible,
        eligible_bytes,
        evicted,
        orphaned,
        orphaned_bytes,
        deleted: (deleted_narinfos, deleted_nars, deleted_orphans),
    }))
}

fn chunked_orphan_bytes(
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
    orphans: &ChunkedOrphans,
) -> Result<u64, StorageError> {
    let retained_chunks = chunk_store
        .reachable_chunk_bytes(entries.iter().map(|entry| entry.raw_hash))
        .map_err(chunk_store_error)?;
    let physical_chunks = chunk_store
        .physical_bytes()
        .map_err(chunk_store_error)?
        .chunks;
    let orphan_files = orphans
        .manifests
        .iter()
        .map(|manifest| manifest.bytes)
        .chain(orphans.outputs.iter().map(|output| output.bytes))
        .try_fold(0_u64, checked_byte_sum("orphan byte count overflow"))?;
    physical_chunks
        .checked_sub(retained_chunks)
        .and_then(|bytes| bytes.checked_add(orphan_files))
        .ok_or_else(|| invalid("orphan byte count underflow or overflow"))
}

fn chunked_eligible_bytes(
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
    orphans: &ChunkedOrphans,
    now: SystemTime,
    min_age: Duration,
) -> Result<u64, StorageError> {
    let eligible_entries = entries
        .iter()
        .filter(|entry| is_chunked_eligible(entry, now, min_age))
        .collect::<Vec<_>>();
    let retained_manifests = entries
        .iter()
        .filter(|entry| !is_chunked_eligible(entry, now, min_age))
        .map(|entry| entry.raw_hash)
        .chain(
            orphans
                .manifests
                .iter()
                .filter(|manifest| !age_reached(manifest.modified, now, min_age))
                .map(|manifest| manifest.hash),
        )
        .collect::<BTreeSet<_>>();
    let retained_chunks = chunk_store
        .reachable_chunk_bytes(retained_manifests.iter().copied())
        .map_err(chunk_store_error)?;
    let physical_chunks = chunk_store
        .physical_bytes()
        .map_err(chunk_store_error)?
        .chunks;
    let manifest_sizes = entries
        .iter()
        .map(|entry| (entry.raw_hash, entry.manifest_bytes))
        .chain(
            orphans
                .manifests
                .iter()
                .map(|manifest| (manifest.hash, manifest.bytes)),
        )
        .collect::<BTreeMap<_, _>>();
    let manifest_bytes = manifest_sizes
        .iter()
        .filter(|(hash, _)| !retained_manifests.contains(hash))
        .map(|(_, bytes)| *bytes)
        .try_fold(
            0_u64,
            checked_byte_sum("eligible manifest byte count overflow"),
        )?;
    let output_sizes = entries
        .iter()
        .filter_map(|entry| {
            entry
                .output_name
                .as_ref()
                .map(|name| (name.clone(), entry.output_bytes))
        })
        .chain(
            orphans
                .outputs
                .iter()
                .map(|output| (output.name.clone(), output.bytes)),
        )
        .collect::<BTreeMap<_, _>>();
    let retained_outputs = entries
        .iter()
        .filter(|entry| !is_chunked_eligible(entry, now, min_age))
        .filter_map(|entry| entry.output_name.clone())
        .chain(
            orphans
                .outputs
                .iter()
                .filter(|output| !age_reached(output.modified, now, min_age))
                .map(|output| output.name.clone()),
        )
        .collect::<BTreeSet<_>>();
    let output_bytes = output_sizes
        .iter()
        .filter(|(name, _)| !retained_outputs.contains(*name))
        .map(|(_, bytes)| *bytes)
        .try_fold(
            0_u64,
            checked_byte_sum("eligible output byte count overflow"),
        )?;
    let metadata_bytes = eligible_entries
        .iter()
        .map(|entry| entry.narinfo_bytes)
        .try_fold(
            0_u64,
            checked_byte_sum("eligible narinfo byte count overflow"),
        )?;
    physical_chunks
        .checked_sub(retained_chunks)
        .and_then(|bytes| bytes.checked_add(manifest_bytes))
        .and_then(|bytes| bytes.checked_add(output_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_bytes))
        .ok_or_else(|| invalid("eligible byte count underflow or overflow"))
}

fn checked_byte_sum(message: &'static str) -> impl FnMut(u64, u64) -> Result<u64, StorageError> {
    move |total, bytes| total.checked_add(bytes).ok_or_else(|| invalid(message))
}

fn scan_chunked(
    storage: &Storage,
    chunk_store: &ChunkStore,
    trusted: &TrustedPublicKeys,
) -> Result<Vec<ChunkedEntry>, StorageError> {
    let root = storage.root_directory()?;
    let nar_directory = storage.nar_directory()?;
    let mut entries = Vec::new();
    for publication in scan_trusted_gc_publications(&root, trusted, read_dir_names(&root)?) {
        let TrustedGcPublication {
            store,
            store_path,
            references,
            narinfo_name: name,
            narinfo_bytes,
            modified,
            representation,
        } = publication?;
        let name_str = name.to_string_lossy();
        let raw_hash = representation.identity().hash();
        let manifest = chunk_store
            .validate_manifest(raw_hash)
            .map_err(chunk_store_error)?
            .ok_or_else(|| invalid(format!("missing chunk manifest for narinfo: {name_str}")))?;
        if manifest.identity() != representation.identity() {
            return Err(invalid(format!(
                "chunk manifest identity mismatch for narinfo: {name_str}"
            )));
        }
        let manifest_bytes = chunk_store
            .open_manifest(raw_hash)?
            .ok_or_else(|| invalid(format!("chunk manifest disappeared: {name_str}")))?
            .metadata()?
            .len();
        let (output_name, output_bytes) = match representation {
            NarRepresentation::Raw(_) => (None, 0),
            NarRepresentation::Compressed(_) => {
                let output_name = representation.file_name().os_string();
                let output = open_regular_at(&nar_directory, &output_name).map_err(|error| {
                    match error.kind() {
                        io::ErrorKind::NotFound => {
                            invalid(format!("missing compressed output: {name_str}"))
                        }
                        _ => error.into(),
                    }
                })?;
                let output_bytes = output.metadata()?.len();
                if output_bytes != representation.encoded_size().get() {
                    return Err(invalid(format!(
                        "compressed output size mismatch for narinfo: {name_str}"
                    )));
                }
                (Some(output_name), output_bytes)
            }
        };
        entries.push(ChunkedEntry {
            store,
            store_path,
            references,
            narinfo_name: name,
            output_name,
            output_bytes,
            raw_hash,
            manifest_bytes,
            narinfo_bytes,
            modified,
            protected: false,
        });
    }
    Ok(entries)
}

fn scan_chunked_orphans(
    storage: &Storage,
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
) -> Result<ChunkedOrphans, StorageError> {
    let live_manifests = entries
        .iter()
        .map(|entry| entry.raw_hash)
        .collect::<BTreeSet<_>>();
    let manifests = chunk_store
        .manifest_files()?
        .into_iter()
        .filter(|manifest| !live_manifests.contains(&manifest.hash))
        .collect();
    let live_outputs = entries
        .iter()
        .filter_map(|entry| entry.output_name.as_ref())
        .collect::<BTreeSet<_>>();
    let nar_directory = storage.nar_directory()?;
    let outputs = read_dir_names(&nar_directory)?
        .into_iter()
        .filter(|name| {
            name.to_str()
                .is_some_and(|name| NarFileName::parse(name).is_ok())
                && !live_outputs.contains(name)
        })
        .map(|name| {
            if !super::entry_is_regular_at(&nar_directory, &name)? {
                return Ok(None);
            }
            let metadata = open_regular_at(&nar_directory, &name)?.metadata()?;
            Ok(Some(Orphan {
                name,
                bytes: metadata.len(),
                modified: metadata.modified()?,
            }))
        })
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>, io::Error>>()?;
    Ok(ChunkedOrphans { manifests, outputs })
}

fn age_reached(modified: SystemTime, now: SystemTime, age: Duration) -> bool {
    now.duration_since(modified).unwrap_or_default() >= age
}

fn chunk_store_error(error: impl std::error::Error + Send + Sync + 'static) -> StorageError {
    StorageError::Io(io::Error::other(error))
}

fn is_chunked_eligible(entry: &ChunkedEntry, now: SystemTime, min_age: Duration) -> bool {
    !entry.protected && now.duration_since(entry.modified).unwrap_or_default() >= min_age
}

fn chunked_projected_bytes(
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
    orphans: &ChunkedOrphans,
    selected: &ChunkedSelection,
) -> Result<u64, StorageError> {
    let mut manifests = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    let narinfo_bytes = entries
        .iter()
        .enumerate()
        .filter(|(index, _)| !selected.entries.contains(index))
        .map(|(_, entry)| entry.narinfo_bytes)
        .try_fold(0_u64, checked_byte_sum("narinfo byte count overflow"))?;
    entries
        .iter()
        .enumerate()
        .filter(|(index, _)| !selected.entries.contains(index))
        .for_each(|(_, entry)| {
            manifests
                .entry(entry.raw_hash)
                .or_insert(entry.manifest_bytes);
            if let Some(name) = &entry.output_name {
                outputs.entry(name.clone()).or_insert(entry.output_bytes);
            }
        });
    orphans
        .manifests
        .iter()
        .enumerate()
        .filter(|(index, _)| !selected.manifests.contains(index))
        .for_each(|(_, manifest)| {
            manifests.entry(manifest.hash).or_insert(manifest.bytes);
        });
    orphans
        .outputs
        .iter()
        .enumerate()
        .filter(|(index, _)| !selected.outputs.contains(index))
        .for_each(|(_, output)| {
            outputs.entry(output.name.clone()).or_insert(output.bytes);
        });

    let chunk_bytes = chunk_store
        .reachable_chunk_bytes(manifests.keys().copied())
        .map_err(chunk_store_error)?;
    chunk_bytes
        .checked_add(manifests.values().copied().sum())
        .and_then(|bytes| bytes.checked_add(outputs.values().copied().sum::<u64>()))
        .and_then(|bytes| bytes.checked_add(narinfo_bytes))
        .ok_or_else(|| invalid("chunked byte count overflow"))
}

fn chunked_bytes_for_entries<'a>(
    chunk_store: &ChunkStore,
    entries: impl IntoIterator<Item = &'a ChunkedEntry>,
) -> Result<u64, StorageError> {
    let mut manifests = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    let mut narinfo_bytes = 0_u64;
    for entry in entries {
        manifests
            .entry(entry.raw_hash)
            .or_insert(entry.manifest_bytes);
        if let Some(name) = &entry.output_name {
            outputs.entry(name.clone()).or_insert(entry.output_bytes);
        }
        narinfo_bytes = narinfo_bytes
            .checked_add(entry.narinfo_bytes)
            .ok_or_else(|| invalid("narinfo byte count overflow"))?;
    }
    let chunk_bytes = chunk_store
        .reachable_chunk_bytes(manifests.keys().copied())
        .map_err(chunk_store_error)?;
    chunk_bytes
        .checked_add(manifests.values().sum())
        .and_then(|bytes| bytes.checked_add(outputs.values().sum::<u64>()))
        .and_then(|bytes| bytes.checked_add(narinfo_bytes))
        .ok_or_else(|| invalid("chunked byte count overflow"))
}

fn chunked_before_bytes(
    storage: &Storage,
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
) -> Result<u64, StorageError> {
    let physical = chunk_store.physical_bytes().map_err(chunk_store_error)?;
    let nar_directory = storage.nar_directory()?;
    let output_bytes =
        read_dir_names(&nar_directory)?
            .into_iter()
            .try_fold(0_u64, |total, name| {
                if !super::entry_is_regular_at(&nar_directory, &name)? {
                    return Ok(total);
                }
                total
                    .checked_add(open_regular_at(&nar_directory, &name)?.metadata()?.len())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "output byte count overflow")
                    })
            })?;
    let metadata_bytes = entries.iter().try_fold(0_u64, |total, entry| {
        total.checked_add(entry.narinfo_bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "narinfo byte count overflow")
        })
    })?;
    physical
        .chunks
        .checked_add(physical.manifests)
        .and_then(|bytes| bytes.checked_add(output_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_bytes))
        .ok_or_else(|| invalid("chunked byte count overflow"))
}

fn select_chunked(
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
    orphans: &ChunkedOrphans,
    current_bytes: u64,
    policy: RetentionPolicy,
) -> Result<ChunkedSelection, StorageError> {
    let mut order = entries
        .iter()
        .enumerate()
        .map(|(index, _)| ChunkedCandidate::Entry(index))
        .chain(
            orphans
                .manifests
                .iter()
                .enumerate()
                .map(|(index, _)| ChunkedCandidate::Manifest(index)),
        )
        .chain(
            orphans
                .outputs
                .iter()
                .enumerate()
                .map(|(index, _)| ChunkedCandidate::Output(index)),
        )
        .filter(|candidate| {
            policy
                .reason(
                    candidate.modified(entries, orphans),
                    candidate.protected(entries),
                    current_bytes,
                )
                .is_some()
        })
        .collect::<Vec<_>>();
    order.sort_unstable_by(|left, right| {
        left.modified(entries, orphans)
            .cmp(&right.modified(entries, orphans))
            .then_with(|| {
                left.name(entries, orphans)
                    .cmp(right.name(entries, orphans))
            })
    });
    let (maximum_age, pressure_candidates): (Vec<_>, Vec<_>) =
        order.into_iter().partition(|candidate| {
            policy.reason(
                candidate.modified(entries, orphans),
                candidate.protected(entries),
                current_bytes,
            ) == Some(CollectionReason::MaximumAge)
        });
    let mut selected = ChunkedSelection::default();
    maximum_age
        .into_iter()
        .for_each(|candidate| selected.include(candidate));
    for candidate in pressure_candidates {
        let remaining = chunked_projected_bytes(chunk_store, entries, orphans, &selected)?;
        if policy
            .reason(
                candidate.modified(entries, orphans),
                candidate.protected(entries),
                remaining,
            )
            .is_some()
        {
            selected.include(candidate);
        }
    }
    Ok(selected)
}

impl ChunkedCandidate {
    fn modified(self, entries: &[ChunkedEntry], orphans: &ChunkedOrphans) -> SystemTime {
        match self {
            Self::Entry(index) => entries[index].modified,
            Self::Manifest(index) => orphans.manifests[index].modified,
            Self::Output(index) => orphans.outputs[index].modified,
        }
    }

    fn protected(self, entries: &[ChunkedEntry]) -> bool {
        match self {
            Self::Entry(index) => entries[index].protected,
            Self::Manifest(_) | Self::Output(_) => false,
        }
    }

    fn name<'a>(self, entries: &'a [ChunkedEntry], orphans: &'a ChunkedOrphans) -> &'a OsStr {
        match self {
            Self::Entry(index) => &entries[index].narinfo_name,
            Self::Manifest(index) => &orphans.manifests[index].name,
            Self::Output(index) => &orphans.outputs[index].name,
        }
    }
}

fn apply_chunked(
    storage: &Storage,
    chunk_store: &ChunkStore,
    entries: &[ChunkedEntry],
    orphans: &ChunkedOrphans,
    selected: &ChunkedSelection,
) -> Result<(usize, usize, usize), StorageError> {
    storage.recovery.require()?;
    let root = storage.root_directory()?;
    let nar_directory = storage.nar_directory()?;
    for &index in &selected.entries {
        unlink_at(&root, &entries[index].narinfo_name)?;
    }
    if !selected.entries.is_empty() {
        root.sync_all()?;
    }
    let selected_outputs = selected
        .entries
        .iter()
        .filter_map(|&index| entries[index].output_name.as_ref())
        .cloned()
        .chain(
            selected
                .outputs
                .iter()
                .map(|&index| orphans.outputs[index].name.clone()),
        )
        .collect::<BTreeSet<_>>();
    let live_outputs = entries
        .iter()
        .enumerate()
        .filter(|(index, _)| !selected.entries.contains(index))
        .filter_map(|(_, entry)| entry.output_name.clone())
        .chain(
            orphans
                .outputs
                .iter()
                .enumerate()
                .filter(|(index, _)| !selected.outputs.contains(index))
                .map(|(_, orphan)| orphan.name.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut deleted_outputs = 0;
    for name in selected_outputs {
        if live_outputs.contains(&name) {
            continue;
        }
        match unlink_at(&nar_directory, &name) {
            Ok(()) => deleted_outputs += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if deleted_outputs > 0 {
        nar_directory.sync_all()?;
    }
    let live_manifests = entries
        .iter()
        .enumerate()
        .filter(|(index, _)| !selected.entries.contains(index))
        .map(|(_, entry)| entry.raw_hash)
        .chain(
            orphans
                .manifests
                .iter()
                .enumerate()
                .filter(|(index, _)| !selected.manifests.contains(index))
                .map(|(_, manifest)| manifest.hash),
        );
    let sweep = chunk_store
        .sweep_unreachable(live_manifests)
        .map_err(chunk_store_error)?;
    Ok((
        selected.entries.len(),
        sweep.deleted_manifests,
        deleted_outputs,
    ))
}

fn chunked_report(input: ChunkedGcReportInput<'_>) -> GcReport {
    let shared = input
        .before_entries
        .iter()
        .fold(BTreeMap::<NarHash, usize>::new(), |mut counts, entry| {
            *counts.entry(entry.raw_hash).or_default() += 1;
            counts
        })
        .values()
        .filter(|&&count| count > 1)
        .count();
    let shared_bytes = input
        .before_entries
        .iter()
        .fold(
            BTreeMap::<NarHash, (usize, u64)>::new(),
            |mut counts, entry| {
                let item = counts
                    .entry(entry.raw_hash)
                    .or_insert((0, entry.manifest_bytes));
                item.0 += 1;
                item.1 = entry.manifest_bytes;
                counts
            },
        )
        .into_values()
        .filter_map(|(count, bytes)| (count > 1).then_some(bytes))
        .sum();
    let deleted_narinfos = input.deleted.0;
    let deleted_nars = input.deleted.1;
    let deleted_orphans = input.deleted.2;
    GcReport {
        accounting_basis: "logical",
        dry_run: input.dry_run,
        before_bytes: input.before_bytes,
        after_bytes: input.after_bytes,
        target_met: input
            .target_bytes
            .is_none_or(|target| input.after_bytes <= target),
        candidates: input.evicted,
        protected: input.protection.protected,
        eligible: input.eligible,
        evicted: input.evicted,
        shared,
        orphaned: input.orphaned,
        temporary: 0,
        malformed: 0,
        missing_roots: input.protection.missing_roots,
        missing_references: input.protection.missing_references,
        protected_bytes: input.protected_bytes,
        eligible_bytes: input.eligible_bytes,
        evicted_bytes: input.before_bytes.saturating_sub(input.after_bytes),
        shared_bytes,
        orphaned_bytes: input.orphaned_bytes,
        temporary_bytes: 0,
        malformed_bytes: 0,
        deleted_narinfos,
        deleted_nars,
        deleted_orphans,
    }
}

fn scan_orphans(storage: &Storage, entries: &[Entry]) -> Result<Vec<Orphan>, StorageError> {
    let referenced = entries
        .iter()
        .flat_map(|entry| {
            [entry.nar_name.clone(), entry.raw_nar_name.clone()]
                .into_iter()
                .map(|name| (name, ()))
        })
        .collect::<BTreeMap<_, _>>();
    let nar_directory = storage.nar_directory()?;
    let mut orphans = Vec::new();
    for name in read_dir_names(&nar_directory)? {
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(_nar_name) = NarFileName::parse(name_str) else {
            continue;
        };
        if !super::entry_is_regular_at(&nar_directory, &name)? {
            continue;
        }
        if referenced.contains_key(OsStr::new(name_str)) {
            continue;
        }
        let metadata = open_regular_at(&nar_directory, &name)?.metadata()?;
        orphans.push(Orphan {
            name,
            bytes: metadata.len(),
            modified: metadata.modified()?,
        });
    }
    Ok(orphans)
}

fn orphan_bytes(orphans: &[Orphan]) -> u64 {
    orphans.iter().map(|orphan| orphan.bytes).sum()
}

fn eligible_count(
    entries: &[Entry],
    orphans: &[Orphan],
    now: SystemTime,
    min_age: Duration,
) -> usize {
    entries
        .iter()
        .filter(|entry| {
            !entry.protected && now.duration_since(entry.modified).unwrap_or_default() >= min_age
        })
        .count()
        + orphans
            .iter()
            .filter(|orphan| now.duration_since(orphan.modified).unwrap_or_default() >= min_age)
            .count()
}

fn shared_count(entries: &[Entry]) -> usize {
    reference_counts(entries)
        .values()
        .filter(|&&count| count > 1)
        .count()
}

fn temporary_inventory(storage: &Storage) -> Result<(usize, u64), StorageError> {
    let directories = [
        storage.temp_directory()?,
        storage.nar_temp_directory()?,
        storage.realisations_temp_directory()?,
    ];
    let mut count = 0;
    let mut bytes = 0;
    for directory in directories {
        let (directory_count, directory_bytes) = temporary_inventory_directory(&directory)?;
        count += directory_count;
        bytes += directory_bytes;
    }
    Ok((count, bytes))
}

fn temporary_inventory_directory(directory: &File) -> Result<(usize, u64), StorageError> {
    let mut count = 0;
    let mut bytes = 0;
    for name in read_dir_names(directory)? {
        if super::entry_is_regular_at(directory, &name)? {
            let metadata = super::open_regular_at(directory, &name)?.metadata()?;
            bytes += metadata.len();
            count += 1;
        }
    }
    Ok((count, bytes))
}

fn category_bytes(entries: &[Entry], include: impl Fn(&Entry) -> bool) -> u64 {
    let mut total = 0;
    let mut nars = BTreeMap::new();
    for entry in entries.iter().filter(|entry| include(entry)) {
        total += entry.narinfo_bytes;
        record_entry_payload_sizes(entry, &mut nars);
    }
    total + nars.values().copied().sum::<u64>()
}

fn shared_bytes(entries: &[Entry]) -> u64 {
    let counts = reference_counts(entries);
    let sizes = payload_sizes(entries);
    counts
        .into_iter()
        .filter_map(|(nar, count)| (count > 1).then(|| sizes[&nar]))
        .sum()
}

fn eligible_bytes(
    entries: &[Entry],
    orphans: &[Orphan],
    now: SystemTime,
    min_age: Duration,
) -> u64 {
    category_bytes(entries, |entry| {
        !entry.protected && now.duration_since(entry.modified).unwrap_or_default() >= min_age
    }) + orphans
        .iter()
        .filter(|orphan| now.duration_since(orphan.modified).unwrap_or_default() >= min_age)
        .map(|orphan| orphan.bytes)
        .sum::<u64>()
}

struct ProtectionNode<'a> {
    store: &'a StoreHash,
    store_path: &'a str,
    references: &'a [String],
    protected: &'a mut bool,
}

fn protect<E>(
    entries: &mut [E],
    path: Option<&Path>,
    project: impl for<'a> Fn(&'a mut E) -> ProtectionNode<'a>,
) -> Result<ProtectionReport, StorageError> {
    let Some(path) = path else {
        return Ok(ProtectionReport {
            protected: 0,
            missing_roots: 0,
            missing_references: 0,
        });
    };
    let contents = fs::read_to_string(path)?;
    let roots = contents
        .lines()
        .map(str::trim)
        .filter(|root| !root.is_empty())
        .try_fold(BTreeSet::new(), |mut roots, root| {
            validate_root(root)?;
            roots.insert(root.to_owned());
            Ok::<_, StorageError>(roots)
        })?;

    let mut pending = roots.iter().cloned().collect::<Vec<_>>();
    let mut missing_roots = BTreeSet::new();
    let mut missing_references = BTreeSet::new();
    std::iter::from_fn(|| {
        let root = pending.pop()?;
        match entries
            .iter_mut()
            .map(&project)
            .find(|entry| entry.store_path == root || entry.store.as_str() == root)
        {
            Some(entry) => match *entry.protected {
                true => {}
                false => {
                    *entry.protected = true;
                    pending.extend(entry.references.iter().cloned());
                }
            },
            None => {
                let missing = if roots.contains(&root) {
                    &mut missing_roots
                } else {
                    &mut missing_references
                };
                missing.insert(root);
            }
        }
        Some(())
    })
    .for_each(drop);

    Ok(ProtectionReport {
        protected: entries
            .iter_mut()
            .map(project)
            .filter(|entry| *entry.protected)
            .count(),
        missing_roots: missing_roots.len(),
        missing_references: missing_references.len(),
    })
}

fn validate_root(root: &str) -> Result<(), StorageError> {
    if StoreHash::parse(root).is_ok() {
        return Ok(());
    }
    let basename = root
        .strip_prefix("/nix/store/")
        .and_then(|value| value.split_once('-').map(|(hash, _)| hash))
        .ok_or_else(|| invalid(format!("invalid protected root: {root}")))?;
    StoreHash::parse(basename)
        .map(|_| ())
        .map_err(|_| invalid(format!("invalid protected root: {root}")))
}

fn total_bytes(entries: &[Entry]) -> u64 {
    let mut total = entries.iter().map(|entry| entry.narinfo_bytes).sum();
    total += payload_sizes(entries).values().copied().sum::<u64>();
    total
}

fn entry_payload_names(entry: &Entry) -> impl Iterator<Item = &OsString> {
    std::iter::once(&entry.nar_name)
        .chain((entry.raw_nar_name != entry.nar_name).then_some(&entry.raw_nar_name))
}

fn record_entry_payload_sizes(entry: &Entry, sizes: &mut BTreeMap<OsString, u64>) {
    sizes
        .entry(entry.nar_name.clone())
        .or_insert(entry.nar_bytes);
    if entry.raw_nar_name != entry.nar_name {
        sizes
            .entry(entry.raw_nar_name.clone())
            .or_insert(entry.raw_nar_bytes);
    }
}

fn payload_sizes(entries: &[Entry]) -> BTreeMap<OsString, u64> {
    let mut sizes = BTreeMap::new();
    entries
        .iter()
        .for_each(|entry| record_entry_payload_sizes(entry, &mut sizes));
    sizes
}

fn reference_counts(entries: &[Entry]) -> BTreeMap<OsString, u64> {
    let mut references = BTreeMap::new();
    for entry in entries {
        for name in entry_payload_names(entry) {
            *references.entry(name.clone()).or_insert(0_u64) += 1;
        }
    }
    references
}

fn select(entries: &[Entry], current_bytes: u64, policy: RetentionPolicy) -> Vec<usize> {
    let mut references = reference_counts(entries);
    let sizes = payload_sizes(entries);
    let mut order = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            policy
                .reason(entry.modified, entry.protected, current_bytes)
                .is_some()
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    order.sort_unstable_by(|&left, &right| {
        entries[left]
            .modified
            .cmp(&entries[right].modified)
            .then_with(|| entries[left].store.cmp(&entries[right].store))
    });

    let mut remaining = current_bytes;
    let mut selected = Vec::new();
    for index in order {
        let entry = &entries[index];
        if policy
            .reason(entry.modified, entry.protected, remaining)
            .is_none()
        {
            continue;
        }

        selected.push(index);
        remaining = remaining.saturating_sub(entry.narinfo_bytes);
        for name in entry_payload_names(entry) {
            let count = references
                .get_mut(name)
                .expect("scanned payload reference count");
            *count -= 1;
            if *count == 0 {
                remaining = remaining.saturating_sub(sizes[name]);
            }
        }
    }
    selected
}

fn select_orphans(orphans: &[Orphan], current_bytes: u64, policy: RetentionPolicy) -> Vec<usize> {
    let mut order = orphans
        .iter()
        .enumerate()
        .filter(|(_, orphan)| {
            policy
                .reason(orphan.modified, false, current_bytes)
                .is_some()
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    order.sort_unstable_by(|&left, &right| {
        orphans[left]
            .modified
            .cmp(&orphans[right].modified)
            .then_with(|| orphans[left].name.cmp(&orphans[right].name))
    });

    let mut remaining = current_bytes;
    let mut selected = Vec::new();
    for index in order {
        let orphan = &orphans[index];
        if policy.reason(orphan.modified, false, remaining).is_none() {
            continue;
        }
        selected.push(index);
        remaining = remaining.saturating_sub(orphan.bytes);
    }
    selected
}

fn logical_after_bytes(
    entries: &[Entry],
    selected_entries: &[usize],
    orphans: &[Orphan],
    selected_orphans: &[usize],
) -> u64 {
    let selected_orphan_bytes = selected_orphans
        .iter()
        .map(|&index| orphans[index].bytes)
        .sum::<u64>();
    projected_published_bytes(entries, selected_entries)
        .saturating_add(orphan_bytes(orphans))
        .saturating_sub(selected_orphan_bytes)
}

fn projected_published_bytes(entries: &[Entry], selected: &[usize]) -> u64 {
    let mut total = total_bytes(entries);
    let mut references = reference_counts(entries);
    let sizes = payload_sizes(entries);
    for &index in selected {
        let entry = &entries[index];
        total = total.saturating_sub(entry.narinfo_bytes);
        for name in entry_payload_names(entry) {
            let count = references
                .get_mut(name)
                .expect("scanned payload reference count");
            *count -= 1;
            if *count == 0 {
                total = total.saturating_sub(sizes[name]);
            }
        }
    }
    total
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    BeforeNarinfoDelete,
    AfterNarinfoDeleteBeforeSync,
    AfterNarinfoSyncBeforeNarDelete,
    AfterNarDeleteBeforeSync,
    DuringOrphanCleanup,
}

fn fail_if(failure: Option<FailurePoint>, point: FailurePoint) -> Result<(), StorageError> {
    if failure == Some(point) {
        Err(invalid(format!("injected GC failure at {point:?}")))
    } else {
        Ok(())
    }
}

fn apply(
    storage: &Storage,
    entries: &[Entry],
    selected: &[usize],
) -> Result<(usize, usize), StorageError> {
    apply_with_failure(storage, entries, selected, None)
}

fn apply_with_failure(
    storage: &Storage,
    entries: &[Entry],
    selected: &[usize],
    failure: Option<FailurePoint>,
) -> Result<(usize, usize), StorageError> {
    storage.recovery.require()?;
    let root = storage.root_directory()?;
    let nar_directory = storage.nar_directory()?;
    let mut references = reference_counts(entries);
    let mut deleted_nars = 0;
    for &index in selected {
        let entry = &entries[index];
        fail_if(failure, FailurePoint::BeforeNarinfoDelete)?;
        unlink_at(&root, &entry.narinfo_name)?;
        fail_if(failure, FailurePoint::AfterNarinfoDeleteBeforeSync)?;
        root.sync_all()?;
        fail_if(failure, FailurePoint::AfterNarinfoSyncBeforeNarDelete)?;
        let mut deleted_payload = false;
        let mut deleted_raw_nar = false;
        for name in entry_payload_names(entry) {
            let count = references
                .get_mut(name)
                .expect("scanned payload reference count");
            *count -= 1;
            if *count != 0 {
                continue;
            }
            unlink_at(&nar_directory, name)?;
            deleted_payload = true;
            deleted_raw_nar |= *name == entry.raw_nar_name;
            fail_if(failure, FailurePoint::AfterNarDeleteBeforeSync)?;
        }
        if deleted_payload {
            nar_directory.sync_all()?;
        }
        if deleted_raw_nar {
            deleted_nars += 1;
        }
    }
    Ok((selected.len(), deleted_nars))
}

fn apply_orphans(
    storage: &Storage,
    orphans: &[Orphan],
    selected: &[usize],
) -> Result<usize, StorageError> {
    apply_orphans_with_failure(storage, orphans, selected, None)
}

fn apply_orphans_with_failure(
    storage: &Storage,
    orphans: &[Orphan],
    selected: &[usize],
    failure: Option<FailurePoint>,
) -> Result<usize, StorageError> {
    let nar_directory = storage.nar_directory()?;
    for &index in selected {
        fail_if(failure, FailurePoint::DuringOrphanCleanup)?;
        unlink_at(&nar_directory, &orphans[index].name)?;
    }
    if !selected.is_empty() {
        nar_directory.sync_all()?;
    }
    Ok(selected.len())
}

fn invalid(message: impl Into<String>) -> StorageError {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::NarFileName;
    use crate::storage::{CacheCreation, Directory, NarUploadPolicy};
    use sha2::Digest;
    use std::{
        fs,
        os::unix::fs::symlink,
        time::{Duration, UNIX_EPOCH},
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Candidate {
        bytes: u64,
        modified: std::time::SystemTime,
        protected: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Policy {
        target_bytes: u64,
        min_age: Duration,
    }

    fn initialize_storage(path: &Path) -> Result<Storage, StorageError> {
        CacheCreation::prepare(&Directory::open(path)?, SupportedStorageBackend::FLAT)
            .and_then(|creation| creation.create_or_complete())
    }

    #[test]
    fn shared_protection_traversal_handles_cycles_aliases_and_missing_paths_once() {
        struct Node {
            store: StoreHash,
            path: String,
            references: Vec<String>,
            protected: bool,
        }
        let a = "00000000000000000000000000000000";
        let b = "11111111111111111111111111111111";
        let missing_root = "22222222222222222222222222222222";
        let missing_reference = "33333333333333333333333333333333";
        let mut entries = [
            Node {
                store: StoreHash::parse(a).unwrap(),
                path: format!("/nix/store/{a}-a"),
                references: vec![b.into(), b.into(), missing_reference.into()],
                protected: false,
            },
            Node {
                store: StoreHash::parse(b).unwrap(),
                path: format!("/nix/store/{b}-b"),
                references: vec![a.into(), missing_reference.into()],
                protected: false,
            },
        ];
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("roots");
        fs::write(
            &path,
            format!("{a}\n/nix/store/{a}-a\n{missing_root}\n{missing_root}\n\n"),
        )
        .unwrap();
        let report = protect(&mut entries, Some(&path), |entry| ProtectionNode {
            store: &entry.store,
            store_path: &entry.path,
            references: &entry.references,
            protected: &mut entry.protected,
        })
        .unwrap();
        assert_eq!(
            (
                report.protected,
                report.missing_roots,
                report.missing_references
            ),
            (2, 1, 1)
        );
        assert!(entries.iter().all(|entry| entry.protected));
    }

    #[cfg(not(target_os = "macos"))]
    fn initialize_chunked_storage(path: &Path) -> Result<Storage, StorageError> {
        use std::os::unix::fs::PermissionsExt;

        let storage = CacheCreation::prepare(
            &Directory::open(path)?,
            StorageBackend::Chunked.try_into().unwrap(),
        )
        .and_then(|creation| creation.create_or_complete())?;
        fs::create_dir_all(path.join("auth"))?;
        fs::set_permissions(path.join("auth"), fs::Permissions::from_mode(0o700))?;
        for (name, contents) in [
            (
                "nix-cache-info",
                "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n",
            ),
            ("trusted-public-keys", ""),
            ("auth/write.tokens", ""),
        ] {
            fs::write(path.join(name), contents)?;
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))?;
        }
        Ok(storage)
    }

    fn select_candidates(
        entries: &[Candidate],
        current_bytes: u64,
        policy: Policy,
        now: std::time::SystemTime,
    ) -> Vec<usize> {
        let mut eligible = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                !entry.protected
                    && now.duration_since(entry.modified).unwrap_or_default() >= policy.min_age
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        eligible.sort_unstable_by_key(|&index| (entries[index].modified, index));

        let mut remaining = current_bytes;
        let mut selected = Vec::new();

        for index in eligible {
            if remaining <= policy.target_bytes {
                break;
            }

            remaining = remaining.saturating_sub(entries[index].bytes);
            selected.push(index);
        }

        selected
    }

    #[test]
    fn retention_selects_oldest_eligible_entries() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let entries = vec![
            Candidate {
                bytes: 70,
                modified: UNIX_EPOCH + Duration::from_secs(100),
                protected: false,
            },
            Candidate {
                bytes: 50,
                modified: UNIX_EPOCH + Duration::from_secs(200),
                protected: false,
            },
            Candidate {
                bytes: 30,
                modified: UNIX_EPOCH + Duration::from_secs(995),
                protected: false,
            },
            Candidate {
                bytes: 40,
                modified: UNIX_EPOCH + Duration::from_secs(10),
                protected: true,
            },
        ];

        assert_eq!(
            select_candidates(
                &entries,
                190,
                Policy {
                    target_bytes: 60,
                    min_age: Duration::from_secs(10),
                },
                now,
            ),
            vec![0, 1]
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn flat_and_chunked_gc_both_wait_until_maximum_pressure_is_crossed() {
        let now = SystemTime::now();
        let mut flat_entries = [Entry {
            store: StoreHash::parse(TEST_STORE_HASH).unwrap(),
            store_path: String::new(),
            references: Vec::new(),
            narinfo_name: OsString::from("flat.narinfo"),
            nar_name: OsString::from("flat.nar"),
            narinfo_bytes: 1,
            nar_bytes: 99,
            raw_nar_name: OsString::from("flat.nar"),
            raw_nar_bytes: 99,
            modified: now,
            protected: false,
        }];
        assert!(
            select(
                &flat_entries,
                100,
                RetentionPolicy {
                    pressure_target: None,
                    max_age: None,
                    min_age: Duration::ZERO,
                    now,
                },
            )
            .is_empty()
        );
        assert_eq!(
            select(
                &flat_entries,
                100,
                RetentionPolicy {
                    pressure_target: Some(0),
                    max_age: None,
                    min_age: Duration::ZERO,
                    now,
                },
            ),
            vec![0],
            "flat GC should collect toward target after exceeding max_bytes"
        );
        flat_entries[0].protected = true;
        assert!(
            select(
                &flat_entries,
                100,
                RetentionPolicy::for_limits(100, Some(0), Some(99), None, Duration::ZERO, now,),
            )
            .is_empty(),
            "flat GC must preserve protected entries during size pressure"
        );

        let directory = tempfile::tempdir().unwrap();
        let storage = initialize_chunked_storage(directory.path()).unwrap();
        let raw = vec![b'x'; 100_000];
        let raw_hash = NarHash::from_digest(sha2::Sha256::digest(&raw).into());
        storage
            .publish_nar(
                NarFileName::raw(raw_hash),
                io::Cursor::new(&raw),
                raw.len() as u64,
                super::super::NarUploadPolicy::new(raw.len() as u64, 0),
            )
            .unwrap();
        let chunk_store = storage.chunk_store().unwrap();
        let physical = chunk_store.physical_bytes().unwrap();
        let mut entries = [ChunkedEntry {
            store: StoreHash::parse(TEST_STORE_HASH).unwrap(),
            store_path: String::new(),
            references: Vec::new(),
            narinfo_name: OsString::from("chunked.narinfo"),
            output_name: Some(NarFileName::raw(raw_hash).to_string().into()),
            output_bytes: raw.len() as u64,
            raw_hash,
            manifest_bytes: physical.manifests,
            narinfo_bytes: 0,
            modified: now,
            protected: false,
        }];
        let before = chunked_before_bytes(&storage, chunk_store, &entries).unwrap();
        let orphans = ChunkedOrphans::default();

        let selected = select_chunked(
            chunk_store,
            &entries,
            &orphans,
            before,
            RetentionPolicy::for_limits(
                before,
                Some(0),
                Some(before + 1),
                None,
                Duration::ZERO,
                now,
            ),
        )
        .unwrap();
        assert!(selected.entries.is_empty());
        assert!(selected.manifests.is_empty());
        assert!(selected.outputs.is_empty());

        let selected = select_chunked(
            chunk_store,
            &entries,
            &orphans,
            before,
            RetentionPolicy::for_limits(
                before,
                Some(0),
                Some(before - 1),
                None,
                Duration::ZERO,
                now,
            ),
        )
        .unwrap();
        assert_eq!(
            selected.entries,
            vec![0],
            "chunked GC should collect toward target after exceeding max_bytes"
        );
        entries[0].protected = true;
        let selected = select_chunked(
            chunk_store,
            &entries,
            &orphans,
            before,
            RetentionPolicy::for_limits(
                before,
                Some(0),
                Some(before - 1),
                None,
                Duration::ZERO,
                now,
            ),
        )
        .unwrap();
        assert!(
            selected.entries.is_empty(),
            "chunked GC must preserve protected entries during size pressure"
        );
    }

    #[test]
    fn temporary_inventory_does_not_follow_symlinks() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let target = directory.path().join("external");
        let temporary = directory.path().join(".tmp");
        fs::create_dir(&temporary).expect("temporary directory should be created");
        fs::write(&target, vec![0; 17]).expect("external target should be written");
        symlink(&target, temporary.join("escaped")).expect("temporary symlink should be created");

        assert_eq!(
            temporary_inventory_directory(
                Directory::open(&temporary)
                    .expect("open temporary directory")
                    .file(),
            )
            .expect("scan temporary directory"),
            (0, 0)
        );
    }

    #[test]
    fn temporary_inventory_rejects_a_symlinked_directory() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let target = directory.path().join("external");
        let temporary = directory.path().join(".tmp");
        fs::create_dir(&target).expect("external directory should be created");
        fs::write(target.join("escaped"), vec![0; 17]).expect("external file should be written");
        symlink(&target, &temporary).expect("temporary directory symlink should be created");

        assert!(Directory::open(&temporary).is_err());
    }

    #[test]
    fn orphan_scan_rejects_a_symlinked_nar_directory() {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_storage(directory.path()).expect("storage should initialize");
        let nar_dir = storage.layout.nar_dir();
        let real_nar_dir = directory.path().join("nar-real");
        let external = directory.path().join("external");
        fs::rename(&nar_dir, &real_nar_dir).expect("move real NAR directory");
        fs::create_dir(&external).expect("create external directory");
        fs::write(
            external.join("0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar"),
            b"external",
        )
        .expect("write external NAR");
        symlink(&external, &nar_dir).expect("create NAR directory symlink");

        assert!(scan_orphans(&storage, &[]).is_err());
    }

    #[test]
    fn scan_error_preserves_published_files_before_gc_can_apply_deletions() {
        let (directory, storage, entry) = pair_fixture();
        let trusted = TrustedPublicKeys::load(
            &Directory::open(directory.path()).expect("storage root should open"),
        )
        .expect("default trust configuration should load");
        let result = run_flat_gc(
            GcOptions {
                data_dir: directory.path().to_owned(),
                max_bytes: None,
                target_bytes: Some(0),
                max_age: None,
                min_age: Duration::ZERO,
                protected_roots: None,
                mode: GcMode::Apply,
                backend: StorageBackend::Flat,
            },
            &storage,
            &trusted,
            Some(0),
            |storage, trusted| {
                scan_with_directory_names(storage, trusted, |_| {
                    Err(io::Error::from_raw_os_error(
                        rustix::io::Errno::IO.raw_os_error(),
                    ))
                })
            },
        );

        assert!(result.is_err(), "an incomplete GC scan must abort");
        assert!(
            directory.path().join(&entry.narinfo_name).exists(),
            "GC must not delete metadata after a scan error"
        );
        assert!(
            directory.path().join("nar").join(&entry.nar_name).exists(),
            "GC must not delete a NAR after a scan error"
        );
    }

    const TEST_STORE_HASH: &str = "00000000000000000000000000000000";
    const TEST_SECOND_STORE_HASH: &str = "11111111111111111111111111111111";
    const TEST_NAR_ID: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    const TEST_ZSTD_ID: &str = "1li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";

    fn pair_fixture() -> (tempfile::TempDir, Storage, Entry) {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_storage(directory.path()).expect("storage should initialize");
        let store = StoreHash::parse(TEST_STORE_HASH).expect("store hash should parse");
        let nar = crate::object::NarHash::parse(TEST_NAR_ID).expect("NAR hash should parse");
        let narinfo_name = OsString::from(format!("{TEST_STORE_HASH}.narinfo"));
        let nar_path = storage.layout.nar_path(nar);
        let narinfo_path = directory.path().join(&narinfo_name);
        fs::write(&narinfo_path, b"published").expect("narinfo should be written");
        fs::write(&nar_path, b"nar").expect("NAR should be written");

        let entry = Entry {
            store,
            store_path: format!("/nix/store/{TEST_STORE_HASH}-narjar"),
            references: Vec::new(),
            narinfo_name,
            nar_name: OsString::from(format!("{TEST_NAR_ID}.nar")),
            narinfo_bytes: 9,
            nar_bytes: 3,
            raw_nar_name: OsString::from(format!("{TEST_NAR_ID}.nar")),
            raw_nar_bytes: 3,
            modified: SystemTime::now(),
            protected: false,
        };
        (directory, storage, entry)
    }

    fn mixed_pair_fixture() -> (tempfile::TempDir, Storage, Vec<Entry>) {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_storage(directory.path()).expect("storage should initialize");
        let raw_name = OsString::from(format!("{TEST_NAR_ID}.nar"));
        let zstd_name = OsString::from(format!("{TEST_ZSTD_ID}.nar.zst"));
        fs::write(directory.path().join("nar").join(&raw_name), b"raw")
            .expect("raw NAR should be written");
        fs::write(directory.path().join("nar").join(&zstd_name), b"zstd")
            .expect("Zstd NAR should be written");

        let raw_entry = Entry {
            store: StoreHash::parse(TEST_STORE_HASH).expect("store hash should parse"),
            store_path: format!("/nix/store/{TEST_STORE_HASH}-narjar"),
            references: Vec::new(),
            narinfo_name: OsString::from(format!("{TEST_STORE_HASH}.narinfo")),
            nar_name: raw_name.clone(),
            narinfo_bytes: 9,
            nar_bytes: 3,
            raw_nar_name: raw_name.clone(),
            raw_nar_bytes: 3,
            modified: SystemTime::now(),
            protected: false,
        };
        let compressed_entry = Entry {
            store: StoreHash::parse(TEST_SECOND_STORE_HASH)
                .expect("second store hash should parse"),
            store_path: format!("/nix/store/{TEST_SECOND_STORE_HASH}-narjar"),
            references: Vec::new(),
            narinfo_name: OsString::from(format!("{TEST_SECOND_STORE_HASH}.narinfo")),
            nar_name: zstd_name,
            narinfo_bytes: 9,
            nar_bytes: 4,
            raw_nar_name: raw_name,
            raw_nar_bytes: 3,
            modified: SystemTime::now(),
            protected: false,
        };
        fs::write(directory.path().join(&raw_entry.narinfo_name), b"published")
            .expect("raw narinfo should be written");
        fs::write(
            directory.path().join(&compressed_entry.narinfo_name),
            b"published",
        )
        .expect("compressed narinfo should be written");
        (directory, storage, vec![raw_entry, compressed_entry])
    }

    #[test]
    fn orphan_scan_distinguishes_raw_and_xz_objects_with_the_same_hash() {
        let (directory, storage, mut entry) = pair_fixture();
        let nar_directory = directory.path().join("nar");
        let raw_name = format!("{TEST_NAR_ID}.nar");
        let xz_name = format!("{TEST_NAR_ID}.nar.xz");
        fs::rename(nar_directory.join(&raw_name), nar_directory.join(&xz_name))
            .expect("rename fixture to XZ object");
        fs::write(nar_directory.join(&raw_name), b"raw").expect("write raw object");
        entry.nar_name = OsString::from(xz_name);
        entry.raw_nar_name = entry.nar_name.clone();
        entry.raw_nar_bytes = 3;

        let orphans = scan_orphans(&storage, &[entry]).expect("scan orphans");

        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].name, OsString::from(raw_name));
    }

    #[test]
    fn gc_unifies_shared_raw_and_output_references() {
        let (directory, storage, entries) = mixed_pair_fixture();
        let raw_path = directory
            .path()
            .join("nar")
            .join(format!("{TEST_NAR_ID}.nar"));
        let zstd_path = directory
            .path()
            .join("nar")
            .join(format!("{TEST_ZSTD_ID}.nar.zst"));

        let result = apply(&storage, &entries, &[0]).expect("first entry should be evicted");
        assert_eq!(result, (1, 0));
        assert!(
            !directory
                .path()
                .join(format!("{TEST_STORE_HASH}.narinfo"))
                .exists()
        );
        assert!(raw_path.exists(), "protected entry still needs its raw NAR");
        assert!(
            zstd_path.exists(),
            "protected entry still needs its output NAR"
        );
    }

    #[test]
    fn gc_deletes_shared_payloads_once_in_either_eviction_order() {
        for selected in [[0, 1], [1, 0]] {
            let (directory, storage, entries) = mixed_pair_fixture();
            let result = apply(&storage, &entries, &selected).expect("entries should be evicted");
            assert_eq!(result, (2, 1));
            assert!(
                !directory
                    .path()
                    .join(format!("nar/{TEST_NAR_ID}.nar"))
                    .exists()
            );
            assert!(
                !directory
                    .path()
                    .join(format!("nar/{TEST_ZSTD_ID}.nar.zst"))
                    .exists()
            );
        }
    }

    #[test]
    fn gc_projection_does_not_double_count_a_raw_only_payload() {
        let (directory, storage, entry) = pair_fixture();
        let entries = [entry];
        assert_eq!(total_bytes(&entries), 12);
        assert_eq!(projected_published_bytes(&entries, &[0]), 0);
        drop(storage);
        drop(directory);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn chunked_gc_sweeps_unreferenced_manifests_and_chunks() {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage =
            initialize_chunked_storage(directory.path()).expect("storage should initialize");
        let raw = vec![b'x'; 100_000];
        let hash = NarHash::from_digest(sha2::Sha256::digest(&raw).into());
        storage
            .publish_nar(
                NarFileName::raw(hash),
                io::Cursor::new(&raw),
                raw.len() as u64,
                NarUploadPolicy::new(raw.len() as u64, 0),
            )
            .expect("chunked NAR should be published");
        let before = storage
            .chunk_store()
            .expect("chunked storage should expose its chunk store")
            .physical_bytes()
            .expect("chunked physical bytes should be readable");
        assert!(before.manifests > 0);
        assert!(before.chunks > 0);
        drop(storage);

        let report = run(GcOptions {
            data_dir: directory.path().to_owned(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age: None,
            min_age: Duration::ZERO,
            protected_roots: None,
            mode: GcMode::Apply,
            backend: StorageBackend::Chunked,
        })
        .expect("chunked GC should complete");

        assert_eq!(report.deleted_narinfos, 0);
        assert_eq!(report.deleted_nars, 1);
        assert_eq!(report.deleted_orphans, 0);
        assert_eq!(report.after_bytes, 0);

        let reopened = initialize_chunked_storage(directory.path()).expect("storage should reopen");
        let after = reopened
            .chunk_store()
            .expect("chunked storage should expose its chunk store")
            .physical_bytes()
            .expect("chunked physical bytes should be readable");
        assert_eq!(after, Default::default());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn chunked_gc_preserves_recent_orphans_then_collects_them_after_the_grace() {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_chunked_storage(directory.path()).expect("initialize storage");
        let raw = vec![b'x'; 100_000];
        let hash = NarHash::from_digest(sha2::Sha256::digest(&raw).into());
        storage
            .publish_nar(
                NarFileName::raw(hash),
                io::Cursor::new(&raw),
                raw.len() as u64,
                super::super::NarUploadPolicy::new(raw.len() as u64, 0),
            )
            .expect("publish payload without its later narinfo");
        let output = storage.layout.nar_path(hash);
        fs::write(&output, b"unreferenced output derivative")
            .expect("create an output orphan alongside the recent manifest");
        let manifest = storage
            .chunk_store()
            .unwrap()
            .manifest_files()
            .unwrap()
            .into_iter()
            .find(|manifest| manifest.hash == hash)
            .unwrap();
        let manifest_path = directory
            .path()
            .join(super::super::MANIFEST_DIRECTORY)
            .join(manifest.name);
        drop(storage);

        let grace = Duration::from_secs(24 * 60 * 60);
        let gc_options = |mode| GcOptions {
            data_dir: directory.path().to_owned(),
            max_bytes: Some(1),
            target_bytes: Some(0),
            max_age: None,
            min_age: grace,
            protected_roots: None,
            mode,
            backend: StorageBackend::Chunked,
        };
        let recent_dry_run = run(gc_options(GcMode::DryRun)).expect("inspect recent orphan");
        assert_eq!(recent_dry_run.evicted, 0);
        assert_eq!(recent_dry_run.orphaned, 2);
        assert_eq!(recent_dry_run.eligible_bytes, 0);
        assert_eq!(recent_dry_run.orphaned_bytes, recent_dry_run.before_bytes);
        assert_eq!(recent_dry_run.after_bytes, recent_dry_run.before_bytes);

        let recent_apply = run(gc_options(GcMode::Apply)).expect("retain recent orphan");
        assert_eq!(recent_apply.after_bytes, recent_apply.before_bytes);
        assert!(output.exists());
        assert!(manifest_path.exists());

        let expired = SystemTime::now() - grace - Duration::from_secs(1);
        for path in [&output, &manifest_path] {
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(expired))
                .unwrap();
        }
        let expired_dry_run = run(gc_options(GcMode::DryRun)).expect("project expired orphans");
        assert_eq!(expired_dry_run.evicted, 2);
        assert_eq!(expired_dry_run.eligible_bytes, expired_dry_run.before_bytes);
        assert_eq!(expired_dry_run.orphaned_bytes, expired_dry_run.before_bytes);
        assert_eq!(expired_dry_run.after_bytes, 0);

        let expired_apply = run(gc_options(GcMode::Apply)).expect("collect expired orphans");
        assert_eq!(expired_apply.after_bytes, expired_dry_run.after_bytes);
        assert!(!output.exists());
        assert!(!manifest_path.exists());
        let reopened = initialize_chunked_storage(directory.path()).expect("reopen storage");
        assert_eq!(
            reopened.chunk_store().unwrap().physical_bytes().unwrap(),
            Default::default()
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn chunked_gc_collects_expired_manifests_without_reading_orphan_chunks() {
        for damage in ["truncated manifest", "missing chunk"] {
            let directory = tempfile::tempdir().expect("fixture directory should be created");
            let storage = initialize_chunked_storage(directory.path()).expect("initialize storage");
            let raw = vec![b'x'; 100_000];
            let hash = NarHash::from_digest(sha2::Sha256::digest(&raw).into());
            storage
                .publish_nar(
                    NarFileName::raw(hash),
                    io::Cursor::new(&raw),
                    raw.len() as u64,
                    super::super::NarUploadPolicy::new(raw.len() as u64, 0),
                )
                .expect("publish an orphan chunk manifest");
            let manifest = storage
                .chunk_store()
                .expect("chunked backend should be active")
                .manifest_files()
                .expect("list orphan manifests")
                .into_iter()
                .find(|manifest| manifest.hash == hash)
                .expect("orphan manifest should exist");
            let manifest_path = directory
                .path()
                .join(super::super::MANIFEST_DIRECTORY)
                .join(manifest.name);
            match damage {
                "truncated manifest" => {
                    fs::write(&manifest_path, b"truncated").expect("truncate orphan manifest");
                }
                "missing chunk" => {
                    let chunks = directory.path().join(super::super::CHUNK_DIRECTORY);
                    let shard = fs::read_dir(chunks)
                        .expect("list chunk shards")
                        .next()
                        .expect("at least one chunk shard")
                        .expect("read chunk shard")
                        .path();
                    let chunk = fs::read_dir(shard)
                        .expect("list shard chunks")
                        .next()
                        .expect("at least one chunk")
                        .expect("read chunk entry")
                        .path();
                    fs::remove_file(chunk).expect("remove one orphan chunk");
                }
                _ => unreachable!(),
            }
            drop(storage);

            let gc_options = |mode| GcOptions {
                data_dir: directory.path().to_owned(),
                max_bytes: None,
                target_bytes: None,
                max_age: Some(Duration::ZERO),
                min_age: Duration::ZERO,
                protected_roots: None,
                mode,
                backend: StorageBackend::Chunked,
            };
            let dry_run = run(gc_options(GcMode::DryRun))
                .unwrap_or_else(|error| panic!("dry-run must collect {damage}: {error}"));
            assert_eq!(dry_run.evicted, 1, "{damage}");
            assert_eq!(dry_run.after_bytes, 0, "{damage}");

            let applied = run(gc_options(GcMode::Apply))
                .unwrap_or_else(|error| panic!("apply must collect {damage}: {error}"));
            assert_eq!(applied.after_bytes, dry_run.after_bytes, "{damage}");
            assert!(!manifest_path.exists(), "{damage}");
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn collecting_an_old_orphan_manifest_keeps_chunks_reachable_from_a_recent_nar() {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_chunked_storage(directory.path()).expect("initialize storage");
        let first_nar = (0..2 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut retained_nar = first_nar.clone();
        let last_byte = retained_nar.len() - 1;
        retained_nar[last_byte] ^= 1;
        let first_hash = NarHash::from_digest(sha2::Sha256::digest(&first_nar).into());
        let retained_hash = NarHash::from_digest(sha2::Sha256::digest(&retained_nar).into());
        for (hash, nar) in [(first_hash, &first_nar), (retained_hash, &retained_nar)] {
            storage
                .publish_nar(
                    NarFileName::raw(hash),
                    io::Cursor::new(nar),
                    nar.len() as u64,
                    super::super::NarUploadPolicy::new(nar.len() as u64, 0),
                )
                .expect("publish NAR into chunked storage");
        }

        let chunk_store = storage
            .chunk_store()
            .expect("chunked backend should be active");
        let manifests = chunk_store.manifest_files().expect("list chunk manifests");
        let orphan_manifest = manifests
            .iter()
            .find(|manifest| manifest.hash == first_hash)
            .expect("first NAR should have a manifest");
        let retained_manifest = manifests
            .iter()
            .find(|manifest| manifest.hash == retained_hash)
            .expect("retained NAR should have a manifest");
        let first_chunk_bytes = chunk_store
            .reachable_chunk_bytes([first_hash])
            .expect("measure chunks in orphan NAR");
        let retained_chunk_bytes = chunk_store
            .reachable_chunk_bytes([retained_hash])
            .expect("measure chunks in retained NAR");
        let shared_chunk_bytes = chunk_store
            .reachable_chunk_bytes([first_hash, retained_hash])
            .expect("measure chunks shared by both NARs");
        assert!(
            shared_chunk_bytes < first_chunk_bytes + retained_chunk_bytes,
            "fixture must contain at least one shared chunk"
        );
        let orphan_manifest_path = directory
            .path()
            .join(super::super::MANIFEST_DIRECTORY)
            .join(&orphan_manifest.name);
        let expired = SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60);
        fs::File::options()
            .write(true)
            .open(&orphan_manifest_path)
            .expect("open orphan manifest")
            .set_times(fs::FileTimes::new().set_modified(expired))
            .expect("age orphan manifest");

        let now = SystemTime::now();
        let entries = [ChunkedEntry {
            store: StoreHash::parse(TEST_STORE_HASH).unwrap(),
            store_path: String::new(),
            references: Vec::new(),
            narinfo_name: OsString::from("retained.narinfo"),
            output_name: None,
            output_bytes: 0,
            raw_hash: retained_hash,
            manifest_bytes: retained_manifest.bytes,
            narinfo_bytes: 0,
            modified: now,
            protected: false,
        }];
        let orphans =
            scan_chunked_orphans(&storage, chunk_store, &entries).expect("find orphan manifest");
        assert_eq!(orphans.manifests.len(), 1);
        assert_eq!(orphans.manifests[0].hash, first_hash);
        let before_bytes =
            chunked_before_bytes(&storage, chunk_store, &entries).expect("measure chunked storage");
        let expected_reachable_chunk_bytes = chunk_store
            .reachable_chunk_bytes([retained_hash])
            .expect("measure chunks reachable from retained NAR");
        let selected = select_chunked(
            chunk_store,
            &entries,
            &orphans,
            before_bytes,
            RetentionPolicy::for_limits(
                before_bytes,
                Some(0),
                Some(before_bytes - 1),
                None,
                Duration::from_secs(24 * 60 * 60),
                now,
            ),
        )
        .expect("select aged orphan manifest");
        assert_eq!(selected.manifests, vec![0]);
        assert!(
            selected.entries.is_empty(),
            "the recent NAR must be retained"
        );
        let projected_after = chunked_projected_bytes(chunk_store, &entries, &orphans, &selected)
            .expect("project retained manifest and chunks");
        assert_eq!(
            chunked_eligible_bytes(
                chunk_store,
                &entries,
                &orphans,
                now,
                Duration::from_secs(24 * 60 * 60),
            )
            .expect("measure uniquely reclaimable eligible bytes"),
            before_bytes - projected_after,
            "eligible accounting must deduplicate chunks shared with retained manifests"
        );
        assert_eq!(
            chunked_orphan_bytes(chunk_store, &entries, &orphans)
                .expect("measure orphan files and unreferenced chunks"),
            before_bytes
                - chunked_bytes_for_entries(chunk_store, &entries)
                    .expect("measure the retained publication"),
            "orphan accounting must exclude chunks still referenced by the live manifest"
        );

        let trusted =
            TrustedPublicKeys::load(&Directory::open(directory.path()).expect("open storage root"))
                .expect("load default trust configuration");
        storage
            .recover_for_mutation(&trusted)
            .expect("complete storage recovery before GC mutation");
        apply_chunked(&storage, chunk_store, &entries, &orphans, &selected)
            .expect("sweep the old manifest and its unreachable chunks");

        assert!(
            !orphan_manifest_path.exists(),
            "the aged unreferenced manifest should be removed"
        );
        assert!(
            chunk_store
                .manifest_files()
                .expect("list remaining manifests")
                .iter()
                .any(|manifest| manifest.hash == retained_hash),
            "the recent NAR manifest should remain"
        );
        assert_eq!(
            chunk_store
                .reachable_chunk_bytes([retained_hash])
                .expect("measure retained chunks after sweep"),
            expected_reachable_chunk_bytes,
            "GC must preserve every chunk reachable from the retained manifest"
        );
        let mut reconstructed = Vec::new();
        chunk_store
            .read_range(
                retained_hash,
                0..retained_nar.len() as u64,
                super::super::chunk_store::MAX_CHUNK_MANIFEST_BYTES,
                &mut reconstructed,
            )
            .expect("reconstruct the retained NAR after sweeping");
        assert_eq!(reconstructed, retained_nar);
    }

    #[test]
    fn sigterm_after_synced_gc_deletions_retains_recovery_state() {
        use std::{os::unix::process::ExitStatusExt, process::Command};

        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_storage(directory.path()).expect("storage should initialize");
        let orphan = storage
            .layout
            .nar_path(NarHash::parse(TEST_NAR_ID).unwrap());
        fs::write(&orphan, b"orphan").expect("orphan should be written");
        drop(storage);

        let output =
            Command::new(std::env::current_exe().expect("test executable should be available"))
                .args(["sigterm_at_post_deletion_scan_probe", "--nocapture"])
                .env("NARJAR_GC_SIGTERM_PROBE_DATA", directory.path())
                .output()
                .expect("GC interruption child should start");
        assert_eq!(
            output.status.signal(),
            Some(signal_hook::consts::SIGTERM),
            "{output:?}"
        );
        assert!(
            !orphan.exists(),
            "GC must delete the orphan before interruption"
        );
        assert!(
            directory.path().join(".narjar-recovery").exists(),
            "interrupted GC must retain recovery state"
        );

        let root = Directory::open(directory.path()).expect("storage root should reopen");
        let reopened = Storage::open(&root, SupportedStorageBackend::FLAT)
            .expect("lease should be released when the child terminates");
        assert!(reopened.recovery_required().unwrap());
        reopened
            .recover_for_mutation(&TrustedPublicKeys::default())
            .expect("interrupted GC should be recoverable");
        assert!(!reopened.recovery_required().unwrap());
        assert!(!directory.path().join(".narjar-recovery").exists());
    }

    #[test]
    fn sigterm_at_post_deletion_scan_probe() {
        let Some(path) = std::env::var_os("NARJAR_GC_SIGTERM_PROBE_DATA") else {
            return;
        };
        let root = Directory::open(Path::new(&path)).expect("probe root should open");
        let storage =
            Storage::open(&root, SupportedStorageBackend::FLAT).expect("probe storage should open");
        let trusted = TrustedPublicKeys::default();
        let recovered = storage
            .recover_for_mutation(&trusted)
            .expect("probe should start with recovered storage");
        let options = GcOptions {
            data_dir: path.into(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age: None,
            min_age: Duration::ZERO,
            protected_roots: None,
            mode: GcMode::Apply,
            backend: StorageBackend::Flat,
        };
        let mut scanned_before_deletion = false;
        run_flat_gc(
            options,
            recovered.storage(),
            &trusted,
            Some(0),
            |storage, trusted| {
                match scanned_before_deletion {
                    false => {
                        scanned_before_deletion = true;
                        scan(storage, trusted)
                    }
                    true => {
                        assert!(
                            storage.recovery_required().unwrap(),
                            "GC cannot clear recovery before its post-deletion scan"
                        );
                        // This probe runs in its own child; parallel tests are not signaled.
                        signal_hook::low_level::raise(signal_hook::consts::SIGTERM)
                            .expect("SIGTERM should be raised in the GC probe");
                        panic!("SIGTERM must terminate the GC probe before completion");
                    }
                }
            },
        )
        .expect("probe must not complete GC");
        panic!("probe must terminate at the post-deletion scan");
    }

    #[test]
    fn deletion_boundaries_preserve_published_pair_invariant() {
        let points = [
            FailurePoint::BeforeNarinfoDelete,
            FailurePoint::AfterNarinfoDeleteBeforeSync,
            FailurePoint::AfterNarinfoSyncBeforeNarDelete,
            FailurePoint::AfterNarDeleteBeforeSync,
        ];

        for point in points {
            let (directory, storage, entry) = pair_fixture();
            let entries = [entry];

            assert!(apply_with_failure(&storage, &entries, &[0], Some(point)).is_err());
            assert!(
                !directory.path().join(&entries[0].narinfo_name).exists()
                    || directory
                        .path()
                        .join("nar")
                        .join(&entries[0].nar_name)
                        .exists()
            );
            assert!(
                storage
                    .recovery_required()
                    .expect("recovery state should be readable")
            );
            drop(storage);
            let reopened = initialize_storage(directory.path()).expect("storage should reopen");
            assert!(
                reopened
                    .recovery_required()
                    .expect("recovery state should be readable")
            );
        }
    }

    #[test]
    fn orphan_cleanup_failure_preserves_orphan() {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = initialize_storage(directory.path()).expect("storage should initialize");
        let nar =
            crate::object::NarHash::parse("0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl")
                .expect("NAR hash should parse");
        let path = storage.layout.nar_path(nar);
        fs::write(&path, b"orphan").expect("orphan should be written");
        let orphan = Orphan {
            name: OsString::from(format!("{TEST_NAR_ID}.nar")),
            bytes: 6,
            modified: SystemTime::now(),
        };

        assert!(
            apply_orphans_with_failure(
                &storage,
                &[orphan],
                &[0],
                Some(FailurePoint::DuringOrphanCleanup),
            )
            .is_err()
        );
        assert!(path.exists());
    }
}
