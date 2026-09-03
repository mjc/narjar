use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::{
    narinfo::{PublishedNarInfoError, TrustedPublicKeys, read_narinfo_file},
    storage::{
        NarObjectId, Storage, StorageError, StoreHash, open_regular_at, read_dir_names, unlink_at,
    },
};

pub struct GcOptions {
    pub data_dir: PathBuf,
    pub max_bytes: Option<u64>,
    pub target_bytes: Option<u64>,
    pub max_age: Option<Duration>,
    pub min_age: Duration,
    pub protected_roots: Option<PathBuf>,
    pub apply: bool,
}

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
    nar: NarObjectId,
    store_path: String,
    references: Vec<String>,
    narinfo_name: OsString,
    nar_name: OsString,
    narinfo_bytes: u64,
    nar_bytes: u64,
    modified: SystemTime,
    protected: bool,
}
struct Orphan {
    name: OsString,
    bytes: u64,
    modified: SystemTime,
}

pub fn run(options: GcOptions) -> Result<GcReport, StorageError> {
    let target_bytes = options.target_bytes.or(options.max_bytes);
    if options.max_bytes.is_none() && options.target_bytes.is_none() && options.max_age.is_none() {
        return Err(invalid("at least one retention policy is required"));
    }
    if options
        .target_bytes
        .zip(options.max_bytes)
        .is_some_and(|(target, max)| target > max)
    {
        return Err(invalid("--target-bytes cannot exceed --max-bytes"));
    }

    let storage = Storage::initialize(&options.data_dir)?;
    let trusted_keys_path = options.data_dir.join("trusted-public-keys");
    let trusted =
        TrustedPublicKeys::load(&trusted_keys_path).map_err(|error| invalid(error.to_string()))?;
    let mut entries = scan(&storage, &trusted)?;
    let protection = protect(&mut entries, options.protected_roots.as_deref())?;
    let orphans = scan_orphans(&storage, &entries)?;
    let protected_bytes = category_bytes(&entries, |entry| entry.protected);

    let before_bytes = total_bytes(&entries) + orphan_bytes(&orphans);
    let now = SystemTime::now();
    let eligible = eligible_count(&entries, &orphans, now, options.min_age);
    let eligible_bytes_total = eligible_bytes(&entries, &orphans, now, options.min_age);
    let shared = shared_count(&entries);
    let shared_bytes_total = shared_bytes(&entries);
    let (temporary, temporary_bytes) = temporary_inventory(&storage)?;
    let selected = select(
        &entries,
        before_bytes,
        target_bytes,
        options.max_bytes,
        options.max_age,
        options.min_age,
        now,
    );
    let after_publications = projected_published_bytes(&entries, &selected);
    let selected_orphans = select_orphans(
        &orphans,
        after_publications + orphan_bytes(&orphans),
        target_bytes,
        options.max_bytes,
        options.max_age,
        options.min_age,
        now,
    );
    let projected_after_bytes =
        logical_after_bytes(&entries, &selected, &orphans, &selected_orphans);
    let mut after_bytes = projected_after_bytes;
    let dry_run = !options.apply;
    let (deleted_narinfos, deleted_nars, deleted_orphans) = if dry_run {
        (0, 0, 0)
    } else {
        let result = (|| {
            let (deleted_narinfos, deleted_nars) = apply(&storage, &entries, &selected)?;
            let deleted_orphans = apply_orphans(&storage, &orphans, &selected_orphans)?;
            Ok((deleted_narinfos, deleted_nars, deleted_orphans))
        })();
        match result {
            Ok(deleted) => {
                let remaining_entries = scan(&storage, &trusted)?;
                let remaining_orphans = scan_orphans(&storage, &remaining_entries)?;
                after_bytes = total_bytes(&remaining_entries) + orphan_bytes(&remaining_orphans);
                storage.recovery.finish(&trusted_keys_path)?;
                deleted
            }
            Err(error) => return Err(error),
        }
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
    let mut entries = Vec::new();
    let root = storage.root_directory()?;
    let nar_directory = storage.nar_directory()?;
    for name in read_dir_names(&root)? {
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(route) = name_str.strip_suffix(".narinfo") else {
            continue;
        };
        let store = StoreHash::parse(route)
            .map_err(|_| invalid(format!("invalid narinfo filename: {name_str}")))?;
        let narinfo = match open_regular_at(&root, &name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(invalid(format!(
                    "narinfo disappeared during scan: {name_str}"
                )));
            }
            Err(error)
                if error.kind() == io::ErrorKind::InvalidData
                    || error.raw_os_error() == Some(libc::ELOOP) =>
            {
                return Err(invalid(format!(
                    "narinfo is not a regular file: {name_str}"
                )));
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = narinfo.metadata()?;

        let bytes = read_narinfo_file(narinfo)?;
        let validated = trusted
            .inspect(&store, bytes)
            .map_err(|error| match error {
                PublishedNarInfoError::Malformed => {
                    invalid(format!("malformed narinfo: {name_str}"))
                }
                PublishedNarInfoError::UntrustedSignature => {
                    invalid(format!("untrusted narinfo: {name_str}"))
                }
            })?;
        let nar_name = OsString::from(format!(
            "{}{}",
            validated.nar().as_str(),
            validated.encoding().suffix()
        ));
        let nar_metadata = open_regular_at(&nar_directory, &nar_name)
            .and_then(|file| file.metadata())
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => invalid(format!("missing NAR for narinfo: {name_str}")),
                _ => error.into(),
            })?;
        if nar_metadata.len() != validated.file_size() {
            return Err(invalid(format!(
                "NAR size mismatch for narinfo: {name_str}"
            )));
        }

        entries.push(Entry {
            store,
            nar: NarObjectId::parse(validated.nar().as_str()).expect("validated NAR id"),
            store_path: validated.store_path().to_owned(),
            references: validated
                .references()
                .split_ascii_whitespace()
                .map(|reference| format!("/nix/store/{reference}"))
                .collect(),
            narinfo_name: name,
            nar_name,
            narinfo_bytes: metadata.len(),
            nar_bytes: nar_metadata.len(),
            modified: metadata.modified()?,
            protected: false,
        });
    }
    Ok(entries)
}

fn scan_orphans(storage: &Storage, entries: &[Entry]) -> Result<Vec<Orphan>, StorageError> {
    let referenced = entries
        .iter()
        .map(|entry| (entry.nar.0.clone(), ()))
        .collect::<BTreeMap<_, _>>();
    let nar_directory = storage.nar_directory()?;
    let mut orphans = Vec::new();
    for name in read_dir_names(&nar_directory)? {
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let identifier = name_str
            .strip_suffix(".nar.xz")
            .or_else(|| name_str.strip_suffix(".nar"));
        let Some(identifier) = identifier else {
            continue;
        };
        if NarObjectId::parse(identifier).is_err()
            || !super::entry_is_regular_at(&nar_directory, &name)?
        {
            continue;
        }
        if referenced.contains_key(identifier) {
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
        nars.entry(entry.nar.0.clone()).or_insert(entry.nar_bytes);
    }
    total + nars.values().copied().sum::<u64>()
}

fn shared_bytes(entries: &[Entry]) -> u64 {
    let counts = reference_counts(entries);
    let mut sizes = BTreeMap::new();
    for entry in entries {
        sizes.entry(entry.nar.0.clone()).or_insert(entry.nar_bytes);
    }
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

fn protect(entries: &mut [Entry], path: Option<&Path>) -> Result<ProtectionReport, StorageError> {
    let Some(path) = path else {
        return Ok(ProtectionReport {
            protected: 0,
            missing_roots: 0,
            missing_references: 0,
        });
    };
    let contents = fs::read_to_string(path)?;
    let mut roots = BTreeSet::new();
    for root in contents
        .lines()
        .map(str::trim)
        .filter(|root| !root.is_empty())
    {
        validate_root(root)?;
        roots.insert(root.to_owned());
    }

    let mut pending = roots.iter().cloned().collect::<Vec<_>>();
    let mut missing_roots = BTreeSet::new();
    let mut missing_references = BTreeSet::new();
    while let Some(root) = pending.pop() {
        let Some(index) = entries
            .iter()
            .position(|entry| entry.store_path == root || entry.store.0 == root)
        else {
            if roots.contains(&root) {
                missing_roots.insert(root);
            } else {
                missing_references.insert(root);
            }
            continue;
        };
        if entries[index].protected {
            continue;
        }
        entries[index].protected = true;
        pending.extend(entries[index].references.iter().cloned());
    }

    Ok(ProtectionReport {
        protected: entries.iter().filter(|entry| entry.protected).count(),
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
    let mut nars = BTreeMap::new();
    for entry in entries {
        nars.entry(entry.nar.0.clone()).or_insert(entry.nar_bytes);
    }
    total += nars.values().copied().sum::<u64>();
    total
}
fn reference_counts(entries: &[Entry]) -> BTreeMap<String, u64> {
    let mut references = BTreeMap::new();
    for entry in entries {
        *references.entry(entry.nar.0.clone()).or_insert(0_u64) += 1;
    }
    references
}

fn select(
    entries: &[Entry],
    current_bytes: u64,
    target_bytes: Option<u64>,
    max_bytes: Option<u64>,
    max_age: Option<Duration>,
    min_age: Duration,
    now: SystemTime,
) -> Vec<usize> {
    let mut references = reference_counts(entries);

    let size_pressure = target_bytes
        .is_some_and(|target| max_bytes.map_or(current_bytes > target, |max| current_bytes > max));
    let mut order = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !entry.protected && now.duration_since(entry.modified).unwrap_or_default() >= min_age
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    order.sort_unstable_by_key(|&index| (entries[index].modified, index));

    let mut remaining = current_bytes;
    let mut selected = Vec::new();
    for index in order {
        let entry = &entries[index];
        let expired = max_age
            .is_some_and(|age| now.duration_since(entry.modified).unwrap_or_default() >= age);
        let pressure = size_pressure && target_bytes.is_some_and(|target| remaining > target);
        if !expired && !pressure {
            continue;
        }

        selected.push(index);
        remaining = remaining.saturating_sub(entry.narinfo_bytes);
        if let Some(count) = references.get_mut(&entry.nar.0) {
            *count -= 1;
            if *count == 0 {
                remaining = remaining.saturating_sub(entry.nar_bytes);
            }
        }
    }
    selected
}

fn select_orphans(
    orphans: &[Orphan],
    current_bytes: u64,
    target_bytes: Option<u64>,
    max_bytes: Option<u64>,
    max_age: Option<Duration>,
    min_age: Duration,
    now: SystemTime,
) -> Vec<usize> {
    let size_pressure = target_bytes
        .is_some_and(|target| max_bytes.map_or(current_bytes > target, |max| current_bytes > max));
    let mut order = orphans
        .iter()
        .enumerate()
        .filter(|(_, orphan)| now.duration_since(orphan.modified).unwrap_or_default() >= min_age)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    order.sort_unstable_by_key(|&index| (orphans[index].modified, index));

    let mut remaining = current_bytes;
    let mut selected = Vec::new();
    for index in order {
        let orphan = &orphans[index];
        let expired = max_age
            .is_some_and(|age| now.duration_since(orphan.modified).unwrap_or_default() >= age);
        let pressure = size_pressure && target_bytes.is_some_and(|target| remaining > target);
        if !expired && !pressure {
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
    for &index in selected {
        let entry = &entries[index];
        total = total.saturating_sub(entry.narinfo_bytes);
        if let Some(count) = references.get_mut(&entry.nar.0) {
            *count -= 1;
            if *count == 0 {
                total = total.saturating_sub(entry.nar_bytes);
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
        let count = references
            .get_mut(&entry.nar.0)
            .expect("scanned reference count");
        *count -= 1;
        fail_if(failure, FailurePoint::AfterNarinfoSyncBeforeNarDelete)?;
        if *count == 0 {
            unlink_at(&nar_directory, &entry.nar_name)?;
            fail_if(failure, FailurePoint::AfterNarDeleteBeforeSync)?;
            nar_directory.sync_all()?;
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
    use crate::storage::open_directory;
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
    fn temporary_inventory_does_not_follow_symlinks() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let target = directory.path().join("external");
        let temporary = directory.path().join(".tmp");
        fs::create_dir(&temporary).expect("temporary directory should be created");
        fs::write(&target, vec![0; 17]).expect("external target should be written");
        symlink(&target, temporary.join("escaped")).expect("temporary symlink should be created");

        assert_eq!(
            temporary_inventory_directory(
                &open_directory(&temporary).expect("open temporary directory"),
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

        assert!(open_directory(&temporary).is_err());
    }

    #[test]
    fn orphan_scan_rejects_a_symlinked_nar_directory() {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = Storage::initialize(directory.path()).expect("storage should initialize");
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

    const TEST_STORE_HASH: &str = "00000000000000000000000000000000";
    const TEST_NAR_ID: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";

    fn pair_fixture() -> (tempfile::TempDir, Storage, Entry) {
        let directory = tempfile::tempdir().expect("fixture directory should be created");
        let storage = Storage::initialize(directory.path()).expect("storage should initialize");
        let store = StoreHash::parse(TEST_STORE_HASH).expect("store hash should parse");
        let nar = NarObjectId::parse(TEST_NAR_ID).expect("NAR id should parse");
        let narinfo_name = OsString::from(format!("{TEST_STORE_HASH}.narinfo"));
        let nar_path = storage.layout.nar_path(&nar);
        let narinfo_path = directory.path().join(&narinfo_name);
        fs::write(&narinfo_path, b"published").expect("narinfo should be written");
        fs::write(&nar_path, b"nar").expect("NAR should be written");

        let entry = Entry {
            store,
            nar,
            store_path: format!("/nix/store/{TEST_STORE_HASH}-narjar"),
            references: Vec::new(),
            narinfo_name,
            nar_name: OsString::from(format!("{TEST_NAR_ID}.nar")),
            narinfo_bytes: 9,
            nar_bytes: 3,
            modified: SystemTime::now(),
            protected: false,
        };
        (directory, storage, entry)
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
            let reopened = Storage::initialize(directory.path()).expect("storage should reopen");
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
        let storage = Storage::initialize(directory.path()).expect("storage should initialize");
        let nar = NarObjectId::parse("0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl")
            .expect("NAR id should parse");
        let path = storage.layout.nar_path(&nar);
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
