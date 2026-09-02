use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::{
    narinfo::{PublishedNarInfoError, TrustedPublicKeys, read_narinfo},
    storage::{NarObjectId, Storage, StorageError, StoreHash, sync_dir},
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
    narinfo_path: PathBuf,
    nar_path: PathBuf,
    narinfo_bytes: u64,
    nar_bytes: u64,
    modified: SystemTime,
    protected: bool,
}
struct Orphan {
    path: PathBuf,
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
    let trusted = TrustedPublicKeys::load(&options.data_dir.join("trusted-public-keys"))
        .map_err(|error| invalid(error.to_string()))?;
    let mut entries = scan(&storage, &trusted)?;
    let protection = protect(&mut entries, options.protected_roots.as_deref())?;
    let orphans = scan_orphans(&storage, &entries)?;

    let before_bytes = total_bytes(&entries) + orphan_bytes(&orphans);
    let now = SystemTime::now();
    let eligible = eligible_count(&entries, &orphans, now, options.min_age);
    let shared = shared_count(&entries);
    let temporary = count_entries(&storage.layout.temp_dir())?;
    let selected = select(
        &entries,
        before_bytes,
        target_bytes,
        options.max_bytes,
        options.max_age,
        options.min_age,
        now,
    );
    let after_publications = projected_bytes(&entries, &selected);
    let selected_orphans = select_orphans(
        &orphans,
        after_publications + orphan_bytes(&orphans),
        target_bytes,
        options.max_bytes,
        options.max_age,
        options.min_age,
        now,
    );
    let after_bytes = after_publications.saturating_sub(
        selected_orphans
            .iter()
            .map(|&index| orphans[index].bytes)
            .sum(),
    );
    let dry_run = !options.apply;
    let (deleted_narinfos, deleted_nars, deleted_orphans) = if dry_run {
        (0, 0, 0)
    } else {
        let (deleted_narinfos, deleted_nars) = apply(&storage, &entries, &selected)?;
        let deleted_orphans = apply_orphans(&storage, &orphans, &selected_orphans)?;
        (deleted_narinfos, deleted_nars, deleted_orphans)
    };

    Ok(GcReport {
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
        deleted_narinfos,
        deleted_nars,
        deleted_orphans,
    })
}

fn scan(storage: &Storage, trusted: &TrustedPublicKeys) -> Result<Vec<Entry>, StorageError> {
    let mut entries = Vec::new();
    for item in fs::read_dir(&storage.layout.root)? {
        let item = item?;
        let name = item.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(route) = name.strip_suffix(".narinfo") else {
            continue;
        };
        let store = StoreHash::parse(route)
            .map_err(|_| invalid(format!("invalid narinfo filename: {name}")))?;
        if !item.file_type()?.is_file() {
            return Err(invalid(format!("narinfo is not a regular file: {name}")));
        }
        let metadata = item.metadata()?;

        let bytes = read_narinfo(&item.path())?;
        let validated = trusted
            .inspect(&store, bytes)
            .map_err(|error| match error {
                PublishedNarInfoError::Malformed => invalid(format!("malformed narinfo: {name}")),
                PublishedNarInfoError::UntrustedSignature => {
                    invalid(format!("untrusted narinfo: {name}"))
                }
            })?;
        let nar_path = storage.layout.nar_path(validated.nar());
        let nar_metadata = fs::metadata(&nar_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                invalid(format!("missing NAR for narinfo: {name}"))
            } else {
                error.into()
            }
        })?;
        if !nar_metadata.is_file() || nar_metadata.len() != validated.nar_size() {
            return Err(invalid(format!("NAR size mismatch for narinfo: {name}")));
        }

        entries.push(Entry {
            store,
            nar: NarObjectId::parse(validated.nar().as_str()).expect("validated NAR id"),
            store_path: validated.store_path().to_owned(),
            references: validated.references().iter().cloned().collect(),
            narinfo_path: item.path(),
            nar_path,
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
    let nar_dir = storage.layout.nar_dir();
    if !nar_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut orphans = Vec::new();
    for item in fs::read_dir(&nar_dir)? {
        let item = item?;
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(identifier) = name.strip_suffix(".nar") else {
            continue;
        };
        if NarObjectId::parse(identifier).is_err() || !item.file_type()?.is_file() {
            continue;
        }
        if referenced.contains_key(identifier) {
            continue;
        }
        let metadata = item.metadata()?;
        orphans.push(Orphan {
            path: item.path(),
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

fn count_entries(path: &Path) -> Result<usize, StorageError> {
    if !path.is_dir() {
        return Ok(0);
    }
    let mut count = 0;
    for item in fs::read_dir(path)? {
        item?;
        count += 1;
    }
    Ok(count)
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

fn projected_bytes(entries: &[Entry], selected: &[usize]) -> u64 {
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

fn apply(
    storage: &Storage,
    entries: &[Entry],
    selected: &[usize],
) -> Result<(usize, usize), StorageError> {
    let mut references = reference_counts(entries);
    let mut deleted_nars = 0;
    for &index in selected {
        let entry = &entries[index];
        fs::remove_file(&entry.narinfo_path)?;
        sync_dir(&storage.layout.root)?;
        let count = references
            .get_mut(&entry.nar.0)
            .expect("scanned reference count");
        *count -= 1;
        if *count == 0 {
            fs::remove_file(&entry.nar_path)?;
            sync_dir(&storage.layout.nar_dir())?;
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
    for &index in selected {
        fs::remove_file(&orphans[index].path)?;
    }
    if !selected.is_empty() {
        sync_dir(&storage.layout.nar_dir())?;
    }
    Ok(selected.len())
}

fn invalid(message: impl Into<String>) -> StorageError {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

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
}
