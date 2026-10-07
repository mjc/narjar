use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{File, FileTimes},
    io,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use enum_map::{Enum, EnumMap};
use rustix::fs::{Mode, OFlags};

use super::{
    NarFileName, StoreHash,
    fs::{ensure_directory_at, open_at, open_regular_at, unlink_at},
};

pub(super) const ACCESS_DIRECTORY: &str = ".narjar-access";
const TOUCH_INTERVAL: Duration = Duration::from_secs(3600);
const RECENT_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum AccessKey {
    Publication(StoreHash),
    Payload(NarFileName),
}

impl AccessKey {
    fn name(self) -> OsString {
        match self {
            Self::Publication(store) => format!("{}.narinfo", store.as_str()).into(),
            Self::Payload(name) => name.to_string().into(),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct AccessRecorder {
    tracking: OnceLock<Tracking>,
    counters: EnumMap<AccessOutcome, AtomicU64>,
}

#[derive(Clone, Copy, Debug, Enum)]
enum AccessOutcome {
    Written,
    Coalesced,
    Failed,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AccessRecordStats {
    pub(crate) written: u64,
    pub(crate) coalesced: u64,
    pub(crate) failed: u64,
}

#[derive(Debug)]
struct Tracking {
    directory: File,
    recent: Mutex<HashMap<AccessKey, Instant>>,
}

impl AccessRecorder {
    pub(super) fn enable(&self, root: &File) -> io::Result<()> {
        let directory = ensure_directory_at(root, ACCESS_DIRECTORY.as_ref(), "access directory")?;
        let _ = self.tracking.set(Tracking {
            directory,
            recent: Mutex::default(),
        });
        Ok(())
    }

    pub(super) fn record(&self, key: AccessKey) {
        // Recency is an eviction hint. A failed hint must not fail a cache read.
        let _ = self.record_at(key, Instant::now(), SystemTime::now());
    }

    fn record_at(&self, key: AccessKey, clock: Instant, time: SystemTime) -> io::Result<()> {
        match self.tracking.get() {
            None => Ok(()),
            Some(tracking) => {
                let result = tracking.record_at(key, clock, time);
                let outcome = match &result {
                    Ok(outcome) => *outcome,
                    Err(_) => AccessOutcome::Failed,
                };
                super::state::increment_saturating(&self.counters[outcome], 1);
                result.map(|_| ())
            }
        }
    }

    pub(super) fn snapshot(&self) -> AccessRecordStats {
        AccessRecordStats {
            written: self.counters[AccessOutcome::Written].load(Ordering::Relaxed),
            coalesced: self.counters[AccessOutcome::Coalesced].load(Ordering::Relaxed),
            failed: self.counters[AccessOutcome::Failed].load(Ordering::Relaxed),
        }
    }
}

impl Tracking {
    fn record_at(
        &self,
        key: AccessKey,
        clock: Instant,
        time: SystemTime,
    ) -> io::Result<AccessOutcome> {
        let mut recent = self
            .recent
            .lock()
            .map_err(|_| io::Error::other("access recorder lock poisoned"))?;
        match recent.get(&key) {
            Some(recorded) if clock.saturating_duration_since(*recorded) < TOUCH_INTERVAL => {
                Ok(AccessOutcome::Coalesced)
            }
            Some(_) | None => {
                let file = open_at(
                    &self.directory,
                    &key.name(),
                    OFlags::CREATE
                        | OFlags::WRONLY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC
                        | OFlags::NONBLOCK,
                    (Mode::RUSR | Mode::WUSR).bits(),
                )?;
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.len() != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "access record must be an empty regular file",
                    ));
                }
                file.set_times(FileTimes::new().set_modified(time))?;
                let discarded = (recent.len() >= RECENT_LIMIT && !recent.contains_key(&key))
                    .then(|| recent.keys().next().copied())
                    .flatten();
                if let Some(discarded) = discarded {
                    recent.remove(&discarded);
                }
                recent.insert(key, clock);
                Ok(AccessOutcome::Written)
            }
        }
    }
}

pub(super) fn last_use(
    root: &File,
    keys: impl IntoIterator<Item = AccessKey>,
) -> Option<SystemTime> {
    let directory = match super::fs::require_directory_at(root, ACCESS_DIRECTORY) {
        Ok(directory) => directory,
        Err(error) => {
            report_advisory_error("open access directory", error);
            return None;
        }
    };
    keys.into_iter()
        .filter_map(|key| match read_access_time(&directory, key) {
            Ok(time) => Some(time),
            Err(error) => {
                report_advisory_error("read access record", error);
                None
            }
        })
        .max()
}

fn read_access_time(directory: &File, key: AccessKey) -> io::Result<SystemTime> {
    let file = open_regular_at(directory, key.name())?;
    let metadata = file.metadata()?;
    if metadata.len() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nonempty access record",
        ));
    }
    metadata.modified()
}

pub(super) fn forget(root: &File, key: AccessKey) {
    let result = super::fs::require_directory_at(root, ACCESS_DIRECTORY)
        .and_then(|directory| unlink_at(&directory, &key.name()));
    if let Err(error) = result {
        report_advisory_error("remove access record", error);
    }
}

fn report_advisory_error(operation: &str, error: io::Error) {
    if error.kind() != io::ErrorKind::NotFound {
        eprintln!("narjar: {operation}: {error}; ignoring advisory hint");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_reads_are_coalesced_but_the_persisted_hint_survives_a_restart() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let recorder = AccessRecorder::default();
        recorder.enable(&root).unwrap();
        let key =
            AccessKey::Publication(StoreHash::parse("00000000000000000000000000000000").unwrap());
        let clock = Instant::now();
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        recorder.record_at(key, clock, first).unwrap();
        recorder
            .record_at(
                key,
                clock + Duration::from_secs(1),
                first + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(recorder.snapshot().written, 1);
        assert_eq!(recorder.snapshot().coalesced, 1);
        drop(recorder);
        assert_eq!(last_use(&root, [key]), Some(first));
        let restarted = AccessRecorder::default();
        restarted.enable(&root).unwrap();
        restarted
            .record_at(key, clock + TOUCH_INTERVAL, first + TOUCH_INTERVAL)
            .unwrap();
        assert_eq!(last_use(&root, [key]), Some(first + TOUCH_INTERVAL));
    }

    #[test]
    fn disabled_tracking_does_not_create_sidecars_and_missing_records_are_not_hits() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let key =
            AccessKey::Publication(StoreHash::parse("00000000000000000000000000000000").unwrap());
        AccessRecorder::default().record(key);
        assert_eq!(last_use(&root, [key]), None);
        assert!(!directory.path().join(ACCESS_DIRECTORY).exists());
    }

    #[test]
    fn malformed_advisory_records_fall_back_to_publication_time() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        AccessRecorder::default().enable(&root).unwrap();
        let key =
            AccessKey::Publication(StoreHash::parse("00000000000000000000000000000000").unwrap());
        std::fs::create_dir(directory.path().join(ACCESS_DIRECTORY).join(key.name())).unwrap();
        assert_eq!(last_use(&root, [key]), None);
    }

    #[test]
    fn unique_payload_reads_cannot_grow_the_resident_cache_past_its_bound() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let recorder = AccessRecorder::default();
        recorder.enable(&root).unwrap();
        let clock = Instant::now();
        for index in 0..RECENT_LIMIT + 1 {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            recorder
                .record_at(
                    AccessKey::Payload(NarFileName::raw(super::super::NarHash::from_digest(
                        digest,
                    ))),
                    clock,
                    SystemTime::UNIX_EPOCH,
                )
                .unwrap();
        }
        assert_eq!(
            recorder
                .tracking
                .get()
                .unwrap()
                .recent
                .lock()
                .unwrap()
                .len(),
            RECENT_LIMIT
        );
        assert_eq!(
            std::fs::read_dir(directory.path().join(ACCESS_DIRECTORY))
                .unwrap()
                .count(),
            RECENT_LIMIT + 1,
            "evicting a coalescing-cache key must not discard its persisted recency"
        );
    }
}
