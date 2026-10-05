use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RECORD_BYTES: u64 = 2 * 1024;
const INVENTORY_CLASS_COUNT: usize = crate::inventory::InventoryClass::ALL.len();
pub const FILE_NAMES: [&str; 6] = [
    ".narjar-maintenance-gc.started",
    ".narjar-maintenance-gc.last",
    ".narjar-maintenance-reconcile.started",
    ".narjar-maintenance-reconcile.last",
    ".narjar-maintenance-verify.started",
    ".narjar-maintenance-verify.last",
];

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, PartialEq, Serialize)]
pub enum Operation {
    Gc,
    Reconcile,
    Verify,
}

impl Operation {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gc => "gc",
            Self::Reconcile => "reconcile",
            Self::Verify => "verify",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Mode {
    GcDryRun,
    GcApply,
    Reconcile,
    Verify,
    Structural,
    Cleanup,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::GcDryRun => "gc_dry_run",
            Self::GcApply => "gc_apply",
            Self::Reconcile => "reconcile",
            Self::Verify => "verify",
            Self::Structural => "structural",
            Self::Cleanup => "cleanup",
        }
    }

    const fn operation(self) -> Operation {
        match self {
            Self::GcDryRun | Self::GcApply => Operation::Gc,
            Self::Reconcile | Self::Structural | Self::Cleanup => Operation::Reconcile,
            Self::Verify => Operation::Verify,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Run {
    pub operation: Operation,
    pub mode: Mode,
    pub outcome: Outcome,
    pub started_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
    pub duration_micros: u64,
    pub objects_examined: Option<u64>,
    pub objects_selected: Option<u64>,
    pub bytes_examined: Option<u64>,
    pub objects_reclaimed: Option<u64>,
    pub bytes_reclaimed: Option<u64>,
    pub inventory_class_counts: Option<[u64; INVENTORY_CLASS_COUNT]>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Started {
    pub operation: Operation,
    pub mode: Mode,
    pub started_at_unix_seconds: u64,
}

/// The discriminant versions the private record; unsupported versions fail decoding.
#[derive(Deserialize, Serialize)]
enum Record<T> {
    V1(T),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub last_runs: EnumMap<Operation, Option<Run>>,
    pub started: EnumMap<Operation, Option<Started>>,
}

pub struct Recorder {
    root: PathBuf,
    operation: Operation,
    mode: Mode,
    started_at_unix_seconds: u64,
    started_at: std::time::Instant,
}

impl Recorder {
    pub fn begin(root: &Path, operation: Operation, mode: Mode) -> io::Result<Self> {
        let recorder = Self {
            root: root.to_owned(),
            operation,
            mode,
            started_at_unix_seconds: unix_seconds_now(),
            started_at: std::time::Instant::now(),
        };
        write_atomic(
            &recorder.root,
            &started_name(operation),
            &encode_record(Started {
                operation,
                mode,
                started_at_unix_seconds: recorder.started_at_unix_seconds,
            })?,
        )?;
        Ok(recorder)
    }

    pub fn finish(self, outcome: Outcome, values: RunValues) -> io::Result<()> {
        let run = Run {
            operation: self.operation,
            mode: self.mode,
            outcome,
            started_at_unix_seconds: self.started_at_unix_seconds,
            completed_at_unix_seconds: unix_seconds_now(),
            duration_micros: u64::try_from(self.started_at.elapsed().as_micros())
                .unwrap_or(u64::MAX),
            objects_examined: values.objects_examined,
            objects_selected: values.objects_selected,
            bytes_examined: values.bytes_examined,
            objects_reclaimed: values.objects_reclaimed,
            bytes_reclaimed: values.bytes_reclaimed,
            inventory_class_counts: values.inventory_class_counts,
        };
        write_atomic(&self.root, &last_name(self.operation), &encode_record(run)?)?;
        match fs::remove_file(self.root.join(started_name(self.operation))) {
            Ok(()) => File::open(&self.root)?.sync_all(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunValues {
    pub objects_examined: Option<u64>,
    pub objects_selected: Option<u64>,
    pub bytes_examined: Option<u64>,
    pub objects_reclaimed: Option<u64>,
    pub bytes_reclaimed: Option<u64>,
    pub inventory_class_counts: Option<[u64; INVENTORY_CLASS_COUNT]>,
}

pub fn read_snapshot(root: &Path) -> io::Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    for (operation, ()) in EnumMap::<Operation, ()>::default() {
        snapshot.last_runs[operation] = read_record(&root.join(last_name(operation)), |text| {
            parse_run(operation, text)
        })?;
        snapshot.started[operation] = read_record(&root.join(started_name(operation)), |text| {
            parse_started(operation, text)
        })?;
    }
    Ok(snapshot)
}

fn read_record<T>(path: &Path, parse: impl FnOnce(&[u8]) -> Option<T>) -> io::Result<Option<T>> {
    match read_bounded_file(path) {
        Ok(text) => parse(&text)
            .map(Some)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn encode_record(value: impl Serialize) -> io::Result<Vec<u8>> {
    let bytes = postcard::to_allocvec(&Record::V1(value)).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

fn decode_record<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Option<T> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    let Record::V1(value) = crate::records::decode_complete(bytes).ok()?;
    Some(value)
}

fn parse_run(operation: Operation, bytes: &[u8]) -> Option<Run> {
    let run: Run = decode_record(bytes)?;
    (run.operation == operation
        && run.mode.operation() == operation
        && run.started_at_unix_seconds <= run.completed_at_unix_seconds)
        .then_some(run)
}

fn parse_started(operation: Operation, bytes: &[u8]) -> Option<Started> {
    let started: Started = decode_record(bytes)?;
    (started.operation == operation && started.mode.operation() == operation).then_some(started)
}

fn read_bounded_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = crate::filesystem::open_regular_at(rustix::fs::CWD, path)?;
    crate::records::read_bounded_bytes(file, MAX_RECORD_BYTES).map_err(Into::into)
}

fn write_atomic(root: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(root.join(name))
        .map_err(|error| error.error)?;
    File::open(root)?.sync_all()
}

fn started_name(operation: Operation) -> String {
    format!(".narjar-maintenance-{}.started", operation.name())
}

fn last_name(operation: Operation) -> String {
    format!(".narjar-maintenance-{}.last", operation.name())
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_run(operation: Operation, mode: Mode, outcome: Outcome) -> Run {
        Run {
            operation,
            mode,
            outcome,
            started_at_unix_seconds: 10,
            completed_at_unix_seconds: 20,
            duration_micros: 123,
            objects_examined: Some(u64::MAX),
            objects_selected: None,
            bytes_examined: Some(0),
            objects_reclaimed: None,
            bytes_reclaimed: Some(42),
            inventory_class_counts: Some([u64::MAX; INVENTORY_CLASS_COUNT]),
        }
    }

    #[test]
    fn completed_records_preserve_all_modes_outcomes_and_optional_values() {
        for (operation, mode) in [
            (Operation::Gc, Mode::GcDryRun),
            (Operation::Gc, Mode::GcApply),
            (Operation::Reconcile, Mode::Reconcile),
            (Operation::Reconcile, Mode::Structural),
            (Operation::Reconcile, Mode::Cleanup),
            (Operation::Verify, Mode::Verify),
        ] {
            for outcome in [Outcome::Success, Outcome::Failure] {
                let run = sample_run(operation, mode, outcome);
                assert_eq!(
                    parse_run(operation, &encode_record(run).unwrap()),
                    Some(run)
                );
                let without_counts = Run {
                    inventory_class_counts: None,
                    ..run
                };
                assert_eq!(
                    parse_run(operation, &encode_record(without_counts).unwrap()),
                    Some(without_counts)
                );
            }
        }
    }

    #[test]
    fn completed_records_reject_wrong_operation_and_backwards_time() {
        let run = sample_run(Operation::Gc, Mode::GcApply, Outcome::Success);
        assert!(parse_run(Operation::Verify, &encode_record(run).unwrap()).is_none());
        let backwards = Run {
            completed_at_unix_seconds: 9,
            ..run
        };
        assert!(parse_run(Operation::Gc, &encode_record(backwards).unwrap()).is_none());
        let mut trailing = encode_record(run).unwrap();
        trailing.extend_from_slice(b"garbage");
        assert!(parse_run(Operation::Gc, &trailing).is_none());
    }

    #[test]
    fn binary_records_reject_truncation_unknown_versions_and_trailing_data() {
        let run = sample_run(Operation::Gc, Mode::GcApply, Outcome::Success);
        let bytes = encode_record(run).unwrap();
        for end in 0..bytes.len() {
            assert!(
                parse_run(Operation::Gc, &bytes[..end]).is_none(),
                "prefix {end}"
            );
        }
        let mut wrong_version = bytes.clone();
        wrong_version[0] = 1;
        assert!(parse_run(Operation::Gc, &wrong_version).is_none());
        let wrong_mode = Run {
            mode: Mode::Verify,
            ..run
        };
        assert!(parse_run(Operation::Gc, &encode_record(wrong_mode).unwrap()).is_none());
        assert!(parse_run(Operation::Gc, &vec![0; MAX_RECORD_BYTES as usize + 1]).is_none());
    }

    #[test]
    fn started_records_bind_the_mode_and_operation_without_a_completed_timestamp() {
        let started = Started {
            operation: Operation::Verify,
            mode: Mode::Verify,
            started_at_unix_seconds: u64::MAX,
        };
        let bytes = encode_record(started).unwrap();
        assert_eq!(parse_started(Operation::Verify, &bytes), Some(started));
        assert!(parse_started(Operation::Gc, &bytes).is_none());
        let wrong_mode = Started {
            mode: Mode::Structural,
            ..started
        };
        assert!(parse_started(Operation::Verify, &encode_record(wrong_mode).unwrap()).is_none());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(parse_started(Operation::Verify, &trailing).is_none());
    }

    #[test]
    fn oversized_and_nonregular_records_fail_before_decoding() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join(last_name(Operation::Gc));
        fs::write(&record, vec![0; MAX_RECORD_BYTES as usize + 1]).unwrap();
        assert_eq!(
            read_snapshot(directory.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap();
        assert_eq!(
            read_snapshot(directory.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn maintenance_records_keep_the_last_completion_separate_from_a_new_start() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let first = Recorder::begin(directory.path(), Operation::Gc, Mode::GcApply)
            .expect("start should be persisted");
        first
            .finish(
                Outcome::Success,
                RunValues {
                    objects_examined: Some(12),
                    objects_reclaimed: Some(3),
                    bytes_reclaimed: Some(4096),
                    ..RunValues::default()
                },
            )
            .expect("completion should be persisted");
        let _interrupted = Recorder::begin(directory.path(), Operation::Gc, Mode::GcDryRun)
            .expect("new start should be persisted");

        let snapshot = read_snapshot(directory.path()).expect("snapshot should load");
        let run = snapshot.last_runs[Operation::Gc].expect("last completion remains");
        let started = snapshot.started[Operation::Gc].expect("current start is visible");
        assert_eq!(run.outcome, Outcome::Success);
        assert_eq!(run.bytes_reclaimed, Some(4096));
        assert_eq!(started.mode, Mode::GcDryRun);
        assert!(started.started_at_unix_seconds >= run.started_at_unix_seconds);
    }

    #[test]
    fn invalid_or_symlink_records_fail_the_sample() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory should be created");
        fs::write(directory.path().join("bad"), b"not a record").unwrap();
        symlink(
            directory.path().join("bad"),
            directory.path().join(last_name(Operation::Verify)),
        )
        .unwrap();
        assert!(read_snapshot(directory.path()).is_err());
    }
}
