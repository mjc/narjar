use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Gc,
    Reconcile,
    Verify,
}

impl Operation {
    pub const ALL: [Self; 3] = [Self::Gc, Self::Reconcile, Self::Verify];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Gc => "gc",
            Self::Reconcile => "reconcile",
            Self::Verify => "verify",
        }
    }

    pub const fn index(self) -> usize {
        match self {
            Self::Gc => 0,
            Self::Reconcile => 1,
            Self::Verify => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "gc_dry_run" => Self::GcDryRun,
            "gc_apply" => Self::GcApply,
            "reconcile" => Self::Reconcile,
            "verify" => Self::Verify,
            "structural" => Self::Structural,
            "cleanup" => Self::Cleanup,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "success" => Self::Success,
            "failure" => Self::Failure,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Started {
    pub operation: Operation,
    pub mode: Mode,
    pub started_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub last_runs: [Option<Run>; 3],
    pub started: [Option<Started>; 3],
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
            format!("1\n{}\n{}\n", mode.name(), recorder.started_at_unix_seconds).as_bytes(),
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
        write_atomic(
            &self.root,
            &last_name(self.operation),
            encode_run(run).as_bytes(),
        )?;
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
    for operation in Operation::ALL {
        snapshot.last_runs[operation.index()] =
            read_record(&root.join(last_name(operation)), |text| {
                parse_run(operation, text)
            })?;
        snapshot.started[operation.index()] =
            read_record(&root.join(started_name(operation)), |text| {
                parse_started(operation, text)
            })?;
    }
    Ok(snapshot)
}

fn read_record<T>(path: &Path, parse: impl FnOnce(&str) -> Option<T>) -> io::Result<Option<T>> {
    match read_bounded_file(path) {
        Ok(text) => parse(&text)
            .map(Some)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn encode_run(run: Run) -> String {
    [
        "1".to_owned(),
        run.mode.name().to_owned(),
        run.outcome.name().to_owned(),
        run.started_at_unix_seconds.to_string(),
        run.completed_at_unix_seconds.to_string(),
        run.duration_micros.to_string(),
        optional_number(run.objects_examined),
        optional_number(run.objects_selected),
        optional_number(run.bytes_examined),
        optional_number(run.objects_reclaimed),
        optional_number(run.bytes_reclaimed),
        encode_inventory_counts(run.inventory_class_counts),
    ]
    .join("\n")
        + "\n"
}

fn parse_run(operation: Operation, text: &str) -> Option<Run> {
    let mut lines = text.lines();
    let version = lines.next()?;
    let mode = parse_mode(operation, lines.next()?)?;
    let outcome = Outcome::parse(lines.next()?)?;
    let started_at_unix_seconds = lines.next()?.parse().ok()?;
    let completed_at_unix_seconds = lines.next()?.parse().ok()?;
    let duration_micros = lines.next()?.parse().ok()?;
    let objects_examined = parse_optional_number(lines.next()?).ok()?;
    let objects_selected = parse_optional_number(lines.next()?).ok()?;
    let bytes_examined = parse_optional_number(lines.next()?).ok()?;
    let objects_reclaimed = parse_optional_number(lines.next()?).ok()?;
    let bytes_reclaimed = parse_optional_number(lines.next()?).ok()?;
    let inventory_class_counts = parse_inventory_counts(lines.next()?).ok()?;
    (version == "1"
        && lines.next().is_none()
        && started_at_unix_seconds <= completed_at_unix_seconds)
        .then_some(Run {
            operation,
            mode,
            outcome,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            duration_micros,
            objects_examined,
            objects_selected,
            bytes_examined,
            objects_reclaimed,
            bytes_reclaimed,
            inventory_class_counts,
        })
}

fn parse_started(operation: Operation, text: &str) -> Option<Started> {
    let mut lines = text.lines();
    let version = lines.next()?;
    let mode = parse_mode(operation, lines.next()?)?;
    let started_at_unix_seconds = lines.next()?.parse().ok()?;
    (version == "1" && lines.next().is_none()).then_some(Started {
        operation,
        mode,
        started_at_unix_seconds,
    })
}

fn parse_mode(operation: Operation, value: &str) -> Option<Mode> {
    let mode = Mode::parse(value)?;
    match (operation, mode) {
        (Operation::Gc, Mode::GcDryRun | Mode::GcApply)
        | (Operation::Reconcile, Mode::Reconcile | Mode::Structural | Mode::Cleanup)
        | (Operation::Verify, Mode::Verify) => Some(mode),
        _ => None,
    }
}

fn parse_optional_number(value: &str) -> Result<Option<u64>, ()> {
    match value {
        "-" => Ok(None),
        _ => value.parse().map(Some).map_err(|_| ()),
    }
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |number| number.to_string())
}

fn encode_inventory_counts(value: Option<[u64; INVENTORY_CLASS_COUNT]>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |counts| {
            counts
                .into_iter()
                .map(|count| count.to_string())
                .collect::<Vec<_>>()
                .join(",")
        },
    )
}

fn parse_inventory_counts(value: &str) -> Result<Option<[u64; INVENTORY_CLASS_COUNT]>, ()> {
    match value {
        "-" => Ok(None),
        _ => {
            let counts = value
                .split(',')
                .map(str::parse)
                .collect::<Result<Vec<u64>, _>>()
                .map_err(|_| ())?;
            counts.try_into().map(Some).map_err(|_| ())
        }
    }
}

fn read_bounded_file(path: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_RECORD_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(text)
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
        let run = snapshot.last_runs[Operation::Gc.index()].expect("last completion remains");
        let started = snapshot.started[Operation::Gc.index()].expect("current start is visible");
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
