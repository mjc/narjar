use rustix::fs::OFlags;
use std::{
    fs::File,
    io::{self, Read, Write},
    num::NonZeroUsize,
};

use crate::storage::StorageError;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvictionOrder {
    #[default]
    Publication,
    LastUse,
}

impl std::str::FromStr for EvictionOrder {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "publication" => Ok(Self::Publication),
            "last-use" => Ok(Self::LastUse),
            _ => Err("expected publication or last-use"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RetentionOptions {
    pub eviction_order: EvictionOrder,
    pub max_deletions: Option<NonZeroUsize>,
    pub free_space: Option<FreeSpaceThresholds>,
}

impl RetentionOptions {
    pub(super) fn validate(self) -> Result<(), StorageError> {
        match self.free_space {
            None => Ok(()),
            Some(space) => {
                FreeSpaceThresholds::new(space.minimum, space.target)?;
                self.max_deletions
                    .ok_or_else(|| invalid("physical-pressure GC requires --max-deletions"))?;
                Ok(())
            }
        }
    }

    pub(super) fn remaining_deletions(self, selected: usize) -> usize {
        self.max_deletions
            .map_or(usize::MAX, |limit| limit.get().saturating_sub(selected))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FreeSpaceThresholds {
    minimum: u64,
    target: u64,
}

impl FreeSpaceThresholds {
    pub fn new(minimum: u64, target: u64) -> Result<Self, StorageError> {
        match target >= minimum {
            true => Ok(Self { minimum, target }),
            false => Err(invalid(
                "--target-free-bytes must be at least --min-free-bytes",
            )),
        }
    }

    #[cfg(test)]
    fn measure(self, available: u64) -> PhysicalPressure {
        self.measure_cycle(available, None)
    }

    pub(super) fn measure_cycle(
        self,
        available: u64,
        unfinished: Option<Self>,
    ) -> PhysicalPressure {
        match available < self.minimum || (unfinished == Some(self) && available < self.target) {
            true => PhysicalPressure::Collect {
                before: available,
                target: self.target,
            },
            false => PhysicalPressure::Idle { before: available },
        }
    }
}

pub(in crate::implementation::storage) const PRESSURE_HINT: &str = ".narjar-gc-pressure";
const PRESSURE_MAGIC: &[u8; 8] = b"NGCP0001";

pub(super) fn unfinished_pressure_cycle(root: &File) -> Option<FreeSpaceThresholds> {
    match read_pressure_hint(root) {
        Ok(thresholds) => Some(thresholds),
        Err(error) => {
            report_hint_error(error);
            None
        }
    }
}

fn read_pressure_hint(root: &File) -> io::Result<FreeSpaceThresholds> {
    let mut file = super::super::fs::open_regular_at(root, PRESSURE_HINT)?;
    let mut bytes = [0; 24];
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid GC pressure hint length",
        ));
    }
    file.read_exact(&mut bytes)?;
    let minimum = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let target = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    if &bytes[..8] != PRESSURE_MAGIC || target < minimum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid GC pressure hint",
        ));
    }
    Ok(FreeSpaceThresholds { minimum, target })
}

pub(super) fn record_pressure_cycle(
    root: &File,
    thresholds: Option<FreeSpaceThresholds>,
    report: &PhysicalSpaceReport,
) {
    let result = match thresholds.filter(|_| !report.target_met()) {
        Some(thresholds) => write_pressure_hint(root, thresholds),
        None => {
            super::super::fs::unlink_at(root, PRESSURE_HINT.as_ref()).and_then(|()| root.sync_all())
        }
    };
    if let Err(error) = result {
        report_hint_error(error);
    }
}

fn write_pressure_hint(root: &File, thresholds: FreeSpaceThresholds) -> io::Result<()> {
    let mut file = super::super::fs::open_at(
        root,
        PRESSURE_HINT.as_ref(),
        OFlags::CREATE | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        0o600,
    )?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GC pressure hint is not a regular file",
        ));
    }
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(PRESSURE_MAGIC);
    bytes[8..16].copy_from_slice(&thresholds.minimum.to_le_bytes());
    bytes[16..24].copy_from_slice(&thresholds.target.to_le_bytes());
    file.set_len(0)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    root.sync_all()
}

fn report_hint_error(error: io::Error) {
    if error.kind() != io::ErrorKind::NotFound {
        eprintln!("narjar: GC pressure hint: {error}; ignoring advisory hint");
    }
}

pub(super) enum PhysicalPressure {
    Unconfigured,
    Idle { before: u64 },
    Collect { before: u64, target: u64 },
}

impl PhysicalPressure {
    pub(super) fn requires_collection(&self) -> bool {
        match self {
            Self::Collect { .. } => true,
            Self::Unconfigured | Self::Idle { .. } => false,
        }
    }

    pub(super) fn report(self, after: Option<u64>) -> PhysicalSpaceReport {
        match self {
            Self::Unconfigured => PhysicalSpaceReport::Unconfigured,
            Self::Idle { before } => PhysicalSpaceReport::Idle {
                available_bytes: before,
            },
            Self::Collect { before, target } => PhysicalSpaceReport::Pressure {
                before_bytes: before,
                after_bytes: after.unwrap_or(before),
                target_bytes: target,
            },
        }
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalSpaceReport {
    #[default]
    Unconfigured,
    Idle {
        available_bytes: u64,
    },
    Pressure {
        before_bytes: u64,
        after_bytes: u64,
        target_bytes: u64,
    },
}

impl PhysicalSpaceReport {
    pub(super) fn target_met(&self) -> bool {
        match self {
            Self::Unconfigured | Self::Idle { .. } => true,
            Self::Pressure {
                after_bytes,
                target_bytes,
                ..
            } => after_bytes >= target_bytes,
        }
    }
}

fn invalid(message: &'static str) -> StorageError {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_pressure_survives_restart_but_not_a_policy_change_or_met_target() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let limits = FreeSpaceThresholds::new(100, 200).unwrap();
        let report = limits.measure(80).report(Some(150));
        record_pressure_cycle(&root, Some(limits), &report);
        drop(root);
        let root = File::open(directory.path()).unwrap();
        let unfinished = unfinished_pressure_cycle(&root);
        assert_eq!(unfinished, Some(limits));
        assert!(limits.measure_cycle(150, unfinished).requires_collection());
        assert!(
            !FreeSpaceThresholds::new(100, 180)
                .unwrap()
                .measure_cycle(150, unfinished)
                .requires_collection()
        );
        let complete = limits.measure_cycle(150, unfinished).report(Some(200));
        record_pressure_cycle(&root, Some(limits), &complete);
        assert_eq!(unfinished_pressure_cycle(&root), None);
        assert!(!limits.measure_cycle(150, None).requires_collection());
    }

    #[test]
    fn malformed_pressure_hints_and_failed_hint_cleanup_cannot_fail_collection() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        std::fs::write(directory.path().join(PRESSURE_HINT), b"broken").unwrap();
        assert_eq!(unfinished_pressure_cycle(&root), None);
        std::fs::remove_file(directory.path().join(PRESSURE_HINT)).unwrap();
        std::fs::create_dir(directory.path().join(PRESSURE_HINT)).unwrap();
        record_pressure_cycle(&root, None, &PhysicalSpaceReport::Unconfigured);
        assert_eq!(unfinished_pressure_cycle(&root), None);
    }

    #[test]
    fn physical_pressure_uses_hysteresis_and_never_infers_reclaimed_space() {
        let limits = FreeSpaceThresholds::new(100, 200).unwrap();
        assert!(!limits.measure(100).requires_collection());
        assert!(!limits.measure(150).requires_collection());
        assert!(limits.measure(99).requires_collection());
        assert!(
            !limits.measure(99).report(Some(99)).target_met(),
            "snapshot-pinned blocks can leave no actual reclaimed space"
        );
        assert!(
            !limits.measure(99).report(None).target_met(),
            "a dry run cannot promise physical reclamation"
        );
        assert!(limits.measure(99).report(Some(200)).target_met());
    }

    #[test]
    fn physical_pressure_cannot_be_configured_as_an_unbounded_drain() {
        assert!(FreeSpaceThresholds::new(200, 100).is_err());
        let mut policy = RetentionOptions {
            free_space: Some(FreeSpaceThresholds::new(100, 200).unwrap()),
            ..Default::default()
        };
        assert!(policy.validate().is_err());
        policy.max_deletions = NonZeroUsize::new(1);
        assert!(policy.validate().is_ok());
        assert_eq!(policy.remaining_deletions(0), 1);
        assert_eq!(policy.remaining_deletions(1), 0);
        assert_eq!(policy.remaining_deletions(usize::MAX), 0);
    }
}
