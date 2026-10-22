use std::{
    fmt,
    fs::File,
    io,
    sync::{Arc, Mutex},
};

use super::{StagingReservation, StorageError, publication::StagingBudget};

#[cfg(unix)]
#[path = "capacity/unix.rs"]
mod unix;
#[cfg(unix)]
pub(crate) use unix::filesystem_space;
#[cfg(windows)]
#[path = "capacity/windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) use windows::filesystem_space;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapacityErrorKind {
    NoSpace,
    Quota,
    Inodes,
    ReadOnly,
    Other,
}

pub(crate) fn capacity_error_kind(error: &io::Error) -> CapacityErrorKind {
    match error.kind() {
        io::ErrorKind::StorageFull => CapacityErrorKind::NoSpace,
        io::ErrorKind::QuotaExceeded => CapacityErrorKind::Quota,
        io::ErrorKind::ReadOnlyFilesystem => CapacityErrorKind::ReadOnly,
        _ => CapacityErrorKind::Other,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum InodeCapacity {
    Measured {
        #[serde(rename = "total_inodes")]
        total: u64,
        #[serde(rename = "available_inodes")]
        available: u64,
    },
    #[cfg_attr(
        unix,
        allow(dead_code, reason = "Unix reports inode counts; other hosts may not.")
    )]
    NotReported,
}

impl fmt::Display for InodeCapacity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Measured { total, available } => {
                write!(formatter, "{available} inodes available / {total} total")
            }
            Self::NotReported => formatter.write_str("inode counts unavailable"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StorageCapacity {
    pub total_bytes: u64,
    pub available_bytes: u64,
    #[serde(flatten)]
    pub inodes: InodeCapacity,
    pub read_only: bool,
}

impl StorageCapacity {
    pub(super) fn required_capacity(self, required_bytes: u64) -> Result<(), StorageError> {
        if self.read_only {
            return Err(StorageError::Io(io::ErrorKind::ReadOnlyFilesystem.into()));
        }
        if self.available_bytes < required_bytes {
            return Err(StorageError::InsufficientSpace);
        }
        match self.inodes {
            InodeCapacity::Measured { available: 0, .. } => Err(StorageError::InsufficientInodes),
            InodeCapacity::Measured { .. } | InodeCapacity::NotReported => Ok(()),
        }
    }
}

pub(super) fn reserve_staging_bytes(
    budget: &Arc<Mutex<StagingBudget>>,
    directory: &File,
    min_free_bytes: u64,
    bytes: u64,
) -> Result<StagingReservation, StorageError> {
    reserve_staging_bytes_with_measurement(budget, min_free_bytes, bytes, || {
        filesystem_space(directory)
    })
}

fn reserve_staging_bytes_with_measurement(
    budget: &Arc<Mutex<StagingBudget>>,
    min_free_bytes: u64,
    bytes: u64,
    measure: impl FnOnce() -> io::Result<StorageCapacity>,
) -> Result<StagingReservation, StorageError> {
    let mut budget_guard = budget
        .lock()
        .map_err(|_| StorageError::Io(io::Error::other("staging budget lock poisoned")))?;
    budget_guard.reserve(measure()?, min_free_bytes, bytes)?;
    drop(budget_guard);
    Ok(StagingReservation {
        budget: Arc::clone(budget),
        bytes,
    })
}

#[cfg(test)]
pub(super) fn reserve_staging_bytes_for_test(
    budget: &Arc<Mutex<StagingBudget>>,
    min_free_bytes: u64,
    bytes: u64,
    measure: impl FnOnce() -> io::Result<StorageCapacity>,
) -> Result<StagingReservation, StorageError> {
    reserve_staging_bytes_with_measurement(budget, min_free_bytes, bytes, measure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::storage::publication::StagingInodeReservation;

    #[test]
    fn measured_inode_capacity_keeps_the_flat_doctor_json_fields() {
        let capacity = StorageCapacity {
            total_bytes: 100,
            available_bytes: 40,
            inodes: InodeCapacity::Measured {
                total: 20,
                available: 8,
            },
            read_only: false,
        };
        assert_eq!(
            serde_json::to_value(capacity).unwrap(),
            serde_json::json!({
                "total_bytes": 100, "available_bytes": 40,
                "total_inodes": 20, "available_inodes": 8, "read_only": false,
            })
        );
        assert_eq!(capacity.inodes.to_string(), "8 inodes available / 20 total");
    }

    #[test]
    fn unreported_inode_capacity_does_not_serialize_fabricated_counts() {
        let capacity = StorageCapacity {
            total_bytes: 100,
            available_bytes: 40,
            inodes: InodeCapacity::NotReported,
            read_only: false,
        };
        assert_eq!(
            serde_json::to_value(capacity).unwrap(),
            serde_json::json!({"total_bytes": 100, "available_bytes": 40, "read_only": false})
        );
        assert_eq!(capacity.inodes.to_string(), "inode counts unavailable");
    }

    #[test]
    fn retained_staging_reserves_its_transient_journal_draft_inode() {
        let budget = Arc::new(Mutex::new(StagingBudget::default()));
        let four_inodes = StorageCapacity {
            total_bytes: 100,
            available_bytes: 100,
            inodes: InodeCapacity::Measured {
                total: 5,
                available: 4,
            },
            read_only: false,
        };
        assert!(matches!(
            StagingInodeReservation::reserve_for_test(&budget, 5, || Ok(four_inodes)),
            Err(StorageError::InsufficientInodes)
        ));

        let five_inodes = StorageCapacity {
            inodes: InodeCapacity::Measured {
                total: 5,
                available: 5,
            },
            ..four_inodes
        };
        let mut first = StagingInodeReservation::reserve_for_test(&budget, 5, || Ok(five_inodes))
            .expect("staging entries and a journal transition draft fit");
        first.record_created_staging_entries(4);
        assert!(matches!(
            StagingInodeReservation::reserve_for_test(&budget, 5, || Ok(five_inodes)),
            Err(StorageError::InsufficientInodes)
        ));

        drop(first);
        assert!(StagingInodeReservation::reserve_for_test(&budget, 5, || Ok(five_inodes)).is_ok());
    }
}
