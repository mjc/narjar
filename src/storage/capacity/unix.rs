use std::{fs::File, io};

use rustix::fs::{self, StatVfs, StatVfsMountFlags};

use super::{InodeCapacity, StorageCapacity};

pub(crate) fn filesystem_space(directory: &File) -> io::Result<StorageCapacity> {
    let statistics = fs::fstatvfs(directory)?;
    Ok(capacity_from_statvfs(&statistics))
}

fn capacity_from_statvfs(statistics: &StatVfs) -> StorageCapacity {
    let scale = u128::from(statistics.f_frsize);
    let bytes = |blocks: u64| {
        u128::from(blocks)
            .saturating_mul(scale)
            .min(u128::from(u64::MAX)) as u64
    };
    StorageCapacity {
        total_bytes: bytes(statistics.f_blocks),
        available_bytes: bytes(statistics.f_bavail),
        inodes: InodeCapacity::Measured {
            total: statistics.f_files,
            available: statistics.f_favail,
        },
        read_only: statistics.f_flag.contains(StatVfsMountFlags::RDONLY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statistics() -> StatVfs {
        StatVfs {
            f_bsize: 0,
            f_frsize: u64::MAX,
            f_blocks: u64::MAX,
            f_bfree: 0,
            f_bavail: u64::MAX,
            f_files: u64::MAX,
            f_ffree: 0,
            f_favail: u64::MAX,
            f_fsid: 0,
            f_flag: StatVfsMountFlags::RDONLY,
            f_namemax: 0,
        }
    }

    #[test]
    fn statvfs_capacity_conversion_saturates_bytes_and_preserves_inode_counts() {
        let capacity = capacity_from_statvfs(&statistics());
        assert_eq!(capacity.total_bytes, u64::MAX);
        assert_eq!(capacity.available_bytes, u64::MAX);
        assert_eq!(
            capacity.inodes,
            InodeCapacity::Measured {
                total: u64::MAX,
                available: u64::MAX
            }
        );
        assert!(capacity.read_only);
    }

    #[test]
    fn statvfs_uses_fragment_size_and_keeps_zero_available_inodes_measured() {
        let mut statistics = statistics();
        statistics.f_bsize = 8192;
        statistics.f_frsize = 4096;
        statistics.f_blocks = 100;
        statistics.f_bavail = 20;
        statistics.f_files = 1000;
        statistics.f_favail = 0;
        statistics.f_flag = StatVfsMountFlags::empty();
        let capacity = capacity_from_statvfs(&statistics);
        assert_eq!(capacity.total_bytes, 409600);
        assert_eq!(capacity.available_bytes, 81920);
        assert_eq!(
            capacity.inodes,
            InodeCapacity::Measured {
                total: 1000,
                available: 0
            }
        );
        assert!(!capacity.read_only);
    }
}
