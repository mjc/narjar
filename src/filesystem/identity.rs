use std::{fs::File, io};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FileIdentity {
    volume: u64,
    object: [u8; 16],
}

impl FileIdentity {
    pub(crate) fn from_file(file: &File) -> io::Result<Self> {
        platform::identity(file)
    }

    pub(crate) const fn volume(self) -> u64 {
        self.volume
    }
}

/// Object identity and mutation evidence; access-time changes do not invalidate it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FileStamp {
    identity: FileIdentity,
    size: u64,
    modified: i128,
    changed: i128,
}

impl FileStamp {
    pub(crate) fn from_file(file: &File) -> io::Result<Self> {
        platform::stamp(file)
    }

    pub(crate) fn update_identity_digest(self, digest: &mut impl sha2::Digest) {
        digest.update(self.identity.volume.to_le_bytes());
        digest.update(self.identity.object);
        digest.update(self.size.to_le_bytes());
        digest.update(self.modified.to_le_bytes());
        digest.update(self.changed.to_le_bytes());
    }
}

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    impl FileStamp {
        #[cfg(test)]
        pub(crate) fn from_metadata(metadata: &std::fs::Metadata) -> Self {
            platform::stamp_from_metadata(metadata)
        }

        pub(crate) fn from_stat(statistics: &rustix::fs::Stat) -> Self {
            let mut object = [0; 16];
            object[..8].copy_from_slice(&statistics.st_ino.to_le_bytes());
            Self {
                identity: FileIdentity {
                    #[allow(
                        clippy::unnecessary_cast,
                        reason = "Darwin stat uses a signed dev_t; Linux uses u64"
                    )]
                    volume: statistics.st_dev as u64,
                    object,
                },
                size: statistics.st_size as u64,
                modified: i128::from(statistics.st_mtime) * 1_000_000_000
                    + i128::from(statistics.st_mtime_nsec),
                changed: i128::from(statistics.st_ctime) * 1_000_000_000
                    + i128::from(statistics.st_ctime_nsec),
            }
        }
    }

    fn identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
        let mut object = [0; 16];
        object[..8].copy_from_slice(&metadata.ino().to_le_bytes());
        FileIdentity {
            volume: metadata.dev(),
            object,
        }
    }

    pub(super) fn identity(file: &File) -> io::Result<FileIdentity> {
        file.metadata()
            .map(|metadata| identity_from_metadata(&metadata))
    }

    pub(super) fn stamp(file: &File) -> io::Result<FileStamp> {
        file.metadata()
            .map(|metadata| stamp_from_metadata(&metadata))
    }

    pub(super) fn stamp_from_metadata(metadata: &std::fs::Metadata) -> FileStamp {
        FileStamp {
            identity: identity_from_metadata(metadata),
            size: metadata.len(),
            modified: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            changed: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::os::windows::io::AsRawHandle;

    impl super::FileIdentity {
        pub(crate) fn namespace_bytes(self) -> [u8; 24] {
            let mut bytes = [0; 24];
            bytes[..8].copy_from_slice(&self.volume.to_le_bytes());
            bytes[8..].copy_from_slice(&self.object);
            bytes
        }
    }

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FILE_ID_INFO, FILE_STANDARD_INFO, FileBasicInfo, FileIdInfo,
        FileStandardInfo, GetFileInformationByHandleEx,
    };

    use super::*;

    pub(super) fn identity(file: &File) -> io::Result<FileIdentity> {
        let mut information = FILE_ID_INFO::default();
        // SAFETY: the borrowed handle and correctly aligned, initialized output
        // live throughout the call. FileIdInfo writes exactly FILE_ID_INFO.
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                std::ptr::from_mut(&mut information).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity {
            volume: information.VolumeSerialNumber,
            object: information.FileId.Identifier,
        })
    }

    pub(super) fn stamp(file: &File) -> io::Result<FileStamp> {
        let identity = identity(file)?;
        let mut basic = FILE_BASIC_INFO::default();
        // SAFETY: FileBasicInfo matches the output type and its byte length;
        // the file and output remain alive and exclusively borrowed for the call.
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                std::ptr::from_mut(&mut basic).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut standard = FILE_STANDARD_INFO::default();
        // SAFETY: FileStandardInfo matches this output's layout and size, and
        // the borrowed file and initialized output outlive this synchronous call.
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStandardInfo,
                std::ptr::from_mut(&mut standard).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileStamp {
            identity,
            size: standard
                .EndOfFile
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative file length"))?,
            modified: i128::from(basic.LastWriteTime),
            changed: i128::from(basic.ChangeTime),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn stat_stamps_preserve_signed_seconds_and_nanoseconds() {
        let file = tempfile::tempfile().unwrap();
        let mut statistics = rustix::fs::fstat(&file).unwrap();
        statistics.st_ctime = -7;
        statistics.st_ctime_nsec = 456_123_987;
        statistics.st_mtime = -2;
        statistics.st_mtime_nsec = 123_456_789;
        let stamp = FileStamp::from_stat(&statistics);
        assert_eq!(stamp.changed, -6_543_876_013);
        assert_eq!(stamp.modified, -1_876_543_211);
    }

    #[test]
    fn an_open_file_keeps_its_identity_after_a_rename() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let file = File::create_new(&source).unwrap();
        let before = FileIdentity::from_file(&file).unwrap();
        std::fs::rename(&source, directory.path().join("destination")).unwrap();
        assert_eq!(FileIdentity::from_file(&file).unwrap(), before);
        let replacement = File::create_new(&source).unwrap();
        assert_ne!(FileIdentity::from_file(&replacement).unwrap(), before);
    }

    #[test]
    fn writing_through_an_open_handle_invalidates_its_stamp() {
        use std::io::Write;

        let directory = tempfile::tempdir().unwrap();
        let mut file = File::create_new(directory.path().join("file")).unwrap();
        let before = FileStamp::from_file(&file).unwrap();
        file.write_all(b"changed").unwrap();
        file.sync_all().unwrap();
        assert_ne!(FileStamp::from_file(&file).unwrap(), before);
    }
}
