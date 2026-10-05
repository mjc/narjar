use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    Flat,
    Chunked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("expected one of: flat, chunked")]
pub struct InvalidStorageBackend;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnsupportedStorageBackend {
    /// Chunked storage has no verified durability contract on macOS.
    #[error("chunked storage is not supported on macOS; choose flat")]
    MacOS,
    /// Chunked storage is supported only on Linux.
    #[error("chunked storage is supported only on Linux")]
    Platform,
}

/// A backend whose publication contract is supported on this platform.
///
/// Storage initialization cannot accept an unchecked backend choice:
/// ```compile_fail
/// use narjar::__private::storage::{Directory, Storage, StorageBackend};
/// fn initialize(root: &Directory) {
///     let _ = Storage::open(root, StorageBackend::Chunked);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportedStorageBackend(pub(super) BackendSupport);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BackendSupport {
    Flat,
    Chunked(ChunkDurability),
}

/// Construction capability for the implemented whole-filesystem publication barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ChunkDurability(());

impl ChunkDurability {
    pub(super) fn synchronize(self, directory: &std::fs::File) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            super::fs::sync_filesystem(directory)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "chunk publication has no supported durability barrier",
            ))
        }
    }
}

impl SupportedStorageBackend {
    pub const FLAT: Self = Self(BackendSupport::Flat);

    pub const fn backend(self) -> StorageBackend {
        match self.0 {
            BackendSupport::Flat => StorageBackend::Flat,
            BackendSupport::Chunked(_) => StorageBackend::Chunked,
        }
    }
}

impl TryFrom<StorageBackend> for SupportedStorageBackend {
    type Error = UnsupportedStorageBackend;

    fn try_from(backend: StorageBackend) -> Result<Self, Self::Error> {
        match backend {
            StorageBackend::Flat => Ok(Self::FLAT),
            StorageBackend::Chunked => {
                #[cfg(target_os = "linux")]
                {
                    Ok(Self(BackendSupport::Chunked(ChunkDurability(()))))
                }
                #[cfg(target_os = "macos")]
                {
                    Err(UnsupportedStorageBackend::MacOS)
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    Err(UnsupportedStorageBackend::Platform)
                }
            }
        }
    }
}

impl FromStr for StorageBackend {
    type Err = InvalidStorageBackend;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "flat" => Ok(Self::Flat),
            "chunked" => Ok(Self::Chunked),
            _ => Err(InvalidStorageBackend),
        }
    }
}

impl StorageBackend {
    pub const fn layout_descriptor(self) -> &'static [u8] {
        match self {
            Self::Flat => b"narjar-layout-v1\nbackend=flat\n",
            Self::Chunked => b"narjar-layout-v1\nbackend=chunked\nprofile=mincdc-hash4-v2\n",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InvalidStorageBackend, StorageBackend, SupportedStorageBackend, UnsupportedStorageBackend,
    };

    #[test]
    fn backend_parsing_recognizes_names_independently_of_platform_support() {
        assert_eq!("flat".parse::<StorageBackend>(), Ok(StorageBackend::Flat));
        assert_eq!(
            "chunked".parse::<StorageBackend>(),
            Ok(StorageBackend::Chunked)
        );
        for invalid in ["unknown", "", "Flat", "Chunked", " chunked", "flat "] {
            assert_eq!(
                invalid.parse::<StorageBackend>(),
                Err(InvalidStorageBackend)
            );
        }
    }

    #[test]
    fn backend_support_is_checked_separately_from_parsing() {
        assert_eq!(
            SupportedStorageBackend::try_from(StorageBackend::Flat),
            Ok(SupportedStorageBackend::FLAT)
        );
        let expected: Result<StorageBackend, UnsupportedStorageBackend> = {
            #[cfg(target_os = "linux")]
            {
                Ok(StorageBackend::Chunked)
            }
            #[cfg(target_os = "macos")]
            {
                Err(UnsupportedStorageBackend::MacOS)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Err(UnsupportedStorageBackend::Platform)
            }
        };
        assert_eq!(
            SupportedStorageBackend::try_from(StorageBackend::Chunked)
                .map(SupportedStorageBackend::backend),
            expected
        );
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (&InvalidStorageBackend, "expected one of: flat, chunked"),
            (
                &UnsupportedStorageBackend::MacOS,
                "chunked storage is not supported on macOS; choose flat",
            ),
            (
                &UnsupportedStorageBackend::Platform,
                "chunked storage is supported only on Linux",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }
}
