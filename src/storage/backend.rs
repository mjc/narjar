use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    Flat,
    Chunked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidStorageBackend;

impl fmt::Display for InvalidStorageBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected one of: flat, chunked")
    }
}

impl std::error::Error for InvalidStorageBackend {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedStorageBackend {
    /// Chunked storage has no verified durability contract on macOS.
    MacOS,
    /// Chunked storage is supported only on Linux.
    Platform,
}

impl fmt::Display for UnsupportedStorageBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MacOS => "chunked storage is not supported on macOS; choose flat",
            Self::Platform => "chunked storage is supported only on Linux",
        })
    }
}

impl std::error::Error for UnsupportedStorageBackend {}

/// A backend whose publication contract is supported on this platform.
///
/// Storage initialization cannot accept an unchecked backend choice:
/// ```compile_fail
/// use narjar::__private::storage::{Directory, Storage, StorageBackend};
/// fn initialize(root: &Directory) {
///     let _ = Storage::initialize(root, StorageBackend::Chunked);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportedStorageBackend(StorageBackend);

impl SupportedStorageBackend {
    pub const FLAT: Self = Self(StorageBackend::Flat);

    pub const fn backend(self) -> StorageBackend {
        self.0
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
                    Ok(Self(backend))
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
