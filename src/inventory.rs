use std::{
    collections::HashSet,
    io::{self, Read},
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::{
    narinfo::{PublishedNarInfoError, TrustedPublicKeys, read_narinfo_file},
    storage::{
        NarObjectId, StoreHash, entry_is_regular_at, nix32_sha256, open_directory,
        open_directory_at, open_regular_at, read_dir_names,
    },
};

pub use crate::narinfo::MAX_NARINFO_BYTES;

pub fn narinfo_is_valid(trusted: &TrustedPublicKeys, store: &StoreHash, bytes: Vec<u8>) -> bool {
    trusted.inspect(store, bytes).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InventoryClass {
    ValidPair,
    OrphanNar,
    MissingNar,
    MalformedNarInfo,
    HashOrSizeMismatch,
    UntrustedSignature,
    InvalidFilename,
}

impl InventoryClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidPair => "valid_pair",
            Self::OrphanNar => "orphan_nar",
            Self::MissingNar => "missing_nar",
            Self::MalformedNarInfo => "malformed_narinfo",
            Self::HashOrSizeMismatch => "hash_or_size_mismatch",
            Self::UntrustedSignature => "untrusted_signature",
            Self::InvalidFilename => "invalid_filename",
        }
    }

    pub const fn action(self) -> &'static str {
        match self {
            Self::ValidPair => "none",
            Self::OrphanNar => "review before deleting",
            Self::MissingNar => "reupload NAR or quarantine narinfo",
            Self::MalformedNarInfo => "quarantine narinfo",
            Self::HashOrSizeMismatch => "quarantine and reupload",
            Self::UntrustedSignature => "restore trust or quarantine narinfo",
            Self::InvalidFilename => "quarantine manually",
        }
    }

    pub const fn invalid_published_pair(self) -> bool {
        matches!(
            self,
            Self::MissingNar
                | Self::MalformedNarInfo
                | Self::HashOrSizeMismatch
                | Self::UntrustedSignature
        )
    }

    pub const fn blocks_serve(self) -> bool {
        matches!(self, Self::MalformedNarInfo | Self::UntrustedSignature)
    }
}

impl std::fmt::Display for InventoryClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InventoryEntry {
    class: InventoryClass,
    identifier: String,
}

impl InventoryEntry {
    pub fn class(&self) -> InventoryClass {
        self.class
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    fn new(class: InventoryClass, identifier: impl Into<String>) -> Self {
        Self {
            class,
            identifier: identifier.into(),
        }
    }
}

#[derive(Debug)]
pub struct Inventory {
    entries: Vec<InventoryEntry>,
}

impl Inventory {
    pub fn scan(root: &Path, trusted: &TrustedPublicKeys, verify_hashes: bool) -> io::Result<Self> {
        let mut entries = Vec::new();
        let mut referenced = HashSet::new();
        let root_directory = open_directory(root)?;
        let nar_directory = open_directory_at(&root_directory, std::ffi::OsStr::new("nar"))?;

        for name in read_dir_names(&root_directory)? {
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(route) = name.strip_suffix(".narinfo") else {
                continue;
            };
            let Ok(store) = StoreHash::parse(route) else {
                entries.push(InventoryEntry::new(InventoryClass::InvalidFilename, name));
                continue;
            };
            let name = std::ffi::OsStr::new(name);
            if !entry_is_regular_at(&root_directory, name)? {
                entries.push(InventoryEntry::new(InventoryClass::MalformedNarInfo, route));
                continue;
            }
            let validated = match trusted.inspect(
                &store,
                read_narinfo_file(open_regular_at(&root_directory, name)?)?,
            ) {
                Ok(validated) => validated,
                Err(PublishedNarInfoError::Malformed) => {
                    entries.push(InventoryEntry::new(InventoryClass::MalformedNarInfo, route));
                    continue;
                }
                Err(PublishedNarInfoError::UntrustedSignature) => {
                    entries.push(InventoryEntry::new(
                        InventoryClass::UntrustedSignature,
                        route,
                    ));
                    continue;
                }
            };
            let nar = validated.nar();
            referenced.insert(nar.as_str().to_owned());
            let nar_name = format!("{}.nar", nar.as_str());
            let Some(mut file) = open_regular_at(&nar_directory, std::ffi::OsStr::new(&nar_name))
                .map(Some)
                .or_else(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        Ok(None)
                    } else {
                        Err(error)
                    }
                })?
            else {
                entries.push(InventoryEntry::new(InventoryClass::MissingNar, route));
                continue;
            };
            let size_matches = file.metadata()?.len() == validated.nar_size();
            let hash_matches = if verify_hashes && size_matches {
                let mut hasher = Sha256::new();
                let mut buffer = [0; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                nix32_sha256(&hasher.finalize()) == nar.as_str()
            } else {
                true
            };
            entries.push(InventoryEntry::new(
                if size_matches && hash_matches {
                    InventoryClass::ValidPair
                } else {
                    InventoryClass::HashOrSizeMismatch
                },
                route,
            ));
        }

        for name in read_dir_names(&nar_directory)? {
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(identifier) = name.strip_suffix(".nar") else {
                entries.push(InventoryEntry::new(InventoryClass::InvalidFilename, name));
                continue;
            };
            if NarObjectId::parse(identifier).is_err()
                || !entry_is_regular_at(&nar_directory, std::ffi::OsStr::new(name))?
            {
                entries.push(InventoryEntry::new(InventoryClass::InvalidFilename, name));
            } else if !referenced.contains(identifier) {
                entries.push(InventoryEntry::new(InventoryClass::OrphanNar, identifier));
            }
        }

        entries.sort();
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    pub fn can_serve(&self) -> bool {
        !self.entries.iter().any(|entry| entry.class.blocks_serve())
    }
}
