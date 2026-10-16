use std::{collections::BTreeSet, fs::File, path::Path};

use serde::{Deserialize, Deserializer, Serialize};

use super::{StorageError, StoreHash, invalid};

/// Maximum text read from a caller-owned roots source, including whitespace.
const MAX_ROOT_SOURCE_BYTES: u64 = 1024 * 1024;

/// Validated roots, detached from the file or process that supplied them.
#[derive(Debug, Default, Serialize)]
#[serde(transparent)]
pub struct ProtectedRoots(BTreeSet<String>);

impl ProtectedRoots {
    pub fn load(path: Option<&Path>) -> Result<Self, StorageError> {
        match path {
            None => Ok(Self::default()),
            Some(path) => {
                let bytes =
                    crate::records::read_bounded_bytes(File::open(path)?, MAX_ROOT_SOURCE_BYTES)
                        .map_err(std::io::Error::from)?;
                let contents =
                    std::str::from_utf8(&bytes).map_err(|error| invalid(error.to_string()))?;
                Self::parse(contents)
            }
        }
    }

    pub fn parse(contents: &str) -> Result<Self, StorageError> {
        Self::try_from(
            contents
                .lines()
                .map(str::trim)
                .filter(|root| !root.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        )
    }

    pub(super) fn values(&self) -> &BTreeSet<String> {
        &self.0
    }
}

impl TryFrom<BTreeSet<String>> for ProtectedRoots {
    type Error = StorageError;

    fn try_from(roots: BTreeSet<String>) -> Result<Self, Self::Error> {
        roots.iter().try_for_each(|root| validate_root(root))?;
        Ok(Self(roots))
    }
}

impl<'de> Deserialize<'de> for ProtectedRoots {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(BTreeSet::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn validate_root(root: &str) -> Result<(), StorageError> {
    if StoreHash::parse(root).is_ok() {
        return Ok(());
    }
    let basename = root
        .strip_prefix("/nix/store/")
        .and_then(|value| value.split_once('-').map(|(hash, _)| hash))
        .ok_or_else(|| invalid(format!("invalid protected root: {root}")))?;
    StoreHash::parse(basename)
        .map(|_| ())
        .map_err(|_| invalid(format!("invalid protected root: {root}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_keep_hash_and_full_path_identity_and_ignore_only_blank_lines_and_whitespace() {
        let hash = "00000000000000000000000000000000";
        let path = format!("/nix/store/{hash}-name");
        let roots = ProtectedRoots::parse(&format!(" {hash}\n\n{path}\n{hash}\n")).unwrap();
        assert_eq!(roots.values(), &BTreeSet::from([hash.to_owned(), path]));
        assert!(ProtectedRoots::parse("not-a-root").is_err());
        assert!(ProtectedRoots::parse("").unwrap().values().is_empty());
    }

    #[test]
    fn wire_decoding_cannot_bypass_root_validation() {
        let bytes = postcard::to_allocvec(&BTreeSet::from(["not-a-root"])).unwrap();
        assert!(crate::records::decode_complete::<ProtectedRoots>(&bytes).is_err());
        let roots = ProtectedRoots::parse("00000000000000000000000000000000").unwrap();
        let bytes = postcard::to_allocvec(&roots).unwrap();
        let decoded: ProtectedRoots = crate::records::decode_complete(&bytes).unwrap();
        assert_eq!(decoded.values(), roots.values());
    }

    #[test]
    fn missing_and_invalid_sources_are_errors_not_empty_protection() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("roots");
        assert!(ProtectedRoots::load(Some(&source)).is_err());
        std::fs::write(&source, b"not-a-root").unwrap();
        assert!(ProtectedRoots::load(Some(&source)).is_err());
        std::fs::write(&source, b"\xff").unwrap();
        assert!(ProtectedRoots::load(Some(&source)).is_err());
        assert!(ProtectedRoots::load(None).unwrap().values().is_empty());
    }

    #[test]
    fn source_limit_accepts_exactly_one_mib_but_rejects_even_one_extra_space() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("roots");
        let hash = "00000000000000000000000000000000";
        let mut bytes = vec![b' '; MAX_ROOT_SOURCE_BYTES as usize + 1];
        bytes[..hash.len()].copy_from_slice(hash.as_bytes());
        bytes[hash.len()] = b'\n';
        std::fs::write(&source, &bytes[..MAX_ROOT_SOURCE_BYTES as usize]).unwrap();
        let roots = ProtectedRoots::load(Some(&source)).unwrap();
        assert_eq!(roots.values(), &BTreeSet::from([hash.to_owned()]));
        std::fs::write(&source, bytes).unwrap();
        let error = ProtectedRoots::load(Some(&source)).unwrap_err();
        let StorageError::Io(error) = error else {
            panic!("the source limit must return an input I/O error: {error}");
        };
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidData,
            "valid roots with oversized whitespace must not be silently truncated"
        );
    }
}
