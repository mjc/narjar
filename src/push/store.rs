use std::{collections::BTreeMap, path::PathBuf};

use sqlite::{Connection, State};

use super::{NarInfoMetadata, PushError};
use crate::native_store::open_supported_metadata_database;
use narjar::object::{NarHash, NarIdentity, NarSize};

pub(super) struct LocalStore {
    database: Connection,
}

impl LocalStore {
    pub(super) fn open() -> Result<Self, PushError> {
        let state_dir = std::env::var_os("NIX_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nix/var/nix"));
        let database = open_supported_metadata_database(&state_dir)?;
        Ok(Self { database })
    }

    pub(super) fn closure_paths(
        &self,
        installables: &[String],
    ) -> Result<Vec<NarInfoMetadata>, PushError> {
        let roots = installables
            .iter()
            .map(|installable| concrete_store_path(installable))
            .collect::<Result<Vec<_>, _>>()?;
        let mut paths = BTreeMap::new();
        let mut pending = roots;
        while let Some(path) = pending.pop() {
            if paths.contains_key(&path) {
                continue;
            }
            let info = self.path_info(&path)?;
            pending.extend(info.claims().reference_paths().map(str::to_owned));
            paths.insert(path, info);
        }
        if paths.is_empty() {
            Err("no store paths were requested".into())
        } else {
            Ok(paths.into_values().collect())
        }
    }

    fn path_info(&self, path: &str) -> Result<NarInfoMetadata, PushError> {
        let mut statement = self
            .database
            .prepare(
                "SELECT id, hash, narSize, deriver, sigs, ca \
                 FROM ValidPaths WHERE path = ?",
            )
            .map_err(|error| format!("preparing Nix path lookup: {error}"))?;
        statement
            .bind((1, path))
            .map_err(|error| format!("binding Nix path lookup: {error}"))?;
        let State::Row = statement
            .next()
            .map_err(|error| format!("reading Nix path lookup: {error}"))?
        else {
            return Err(format!("store path is not valid: {path}").into());
        };
        let id = statement
            .read::<i64, _>("id")
            .map_err(|error| format!("reading Nix path id: {error}"))?;
        let hash = statement
            .read::<String, _>("hash")
            .map_err(|error| format!("reading Nix path hash: {error}"))?;
        let nar_size = statement
            .read::<i64, _>("narSize")
            .map_err(|error| format!("reading Nix path size: {error}"))?
            .try_into()
            .map_err(|_| format!("invalid Nix path size for {path}"))?;
        let deriver = statement
            .read::<Option<String>, _>("deriver")
            .map_err(|error| format!("reading Nix path deriver: {error}"))?;
        let signatures = statement
            .read::<Option<String>, _>("sigs")
            .map_err(|error| format!("reading Nix path signatures: {error}"))?
            .map(|value| value.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let ca = statement
            .read::<Option<String>, _>("ca")
            .map_err(|error| format!("reading Nix path content address: {error}"))?;
        let references = self.references(id)?;
        NarInfoMetadata::from_store_metadata(
            path.to_owned(),
            ca,
            deriver,
            NarIdentity::new(nar_hash_from_base16(&hash)?, NarSize::new(nar_size)),
            references,
            signatures,
        )
        .map_err(|error| PushError::new(format!("invalid Nix path metadata for {path}: {error}")))
    }

    fn references(&self, id: i64) -> Result<Vec<String>, PushError> {
        let mut statement = self
            .database
            .prepare(
                "SELECT reference.path FROM Refs \
                 JOIN ValidPaths AS reference ON reference.id = Refs.reference \
                 WHERE Refs.referrer = ? ORDER BY reference.path",
            )
            .map_err(|error| format!("preparing Nix references lookup: {error}"))?;
        statement
            .bind((1, id))
            .map_err(|error| format!("binding Nix references lookup: {error}"))?;
        let mut references = Vec::new();
        while let State::Row = statement
            .next()
            .map_err(|error| format!("reading Nix references: {error}"))?
        {
            references.push(
                statement
                    .read::<String, _>(0)
                    .map_err(|error| format!("reading Nix reference: {error}"))?,
            );
        }
        Ok(references)
    }
}

fn concrete_store_path(value: &str) -> Result<String, PushError> {
    let relative = value
        .strip_prefix("/nix/store/")
        .filter(|relative| !relative.is_empty() && !relative.contains('/'))
        .ok_or_else(|| format!("native push requires a concrete store path: {value}"))?;
    if relative.split_once('-').is_none() {
        return Err(format!("invalid concrete store path: {value}").into());
    }
    Ok(format!("/nix/store/{relative}"))
}

fn nar_hash_from_base16(value: &str) -> Result<NarHash, PushError> {
    let value = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("unsupported Nix path hash: {value}"))?;
    if value.len() != 64 {
        return Err(format!("invalid Nix SHA-256 length: {}", value.len()).into());
    }
    let mut digest = [0; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (byte, pair) in digest.iter_mut().zip(pairs) {
        let high = hex_nibble(pair[0]).ok_or_else(|| "invalid Nix base16 SHA-256".to_owned())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "invalid Nix base16 SHA-256".to_owned())?;
        *byte = (high << 4) | low;
    }
    Ok(NarHash::from_digest(digest))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::nar_hash_from_base16;
    use narjar::object::NarHash;

    #[test]
    fn converts_nix_store_hash_to_binary_identity() {
        assert_eq!(
            nar_hash_from_base16(
                "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
            .expect("valid base16 SHA-256"),
            NarHash::from_digest([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ])
        );
    }

    #[test]
    fn rejects_non_hex_bytes_without_slicing_utf8() {
        let value = format!("sha256:0é{}", "0".repeat(61));
        assert!(nar_hash_from_base16(&value).is_err());
    }
}
