use std::{collections::BTreeMap, path::PathBuf};

use data_encoding::BASE64;
use sqlite::{Connection, OpenFlags, State};

use super::PathInfo;

pub(super) struct LocalStore {
    database: Connection,
}

impl LocalStore {
    pub(super) fn open() -> Result<Self, String> {
        let state_dir = std::env::var_os("NIX_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nix/var/nix"));
        let database_path = state_dir.join("db/db.sqlite");
        let database =
            Connection::open_with_flags(database_path, OpenFlags::new().with_read_only())
                .map_err(|error| format!("opening the Nix store database: {error}"))?;
        database
            .execute("BEGIN")
            .map_err(|error| format!("starting the Nix store database snapshot: {error}"))?;
        Ok(Self { database })
    }

    pub(super) fn closure_paths(&self, installables: &[String]) -> Result<Vec<PathInfo>, String> {
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
            pending.extend(info.references.iter().cloned());
            paths.insert(path, info);
        }
        if paths.is_empty() {
            Err("no store paths were requested".into())
        } else {
            Ok(paths.into_values().collect())
        }
    }

    fn path_info(&self, path: &str) -> Result<PathInfo, String> {
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
            return Err(format!("store path is not valid: {path}"));
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
        Ok(PathInfo {
            path: path.to_owned(),
            ca,
            deriver,
            nar_hash: sri_sha256_from_base16(&hash)?,
            nar_size,
            references,
            signatures,
        })
    }

    fn references(&self, id: i64) -> Result<Vec<String>, String> {
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

pub(super) fn closure_paths(installables: &[String]) -> Result<Vec<PathInfo>, String> {
    LocalStore::open()?.closure_paths(installables)
}

fn concrete_store_path(value: &str) -> Result<String, String> {
    let relative = value
        .strip_prefix("/nix/store/")
        .filter(|relative| !relative.is_empty() && !relative.contains('/'))
        .ok_or_else(|| format!("native push requires a concrete store path: {value}"))?;
    if relative.split_once('-').is_none() {
        return Err(format!("invalid concrete store path: {value}"));
    }
    Ok(format!("/nix/store/{relative}"))
}

fn sri_sha256_from_base16(value: &str) -> Result<String, String> {
    let value = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("unsupported Nix path hash: {value}"))?;
    if value.len() != 64 {
        return Err(format!("invalid Nix SHA-256 length: {}", value.len()));
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid Nix base16 SHA-256".to_owned())?;
    }
    Ok(format!("sha256-{}", BASE64.encode(&digest)))
}

#[cfg(test)]
mod tests {
    use super::sri_sha256_from_base16;

    #[test]
    fn converts_nix_store_hash_to_sri() {
        assert_eq!(
            sri_sha256_from_base16(
                "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
            .expect("valid base16 SHA-256"),
            "sha256-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        );
    }
}
