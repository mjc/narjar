use std::{collections::BTreeMap, path::Path};

use super::{NarInfoMetadata, PushError};
use crate::native_store::metadata::NativeMetadataSnapshot;

pub(super) struct LocalStore {
    metadata: NativeMetadataSnapshot,
}

impl LocalStore {
    pub(super) fn open(state_dir: &Path) -> Result<Self, PushError> {
        let metadata = NativeMetadataSnapshot::open(state_dir)
            .map_err(|error| PushError::new(error.to_string()))?;
        Ok(Self { metadata })
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
            let info = self
                .metadata
                .validated_claims_for(&path)
                .map_err(|error| PushError::new(error.to_string()))?;
            pending.extend(info.claims().reference_paths().map(str::to_owned));
            paths.insert(path, info.into_narinfo_metadata());
        }
        if paths.is_empty() {
            Err("no store paths were requested".into())
        } else {
            Ok(paths.into_values().collect())
        }
    }
}

fn concrete_store_path(value: &str) -> Result<String, PushError> {
    let relative = value
        .strip_prefix("/nix/store/")
        .filter(|relative| !relative.is_empty() && !relative.contains('/'))
        .ok_or_else(|| format!("native push requires a concrete store path: {value}"))?;
    narjar::__private::storage::validate_store_basename(relative)
        .map_err(|_| PushError::new(format!("invalid concrete store path: {value}")))?;
    Ok(format!("/nix/store/{relative}"))
}
