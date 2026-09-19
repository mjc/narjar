use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use narjar::narinfo::NarInfoMetadata;
use narjar::storage::StoreHash;

pub(super) fn dependency_waves(
    metadata: Vec<NarInfoMetadata>,
) -> Result<Vec<Vec<NarInfoMetadata>>, Error> {
    let mut by_path = BTreeMap::new();
    for info in metadata {
        if by_path.insert(*info.claims().store(), info).is_some() {
            return Err(Error::runtime(
                "local store metadata returned a duplicate store path",
            ));
        }
    }

    let mut indegree = by_path
        .keys()
        .map(|path| (*path, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents = BTreeMap::<StoreHash, Vec<StoreHash>>::new();
    for info in by_path.values() {
        let store = info.claims().store();
        for (reference, reference_path) in info.claims().reference_store_paths() {
            if reference == store {
                continue;
            }
            if !by_path.contains_key(reference) {
                return Err(Error::runtime(format!(
                    "{} has missing referenced store path {}",
                    info.claims().store_path(),
                    reference_path,
                )));
            }
            *indegree.get_mut(store).expect("every path has an indegree") += 1;
            dependents.entry(*reference).or_default().push(*store);
        }
    }

    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(path, _)| *path)
        .collect::<BTreeSet<_>>();
    let waves = std::iter::from_fn(|| match ready.is_empty() {
        true => None,
        false => Some(take_ready_dependency_wave(
            &mut ready,
            &mut by_path,
            &mut indegree,
            &dependents,
        )),
    })
    .collect::<Result<Vec<_>, _>>()?;

    if !by_path.is_empty() {
        return Err(Error::runtime(
            "local store metadata returned cyclic store references",
        ));
    }
    Ok(waves)
}

fn take_ready_dependency_wave(
    ready: &mut BTreeSet<StoreHash>,
    metadata: &mut BTreeMap<StoreHash, NarInfoMetadata>,
    indegree: &mut BTreeMap<StoreHash, usize>,
    dependents: &BTreeMap<StoreHash, Vec<StoreHash>>,
) -> Result<Vec<NarInfoMetadata>, Error> {
    let wave = std::mem::take(ready)
        .into_iter()
        .map(|store| {
            metadata
                .remove(&store)
                .ok_or_else(|| Error::runtime("dependency planner lost ready store metadata"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    wave.iter()
        .flat_map(|info| dependents.get(info.claims().store()).into_iter().flatten())
        .try_for_each(|dependent| {
            let degree = indegree
                .get_mut(dependent)
                .ok_or_else(|| Error::runtime("dependency planner lost a dependent store path"))?;
            *degree = degree.checked_sub(1).ok_or_else(|| {
                Error::runtime("dependency planner observed a duplicate dependency edge")
            })?;
            if *degree == 0 {
                ready.insert(*dependent);
            }
            Ok::<(), Error>(())
        })?;
    Ok(wave)
}
