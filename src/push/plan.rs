use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;

use super::PathInfo;

pub(super) fn dependency_waves(metadata: Vec<PathInfo>) -> Result<Vec<Vec<PathInfo>>, Error> {
    let mut by_path = BTreeMap::new();
    for info in metadata {
        if by_path.insert(info.path.clone(), info).is_some() {
            return Err(Error::runtime(
                "nix path-info returned a duplicate store path",
            ));
        }
    }

    let mut indegree = by_path
        .keys()
        .map(|path| (path.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents = BTreeMap::<String, Vec<String>>::new();
    for info in by_path.values() {
        let mut references = info.references.iter().collect::<Vec<_>>();
        references.sort_unstable();
        references.dedup();
        for reference in references {
            if reference == &info.path {
                continue;
            }
            if !by_path.contains_key(reference) {
                return Err(Error::runtime(format!(
                    "{} has missing referenced store path {}",
                    info.path, reference
                )));
            }
            *indegree
                .get_mut(&info.path)
                .expect("every path has an indegree") += 1;
            dependents
                .entry(reference.clone())
                .or_default()
                .push(info.path.clone());
        }
    }

    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    let mut waves = Vec::new();
    let mut emitted = 0;

    while !ready.is_empty() {
        let paths = ready.iter().cloned().collect::<Vec<_>>();
        ready.clear();
        let mut wave = Vec::with_capacity(paths.len());
        for path in paths {
            wave.push(
                by_path
                    .remove(&path)
                    .expect("ready path should have metadata"),
            );
            emitted += 1;
        }
        for info in &wave {
            if let Some(children) = dependents.get(&info.path) {
                for child in children {
                    let degree = indegree
                        .get_mut(child)
                        .expect("dependent path has an indegree");
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }
        waves.push(wave);
    }

    if emitted != indegree.len() {
        return Err(Error::runtime(
            "nix path-info returned cyclic store references",
        ));
    }
    Ok(waves)
}
