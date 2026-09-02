use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    bytes: u64,
    modified: SystemTime,
    protected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Policy {
    target_bytes: u64,
    min_age: Duration,
}

fn select_candidates(
    entries: &[Candidate],
    current_bytes: u64,
    policy: Policy,
    now: SystemTime,
) -> Vec<usize> {
    let mut eligible = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !entry.protected
                && now
                    .duration_since(entry.modified)
                    .unwrap_or_default()
                    >= policy.min_age
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    eligible.sort_unstable_by_key(|&index| (entries[index].modified, index));

    let mut remaining = current_bytes;
    let mut selected = Vec::new();

    for index in eligible {
        if remaining <= policy.target_bytes {
            break;
        }

        remaining = remaining.saturating_sub(entries[index].bytes);
        selected.push(index);
    }

    selected
}


#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{Candidate, Policy, select_candidates};

    #[test]
    fn retention_selects_oldest_eligible_entries() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let entries = vec![
            Candidate {
                bytes: 70,
                modified: UNIX_EPOCH + Duration::from_secs(100),
                protected: false,
            },
            Candidate {
                bytes: 50,
                modified: UNIX_EPOCH + Duration::from_secs(200),
                protected: false,
            },
            Candidate {
                bytes: 30,
                modified: UNIX_EPOCH + Duration::from_secs(995),
                protected: false,
            },
            Candidate {
                bytes: 40,
                modified: UNIX_EPOCH + Duration::from_secs(10),
                protected: true,
            },
        ];

        assert_eq!(
            select_candidates(
                &entries,
                190,
                Policy {
                    target_bytes: 60,
                    min_age: Duration::from_secs(10),
                },
                now,
            ),
            vec![0, 1]
        );
    }
}
