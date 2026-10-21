use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};

use crate::cache::{
    object::{EncodedSize, NarFileName, NarHash},
    storage::StoreHash,
};

use super::{Deadline, EdgeFailure, EdgeMiss};

const MAX_TABLE_ENTRIES: usize = 4096;
const MAX_WAITERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Key {
    Store(StoreHash),
    Nar(NarHash),
    Representation(NarFileName, EncodedSize),
}

pub(super) enum Join {
    Leader(Arc<Flight>),
    Follower(Arc<Flight>),
    Cached(EdgeFailure),
}

struct Negative {
    failure: EdgeFailure,
    expires: Instant,
}

pub(super) struct State {
    flights: HashMap<Key, Weak<Flight>>,
    negatives: HashMap<Key, Negative>,
    flight_limit: usize,
    negative_limit: usize,
}

impl State {
    pub(super) fn negative_entries(&self) -> usize {
        self.negatives.len()
    }

    pub(super) fn new(max_fills: usize) -> Self {
        Self {
            flights: HashMap::new(),
            negatives: HashMap::new(),
            flight_limit: max_fills.saturating_mul(4).clamp(64, MAX_TABLE_ENTRIES),
            negative_limit: max_fills.saturating_mul(32).clamp(64, MAX_TABLE_ENTRIES),
        }
    }

    pub(super) fn join(&mut self, key: Key, now: Instant) -> Result<Join, EdgeFailure> {
        // Join an existing request before checking cached failures: it may have just
        // recorded its failure but not yet notified everyone waiting for it.
        if let Some(flight) = self.flights.get(&key).and_then(Weak::upgrade) {
            return Ok(Join::Follower(flight));
        }
        if let Some(negative) = self.negatives.get(&key).filter(|entry| entry.expires > now) {
            return Ok(Join::Cached(negative.failure));
        }
        if self.flights.len() >= self.flight_limit {
            self.prune(now);
        }
        if self.flights.len() >= self.flight_limit {
            return Err(EdgeFailure::Capacity);
        }
        let flight = Arc::new(Flight::default());
        self.flights.insert(key, Arc::downgrade(&flight));
        Ok(Join::Leader(flight))
    }

    pub(super) fn remember(&mut self, key: Key, failure: EdgeFailure, now: Instant, ttl: Duration) {
        match key {
            // A failed download of one encoding must not block trying another encoding.
            Key::Nar(_) => return,
            Key::Store(_) | Key::Representation(_, _) => {}
        }
        if !failure.cacheable() || ttl.is_zero() {
            return;
        }
        self.negatives.retain(|_, entry| entry.expires > now);
        if self.negatives.len() >= self.negative_limit {
            let oldest = self
                .negatives
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.negatives.remove(&oldest);
            }
        }
        if let Some(expires) = now.checked_add(ttl) {
            self.negatives.insert(key, Negative { failure, expires });
        }
    }

    pub(super) fn prune(&mut self, now: Instant) {
        self.flights.retain(|_, flight| flight.strong_count() > 0);
        self.negatives.retain(|_, entry| entry.expires > now);
    }
}

enum Progress {
    Running { waiters: usize },
    Complete(Result<(), EdgeMiss>),
}

impl Default for Progress {
    fn default() -> Self {
        Self::Running { waiters: 0 }
    }
}

#[derive(Default)]
pub(super) struct Flight {
    progress: Mutex<Progress>,
    completed: Condvar,
}

impl Flight {
    pub(super) fn wait(
        &self,
        deadline: Deadline,
        completed: impl FnOnce(Result<(), EdgeMiss>) -> Result<(), EdgeMiss>,
    ) -> Result<(), EdgeMiss> {
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| EdgeMiss::Failed(EdgeFailure::Storage))?;
        let remaining = deadline.remaining().map_err(EdgeMiss::Failed)?;
        match &mut *progress {
            Progress::Complete(result) => {
                deadline.remaining().map_err(EdgeMiss::Failed)?;
                let result = *result;
                drop(progress);
                return completed(result);
            }
            Progress::Running { waiters } if *waiters >= MAX_WAITERS => {
                return Err(EdgeMiss::Failed(EdgeFailure::Capacity));
            }
            Progress::Running { waiters } => *waiters += 1,
        }
        let (mut progress, _) = self
            .completed
            .wait_timeout_while(progress, remaining, |progress| match progress {
                Progress::Running { .. } => true,
                Progress::Complete(_) => false,
            })
            .map_err(|_| EdgeMiss::Failed(EdgeFailure::Storage))?;
        match &mut *progress {
            Progress::Complete(result) => {
                deadline.remaining().map_err(EdgeMiss::Failed)?;
                let result = *result;
                drop(progress);
                completed(result)
            }
            Progress::Running { waiters } => {
                *waiters -= 1;
                Err(EdgeMiss::Failed(EdgeFailure::Transient))
            }
        }
    }

    pub(super) fn finish(&self, result: Result<(), EdgeMiss>) {
        if let Ok(mut progress) = self.progress.lock() {
            *progress = Progress::Complete(result);
            self.completed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u64) -> Key {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&index.to_le_bytes());
        Key::Representation(NarFileName::raw(NarHash::from_digest(bytes)), 0.into())
    }

    #[test]
    fn negative_cache_bounds_classes_and_expiry() {
        let mut state = State::new(1);
        let now = Instant::now();
        let ttl = Duration::from_secs(1);
        for index in 0..1000 {
            let failure = [
                EdgeFailure::Authoritative404,
                EdgeFailure::Transient,
                EdgeFailure::Invalid,
            ][index as usize % 3];
            state.remember(key(index), failure, now, ttl);
            assert!(state.negatives.len() <= state.negative_limit);
        }
        state.remember(key(1001), EdgeFailure::Capacity, now, ttl);
        state.remember(key(1002), EdgeFailure::Storage, now, ttl);
        assert!(!state.negatives.contains_key(&key(1001)));
        assert!(!state.negatives.contains_key(&key(1002)));
        state.prune(now + ttl);
        assert!(state.negatives.is_empty());
    }

    #[test]
    fn weak_flights_remain_bounded_and_reclaim_dead_generations() {
        let mut state = State::new(1);
        let now = Instant::now();
        let held = (0..state.flight_limit as u64)
            .map(|index| match state.join(key(index), now).unwrap() {
                Join::Leader(flight) => flight,
                _ => panic!("new key must lead"),
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            state.join(key(1000), now),
            Err(EdgeFailure::Capacity)
        ));
        assert!(matches!(state.join(key(0), now), Ok(Join::Follower(_))));
        drop(held);
        assert!(matches!(state.join(key(1000), now), Ok(Join::Leader(_))));
        assert!(state.flights.len() <= state.flight_limit);
        state.prune(now);
        assert!(state.flights.is_empty());
    }

    #[test]
    fn followers_share_a_failed_generation_even_without_negative_caching() {
        let flight = Flight::default();
        flight.finish(Err(EdgeMiss::Failed(EdgeFailure::Invalid)));
        assert_eq!(
            flight.wait(
                Deadline::new(Duration::from_secs(1)).unwrap(),
                std::convert::identity
            ),
            Err(EdgeMiss::Failed(EdgeFailure::Invalid))
        );
    }

    #[test]
    fn expired_follower_releases_its_waiter_slot_without_canceling_the_fill() {
        let flight = Flight::default();
        let expired = Deadline(Instant::now() - Duration::from_secs(1));
        assert_eq!(
            flight.wait(expired, |_| panic!(
                "an expired wait must not retry a running fill"
            )),
            Err(EdgeMiss::Failed(EdgeFailure::Transient))
        );
        assert!(matches!(
            *flight.progress.lock().unwrap(),
            Progress::Running { waiters: 0 }
        ));
        flight.finish(Ok(()));
        assert_eq!(
            flight.wait(
                Deadline::new(Duration::from_secs(1)).unwrap(),
                std::convert::identity
            ),
            Ok(())
        );
    }

    #[test]
    fn a_representation_failure_never_negative_caches_the_logical_nar() {
        let mut state = State::new(1);
        let key = Key::Nar(NarHash::from_digest([42; 32]));
        state.remember(
            key,
            EdgeFailure::Invalid,
            Instant::now(),
            Duration::from_secs(60),
        );
        assert_eq!(state.negative_entries(), 0);
        assert!(matches!(
            state.join(key, Instant::now()).unwrap(),
            Join::Leader(_)
        ));
    }

    #[test]
    fn follower_queue_is_bounded_for_a_running_key() {
        let flight = Flight::default();
        *flight.progress.lock().unwrap() = Progress::Running {
            waiters: MAX_WAITERS,
        };
        assert_eq!(
            flight.wait(
                Deadline::new(Duration::from_secs(1)).unwrap(),
                std::convert::identity
            ),
            Err(EdgeMiss::Failed(EdgeFailure::Capacity))
        );
    }
}
