//! Fill local storage before making upstream metadata available to readers.

#[path = "read_through/state.rs"]
mod state;

use std::{
    fmt::Write as _,
    io::{self, Read},
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use enum_map::{Enum, EnumMap};
use ureq::{Agent, http::StatusCode};

use crate::{
    cache::{
        narinfo::{MAX_NARINFO_BYTES, TrustedPublicKeys, ValidatedNarInfo, read_narinfo_file},
        object::NarRepresentation,
        storage::{AdvertisementEvidence, NarUploadPolicy, Storage, StorageError, StoreHash},
    },
    http_client::idle_agent,
    http_url::HttpUrl,
};

use state::{Flight, Join, Key, State};

const MAX_NEGATIVE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub(crate) struct EdgeSettings {
    pub(crate) upstream: HttpUrl,
    pub(crate) lease_seconds: NonZeroU64,
    pub(crate) max_fills: NonZeroUsize,
    pub(crate) timeout: Duration,
    pub(crate) negative_ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EdgeLookup {
    Ready,
    Miss(EdgeFailure),
}

enum LocalLookup {
    Ready,
    Repair,
    Missing,
}

#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(crate) enum EdgeFailure {
    Authoritative404,
    Transient,
    Invalid,
    Capacity,
    Storage,
}

impl EdgeFailure {
    const fn label(self) -> &'static str {
        match self {
            Self::Authoritative404 => "not_found",
            Self::Transient => "transient",
            Self::Invalid => "invalid",
            Self::Capacity => "capacity",
            Self::Storage => "storage",
        }
    }

    const fn cacheable(self) -> bool {
        match self {
            Self::Authoritative404 | Self::Transient | Self::Invalid => true,
            Self::Capacity | Self::Storage => false,
        }
    }

    fn ingestion(error: StorageError) -> Self {
        match error {
            StorageError::Conflict
            | StorageError::NarMismatch
            | StorageError::DecodedSizeLimitExceeded
            | StorageError::DecoderMemoryLimitExceeded
            | StorageError::UploadTooLarge => Self::Invalid,
            StorageError::InsufficientSpace | StorageError::InsufficientInodes => Self::Capacity,
            StorageError::Io(error) => match error.kind() {
                io::ErrorKind::InvalidData => Self::Invalid,
                io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset => Self::Transient,
                _ => Self::Storage,
            },
            StorageError::CollectionBusy
            | StorageError::CollectionChanged
            | StorageError::Locked
            | StorageError::MissingNar => Self::Storage,
        }
    }
}

#[derive(Default)]
struct Counters {
    local_hits: AtomicU64,
    started: AtomicU64,
    completed: AtomicU64,
    followers: AtomicU64,
    negative_hits: AtomicU64,
    failures: EnumMap<EdgeFailure, AtomicU64>,
}

pub(crate) struct ReadThroughSource {
    upstream: HttpUrl,
    keys: Arc<TrustedPublicKeys>,
    policy: NarUploadPolicy,
    agent: Agent,
    timeout: Duration,
    negative_ttl: Duration,
    max_fills: usize,
    active: AtomicUsize,
    state: Mutex<State>,
    counters: Counters,
}

impl ReadThroughSource {
    pub(crate) fn new(
        settings: EdgeSettings,
        keys: Arc<TrustedPublicKeys>,
        policy: NarUploadPolicy,
    ) -> Result<Self, io::Error> {
        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "edge requires trusted public keys",
            ));
        }
        if settings.timeout.is_zero() || Instant::now().checked_add(settings.timeout).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid edge fill timeout",
            ));
        }
        Ok(Self {
            upstream: settings.upstream,
            keys,
            policy,
            agent: idle_agent(settings.timeout),
            timeout: settings.timeout,
            negative_ttl: settings.negative_ttl.min(MAX_NEGATIVE_TTL),
            max_fills: settings.max_fills.get(),
            active: AtomicUsize::new(0),
            state: Mutex::new(State::new(settings.max_fills.get())),
            counters: Counters::default(),
        })
    }

    /// HTTP performs the advertised read and lease renewal after this succeeds.
    pub(crate) fn ensure_local(&self, storage: &Storage, store: &StoreHash) -> EdgeLookup {
        let result = self.lookup(storage, store);
        match result {
            Ok(()) => EdgeLookup::Ready,
            Err(failure) => {
                increment(&self.counters.failures[failure]);
                EdgeLookup::Miss(failure)
            }
        }
    }

    fn lookup(&self, storage: &Storage, store: &StoreHash) -> Result<(), EdgeFailure> {
        match Self::local_lookup(storage, store)? {
            LocalLookup::Ready => {
                increment(&self.counters.local_hits);
                return Ok(());
            }
            LocalLookup::Repair | LocalLookup::Missing => {}
        }
        let deadline = Deadline::new(self.timeout)?;
        self.coalesce(Key::Store(*store), deadline, || {
            // Another completed flight may have published between the first lookup and admission.
            match Self::local_lookup(storage, store)? {
                LocalLookup::Ready => Ok(()),
                LocalLookup::Repair => {
                    let _active = self.admit()?;
                    self.repair_local(storage, store, deadline)
                }
                LocalLookup::Missing => {
                    let _active = self.admit()?;
                    increment(&self.counters.started);
                    self.fill(storage, store, deadline)?;
                    increment(&self.counters.completed);
                    Ok(())
                }
            }
        })
    }

    fn local_lookup(storage: &Storage, store: &StoreHash) -> Result<LocalLookup, EdgeFailure> {
        if storage
            .open_narinfo(store)
            .map_err(|_| EdgeFailure::Storage)?
            .is_none()
        {
            return Ok(LocalLookup::Missing);
        }
        match storage
            .advertisement_evidence(*store)
            .map_err(|_| EdgeFailure::Storage)?
        {
            AdvertisementEvidence::Recorded => Ok(LocalLookup::Ready),
            AdvertisementEvidence::Missing => Ok(LocalLookup::Repair),
        }
    }

    fn repair_local(
        &self,
        storage: &Storage,
        store: &StoreHash,
        deadline: Deadline,
    ) -> Result<(), EdgeFailure> {
        let file = storage
            .open_narinfo(store)
            .map_err(|_| EdgeFailure::Storage)?
            .ok_or(EdgeFailure::Storage)?;
        let bytes = read_narinfo_file(file).map_err(|_| EdgeFailure::Invalid)?;
        let metadata = self
            .keys
            .validate(store, bytes)
            .map_err(|_| EdgeFailure::Invalid)?;
        let bound = storage
            .bind_canonical_narinfo(metadata)
            .map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        bound.publish().map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        Ok(())
    }

    fn fill(
        &self,
        storage: &Storage,
        store: &StoreHash,
        deadline: Deadline,
    ) -> Result<(), EdgeFailure> {
        let metadata = self.metadata(store, deadline)?;
        let payload = metadata.payload();
        self.policy
            .ensure_representation_within_limits(payload)
            .map_err(EdgeFailure::ingestion)?;
        self.coalesce(
            Key::Nar(payload.identity().hash()),
            deadline,
            || match storage.ensure_canonical_nar_available(payload.identity()) {
                Ok(()) => Ok(()),
                Err(StorageError::MissingNar) => self.receive_payload(storage, payload, deadline),
                Err(error) => Err(EdgeFailure::ingestion(error)),
            },
        )?;
        deadline.remaining()?;
        // Binding proves the signed logical identity against canonical bytes, including aliases
        // whose upstream transport encoding differs from the first fill's encoding.
        let bound = storage
            .bind_canonical_narinfo(metadata)
            .map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        // Storage publishes metadata and its durable advertisement lease in this order.
        bound.publish().map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        Ok(())
    }

    fn metadata(
        &self,
        store: &StoreHash,
        deadline: Deadline,
    ) -> Result<ValidatedNarInfo, EdgeFailure> {
        let url = self
            .upstream
            .endpoint(&[&format!("{}.narinfo", store.as_str())]);
        let response = self.get(&url, deadline)?;
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > MAX_NARINFO_BYTES)
        {
            return Err(EdgeFailure::Invalid);
        }
        let mut reader = DeadlineReader::new(response.into_body().into_reader(), deadline);
        let mut bytes = Vec::new();
        (&mut reader)
            .take(MAX_NARINFO_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| EdgeFailure::Transient)?;
        if bytes.len() as u64 > MAX_NARINFO_BYTES {
            return Err(EdgeFailure::Invalid);
        }
        self.keys
            .validate(store, bytes)
            .map_err(|_| EdgeFailure::Invalid)
    }

    fn receive_payload(
        &self,
        storage: &Storage,
        payload: NarRepresentation,
        deadline: Deadline,
    ) -> Result<(), EdgeFailure> {
        let encoded_size = payload.encoded_size().get();
        let reservation = storage
            .reserve_staging(encoded_size, self.policy.min_free_bytes())
            .map_err(EdgeFailure::ingestion)?;
        let name = payload.file_name();
        let url = self.upstream.endpoint(&["nar", &name.to_string()]);
        let response = self.get(&url, deadline)?;
        if response
            .body()
            .content_length()
            .is_some_and(|length| length != encoded_size)
        {
            return Err(EdgeFailure::Invalid);
        }
        let reader = DeadlineReader::new(response.into_body().into_reader(), deadline);
        storage
            .publish_nar_with_staging(name, reader, encoded_size, self.policy, reservation)
            .map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        // Ingestion checks the transport hash and computes the decoded identity. A compressed
        // stream must also agree with the signed identity before its flight can succeed.
        storage
            .ensure_canonical_nar_available(payload.identity())
            .map_err(|error| match error {
                StorageError::MissingNar | StorageError::NarMismatch => EdgeFailure::Invalid,
                error => EdgeFailure::ingestion(error),
            })?;
        Ok(())
    }

    fn get(
        &self,
        url: &HttpUrl,
        deadline: Deadline,
    ) -> Result<ureq::http::Response<ureq::Body>, EdgeFailure> {
        let response = self
            .agent
            .get(url.as_str())
            .header("Accept-Encoding", "identity")
            .config()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(deadline.remaining()?))
            .build()
            .call()
            .map_err(|_| EdgeFailure::Transient)?;
        deadline.remaining()?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(EdgeFailure::Authoritative404),
            status if status.is_redirection() => return Err(EdgeFailure::Invalid),
            _ => return Err(EdgeFailure::Transient),
        }
        if response
            .headers()
            .get("Content-Encoding")
            .is_some_and(|value| value != "identity")
        {
            return Err(EdgeFailure::Invalid);
        }
        Ok(response)
    }

    fn coalesce(
        &self,
        key: Key,
        deadline: Deadline,
        fill: impl FnOnce() -> Result<(), EdgeFailure>,
    ) -> Result<(), EdgeFailure> {
        let joined = self
            .state
            .lock()
            .map_err(|_| EdgeFailure::Storage)?
            .join(key, Instant::now())?;
        match joined {
            Join::Cached(failure) => {
                increment(&self.counters.negative_hits);
                Err(failure)
            }
            Join::Follower(flight) => {
                increment(&self.counters.followers);
                flight.wait(deadline)
            }
            Join::Leader(flight) => {
                let completion = Completion::new(&flight);
                let result = fill();
                if let Err(failure) = result {
                    self.state
                        .lock()
                        .map_err(|_| EdgeFailure::Storage)?
                        .remember(key, failure, Instant::now(), self.negative_ttl);
                }
                completion.finish(result);
                result
            }
        }
    }

    fn admit(&self) -> Result<ActiveFill<'_>, EdgeFailure> {
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < self.max_fills).then(|| active + 1)
            })
            .map_err(|_| EdgeFailure::Capacity)?;
        Ok(ActiveFill(&self.active))
    }

    pub(crate) fn maintain(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.prune(Instant::now());
        }
    }

    pub(crate) fn append_metrics(&self, output: &mut String) {
        for (name, counter) in [
            ("local_hits", &self.counters.local_hits),
            ("fills_started", &self.counters.started),
            ("fills_completed", &self.counters.completed),
            ("followers", &self.counters.followers),
            ("negative_hits", &self.counters.negative_hits),
        ] {
            let _ = writeln!(
                output,
                "# TYPE narjar_edge_{name}_total counter\nnarjar_edge_{name}_total {}",
                counter.load(Ordering::Relaxed)
            );
        }
        output.push_str("# TYPE narjar_edge_failures_total counter\n");
        for (failure, counter) in &self.counters.failures {
            let _ = writeln!(
                output,
                "narjar_edge_failures_total{{reason=\"{}\"}} {}",
                failure.label(),
                counter.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            output,
            "# TYPE narjar_edge_active_fills gauge\nnarjar_edge_active_fills {}",
            self.active.load(Ordering::Relaxed)
        );
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

struct ActiveFill<'a>(&'a AtomicUsize);

impl Drop for ActiveFill<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// Wake followers even when the leader unwinds before recording its result.
struct Completion<'a> {
    flight: &'a Flight,
    result: Result<(), EdgeFailure>,
}

impl<'a> Completion<'a> {
    fn new(flight: &'a Flight) -> Self {
        Self {
            flight,
            result: Err(EdgeFailure::Storage),
        }
    }

    fn finish(mut self, result: Result<(), EdgeFailure>) {
        self.result = result;
    }
}

impl Drop for Completion<'_> {
    fn drop(&mut self) {
        self.flight.finish(self.result);
    }
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn new(timeout: Duration) -> Result<Self, EdgeFailure> {
        Instant::now()
            .checked_add(timeout)
            .map(Self)
            .ok_or(EdgeFailure::Transient)
    }

    fn remaining(self) -> Result<Duration, EdgeFailure> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(EdgeFailure::Transient)
    }
}

struct DeadlineReader<R> {
    inner: R,
    deadline: Deadline,
}

impl<R> DeadlineReader<R> {
    fn new(inner: R, deadline: Deadline) -> Self {
        Self { inner, deadline }
    }
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let check = || {
            self.deadline
                .remaining()
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        };
        check()?;
        let amount = self
            .inner
            .read(buffer)
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
        check()?;
        Ok(amount)
    }
}

#[cfg(test)]
#[path = "read_through/tests.rs"]
mod tests;
