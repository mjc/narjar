//! Download and verify upstream NARs before returning their metadata to clients.

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
        inventory::{Inventory, InventoryClass, VerificationMode},
        narinfo::{
            MAX_NARINFO_BYTES, SignatureVerifiedExternalNarInfo, TrustedPublicKeys,
            ValidatedNarInfo, read_narinfo_file,
        },
        object::{CompressionCodec, EncodedIdentity, NarRepresentation, WireEncoding},
        storage::{
            AdvertisedNarInfo, AdvertisementEvidence, NarUploadPolicy, Storage, StorageError,
            StoreHash, UpstreamNarSource,
        },
    },
    http_client::idle_agent,
    http_url::HttpUrl,
};

use state::{Flight, Join, Key, State};

const MAX_NEGATIVE_TTL: Duration = Duration::from_secs(60);
const MAX_UPSTREAM_REDIRECTS: usize = 5;

#[derive(Clone, Copy)]
enum EdgeOutputPlan {
    Raw,
    RetainUpstream(EncodedIdentity),
    Generate(CompressionCodec),
}

impl EdgeOutputPlan {
    const fn encoding(self) -> WireEncoding {
        match self {
            Self::Raw => WireEncoding::Raw,
            Self::RetainUpstream(encoded) => WireEncoding::Compressed(encoded.codec()),
            Self::Generate(codec) => WireEncoding::Compressed(codec),
        }
    }

    const fn retained_encoding(self) -> Option<EncodedIdentity> {
        match self {
            Self::RetainUpstream(encoded) => Some(encoded),
            Self::Raw | Self::Generate(_) => None,
        }
    }
}

fn compressed_edge_output(codec: CompressionCodec, payload: NarRepresentation) -> EdgeOutputPlan {
    match payload {
        NarRepresentation::Compressed(compressed) if compressed.encoded().codec() == codec => {
            EdgeOutputPlan::RetainUpstream(compressed.encoded())
        }
        NarRepresentation::Raw(_) | NarRepresentation::Compressed(_) => {
            EdgeOutputPlan::Generate(codec)
        }
    }
}

struct ResolvedUpstreamNarInfo {
    publication: ValidatedNarInfo,
    download_url: HttpUrl,
}

impl ResolvedUpstreamNarInfo {
    fn new(verified: SignatureVerifiedExternalNarInfo, download_url: HttpUrl) -> Self {
        Self {
            publication: verified.into_publication(),
            download_url,
        }
    }

    const fn payload(&self) -> NarRepresentation {
        self.publication.payload()
    }

    fn download_url(&self) -> &HttpUrl {
        &self.download_url
    }

    fn into_publication(self) -> ValidatedNarInfo {
        self.publication
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EdgeSettings {
    pub(crate) upstream: HttpUrl,
    pub(crate) egress_compression: WireEncoding,
    pub(crate) lease_seconds: NonZeroU64,
    pub(crate) max_fills: NonZeroUsize,
    pub(crate) request_workers: NonZeroUsize,
    pub(crate) max_in_flight: NonZeroUsize,
    pub(crate) timeout: Duration,
    pub(crate) fill_timeout: Duration,
    pub(crate) negative_ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EdgeHit {
    Local,
    Filled,
    Coalesced,
}

impl EdgeHit {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Local => "hit",
            Self::Filled => "fill",
            Self::Coalesced => "coalesced",
        }
    }

    const fn reported_for_follower(self) -> Self {
        match self {
            Self::Local => Self::Local,
            Self::Filled | Self::Coalesced => Self::Coalesced,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EdgeMiss {
    Failed(EdgeFailure),
    Cached(EdgeFailure),
}

impl EdgeMiss {
    pub(crate) const fn reason(self) -> EdgeFailure {
        match self {
            Self::Failed(reason) | Self::Cached(reason) => reason,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Failed(_) => "error",
            Self::Cached(_) => "negative",
        }
    }
}

impl From<EdgeFailure> for EdgeMiss {
    fn from(reason: EdgeFailure) -> Self {
        Self::Failed(reason)
    }
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
    pub(crate) const fn label(self) -> &'static str {
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
    egress_compression: WireEncoding,
    keys: Arc<TrustedPublicKeys>,
    policy: NarUploadPolicy,
    agent: Agent,
    timeout: Duration,
    fill_timeout: Duration,
    negative_ttl: Duration,
    max_fills: usize,
    active: AtomicUsize,
    blocked_requests: AtomicUsize,
    max_blocked_requests: usize,
    state: Mutex<State>,
    counters: Counters,
}

impl ReadThroughSource {
    pub(crate) fn advertise<'storage>(
        &self,
        storage: &'storage Storage,
        store: &StoreHash,
    ) -> Result<(AdvertisedNarInfo<'storage>, EdgeHit), EdgeMiss> {
        let hit = self.ensure_local(storage, store)?;
        self.open_advertisement_after_lease_renewal(storage, store)
            .inspect_err(|failure| increment(&self.counters.failures[*failure]))
            .map(|advertisement| (advertisement, hit))
            .map_err(EdgeMiss::Failed)
    }

    fn open_advertisement_after_lease_renewal<'storage>(
        &self,
        storage: &'storage Storage,
        store: &StoreHash,
    ) -> Result<AdvertisedNarInfo<'storage>, EdgeFailure> {
        storage
            .read_advertised_narinfo(store)
            .map_err(EdgeFailure::ingestion)?
            .ok_or(EdgeFailure::Storage)
    }

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
        if settings.timeout.is_zero()
            || settings.fill_timeout.is_zero()
            || Instant::now().checked_add(settings.timeout).is_none()
            || Instant::now().checked_add(settings.fill_timeout).is_none()
            || settings.request_workers.get() < 2
            || settings.max_in_flight.get() < 2
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "edge requires bounded timeouts, two HTTP workers and two connection admissions",
            ));
        }
        Ok(Self {
            upstream: settings.upstream,
            egress_compression: settings.egress_compression,
            keys,
            policy,
            agent: idle_agent(settings.timeout),
            timeout: settings.timeout,
            fill_timeout: settings.fill_timeout,
            negative_ttl: settings.negative_ttl.min(MAX_NEGATIVE_TTL),
            max_fills: settings.max_fills.get(),
            active: AtomicUsize::new(0),
            blocked_requests: AtomicUsize::new(0),
            max_blocked_requests: settings
                .request_workers
                .get()
                .min(settings.max_in_flight.get())
                - 1,
            state: Mutex::new(State::new(settings.max_fills.get())),
            counters: Counters::default(),
        })
    }

    /// Make the NAR and metadata available locally. HTTP then renews retention and reads the metadata.
    fn ensure_local(&self, storage: &Storage, store: &StoreHash) -> Result<EdgeHit, EdgeMiss> {
        self.lookup(storage, store)
            .inspect_err(|miss| increment(&self.counters.failures[miss.reason()]))
    }

    pub(crate) fn repair_recovery_blockers(&self, storage: &Storage) -> Result<(), EdgeFailure> {
        let inventory =
            Inventory::scan_storage(storage, &self.keys, VerificationMode::Availability)
                .map_err(|_| EdgeFailure::Storage)?;
        inventory
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.class(),
                    InventoryClass::MissingNar | InventoryClass::HashOrSizeMismatch
                )
            })
            .try_for_each(|entry| {
                let store =
                    StoreHash::parse(entry.identifier()).map_err(|_| EdgeFailure::Invalid)?;
                self.repair_local(storage, &store, Deadline::new(self.fill_timeout)?)
            })
    }

    fn lookup(&self, storage: &Storage, store: &StoreHash) -> Result<EdgeHit, EdgeMiss> {
        match self.local_lookup(storage, store)? {
            LocalLookup::Ready => {
                increment(&self.counters.local_hits);
                return Ok(EdgeHit::Local);
            }
            LocalLookup::Repair | LocalLookup::Missing => {}
        }
        // Count requests downloading and waiting for downloads. Leave a worker and
        // connection free for cached responses and health checks if upstream stalls.
        let _request = reserve_activity_slot(&self.blocked_requests, self.max_blocked_requests)?;
        let deadline = Deadline::new(self.fill_timeout)?;
        self.coalesce(Key::Store(*store), deadline, || {
            // Another request may have stored the object since our first lookup.
            match self.local_lookup(storage, store)? {
                LocalLookup::Ready => Ok(EdgeHit::Local),
                LocalLookup::Repair => {
                    let _active = self.admit()?;
                    self.repair_local(storage, store, deadline)?;
                    Ok(EdgeHit::Local)
                }
                LocalLookup::Missing => {
                    let _active = self.admit()?;
                    increment(&self.counters.started);
                    self.fill(storage, store, deadline)?;
                    increment(&self.counters.completed);
                    Ok(EdgeHit::Filled)
                }
            }
        })
    }

    fn local_lookup(
        &self,
        storage: &Storage,
        store: &StoreHash,
    ) -> Result<LocalLookup, EdgeFailure> {
        let Some(file) = storage
            .open_narinfo(store)
            .map_err(|_| EdgeFailure::Storage)?
        else {
            return Ok(LocalLookup::Missing);
        };
        let bytes = read_narinfo_file(file).map_err(|_| EdgeFailure::Storage)?;
        let metadata = self
            .keys
            .validate(store, bytes)
            .map_err(|_| EdgeFailure::Invalid)?;
        if !storage
            .read_through_payloads_are_usable(metadata.payload())
            .map_err(EdgeFailure::ingestion)?
        {
            return Ok(LocalLookup::Repair);
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
            .validate(store, bytes.clone())
            .map_err(|_| EdgeFailure::Invalid)?;
        let output = metadata.payload();
        let output_encoding = output.wire_encoding();
        let mut source = storage
            .read_through_source(*store)
            .map_err(EdgeFailure::ingestion)?;
        match storage.bind_read_through_narinfo(metadata, output_encoding, self.policy) {
            Ok(bound) => {
                bound
                    .publish_read_through(source)
                    .map_err(EdgeFailure::ingestion)?;
            }
            Err(StorageError::MissingNar | StorageError::NarMismatch) => {
                let upstream_source = self.source_for_repair(store, output, source, deadline)?;
                self.restore_missing_local_payload(storage, output, &upstream_source, deadline)?;
                source = Some(upstream_source);
                let metadata = self
                    .keys
                    .validate(store, bytes)
                    .map_err(|_| EdgeFailure::Invalid)?;
                storage
                    .bind_read_through_narinfo(metadata, output_encoding, self.policy)
                    .map_err(EdgeFailure::ingestion)?
                    .publish_read_through(source)
                    .map_err(EdgeFailure::ingestion)?;
            }
            Err(error) => return Err(EdgeFailure::ingestion(error)),
        }
        deadline.remaining()?;
        Ok(())
    }

    fn source_for_repair(
        &self,
        store: &StoreHash,
        output: NarRepresentation,
        recorded: Option<UpstreamNarSource>,
        deadline: Deadline,
    ) -> Result<UpstreamNarSource, EdgeFailure> {
        match recorded {
            Some(source) if source.payload().identity() == output.identity() => Ok(source),
            Some(_) => Err(EdgeFailure::Invalid),
            None => {
                let metadata = self.metadata(store, deadline)?;
                if metadata.payload().identity() != output.identity() {
                    return Err(EdgeFailure::Invalid);
                }
                UpstreamNarSource::new(metadata.payload(), metadata.download_url().as_str())
                    .map_err(EdgeFailure::ingestion)
            }
        }
    }

    fn restore_missing_local_payload(
        &self,
        storage: &Storage,
        published_output: NarRepresentation,
        source: &UpstreamNarSource,
        deadline: Deadline,
    ) -> Result<(), EdgeFailure> {
        let source_payload = source.payload();
        let output_plan = match (source_payload, published_output) {
            (NarRepresentation::Compressed(source), NarRepresentation::Compressed(output))
                if source.encoded() == output.encoded() =>
            {
                EdgeOutputPlan::RetainUpstream(output.encoded())
            }
            (NarRepresentation::Raw(_) | NarRepresentation::Compressed(_), _) => {
                EdgeOutputPlan::Raw
            }
        };
        let download_url = self
            .upstream
            .resolve_trusted_cache_resource(source.url())
            .map_err(|_| EdgeFailure::Invalid)?;
        self.receive_encoded_representation(
            storage,
            source_payload,
            output_plan,
            &download_url,
            deadline,
        )
    }

    fn fill(
        &self,
        storage: &Storage,
        store: &StoreHash,
        deadline: Deadline,
    ) -> Result<(), EdgeMiss> {
        let metadata = self.metadata(store, deadline)?;
        let payload = metadata.payload();
        let source = UpstreamNarSource::new(payload, metadata.download_url().as_str())
            .map_err(EdgeFailure::ingestion)?;
        let output_plan = self.output_plan(payload);
        self.policy
            .ensure_decoded_size_within_limit(payload.identity().size())
            .map_err(EdgeFailure::ingestion)?;
        self.coalesce(Key::Nar(payload.identity()), deadline, || {
            match storage.ensure_canonical_nar_available(payload.identity()) {
                Ok(()) => Ok(EdgeHit::Local),
                Err(StorageError::MissingNar) => self
                    .receive_missing_canonical_nar(
                        storage,
                        payload,
                        output_plan,
                        metadata.download_url(),
                        deadline,
                    )
                    .map(|()| EdgeHit::Filled),
                Err(error) => Err(EdgeMiss::Failed(EdgeFailure::ingestion(error))),
            }
        })?;
        self.ensure_retained_upstream_output(
            storage,
            payload,
            output_plan,
            metadata.download_url(),
            deadline,
        )?;
        deadline.remaining()?;
        // Check the signed NarHash and NarSize against the stored uncompressed NAR,
        // even if another request downloaded it with a different compression format.
        let bound = storage
            .bind_read_through_narinfo(
                metadata.into_publication(),
                output_plan.encoding(),
                self.policy,
            )
            .map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        // Store and sync the metadata, then its retention record, before returning success.
        bound
            .publish_read_through(Some(source))
            .map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        Ok(())
    }

    fn ensure_retained_upstream_output(
        &self,
        storage: &Storage,
        payload: NarRepresentation,
        output_plan: EdgeOutputPlan,
        download_url: &HttpUrl,
        deadline: Deadline,
    ) -> Result<(), EdgeMiss> {
        match output_plan {
            EdgeOutputPlan::RetainUpstream(encoded) => self
                .coalesce(
                    Key::Representation(payload.identity(), encoded),
                    deadline,
                    || match storage
                        .retained_egress_candidate_is_usable(payload.identity(), encoded)
                    {
                        Ok(true) => Ok(EdgeHit::Local),
                        Ok(false) => self.receive_and_confirm_canonical_nar(
                            storage,
                            payload,
                            output_plan,
                            download_url,
                            deadline,
                        ),
                        Err(error) => Err(EdgeMiss::Failed(EdgeFailure::ingestion(error))),
                    },
                )
                .map(|_| ()),
            EdgeOutputPlan::Raw | EdgeOutputPlan::Generate(_) => Ok(()),
        }
    }

    fn receive_missing_canonical_nar(
        &self,
        storage: &Storage,
        payload: NarRepresentation,
        output_plan: EdgeOutputPlan,
        download_url: &HttpUrl,
        deadline: Deadline,
    ) -> Result<(), EdgeMiss> {
        let receive = || {
            self.receive_and_confirm_canonical_nar(
                storage,
                payload,
                output_plan,
                download_url,
                deadline,
            )
        };
        match payload {
            NarRepresentation::Raw(_) => {
                receive()?;
            }
            NarRepresentation::Compressed(compressed) => {
                self.coalesce(
                    Key::Representation(payload.identity(), compressed.encoded()),
                    deadline,
                    receive,
                )?;
            }
        }
        Ok(())
    }

    fn receive_and_confirm_canonical_nar(
        &self,
        storage: &Storage,
        payload: NarRepresentation,
        output_plan: EdgeOutputPlan,
        download_url: &HttpUrl,
        deadline: Deadline,
    ) -> Result<EdgeHit, EdgeMiss> {
        self.receive_encoded_representation(storage, payload, output_plan, download_url, deadline)
            .map_err(EdgeMiss::Failed)?;
        // Coalescing the stream never removes the signed identity check.
        storage
            .ensure_canonical_nar_available(payload.identity())
            .map_err(|error| match error {
                StorageError::MissingNar | StorageError::NarMismatch => {
                    EdgeMiss::Failed(EdgeFailure::Invalid)
                }
                error => EdgeMiss::Failed(EdgeFailure::ingestion(error)),
            })?;
        Ok(EdgeHit::Filled)
    }

    fn metadata(
        &self,
        store: &StoreHash,
        deadline: Deadline,
    ) -> Result<ResolvedUpstreamNarInfo, EdgeFailure> {
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
        let verified = self
            .keys
            .verify_external_narinfo_for_transfer(store, bytes)
            .map_err(|_| EdgeFailure::Invalid)?;
        let download_url = self
            .upstream
            .resolve_trusted_cache_resource(verified.download_url())
            .map_err(|_| EdgeFailure::Invalid)?;
        Ok(ResolvedUpstreamNarInfo::new(verified, download_url))
    }

    fn receive_encoded_representation(
        &self,
        storage: &Storage,
        payload: NarRepresentation,
        output_plan: EdgeOutputPlan,
        download_url: &HttpUrl,
        deadline: Deadline,
    ) -> Result<(), EdgeFailure> {
        let encoded_size = payload.encoded_size().get();
        let policy = self.policy.bounded_by_nar_size(payload.identity());
        policy
            .ensure_encoded_size_within_limit(encoded_size)
            .map_err(EdgeFailure::ingestion)?;
        let retention = output_plan.retained_encoding();
        let reservations = storage
            .reserve_read_through_staging(
                payload.identity(),
                encoded_size,
                policy.min_free_bytes(),
                retention,
            )
            .map_err(EdgeFailure::ingestion)?;
        let name = payload.file_name();
        let response = self.get(download_url, deadline)?;
        if response
            .body()
            .content_length()
            .is_some_and(|length| length != encoded_size)
        {
            return Err(EdgeFailure::Invalid);
        }
        let reader = DeadlineReader::new(response.into_body().into_reader(), deadline);
        storage
            .publish_read_through_nar(name, reader, encoded_size, policy, reservations)
            .map_err(EdgeFailure::ingestion)?;
        deadline.remaining()?;
        Ok(())
    }

    fn output_plan(&self, payload: NarRepresentation) -> EdgeOutputPlan {
        match self.egress_compression {
            WireEncoding::Raw => EdgeOutputPlan::Raw,
            WireEncoding::Compressed(codec) => compressed_edge_output(codec, payload),
        }
    }

    fn get(
        &self,
        url: &HttpUrl,
        deadline: Deadline,
    ) -> Result<ureq::http::Response<ureq::Body>, EdgeFailure> {
        let mut current_url = self
            .upstream
            .resolve_trusted_cache_resource(url.as_str())
            .map_err(|_| EdgeFailure::Invalid)?;
        for redirect_count in 0..=MAX_UPSTREAM_REDIRECTS {
            let response = self
                .agent
                .get(current_url.as_str())
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
                StatusCode::OK => return validate_upstream_response(response),
                StatusCode::NOT_FOUND => return Err(EdgeFailure::Authoritative404),
                StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT => {
                    if redirect_count == MAX_UPSTREAM_REDIRECTS {
                        return Err(EdgeFailure::Invalid);
                    }
                    let location = response
                        .headers()
                        .get("Location")
                        .and_then(|value| value.to_str().ok())
                        .ok_or(EdgeFailure::Invalid)?;
                    current_url = self
                        .upstream
                        .resolve_trusted_cache_redirect(&current_url, location)
                        .map_err(|_| EdgeFailure::Invalid)?;
                }
                status if status.is_redirection() => return Err(EdgeFailure::Invalid),
                _ => return Err(EdgeFailure::Transient),
            }
        }
        unreachable!("the bounded redirect attempts always return a response or error")
    }

    fn coalesce(
        &self,
        key: Key,
        deadline: Deadline,
        fill: impl FnOnce() -> Result<EdgeHit, EdgeMiss>,
    ) -> Result<EdgeHit, EdgeMiss> {
        let joined = self
            .state
            .lock()
            .map_err(|_| EdgeMiss::Failed(EdgeFailure::Storage))?
            .join(key, Instant::now())?;
        match joined {
            Join::Cached(failure) => {
                increment(&self.counters.negative_hits);
                Err(EdgeMiss::Cached(failure))
            }
            Join::Follower(flight) => {
                increment(&self.counters.followers);
                flight
                    .wait(Deadline::new(self.timeout)?.earlier(deadline), |result| {
                        finish_shared_fill_or_retry_representation(key, result, fill)
                    })
                    .map(EdgeHit::reported_for_follower)
            }
            Join::Leader(flight) => {
                let completion = Completion::new(&flight);
                let result = fill();
                if let Err(miss) = result {
                    self.state
                        .lock()
                        .map_err(|_| EdgeMiss::Failed(EdgeFailure::Storage))?
                        .remember(key, miss.reason(), Instant::now(), self.negative_ttl);
                }
                completion.finish(result);
                result
            }
        }
    }

    fn admit(&self) -> Result<ActiveSlot<'_>, EdgeFailure> {
        reserve_activity_slot(&self.active, self.max_fills)
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
        let _ = writeln!(
            output,
            "# TYPE narjar_edge_blocked_requests gauge\nnarjar_edge_blocked_requests {}",
            self.blocked_requests.load(Ordering::Relaxed)
        );
        if let Ok(state) = self.state.lock() {
            let _ = writeln!(
                output,
                "# TYPE narjar_edge_negative_entries gauge\nnarjar_edge_negative_entries {}",
                state.negative_entries()
            );
        }
    }
}

fn validate_upstream_response(
    response: ureq::http::Response<ureq::Body>,
) -> Result<ureq::http::Response<ureq::Body>, EdgeFailure> {
    if response
        .headers()
        .get("Content-Encoding")
        .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(EdgeFailure::Invalid);
    }
    Ok(response)
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn finish_shared_fill_or_retry_representation(
    key: Key,
    result: Result<EdgeHit, EdgeMiss>,
    retry: impl FnOnce() -> Result<EdgeHit, EdgeMiss>,
) -> Result<EdgeHit, EdgeMiss> {
    match key {
        Key::Store(_) | Key::Representation(_, _) => result,
        Key::Nar(_) => result.or_else(|miss| match miss {
            EdgeMiss::Failed(
                EdgeFailure::Authoritative404 | EdgeFailure::Transient | EdgeFailure::Invalid,
            )
            | EdgeMiss::Cached(_) => retry(),
            EdgeMiss::Failed(EdgeFailure::Capacity | EdgeFailure::Storage) => Err(miss),
        }),
    }
}

struct ActiveSlot<'a>(&'a AtomicUsize);

fn reserve_activity_slot(
    counter: &AtomicUsize,
    limit: usize,
) -> Result<ActiveSlot<'_>, EdgeFailure> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
            (active < limit).then(|| active + 1)
        })
        .map_err(|_| EdgeFailure::Capacity)?;
    Ok(ActiveSlot(counter))
}

impl Drop for ActiveSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// Wake waiting requests even if the downloading request panics before recording its result.
struct Completion<'a> {
    flight: &'a Flight,
    result: Result<EdgeHit, EdgeMiss>,
}

impl<'a> Completion<'a> {
    fn new(flight: &'a Flight) -> Self {
        Self {
            flight,
            result: Err(EdgeMiss::Failed(EdgeFailure::Storage)),
        }
    }

    fn finish(mut self, result: Result<EdgeHit, EdgeMiss>) {
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
    fn earlier(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

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
