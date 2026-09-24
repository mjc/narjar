use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::http_server::{StatusCode, TransferFailure};
use serde::Deserialize;

use crate::{
    http_server::Method,
    maintenance,
    storage::{
        CapacityErrorKind, PopulationCounts, PublishOutcome, StorageActivitySnapshot,
        StorageBackend, StorageCapacity, StorageError, StorageReadiness,
    },
};

const METHODS: [RequestMethod; 4] = [
    RequestMethod::Get,
    RequestMethod::Head,
    RequestMethod::Put,
    RequestMethod::Other,
];
const ROUTES: [RequestRoute; 9] = [
    RequestRoute::Health,
    RequestRoute::Ready,
    RequestRoute::Metrics,
    RequestRoute::CacheInfo,
    RequestRoute::Nar,
    RequestRoute::NarInfo,
    RequestRoute::Invalid,
    RequestRoute::Missing,
    RequestRoute::Other,
];
const STATUS_CODES: [(&str, Option<u16>); 17] = [
    ("200", Some(200)),
    ("201", Some(201)),
    ("206", Some(206)),
    ("400", Some(400)),
    ("401", Some(401)),
    ("404", Some(404)),
    ("405", Some(405)),
    ("411", Some(411)),
    ("413", Some(413)),
    ("415", Some(415)),
    ("416", Some(416)),
    ("422", Some(422)),
    ("429", Some(429)),
    ("500", Some(500)),
    ("503", Some(503)),
    ("507", Some(507)),
    ("other", None),
];
const CONNECTION_OUTCOMES: [ConnectionOutcome; 6] = [
    ConnectionOutcome::Admitted,
    ConnectionOutcome::AdmissionRejected,
    ConnectionOutcome::RequestQueueFull,
    ConnectionOutcome::MalformedRequest,
    ConnectionOutcome::TimedOut,
    ConnectionOutcome::Disconnected,
];
const RESPONSE_TRANSFER_FAILURES: [ResponseTransferFailureKind; 3] = [
    ResponseTransferFailureKind::TimedOut,
    ResponseTransferFailureKind::Disconnected,
    ResponseTransferFailureKind::Other,
];
const REQUEST_SERIES: usize = METHODS.len() * ROUTES.len() * STATUS_CODES.len();
const NAR_RANGE_OUTCOMES: [NarRangeOutcome; 4] = [
    NarRangeOutcome::Full,
    NarRangeOutcome::Partial,
    NarRangeOutcome::Unsatisfiable,
    NarRangeOutcome::Invalid,
];
// A 5-second sampler needs both endpoints to cover an exact five-minute window.
const TRAFFIC_SAMPLE_CAPACITY: usize = 61;
#[cfg(target_os = "linux")]
const MAX_PROCESS_FD_ENTRIES: usize = 16_384;
const MAX_ZFS_SAMPLE_BYTES: u64 = 16 * 1024;
const ZFS_SAMPLE_MAX_AGE: u64 = 180;
const LATENCY_BUCKET_BOUNDS_SECONDS: [f64; 13] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0,
];
const LATENCY_BUCKETS: usize = LATENCY_BUCKET_BOUNDS_SECONDS.len() + 1;

#[derive(Debug)]
struct DurationHistogram {
    count: AtomicU64,
    sum_nanos: AtomicU64,
    max_nanos: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS],
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum_nanos: AtomicU64::new(0),
            max_nanos: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl DurationHistogram {
    fn observe(&self, elapsed: Duration) {
        let elapsed_nanos = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
        let elapsed_seconds = elapsed.as_secs_f64();
        let bucket = LATENCY_BUCKET_BOUNDS_SECONDS
            .iter()
            .position(|bound| elapsed_seconds <= *bound)
            .unwrap_or(LATENCY_BUCKET_BOUNDS_SECONDS.len());
        saturating_atomic_add(&self.count, 1);
        saturating_atomic_add(&self.sum_nanos, elapsed_nanos);
        self.max_nanos.fetch_max(elapsed_nanos, Ordering::Relaxed);
        saturating_atomic_add(&self.buckets[bucket], 1);
    }

    fn snapshot(&self) -> DurationHistogramSnapshot {
        DurationHistogramSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_seconds: self.sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
            max_seconds: self.max_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
            upper_bounds_seconds: LATENCY_BUCKET_BOUNDS_SECONDS,
            bucket_counts: std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed)),
        }
    }
}

fn saturating_atomic_add(counter: &AtomicU64, amount: u64) -> bool {
    let mut overflowed = false;
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            let next = value.checked_add(amount);
            overflowed = next.is_none();
            Some(next.unwrap_or(u64::MAX))
        })
        .expect("saturating update always returns a value");
    overflowed
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RequestMethod {
    Get,
    Head,
    Put,
    Other,
}

impl RequestMethod {
    const fn index(self) -> usize {
        match self {
            Self::Get => 0,
            Self::Head => 1,
            Self::Put => 2,
            Self::Other => 3,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Other => "other",
        }
    }

    pub(crate) const fn from(method: Method) -> Self {
        match method {
            Method::Get => Self::Get,
            Method::Head => Self::Head,
            Method::Put => Self::Put,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RequestRoute {
    Health,
    Ready,
    Metrics,
    CacheInfo,
    Nar,
    NarInfo,
    Invalid,
    Missing,
    Other,
}

impl RequestRoute {
    const fn index(self) -> usize {
        match self {
            Self::Health => 0,
            Self::Ready => 1,
            Self::Metrics => 2,
            Self::CacheInfo => 3,
            Self::Nar => 4,
            Self::NarInfo => 5,
            Self::Invalid => 6,
            Self::Missing => 7,
            Self::Other => 8,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Health => "healthz",
            Self::Ready => "readyz",
            Self::Metrics => "metrics",
            Self::CacheInfo => "cache_info",
            Self::Nar => "nar",
            Self::NarInfo => "narinfo",
            Self::Invalid => "invalid",
            Self::Missing => "missing",
            Self::Other => "other",
        }
    }

    const fn is_artifact(self) -> bool {
        match self {
            Self::Nar | Self::NarInfo => true,
            Self::Health
            | Self::Ready
            | Self::Metrics
            | Self::CacheInfo
            | Self::Invalid
            | Self::Missing
            | Self::Other => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NarRangeOutcome {
    Full,
    Partial,
    Unsatisfiable,
    Invalid,
}

impl NarRangeOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Full => 0,
            Self::Partial => 1,
            Self::Unsatisfiable => 2,
            Self::Invalid => 3,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Unsatisfiable => "unsatisfiable",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug)]
pub struct Metrics {
    requests: [AtomicU64; REQUEST_SERIES],
    connection_outcomes: [AtomicU64; CONNECTION_OUTCOMES.len()],
    response_transfer_failures: [AtomicU64; RESPONSE_TRANSFER_FAILURES.len()],
    publication_outcomes: [AtomicU64; 4],
    completed_responses: AtomicU64,
    aborted_responses: AtomicU64,
    nar_get_lookups: [AtomicU64; 3],
    nar_head_lookups: [AtomicU64; 3],
    narinfo_get_lookups: [AtomicU64; 3],
    narinfo_head_lookups: [AtomicU64; 3],
    nar_range_requests: [AtomicU64; NAR_RANGE_OUTCOMES.len() * 2],
    started_at_unix_seconds: u64,
    started_at: Instant,
    traffic_samples: Mutex<TrafficSamples>,
    process_sample: Mutex<SampleState<ProcessResources>>,
    population_sample: Mutex<PopulationSamples>,
    filesystem_sample: Mutex<SampleState<FilesystemStats>>,
    maintenance_sample: Mutex<SampleState<maintenance::Snapshot>>,
    requests_in_flight: AtomicU64,
    connections_in_flight: AtomicU64,
    connections_limit: AtomicU64,
    queued_connections: AtomicU64,
    request_queue_capacity: AtomicU64,
    active_publication_workers: AtomicU64,
    publication_worker_limit: AtomicU64,
    publication_queue_capacity: AtomicU64,
    declared_upload_bytes: AtomicU64,
    received_upload_bytes: AtomicU64,
    bytes_out: AtomicU64,
    traffic_bytes_overflowed: AtomicBool,
    auth_read_failures: AtomicU64,
    auth_write_failures: AtomicU64,
    validation_body_failures: AtomicU64,
    validation_nar_failures: AtomicU64,
    validation_narinfo_failures: AtomicU64,
    uploads_in_flight: AtomicU64,
    temp_objects: AtomicU64,
    disk_full: AtomicU64,
    capacity_no_space: AtomicU64,
    capacity_quota: AtomicU64,
    capacity_inodes: AtomicU64,
    capacity_read_only: AtomicU64,
    publications: AtomicU64,
    publication_count: AtomicU64,
    publication_micros: AtomicU64,
    publication_max_micros: AtomicU64,
    publication_queue_depth: AtomicU64,
    publication_queue_wait_count: AtomicU64,
    publication_queue_wait_micros: AtomicU64,
    publication_queue_wait_max_micros: AtomicU64,
    nar_lookup_latency: DurationHistogram,
    narinfo_lookup_latency: DurationHistogram,
    nar_delivery_latency: DurationHistogram,
    narinfo_delivery_latency: DurationHistogram,
    publication_latency: DurationHistogram,
    publication_queue_wait_latency: DurationHistogram,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            connection_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            response_transfer_failures: std::array::from_fn(|_| AtomicU64::new(0)),
            publication_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            completed_responses: AtomicU64::new(0),
            aborted_responses: AtomicU64::new(0),
            nar_get_lookups: std::array::from_fn(|_| AtomicU64::new(0)),
            nar_head_lookups: std::array::from_fn(|_| AtomicU64::new(0)),
            narinfo_get_lookups: std::array::from_fn(|_| AtomicU64::new(0)),
            narinfo_head_lookups: std::array::from_fn(|_| AtomicU64::new(0)),
            nar_range_requests: std::array::from_fn(|_| AtomicU64::new(0)),
            started_at_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            started_at: Instant::now(),
            traffic_samples: Mutex::new(TrafficSamples::default()),
            process_sample: Mutex::new(SampleState::NeverSampled),
            population_sample: Mutex::new(PopulationSamples::default()),
            filesystem_sample: Mutex::new(SampleState::Unavailable {
                reason: "not_configured".to_owned(),
            }),
            maintenance_sample: Mutex::new(SampleState::NeverSampled),
            requests_in_flight: AtomicU64::new(0),
            connections_in_flight: AtomicU64::new(0),
            connections_limit: AtomicU64::new(0),
            queued_connections: AtomicU64::new(0),
            request_queue_capacity: AtomicU64::new(0),
            active_publication_workers: AtomicU64::new(0),
            publication_worker_limit: AtomicU64::new(0),
            publication_queue_capacity: AtomicU64::new(0),
            declared_upload_bytes: AtomicU64::new(0),
            received_upload_bytes: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            traffic_bytes_overflowed: AtomicBool::new(false),
            auth_read_failures: AtomicU64::new(0),
            auth_write_failures: AtomicU64::new(0),
            validation_body_failures: AtomicU64::new(0),
            validation_nar_failures: AtomicU64::new(0),
            validation_narinfo_failures: AtomicU64::new(0),
            uploads_in_flight: AtomicU64::new(0),
            temp_objects: AtomicU64::new(0),
            disk_full: AtomicU64::new(0),
            capacity_no_space: AtomicU64::new(0),
            capacity_quota: AtomicU64::new(0),
            capacity_inodes: AtomicU64::new(0),
            capacity_read_only: AtomicU64::new(0),
            publications: AtomicU64::new(0),
            publication_count: AtomicU64::new(0),
            publication_micros: AtomicU64::new(0),
            publication_max_micros: AtomicU64::new(0),
            publication_queue_depth: AtomicU64::new(0),
            publication_queue_wait_count: AtomicU64::new(0),
            publication_queue_wait_micros: AtomicU64::new(0),
            publication_queue_wait_max_micros: AtomicU64::new(0),
            nar_lookup_latency: DurationHistogram::default(),
            narinfo_lookup_latency: DurationHistogram::default(),
            nar_delivery_latency: DurationHistogram::default(),
            narinfo_delivery_latency: DurationHistogram::default(),
            publication_latency: DurationHistogram::default(),
            publication_queue_wait_latency: DurationHistogram::default(),
        }
    }
}

impl Metrics {
    pub(crate) fn request(&self, method: RequestMethod, route: RequestRoute) -> RequestGuard<'_> {
        self.requests_in_flight.fetch_add(1, Ordering::Relaxed);
        RequestGuard {
            metrics: self,
            method,
            route,
            recording: Cell::new(RequestRecordingState::Pending),
        }
    }

    pub(crate) fn cache_lookup(
        &self,
        object: CacheObject,
        method: RequestMethod,
        outcome: CacheLookupOutcome,
    ) {
        let counters = match (object, method) {
            (CacheObject::Nar, RequestMethod::Get) => &self.nar_get_lookups,
            (CacheObject::Nar, RequestMethod::Head) => &self.nar_head_lookups,
            (CacheObject::NarInfo, RequestMethod::Get) => &self.narinfo_get_lookups,
            (CacheObject::NarInfo, RequestMethod::Head) => &self.narinfo_head_lookups,
            (_, RequestMethod::Put | RequestMethod::Other) => return,
        };
        counters[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(
        &self,
        readiness: StorageReadiness,
        capacity: Option<StorageCapacity>,
        temporary_objects: u64,
        min_free_bytes: u64,
        staging_bytes: u64,
    ) -> StatsSnapshot {
        let traffic_bytes_overflowed = self.traffic_bytes_overflowed.load(Ordering::Relaxed);
        let traffic_rates = self.recent_traffic_rates(traffic_bytes_overflowed);
        let process_resources = self
            .process_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let population = self
            .population_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let filesystem = self
            .filesystem_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let maintenance = self
            .maintenance_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        StatsSnapshot {
            http_requests: self.http_request_counts(),
            connections: self.connection_stats(),
            response_transfer_failures: self.response_transfer_failure_stats(),
            publication_outcomes: self.publication_outcome_stats(),
            storage_activity: StorageActivitySnapshot::default(),
            process: ProcessStats {
                started_at_unix_seconds: self.started_at_unix_seconds,
                uptime_seconds: self.started_at.elapsed().as_secs(),
                resources: process_resources,
            },
            cache: CacheStats {
                nar_get: lookup_snapshot(&self.nar_get_lookups),
                nar_head: lookup_snapshot(&self.nar_head_lookups),
                narinfo_get: lookup_snapshot(&self.narinfo_get_lookups),
                narinfo_head: lookup_snapshot(&self.narinfo_head_lookups),
            },
            nar_range_requests: NarRangeStats {
                get: nar_range_method_snapshot(&self.nar_range_requests, 0),
                head: nar_range_method_snapshot(&self.nar_range_requests, 1),
            },
            latency: self.latency_snapshot(),
            traffic: self.traffic_stats(traffic_bytes_overflowed, traffic_rates),
            reliability: self.reliability_stats(),
            pressure: self.pressure_stats(
                readiness,
                capacity,
                temporary_objects,
                min_free_bytes,
                staging_bytes,
            ),
            inventory: population.last_complete,
            inventory_attempt: population.last_attempt,
            filesystem,
            maintenance,
        }
    }

    fn recent_traffic_rates(&self, counters_overflowed: bool) -> RecentTrafficRates {
        match counters_overflowed {
            true => RecentTrafficRates {
                one_minute: None,
                five_minutes: None,
            },
            false => self
                .traffic_samples
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .rates(),
        }
    }

    fn traffic_stats(
        &self,
        counters_overflowed: bool,
        recent_rates: RecentTrafficRates,
    ) -> TrafficStats {
        TrafficStats {
            requests_in_flight: self.requests_in_flight.load(Ordering::Relaxed),
            uploads_in_flight: self.uploads_in_flight.load(Ordering::Relaxed),
            declared_upload_bytes: self.declared_upload_bytes.load(Ordering::Relaxed),
            received_upload_body_bytes: self.received_upload_bytes.load(Ordering::Relaxed),
            response_body_bytes: self.bytes_out.load(Ordering::Relaxed),
            completed_responses: self.completed_responses.load(Ordering::Relaxed),
            aborted_responses: self.aborted_responses.load(Ordering::Relaxed),
            cumulative_byte_counters_overflowed: counters_overflowed,
            recent_rates,
        }
    }

    fn reliability_stats(&self) -> ReliabilityStats {
        ReliabilityStats {
            auth_read_failures: self.auth_read_failures.load(Ordering::Relaxed),
            auth_write_failures: self.auth_write_failures.load(Ordering::Relaxed),
            validation_body_failures: self.validation_body_failures.load(Ordering::Relaxed),
            validation_nar_failures: self.validation_nar_failures.load(Ordering::Relaxed),
            validation_narinfo_failures: self.validation_narinfo_failures.load(Ordering::Relaxed),
            capacity_no_space: self.capacity_no_space.load(Ordering::Relaxed),
            capacity_quota: self.capacity_quota.load(Ordering::Relaxed),
            capacity_inodes: self.capacity_inodes.load(Ordering::Relaxed),
            capacity_read_only: self.capacity_read_only.load(Ordering::Relaxed),
        }
    }

    fn pressure_stats(
        &self,
        readiness: StorageReadiness,
        capacity: Option<StorageCapacity>,
        temporary_objects: u64,
        min_free_bytes: u64,
        staging_bytes: u64,
    ) -> PressureStats {
        PressureStats {
            readiness,
            temporary_objects,
            connections_in_flight: self.connections_in_flight.load(Ordering::Relaxed),
            connections_limit: self.connections_limit.load(Ordering::Relaxed),
            request_queue_depth: self.queued_connections.load(Ordering::Relaxed),
            request_queue_capacity: self.request_queue_capacity.load(Ordering::Relaxed),
            active_publication_workers: self.active_publication_workers.load(Ordering::Relaxed),
            publication_worker_limit: self.publication_worker_limit.load(Ordering::Relaxed),
            publication_queue_depth: self.publication_queue_depth.load(Ordering::Relaxed),
            publication_queue_capacity: self.publication_queue_capacity.load(Ordering::Relaxed),
            capacity: capacity.map(|capacity| {
                CapacityStats::from_storage(capacity, min_free_bytes, staging_bytes)
            }),
        }
    }

    fn http_request_counts(&self) -> Vec<HttpRequestCount> {
        METHODS
            .into_iter()
            .flat_map(|method| self.request_counts_for_method(method))
            .collect()
    }

    fn request_counts_for_method(
        &self,
        method: RequestMethod,
    ) -> impl Iterator<Item = HttpRequestCount> + '_ {
        ROUTES
            .into_iter()
            .flat_map(move |route| self.request_counts_for_route(method, route))
    }

    fn request_counts_for_route(
        &self,
        method: RequestMethod,
        route: RequestRoute,
    ) -> impl Iterator<Item = HttpRequestCount> + '_ {
        STATUS_CODES
            .into_iter()
            .enumerate()
            .filter_map(move |(status_index, (status_code, _))| {
                self.request_count(method, route, status_index, status_code)
            })
    }

    fn request_count(
        &self,
        method: RequestMethod,
        route: RequestRoute,
        status_index: usize,
        status_code: &'static str,
    ) -> Option<HttpRequestCount> {
        let count = self.requests[request_index(method.index(), route.index(), status_index)]
            .load(Ordering::Relaxed);
        (count != 0).then(|| HttpRequestCount {
            method: method.label().to_owned(),
            route: route.label().to_owned(),
            status_code: status_code.to_owned(),
            count,
        })
    }

    pub fn configure_pressure_limits(&self, connections: u64, workers: u64) {
        self.connections_limit.store(connections, Ordering::Relaxed);
        self.request_queue_capacity
            .store(connections, Ordering::Relaxed);
        self.publication_worker_limit
            .store(workers, Ordering::Relaxed);
        self.publication_queue_capacity
            .store(connections, Ordering::Relaxed);
    }

    pub fn connection_admitted(&self) {
        self.connections_in_flight.fetch_add(1, Ordering::Relaxed);
        self.record_connection_outcome(ConnectionOutcome::Admitted);
    }

    pub fn record_connection_outcome(&self, outcome: ConnectionOutcome) {
        self.connection_outcomes[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn socket_read_failure(kind: std::io::ErrorKind) -> Option<ConnectionOutcome> {
        match kind {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected => Some(ConnectionOutcome::Disconnected),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                Some(ConnectionOutcome::TimedOut)
            }
            _ => None,
        }
    }

    fn connection_stats(&self) -> ConnectionStats {
        let count = |outcome: ConnectionOutcome| {
            self.connection_outcomes[outcome.index()].load(Ordering::Relaxed)
        };
        ConnectionStats {
            admitted: count(ConnectionOutcome::Admitted),
            admission_rejected: count(ConnectionOutcome::AdmissionRejected),
            request_queue_full: count(ConnectionOutcome::RequestQueueFull),
            malformed_requests: count(ConnectionOutcome::MalformedRequest),
            timeouts: count(ConnectionOutcome::TimedOut),
            disconnected: count(ConnectionOutcome::Disconnected),
        }
    }

    fn response_transfer_failure_stats(&self) -> ResponseTransferFailureStats {
        ResponseTransferFailureStats {
            timed_out: self.response_transfer_failures[0].load(Ordering::Relaxed),
            disconnected: self.response_transfer_failures[1].load(Ordering::Relaxed),
            other: self.response_transfer_failures[2].load(Ordering::Relaxed),
        }
    }

    fn record_response_transfer_failure(&self, failure: &TransferFailure) {
        let kind = ResponseTransferFailureKind::from_error(&failure.error);
        self.response_transfer_failures[kind.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn publication_outcome_stats(&self) -> PublicationOutcomeStats {
        PublicationOutcomeStats {
            created: self.publication_outcomes[0].load(Ordering::Relaxed),
            identical: self.publication_outcomes[1].load(Ordering::Relaxed),
            conflicts: self.publication_outcomes[2].load(Ordering::Relaxed),
            failures: self.publication_outcomes[3].load(Ordering::Relaxed),
        }
    }

    pub fn connection_released(&self) {
        self.connections_in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn connection_queued(&self) {
        self.queued_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_dequeued(&self) {
        self.queued_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn publication_worker_started(&self) {
        self.active_publication_workers
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn publication_worker_finished(&self) {
        self.active_publication_workers
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn sample_periodic(&self) {
        let process_resources = sample_process_resources();
        let process_cpu_seconds = process_resources
            .as_ref()
            .ok()
            .map(|resources| resources.user_cpu_seconds + resources.system_cpu_seconds);
        let mut samples = self
            .traffic_samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        samples.record(TrafficSample {
            at: Instant::now(),
            upload_bytes: self.received_upload_bytes.load(Ordering::Relaxed),
            download_bytes: self.bytes_out.load(Ordering::Relaxed),
            process_cpu_seconds,
            byte_counters_overflowed: self.traffic_bytes_overflowed.load(Ordering::Relaxed),
        });
        drop(samples);

        let mut process_sample = self
            .process_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *process_sample = next_sample_state(
            &process_sample,
            process_resources,
            unix_seconds_now(),
            "procfs_read_failed",
        );
    }

    pub fn sample_filesystem_sidecar(&self, path: &Path, expected_root: &Path) {
        let now = unix_seconds_now();
        let result = read_zfs_sample(path, expected_root, now);
        let mut previous = self
            .filesystem_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *previous = filesystem_sample_after_read(&previous, result, now);
    }

    pub fn sample_maintenance_sidecar(&self, root: &Path) {
        let sample = maintenance::read_snapshot(root).map_err(|_| ());
        let mut previous = self
            .maintenance_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *previous = next_sample_state(
            &previous,
            sample,
            unix_seconds_now(),
            "maintenance_record_read_failed",
        );
    }

    pub fn record_population_scan(
        &self,
        backend: StorageBackend,
        result: PopulationScanResult,
        started_at_unix_seconds: u64,
        elapsed_seconds: f64,
    ) {
        let completed_at_unix_seconds = unix_seconds_now();
        let (complete_sample, attempt) = population_scan_update(
            backend,
            result,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            elapsed_seconds,
        );
        let mut samples = self
            .population_sample
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        samples.last_complete = next_sample_state(
            &samples.last_complete,
            complete_sample,
            completed_at_unix_seconds,
            "population_scan_incomplete",
        );
        samples.last_attempt = Some(attempt);
    }

    pub(crate) fn auth_failure(&self, write: bool) {
        let counter = if write {
            &self.auth_write_failures
        } else {
            &self.auth_read_failures
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn validation_failure(&self, class: ValidationClass) {
        let counter = match class {
            ValidationClass::Body => &self.validation_body_failures,
            ValidationClass::Nar => &self.validation_nar_failures,
            ValidationClass::NarInfo => &self.validation_narinfo_failures,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn upload(&self, bytes: u64) -> UploadGuard<'_> {
        self.declared_upload_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.uploads_in_flight.fetch_add(1, Ordering::Relaxed);
        UploadGuard(self)
    }

    pub(crate) fn received_upload_body_bytes(&self, bytes: usize) {
        self.record_traffic_bytes(&self.received_upload_bytes, bytes as u64);
    }

    pub(crate) fn bytes_out(&self, bytes: u64) {
        self.record_traffic_bytes(&self.bytes_out, bytes);
    }

    fn record_traffic_bytes(&self, counter: &AtomicU64, bytes: u64) {
        if saturating_atomic_add(counter, bytes) {
            self.traffic_bytes_overflowed.store(true, Ordering::Relaxed);
        }
    }

    pub(crate) fn set_temp_objects(&self, count: u64) {
        self.temp_objects.store(count, Ordering::Relaxed);
    }

    pub(crate) fn publication(&self, elapsed: Duration) {
        self.publication_latency.observe(elapsed);
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.publications.fetch_add(1, Ordering::Relaxed);
        self.publication_count.fetch_add(1, Ordering::Relaxed);
        self.publication_micros.fetch_add(micros, Ordering::Relaxed);
        self.publication_max_micros
            .fetch_max(micros, Ordering::Relaxed);
    }

    pub fn record_publication_result(&self, result: &Result<PublishOutcome, StorageError>) {
        let index = match result {
            Ok(PublishOutcome::Created) => 0,
            Ok(PublishOutcome::Identical) => 1,
            Err(StorageError::Conflict) => 2,
            Err(_) => 3,
        };
        self.publication_outcomes[index].fetch_add(1, Ordering::Relaxed);
    }

    fn latency_snapshot(&self) -> LatencyStats {
        LatencyStats {
            nar_lookup: self.nar_lookup_latency.snapshot(),
            narinfo_lookup: self.narinfo_lookup_latency.snapshot(),
            nar_delivery: self.nar_delivery_latency.snapshot(),
            narinfo_delivery: self.narinfo_delivery_latency.snapshot(),
            publication: self.publication_latency.snapshot(),
            publication_queue_wait: self.publication_queue_wait_latency.snapshot(),
        }
    }

    pub fn publication_enqueued(&self) {
        self.publication_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn publication_enqueue_failed(&self) {
        let queued = self.publication_queue_depth.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(queued > 0);
    }

    pub fn publication_dequeued(&self, queued_at: Instant) {
        let queued = self.publication_queue_depth.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(queued > 0);
        let micros = queued_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        self.publication_queue_wait_latency
            .observe(Duration::from_micros(micros));
        self.publication_queue_wait_count
            .fetch_add(1, Ordering::Relaxed);
        self.publication_queue_wait_micros
            .fetch_add(micros, Ordering::Relaxed);
        self.publication_queue_wait_max_micros
            .fetch_max(micros, Ordering::Relaxed);
    }

    pub(crate) fn capacity_failure(&self, kind: CapacityErrorKind) {
        let counter = match kind {
            CapacityErrorKind::NoSpace => &self.capacity_no_space,
            CapacityErrorKind::Quota => &self.capacity_quota,
            CapacityErrorKind::Inodes => &self.capacity_inodes,
            CapacityErrorKind::ReadOnly => &self.capacity_read_only,
            CapacityErrorKind::Other => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if kind == CapacityErrorKind::NoSpace {
            self.disk_full.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) fn render(
        &self,
        ready: bool,
        capacity: Option<StorageCapacity>,
        staging_bytes: u64,
        min_free_bytes: u64,
    ) -> String {
        let readiness = if ready {
            StorageReadiness::Ready
        } else {
            StorageReadiness::LowSpace
        };
        render_prometheus(&self.snapshot(
            readiness,
            capacity,
            self.temp_objects.load(Ordering::Relaxed),
            min_free_bytes,
            staging_bytes,
        ))
    }
}

fn population_scan_update(
    backend: StorageBackend,
    result: PopulationScanResult,
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
    elapsed_seconds: f64,
) -> (Result<PopulationStats, ()>, PopulationAttempt) {
    match result {
        Ok(counts) => completed_population_scan(
            backend,
            counts,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            elapsed_seconds,
        ),
        Err(PopulationScanFailure) => failed_population_scan(
            started_at_unix_seconds,
            completed_at_unix_seconds,
            elapsed_seconds,
        ),
    }
}

pub type PopulationScanResult = Result<PopulationCounts, PopulationScanFailure>;

#[derive(Clone, Copy, Debug)]
pub struct PopulationScanFailure;

fn completed_population_scan(
    backend: StorageBackend,
    counts: PopulationCounts,
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
    elapsed_seconds: f64,
) -> (Result<PopulationStats, ()>, PopulationAttempt) {
    let quality = PopulationQuality::from_counts(&counts);
    let complete_sample = match quality {
        PopulationQuality::Complete => Ok(PopulationStats::from_scan(backend, counts)),
        PopulationQuality::ChangedDuringScan
        | PopulationQuality::EntryErrors
        | PopulationQuality::Failed => Err(()),
    };
    let attempt = PopulationAttempt {
        started_at_unix_seconds,
        completed_at_unix_seconds,
        elapsed_seconds,
        quality,
        coverage: Some(PopulationScanCoverage::from_counts(&counts)),
    };
    (complete_sample, attempt)
}

fn failed_population_scan(
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
    elapsed_seconds: f64,
) -> (Result<PopulationStats, ()>, PopulationAttempt) {
    (
        Err(()),
        PopulationAttempt {
            started_at_unix_seconds,
            completed_at_unix_seconds,
            elapsed_seconds,
            quality: PopulationQuality::Failed,
            coverage: None,
        },
    )
}

fn filesystem_sample_after_read(
    previous: &SampleState<FilesystemStats>,
    result: Result<(u64, FilesystemStats), &'static str>,
    now: u64,
) -> SampleState<FilesystemStats> {
    match result {
        Ok((sampled_at, value)) if now.saturating_sub(sampled_at) <= ZFS_SAMPLE_MAX_AGE => {
            SampleState::Measured {
                sampled_at_unix_seconds: sampled_at,
                value,
            }
        }
        Ok((sampled_at, value)) => SampleState::Stale {
            sampled_at_unix_seconds: sampled_at,
            value,
            reason: "sample_too_old".to_owned(),
        },
        Err(reason) => retain_or_explain_filesystem_sample(previous, reason),
    }
}

fn retain_or_explain_filesystem_sample(
    previous: &SampleState<FilesystemStats>,
    reason: &str,
) -> SampleState<FilesystemStats> {
    match previous {
        SampleState::Measured {
            sampled_at_unix_seconds,
            value,
        }
        | SampleState::Stale {
            sampled_at_unix_seconds,
            value,
            ..
        } => SampleState::Stale {
            sampled_at_unix_seconds: *sampled_at_unix_seconds,
            value: value.clone(),
            reason: reason.to_owned(),
        },
        SampleState::NeverSampled | SampleState::Unavailable { .. } => SampleState::Unavailable {
            reason: reason.to_owned(),
        },
    }
}

pub(crate) fn render_prometheus(snapshot: &StatsSnapshot) -> String {
    let mut output = String::new();
    append_http_request_metrics(&mut output, snapshot);
    append_admission_and_publication_outcomes(
        &mut output,
        &snapshot.connections,
        &snapshot.response_transfer_failures,
        &snapshot.publication_outcomes,
    );
    append_storage_activity_metrics(&mut output, snapshot.storage_activity);
    append_process_lifecycle_metrics(&mut output, snapshot);
    append_traffic_and_reliability_metrics(&mut output, snapshot);
    append_readiness_reason(&mut output, snapshot.pressure.readiness);
    append_pressure_metrics(&mut output, snapshot);
    append_cache_lookup_metrics(&mut output, &snapshot.cache, &snapshot.nar_range_requests);
    append_capacity_metrics(&mut output, snapshot.pressure.capacity.as_ref());
    append_process_metrics(&mut output, &snapshot.process.resources);
    append_latency_metrics(&mut output, &snapshot.latency);
    append_traffic_rate_metrics(&mut output, &snapshot.traffic.recent_rates);
    append_population_metrics(
        &mut output,
        &snapshot.inventory,
        snapshot.inventory_attempt.as_ref(),
    );
    append_filesystem_metrics(&mut output, &snapshot.filesystem);
    append_maintenance_metrics(&mut output, &snapshot.maintenance);
    output
}

fn append_http_request_metrics(output: &mut String, snapshot: &StatsSnapshot) {
    output.push_str("# HELP narjar_http_requests_total HTTP requests by method, validated route, and response status code.\n# TYPE narjar_http_requests_total counter\n");
    for request in &snapshot.http_requests {
        output.push_str(&format!(
            "narjar_http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {}\n",
            request.method, request.route, request.status_code, request.count
        ));
    }
}

fn append_process_lifecycle_metrics(output: &mut String, snapshot: &StatsSnapshot) {
    output.push_str(&format!(
        "# HELP narjar_stats_snapshot_timestamp_seconds Unix time when this exposition snapshot was rendered.\n# TYPE narjar_stats_snapshot_timestamp_seconds gauge\nnarjar_stats_snapshot_timestamp_seconds {}\n\
         # HELP narjar_process_start_time_seconds Unix time when this process started.\n# TYPE narjar_process_start_time_seconds gauge\nnarjar_process_start_time_seconds {}\n\
         # HELP narjar_process_uptime_seconds Process uptime in seconds.\n# TYPE narjar_process_uptime_seconds gauge\nnarjar_process_uptime_seconds {}\n",
        unix_seconds_now(),
        snapshot.process.started_at_unix_seconds,
        snapshot.process.uptime_seconds,
    ));
}

fn append_traffic_and_reliability_metrics(output: &mut String, snapshot: &StatsSnapshot) {
    let traffic = &snapshot.traffic;
    let reliability = &snapshot.reliability;
    output.push_str(&format!(
        "# HELP narjar_http_upload_declared_bytes_total Declared upload body bytes.\n# TYPE narjar_http_upload_declared_bytes_total counter\nnarjar_http_upload_declared_bytes_total {}\n\
         # HELP narjar_http_upload_received_bytes_total Upload body bytes actually read.\n# TYPE narjar_http_upload_received_bytes_total counter\nnarjar_http_upload_received_bytes_total {}\n\
         # HELP narjar_http_bytes_out_total Served artifact bytes.\n# TYPE narjar_http_bytes_out_total counter\nnarjar_http_bytes_out_total {}\n\
         # HELP narjar_auth_failures_total Authentication failures by permission scope.\n# TYPE narjar_auth_failures_total counter\nnarjar_auth_failures_total{{scope=\"read\"}} {}\nnarjar_auth_failures_total{{scope=\"write\"}} {}\n\
         # HELP narjar_validation_failures_total Rejected request bodies by validation class.\n# TYPE narjar_validation_failures_total counter\nnarjar_validation_failures_total{{class=\"body\"}} {}\nnarjar_validation_failures_total{{class=\"nar\"}} {}\nnarjar_validation_failures_total{{class=\"narinfo\"}} {}\n\
         # HELP narjar_uploads_in_flight Accepted uploads currently being processed.\n# TYPE narjar_uploads_in_flight gauge\nnarjar_uploads_in_flight {}\n\
         # HELP narjar_requests_in_flight Requests currently being processed.\n# TYPE narjar_requests_in_flight gauge\nnarjar_requests_in_flight {}\n\
         # HELP narjar_temp_objects Temporary publication objects currently owned by this process.\n# TYPE narjar_temp_objects gauge\nnarjar_temp_objects {}\n\
         # HELP narjar_disk_full_total No-space capacity failures.\n# TYPE narjar_disk_full_total counter\nnarjar_disk_full_total {}\n\
         # HELP narjar_capacity_failures_total Capacity failures by reason.\n# TYPE narjar_capacity_failures_total counter\nnarjar_capacity_failures_total{{reason=\"no_space\"}} {}\nnarjar_capacity_failures_total{{reason=\"quota\"}} {}\nnarjar_capacity_failures_total{{reason=\"inodes\"}} {}\nnarjar_capacity_failures_total{{reason=\"read_only\"}} {}\n\
         # HELP narjar_publications_total Publication attempts.\n# TYPE narjar_publications_total counter\nnarjar_publications_total {}\n\
         # HELP narjar_publication_duration_seconds Publication duration summary.\n# TYPE narjar_publication_duration_seconds summary\nnarjar_publication_duration_seconds_count {}\nnarjar_publication_duration_seconds_sum {}\nnarjar_publication_duration_seconds_max {}\n\
         # HELP narjar_publication_queue_depth Valid PUT requests waiting for the publication worker.\n# TYPE narjar_publication_queue_depth gauge\nnarjar_publication_queue_depth {}\n\
         # HELP narjar_ready Whether the configured destination is ready.\n# TYPE narjar_ready gauge\nnarjar_ready {}\n",
        traffic.declared_upload_bytes, traffic.received_upload_body_bytes,
        traffic.response_body_bytes, reliability.auth_read_failures,
        reliability.auth_write_failures, reliability.validation_body_failures,
        reliability.validation_nar_failures, reliability.validation_narinfo_failures,
        traffic.uploads_in_flight, traffic.requests_in_flight,
        snapshot.pressure.temporary_objects, reliability.capacity_no_space,
        reliability.capacity_no_space,
        reliability.capacity_quota, reliability.capacity_inodes,
        reliability.capacity_read_only, snapshot.latency.publication.count,
        snapshot.latency.publication.sum_seconds,
        snapshot.latency.publication.max_seconds,
        snapshot.latency.publication.count,
        snapshot.pressure.publication_queue_depth,
        u8::from(snapshot.pressure.readiness.is_ready()),
    ));
    output.push_str(&format!(
        "# HELP narjar_traffic_byte_counters_overflowed Whether cumulative traffic byte counters saturated; recent byte rates are omitted when true.\n# TYPE narjar_traffic_byte_counters_overflowed gauge\nnarjar_traffic_byte_counters_overflowed {}\n",
        u8::from(traffic.cumulative_byte_counters_overflowed),
    ));
}

fn append_pressure_metrics(output: &mut String, snapshot: &StatsSnapshot) {
    let traffic = &snapshot.traffic;
    let pressure = &snapshot.pressure;
    output.push_str(&format!(
        "# HELP narjar_responses_completed_total Responses whose full body was written.\n# TYPE narjar_responses_completed_total counter\nnarjar_responses_completed_total {}\n\
         # HELP narjar_responses_aborted_total Responses that did not finish writing.\n# TYPE narjar_responses_aborted_total counter\nnarjar_responses_aborted_total {}\n\
         # HELP narjar_connections_in_flight Accepted connections currently admitted.\n# TYPE narjar_connections_in_flight gauge\nnarjar_connections_in_flight {}\n\
         # HELP narjar_connections_limit Configured admitted-connection limit.\n# TYPE narjar_connections_limit gauge\nnarjar_connections_limit {}\n\
         # HELP narjar_request_queue_depth Parsed-connection worker queue depth.\n# TYPE narjar_request_queue_depth gauge\nnarjar_request_queue_depth {}\n\
         # HELP narjar_request_queue_capacity Parsed-connection worker queue capacity.\n# TYPE narjar_request_queue_capacity gauge\nnarjar_request_queue_capacity {}\n\
         # HELP narjar_publication_workers_active Publication workers currently processing a request.\n# TYPE narjar_publication_workers_active gauge\nnarjar_publication_workers_active {}\n\
         # HELP narjar_publication_workers_limit Configured publication worker count.\n# TYPE narjar_publication_workers_limit gauge\nnarjar_publication_workers_limit {}\n\
         # HELP narjar_publication_queue_capacity Publication worker queue capacity.\n# TYPE narjar_publication_queue_capacity gauge\nnarjar_publication_queue_capacity {}\n",
        traffic.completed_responses, traffic.aborted_responses,
        pressure.connections_in_flight, pressure.connections_limit,
        pressure.request_queue_depth, pressure.request_queue_capacity,
        pressure.active_publication_workers,
        pressure.publication_worker_limit,
        pressure.publication_queue_capacity,
    ));
}

fn append_cache_lookup_metrics(output: &mut String, cache: &CacheStats, ranges: &NarRangeStats) {
    output.push_str(
        "# HELP narjar_cache_lookup_outcomes_total Validated cache object lookup outcomes.\n# TYPE narjar_cache_lookup_outcomes_total counter\n",
    );
    for (object, method, lookup) in cache.lookups() {
        append_lookup_metrics(output, object, method, lookup);
    }
    append_nar_range_metrics(output, ranges);
    output.push_str(
        "# HELP narjar_cache_lookup_hit_ratio Successful lookups divided by successful lookups plus genuine misses. Failures are excluded.\n# TYPE narjar_cache_lookup_hit_ratio gauge\n# HELP narjar_cache_lookup_failure_ratio Failed lookups divided by all lookup decisions.\n# TYPE narjar_cache_lookup_failure_ratio gauge\n",
    );
    for (object, method, lookup) in cache.lookups() {
        append_lookup_ratios(output, object, method, lookup);
    }
}

fn append_capacity_metrics(output: &mut String, capacity: Option<&CapacityStats>) {
    if let Some(capacity) = capacity {
        output.push_str(&format!(
            "# HELP narjar_storage_capacity_bytes Destination filesystem bytes.\n# TYPE narjar_storage_capacity_bytes gauge\nnarjar_storage_capacity_bytes{{kind=\"total\"}} {}\nnarjar_storage_capacity_bytes{{kind=\"available\"}} {}\n\
             # HELP narjar_storage_capacity_inodes Destination filesystem inodes.\n# TYPE narjar_storage_capacity_inodes gauge\nnarjar_storage_capacity_inodes{{kind=\"total\"}} {}\nnarjar_storage_capacity_inodes{{kind=\"available\"}} {}\n\
             # HELP narjar_storage_read_only Whether the destination filesystem is read-only.\n# TYPE narjar_storage_read_only gauge\nnarjar_storage_read_only {}\n\
             # HELP narjar_staging_outstanding_bytes Staging bytes currently reserved by active work.\n# TYPE narjar_staging_outstanding_bytes gauge\nnarjar_staging_outstanding_bytes {}\n\
             # HELP narjar_staging_min_free_reserve_bytes Configured filesystem free-space reserve.\n# TYPE narjar_staging_min_free_reserve_bytes gauge\nnarjar_staging_min_free_reserve_bytes {}\n\
             # HELP narjar_storage_estimated_headroom_bytes Observed available bytes minus reserve and outstanding staging credit.\n# TYPE narjar_storage_estimated_headroom_bytes gauge\nnarjar_storage_estimated_headroom_bytes {}\n",
            capacity.total_bytes, capacity.available_bytes, capacity.total_inodes,
            capacity.available_inodes, u8::from(capacity.read_only),
            capacity.outstanding_staging_bytes, capacity.configured_min_free_bytes,
            capacity.estimated_headroom_bytes,
        ));
    }
}

fn append_maintenance_metrics(output: &mut String, sample: &SampleState<maintenance::Snapshot>) {
    output.push_str(
        "# HELP narjar_maintenance_sample_available Whether maintenance history could be read.\n# TYPE narjar_maintenance_sample_available gauge\n\
         # HELP narjar_maintenance_sample_timestamp_seconds Time the maintenance history was last sampled.\n# TYPE narjar_maintenance_sample_timestamp_seconds gauge\n\
         # HELP narjar_maintenance_sample_age_seconds Age of the last readable maintenance history.\n# TYPE narjar_maintenance_sample_age_seconds gauge\n\
         # HELP narjar_maintenance_last_completed_timestamp_seconds Unix time of the last completed maintenance operation.\n# TYPE narjar_maintenance_last_completed_timestamp_seconds gauge\n\
         # HELP narjar_maintenance_last_duration_seconds Duration of the last completed maintenance operation.\n# TYPE narjar_maintenance_last_duration_seconds gauge\n\
         # HELP narjar_maintenance_last_objects Number of objects examined, selected, or reclaimed by the last maintenance operation.\n# TYPE narjar_maintenance_last_objects gauge\n\
         # HELP narjar_maintenance_last_bytes Bytes examined or logically reclaimed by the last maintenance operation. Reclaimed bytes are not physical filesystem space.\n# TYPE narjar_maintenance_last_bytes gauge\n\
         # HELP narjar_maintenance_inventory_entries Counts by inventory verification class from the last reconcile or verify.\n# TYPE narjar_maintenance_inventory_entries gauge\n\
         # HELP narjar_maintenance_started_timestamp_seconds Start time for an operation without a recorded completion; this may be running or interrupted.\n# TYPE narjar_maintenance_started_timestamp_seconds gauge\n",
    );
    let (sampled_at, snapshot, state) = match sample {
        SampleState::Measured {
            sampled_at_unix_seconds,
            value,
        } => (*sampled_at_unix_seconds, value, "measured"),
        SampleState::Stale {
            sampled_at_unix_seconds,
            value,
            ..
        } => (*sampled_at_unix_seconds, value, "stale"),
        SampleState::NeverSampled | SampleState::Unavailable { .. } => {
            output.push_str("narjar_maintenance_sample_available 0\n");
            return;
        }
    };
    output.push_str(&format!(
        "narjar_maintenance_sample_available{{state=\"{state}\"}} 1\nnarjar_maintenance_sample_timestamp_seconds {sampled_at}\nnarjar_maintenance_sample_age_seconds {}\n",
        unix_seconds_now().saturating_sub(sampled_at),
    ));
    for operation in maintenance::Operation::ALL {
        let index = operation.index();
        if let Some(run) = snapshot.last_runs[index] {
            output.push_str(&format!(
                "narjar_maintenance_last_completed_timestamp_seconds{{operation=\"{}\",mode=\"{}\",outcome=\"{}\"}} {}\n\
                 narjar_maintenance_last_duration_seconds{{operation=\"{}\"}} {}\n",
                operation.name(), run.mode.name(), run.outcome.name(),
                run.completed_at_unix_seconds, operation.name(),
                run.duration_micros as f64 / 1_000_000.0,
            ));
            append_maintenance_count(output, operation.name(), "examined", run.objects_examined);
            append_maintenance_count(output, operation.name(), "selected", run.objects_selected);
            append_maintenance_count(output, operation.name(), "reclaimed", run.objects_reclaimed);
            append_maintenance_bytes(output, operation.name(), "examined", run.bytes_examined);
            append_maintenance_bytes(output, operation.name(), "reclaimed", run.bytes_reclaimed);
            if let Some(counts) = run.inventory_class_counts {
                for (class, count) in crate::inventory::InventoryClass::ALL
                    .into_iter()
                    .zip(counts)
                {
                    output.push_str(&format!(
                        "narjar_maintenance_inventory_entries{{operation=\"{}\",class=\"{}\"}} {count}\n",
                        operation.name(),
                        class.as_str(),
                    ));
                }
            }
        }
        if let Some(started) = snapshot.started[index] {
            output.push_str(&format!(
                "narjar_maintenance_started_timestamp_seconds{{operation=\"{}\",mode=\"{}\"}} {}\n",
                operation.name(),
                started.mode.name(),
                started.started_at_unix_seconds,
            ));
        }
    }
}

fn append_maintenance_count(output: &mut String, operation: &str, kind: &str, value: Option<u64>) {
    if let Some(value) = value {
        output.push_str(&format!(
            "narjar_maintenance_last_objects{{operation=\"{operation}\",kind=\"{kind}\"}} {value}\n"
        ));
    }
}

fn append_maintenance_bytes(output: &mut String, operation: &str, kind: &str, value: Option<u64>) {
    if let Some(value) = value {
        output.push_str(&format!(
            "narjar_maintenance_last_bytes{{operation=\"{operation}\",kind=\"{kind}\"}} {value}\n"
        ));
    }
}

fn append_readiness_reason(output: &mut String, readiness: StorageReadiness) {
    output.push_str(
        "# HELP narjar_readiness Current storage readiness reason, represented as a one-hot series.\n# TYPE narjar_readiness gauge\n",
    );
    for (reason, state) in [
        ("available", StorageReadiness::Ready),
        ("low_space", StorageReadiness::LowSpace),
        ("no_inodes", StorageReadiness::NoInodes),
        ("read_only", StorageReadiness::ReadOnly),
        ("probe_failed", StorageReadiness::ProbeFailed),
    ] {
        output.push_str(&format!(
            "narjar_readiness{{reason=\"{reason}\"}} {}\n",
            u8::from(readiness == state)
        ));
    }
}

fn append_storage_activity_metrics(output: &mut String, activity: StorageActivitySnapshot) {
    output.push_str(
        "# HELP narjar_nar_upload_validated_logical_bytes_total Logical NAR bytes in uploads whose complete encoded representation and decoded hash/size validation succeeded; this does not validate NAR grammar or signatures.\n# TYPE narjar_nar_upload_validated_logical_bytes_total counter\n",
    );
    output.push_str(&format!(
        "narjar_nar_upload_validated_logical_bytes_total {}\n",
        activity.upload_validated_logical_bytes,
    ));
    output.push_str(
        "# HELP narjar_nar_upload_committed_logical_bytes_total Logical NAR bytes at durable upload publication, by canonical payload outcome.\n# TYPE narjar_nar_upload_committed_logical_bytes_total counter\n",
    );
    for (outcome, bytes) in [
        ("created", activity.upload_created_logical_bytes),
        ("identical", activity.upload_identical_logical_bytes),
    ] {
        output.push_str(&format!(
            "narjar_nar_upload_committed_logical_bytes_total{{outcome=\"{outcome}\"}} {bytes}\n"
        ));
    }
    output.push_str(
        "# HELP narjar_egress_derivatives_total Compressed egress derivative work by outcome.\n# TYPE narjar_egress_derivatives_total counter\n",
    );
    for (outcome, count) in [
        ("reused", activity.egress_reuses),
        ("generation_started", activity.egress_generations_started),
        (
            "generation_succeeded",
            activity.egress_generations_succeeded,
        ),
        ("generation_failed", activity.egress_generations_failed),
        ("repaired", activity.egress_repairs),
        ("coalesced_wait", activity.egress_coalesced_waits),
    ] {
        output.push_str(&format!(
            "narjar_egress_derivatives_total{{outcome=\"{outcome}\"}} {count}\n"
        ));
    }
    output.push_str(&format!(
        "# HELP narjar_egress_coalesced_wait_seconds_total Time callers waited behind compressed derivative generation.\n# TYPE narjar_egress_coalesced_wait_seconds_total counter\nnarjar_egress_coalesced_wait_seconds_total {}\n",
        activity.egress_coalesced_wait_seconds,
    ));
    if let StorageBackend::Chunked = activity.backend {
        output.push_str(&format!(
            "# HELP narjar_chunks_total Chunk publication outcomes by whether bytes were newly stored or reused.\n# TYPE narjar_chunks_total counter\nnarjar_chunks_total{{outcome=\"created\"}} {}\nnarjar_chunks_total{{outcome=\"reused\"}} {}\n\
             # HELP narjar_chunk_bytes_total Chunk bytes newly stored or reused.\n# TYPE narjar_chunk_bytes_total counter\nnarjar_chunk_bytes_total{{outcome=\"created\"}} {}\nnarjar_chunk_bytes_total{{outcome=\"reused\"}} {}\n",
            activity.chunks_created,
            activity.chunks_reused,
            activity.chunk_bytes_created,
            activity.chunk_bytes_reused,
        ));
    }
}

fn append_admission_and_publication_outcomes(
    output: &mut String,
    connections: &ConnectionStats,
    transfer_failures: &ResponseTransferFailureStats,
    publication_outcomes: &PublicationOutcomeStats,
) {
    output.push_str(
        "# HELP narjar_connections_total Accepted and rejected connection/request events.\n# TYPE narjar_connections_total counter\n",
    );
    for (outcome, count) in [
        ("admitted", connections.admitted),
        ("admission_rejected", connections.admission_rejected),
        ("request_queue_full", connections.request_queue_full),
        ("malformed_request", connections.malformed_requests),
        ("timeout", connections.timeouts),
        ("disconnected", connections.disconnected),
    ] {
        output.push_str(&format!(
            "narjar_connections_total{{outcome=\"{outcome}\"}} {count}\n"
        ));
    }
    output.push_str(
        "# HELP narjar_response_transfer_failures_total Failed response transfers by bounded I/O error class; partial body bytes remain in narjar_http_bytes_out_total.\n# TYPE narjar_response_transfer_failures_total counter\n",
    );
    for (kind, count) in [
        ("timeout", transfer_failures.timed_out),
        ("disconnected", transfer_failures.disconnected),
        ("other", transfer_failures.other),
    ] {
        output.push_str(&format!(
            "narjar_response_transfer_failures_total{{kind=\"{kind}\"}} {count}\n"
        ));
    }
    output.push_str(
        "# HELP narjar_publication_outcomes_total Durable publication results.\n# TYPE narjar_publication_outcomes_total counter\n",
    );
    for (outcome, count) in [
        ("created", publication_outcomes.created),
        ("identical", publication_outcomes.identical),
        ("conflict", publication_outcomes.conflicts),
        ("failure", publication_outcomes.failures),
    ] {
        output.push_str(&format!(
            "narjar_publication_outcomes_total{{outcome=\"{outcome}\"}} {count}\n"
        ));
    }
}

fn append_lookup_metrics(output: &mut String, object: &str, method: &str, lookup: &LookupStats) {
    for (outcome, count) in [
        ("hit", lookup.hits),
        ("miss", lookup.misses),
        ("failure", lookup.failures),
    ] {
        output.push_str(&format!(
            "narjar_cache_lookup_outcomes_total{{object=\"{object}\",method=\"{method}\",outcome=\"{outcome}\"}} {count}\n"
        ));
    }
}

fn append_nar_range_metrics(output: &mut String, ranges: &NarRangeStats) {
    output.push_str(
        "# HELP narjar_nar_range_requests_total Existing NAR requests by method and parsed Range header outcome.\n# TYPE narjar_nar_range_requests_total counter\n",
    );
    for (method, counts) in [("GET", &ranges.get), ("HEAD", &ranges.head)] {
        for outcome in NAR_RANGE_OUTCOMES {
            let count = counts.count(outcome);
            output.push_str(&format!(
                "narjar_nar_range_requests_total{{method=\"{method}\",outcome=\"{}\"}} {count}\n",
                outcome.label(),
            ));
        }
    }
}

fn nar_range_method_snapshot(
    counters: &[AtomicU64; NAR_RANGE_OUTCOMES.len() * 2],
    method_index: usize,
) -> NarRangeMethodStats {
    let count = |outcome: NarRangeOutcome| {
        counters[method_index * NAR_RANGE_OUTCOMES.len() + outcome.index()].load(Ordering::Relaxed)
    };
    NarRangeMethodStats {
        full: count(NarRangeOutcome::Full),
        partial: count(NarRangeOutcome::Partial),
        unsatisfiable: count(NarRangeOutcome::Unsatisfiable),
        invalid: count(NarRangeOutcome::Invalid),
    }
}

fn append_filesystem_metrics(output: &mut String, sample: &SampleState<FilesystemStats>) {
    let (sampled_at, value, state) = match sample {
        SampleState::Measured {
            sampled_at_unix_seconds,
            value,
        } => (*sampled_at_unix_seconds, value, "measured"),
        SampleState::Stale {
            sampled_at_unix_seconds,
            value,
            ..
        } => (*sampled_at_unix_seconds, value, "stale"),
        SampleState::NeverSampled => {
            append_filesystem_availability(output, "never_sampled", false);
            return;
        }
        SampleState::Unavailable { .. } => {
            append_filesystem_availability(output, "unavailable", false);
            return;
        }
    };
    append_filesystem_availability(output, state, state == "measured");
    output.push_str(&format!(
        "# HELP narjar_zfs_sample_timestamp_seconds Timestamp of the latest ZFS sample.\n# TYPE narjar_zfs_sample_timestamp_seconds gauge\nnarjar_zfs_sample_timestamp_seconds {sampled_at}\n\
         # HELP narjar_zfs_sample_age_seconds Age of the latest ZFS sample.\n# TYPE narjar_zfs_sample_age_seconds gauge\nnarjar_zfs_sample_age_seconds {}\n",
        unix_seconds_now().saturating_sub(sampled_at),
    ));
    for (kind, bytes) in [
        ("used", value.used_bytes),
        ("logical_used", value.logical_used_bytes),
        ("referenced", value.referenced_bytes),
        ("logical_referenced", value.logical_referenced_bytes),
        ("used_by_dataset", value.used_by_dataset_bytes),
        ("used_by_snapshots", value.used_by_snapshots_bytes),
        ("used_by_children", value.used_by_children_bytes),
        ("used_by_refreservation", value.used_by_refreservation_bytes),
        ("available", value.available_bytes),
    ] {
        output.push_str(&format!(
            "narjar_zfs_bytes{{kind=\"{kind}\",state=\"{state}\"}} {bytes}\n"
        ));
    }
    for (kind, ratio) in [
        ("compression", value.compression_ratio.as_str()),
        (
            "referenced_compression",
            value.referenced_compression_ratio.as_str(),
        ),
    ] {
        if let Some(ratio) = parse_zfs_ratio(ratio) {
            output.push_str(&format!(
                "narjar_zfs_compression_ratio{{kind=\"{kind}\",state=\"{state}\"}} {ratio}\n"
            ));
        }
    }
    output.push_str(&format!(
        "narjar_zfs_record_size_bytes{{state=\"{state}\"}} {}\n",
        value.record_size_bytes,
    ));
    if let Some(ratio) = value.logical_to_used_ratio {
        output.push_str(&format!(
            "narjar_zfs_logical_to_used_ratio{{state=\"{state}\"}} {ratio}\n"
        ));
    }
    output.push_str(
        "# HELP narjar_zfs_compression_info Configured ZFS compression algorithm; unknown values are grouped as other.\n# TYPE narjar_zfs_compression_info gauge\n# HELP narjar_zfs_compression_level Configured or implied ZFS compression level, when applicable.\n# TYPE narjar_zfs_compression_level gauge\n",
    );
    let (algorithm, level) = zfs_compression_properties(&value.compression);
    output.push_str(&format!(
        "narjar_zfs_compression_info{{algorithm=\"{algorithm}\",state=\"{state}\"}} 1\n"
    ));
    if let Some(level) = level {
        output.push_str(&format!(
            "narjar_zfs_compression_level{{algorithm=\"{algorithm}\",state=\"{state}\"}} {level}\n"
        ));
    }
}

fn zfs_compression_properties(value: &str) -> (&'static str, Option<u64>) {
    match value {
        "on" => ("on", None),
        "off" => ("off", None),
        "lz4" => ("lz4", None),
        "lzjb" => ("lzjb", None),
        "zle" => ("zle", None),
        "gzip" => ("gzip", Some(6)),
        "zstd" => ("zstd", Some(3)),
        "zstd-fast" => ("zstd_fast", Some(1)),
        _ => {
            if let Some(level) = zfs_level(value, "gzip-", 1..=9) {
                return ("gzip", Some(level));
            }
            if let Some(level) = zfs_level(value, "zstd-", 1..=19) {
                return ("zstd", Some(level));
            }
            if let Some(level) = zstd_fast_level(value) {
                return ("zstd_fast", Some(level));
            }
            ("other", None)
        }
    }
}

fn zfs_level(value: &str, prefix: &str, accepted: std::ops::RangeInclusive<u64>) -> Option<u64> {
    let level = value.strip_prefix(prefix)?.parse().ok()?;
    accepted.contains(&level).then_some(level)
}

fn zstd_fast_level(value: &str) -> Option<u64> {
    let level = value.strip_prefix("zstd-fast-")?.parse::<u64>().ok()?;
    (level <= 10 || (20..=100).contains(&level) && level % 10 == 0 || level == 500 || level == 1000)
        .then_some(level)
}

fn append_filesystem_availability(output: &mut String, state: &str, available: bool) {
    output.push_str(
        "# HELP narjar_zfs_sample_available Whether a current ZFS sample is available.\n# TYPE narjar_zfs_sample_available gauge\n",
    );
    output.push_str(&format!(
        "narjar_zfs_sample_available{{state=\"{state}\"}} {}\n",
        u8::from(available),
    ));
}

fn parse_zfs_ratio(value: &str) -> Option<f64> {
    value
        .strip_suffix('x')
        .and_then(|ratio| ratio.parse::<f64>().ok())
        .filter(|ratio| ratio.is_finite() && *ratio > 0.0)
}

fn append_lookup_ratios(output: &mut String, object: &str, method: &str, lookup: &LookupStats) {
    if let Some(hit_ratio) = lookup.hit_ratio {
        output.push_str(&format!(
            "narjar_cache_lookup_hit_ratio{{object=\"{object}\",method=\"{method}\"}} {hit_ratio}\n"
        ));
    }
    if let Some(failure_ratio) = lookup.failure_ratio {
        output.push_str(&format!(
            "narjar_cache_lookup_failure_ratio{{object=\"{object}\",method=\"{method}\"}} {failure_ratio}\n"
        ));
    }
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZfsSampleFile {
    schema_version: u32,
    storage_root: PathBuf,
    dataset: String,
    mountpoint: PathBuf,
    sampled_at_unix_seconds: u64,
    used_bytes: u64,
    logical_used_bytes: u64,
    referenced_bytes: u64,
    logical_referenced_bytes: u64,
    used_by_dataset_bytes: u64,
    used_by_snapshots_bytes: u64,
    used_by_children_bytes: u64,
    used_by_refreservation_bytes: u64,
    available_bytes: u64,
    compression_ratio: String,
    referenced_compression_ratio: String,
    compression: String,
    record_size_bytes: u64,
}

fn read_zfs_sample(
    path: &Path,
    expected_root: &Path,
    now_unix_seconds: u64,
) -> Result<(u64, FilesystemStats), &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let sample_file = options.open(path).map_err(|_| "sample_unreadable")?;
    let metadata = sample_file.metadata().map_err(|_| "sample_unreadable")?;
    if !metadata.is_file() {
        return Err("sample_not_regular_file");
    }
    if metadata.len() > MAX_ZFS_SAMPLE_BYTES {
        return Err("sample_too_large");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    sample_file
        .take(MAX_ZFS_SAMPLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "sample_unreadable")?;
    if bytes.len() as u64 > MAX_ZFS_SAMPLE_BYTES {
        return Err("sample_too_large");
    }
    let sample: ZfsSampleFile = serde_json::from_slice(&bytes).map_err(|_| "sample_invalid")?;
    if sample.schema_version != 1 {
        return Err("sample_version_unsupported");
    }
    if sample.storage_root != expected_root
        || !same_canonical_directory(&sample.mountpoint, expected_root)
    {
        return Err("sample_wrong_storage_root");
    }
    if sample.dataset.is_empty()
        || !valid_zfs_compression_name(&sample.compression)
        || sample.record_size_bytes == 0
        || !valid_zfs_ratio(&sample.compression_ratio)
        || !valid_zfs_ratio(&sample.referenced_compression_ratio)
    {
        return Err("sample_invalid");
    }
    if sample.sampled_at_unix_seconds > now_unix_seconds.saturating_add(30) {
        return Err("sample_timestamp_in_future");
    }
    let sampled_at = sample.sampled_at_unix_seconds;
    let logical_to_used_ratio = (sample.used_bytes != 0)
        .then(|| sample.logical_used_bytes as f64 / sample.used_bytes as f64);
    let value = FilesystemStats {
        used_bytes: sample.used_bytes,
        logical_used_bytes: sample.logical_used_bytes,
        referenced_bytes: sample.referenced_bytes,
        logical_referenced_bytes: sample.logical_referenced_bytes,
        used_by_dataset_bytes: sample.used_by_dataset_bytes,
        used_by_snapshots_bytes: sample.used_by_snapshots_bytes,
        used_by_children_bytes: sample.used_by_children_bytes,
        used_by_refreservation_bytes: sample.used_by_refreservation_bytes,
        available_bytes: sample.available_bytes,
        compression_ratio: sample.compression_ratio,
        referenced_compression_ratio: sample.referenced_compression_ratio,
        compression: sample.compression,
        record_size_bytes: sample.record_size_bytes,
        logical_to_used_ratio,
    };
    Ok((sampled_at, value))
}

fn valid_zfs_ratio(value: &str) -> bool {
    parse_zfs_ratio(value).is_some()
}

fn same_canonical_directory(first: &Path, second: &Path) -> bool {
    first
        .canonicalize()
        .ok()
        .zip(second.canonicalize().ok())
        .is_some_and(|(first, second)| first == second)
}

fn valid_zfs_compression_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn append_process_metrics(output: &mut String, sample: &SampleState<ProcessResources>) {
    let (sampled_at, resources, state) = match sample {
        SampleState::Measured {
            sampled_at_unix_seconds,
            value,
        } => (*sampled_at_unix_seconds, value, "measured"),
        SampleState::Stale {
            sampled_at_unix_seconds,
            value,
            ..
        } => (*sampled_at_unix_seconds, value, "stale"),
        SampleState::NeverSampled => {
            output.push_str(
                "# HELP narjar_process_sample_available Whether process resource sampling has produced a value.\n# TYPE narjar_process_sample_available gauge\nnarjar_process_sample_available 0\n",
            );
            append_process_sample_state(output, "never_sampled");
            return;
        }
        SampleState::Unavailable { .. } => {
            output.push_str(
                "# HELP narjar_process_sample_available Whether process resource sampling has produced a value.\n# TYPE narjar_process_sample_available gauge\nnarjar_process_sample_available 0\n",
            );
            append_process_sample_state(output, "unavailable");
            return;
        }
    };
    append_process_sample_state(output, state);
    output.push_str(&format!(
        "# HELP narjar_process_sample_available Whether process resource sampling has produced a value.\n# TYPE narjar_process_sample_available gauge\nnarjar_process_sample_available 1\n\
         # HELP narjar_process_sample_timestamp_seconds Unix timestamp of the process sample.\n# TYPE narjar_process_sample_timestamp_seconds gauge\nnarjar_process_sample_timestamp_seconds{{state=\"{state}\"}} {sampled_at}\n\
         # HELP narjar_process_resident_memory_bytes Process resident memory in bytes.\n# TYPE narjar_process_resident_memory_bytes gauge\nnarjar_process_resident_memory_bytes{{state=\"{state}\"}} {}\n\
         # HELP narjar_process_cpu_seconds_total Process CPU time by mode.\n# TYPE narjar_process_cpu_seconds_total counter\nnarjar_process_cpu_seconds_total{{mode=\"user\"}} {}\nnarjar_process_cpu_seconds_total{{mode=\"system\"}} {}\n",
        resources.resident_bytes,
        resources.user_cpu_seconds,
        resources.system_cpu_seconds,
    ));
    let source = match resources.source {
        ProcessResourceSource::LinuxProcfs => "linux_procfs",
    };
    output.push_str(&format!(
        "# HELP narjar_process_resource_source_info Source of process resource measurements.\n# TYPE narjar_process_resource_source_info gauge\nnarjar_process_resource_source_info{{source=\"{source}\"}} 1\n"
    ));
    if let Some(high_water_bytes) = resources.high_water_bytes {
        output.push_str(&format!(
            "# HELP narjar_process_high_water_memory_bytes Process high-water resident memory in bytes.\n# TYPE narjar_process_high_water_memory_bytes gauge\nnarjar_process_high_water_memory_bytes{{state=\"{state}\"}} {high_water_bytes}\n"
        ));
    }
    if let Some(threads) = resources.threads {
        output.push_str(&format!(
            "# HELP narjar_process_threads Number of process threads.\n# TYPE narjar_process_threads gauge\nnarjar_process_threads{{state=\"{state}\"}} {threads}\n"
        ));
    }
    if let Some(open_file_descriptors) = resources.open_file_descriptors {
        output.push_str(&format!(
            "# HELP narjar_process_open_file_descriptors Number of open process file descriptors; sampled with a bounded procfs directory read.\n# TYPE narjar_process_open_file_descriptors gauge\nnarjar_process_open_file_descriptors{{state=\"{state}\"}} {open_file_descriptors}\n"
        ));
    }
}

fn append_process_sample_state(output: &mut String, state: &str) {
    output.push_str(&format!(
        "# HELP narjar_process_sample_state State of process resource sampling.\n# TYPE narjar_process_sample_state gauge\nnarjar_process_sample_state{{state=\"{state}\"}} 1\n"
    ));
}

fn append_traffic_rate_metrics(output: &mut String, rates: &RecentTrafficRates) {
    output.push_str(
        "# HELP narjar_http_upload_bytes_per_second Recent upload body throughput in bytes per second.\n# TYPE narjar_http_upload_bytes_per_second gauge\n# HELP narjar_http_artifact_bytes_per_second Recent artifact response throughput in bytes per second.\n# TYPE narjar_http_artifact_bytes_per_second gauge\n# HELP narjar_traffic_rate_window_coverage_seconds Actual elapsed coverage of a recent traffic rate window.\n# TYPE narjar_traffic_rate_window_coverage_seconds gauge\n# HELP narjar_process_cpu_cores Recent process CPU use in fully occupied core equivalents.\n# TYPE narjar_process_cpu_cores gauge\n",
    );
    append_traffic_rate_window(output, "60", rates.one_minute.as_ref());
    append_traffic_rate_window(output, "300", rates.five_minutes.as_ref());
}

fn append_traffic_rate_window(output: &mut String, window: &str, rate: Option<&TrafficRate>) {
    let Some(rate) = rate else {
        return;
    };
    output.push_str(&format!(
        "narjar_http_upload_bytes_per_second{{window=\"{window}\"}} {}\nnarjar_http_artifact_bytes_per_second{{window=\"{window}\"}} {}\nnarjar_traffic_rate_window_coverage_seconds{{window=\"{window}\"}} {}\n",
        rate.upload_bytes_per_second,
        rate.artifact_bytes_per_second,
        rate.coverage_seconds,
    ));
    if let Some(cpu_cores) = rate.process_cpu_cores {
        output.push_str(&format!(
            "narjar_process_cpu_cores{{window=\"{window}\"}} {cpu_cores}\n"
        ));
    }
}

fn append_latency_metrics(output: &mut String, latency: &LatencyStats) {
    output.push_str(
        "# HELP narjar_operation_duration_seconds Operation duration distribution in seconds; lookup ends at object decision and delivery includes socket writing.\n# TYPE narjar_operation_duration_seconds histogram\n",
    );
    append_duration_histogram(output, "nar_lookup", &latency.nar_lookup);
    append_duration_histogram(output, "narinfo_lookup", &latency.narinfo_lookup);
    append_duration_histogram(output, "nar_delivery", &latency.nar_delivery);
    append_duration_histogram(output, "narinfo_delivery", &latency.narinfo_delivery);
    append_duration_histogram(output, "publication", &latency.publication);
    append_duration_histogram(
        output,
        "publication_queue_wait",
        &latency.publication_queue_wait,
    );
}

fn append_duration_histogram(
    output: &mut String,
    operation: &str,
    histogram: &DurationHistogramSnapshot,
) {
    let mut cumulative = 0_u64;
    for (upper_bound, bucket_count) in histogram
        .upper_bounds_seconds
        .iter()
        .zip(histogram.bucket_counts)
    {
        cumulative = cumulative.saturating_add(bucket_count);
        output.push_str(&format!(
            "narjar_operation_duration_seconds_bucket{{operation=\"{operation}\",le=\"{upper_bound}\"}} {cumulative}\n"
        ));
    }
    output.push_str(&format!(
        "narjar_operation_duration_seconds_bucket{{operation=\"{operation}\",le=\"+Inf\"}} {}\nnarjar_operation_duration_seconds_sum{{operation=\"{operation}\"}} {}\nnarjar_operation_duration_seconds_count{{operation=\"{operation}\"}} {}\n",
        histogram.count, histogram.sum_seconds, histogram.count,
    ));
}

fn append_population_metrics(
    output: &mut String,
    sample: &SampleState<PopulationStats>,
    attempt: Option<&PopulationAttempt>,
) {
    output.push_str(
        "# HELP narjar_cache_population_sample_available Whether a complete cache population scan is available.\n# TYPE narjar_cache_population_sample_available gauge\n# HELP narjar_cache_population_refresh_failed Whether the most recent population refresh was incomplete or failed.\n# TYPE narjar_cache_population_refresh_failed gauge\n",
    );
    let sample = PopulationSampleView::from(sample);
    let refresh_failed =
        attempt.is_some_and(|attempt| attempt.quality != PopulationQuality::Complete);
    match sample.availability_label() {
        Some(state) => output.push_str(&format!(
            "narjar_cache_population_sample_available{{state=\"{state}\"}} 1\n"
        )),
        None => output.push_str("narjar_cache_population_sample_available 0\n"),
    }
    output.push_str(&format!(
        "narjar_cache_population_refresh_failed {}\n",
        u8::from(refresh_failed),
    ));
    append_population_attempt_metrics(output, attempt);
    let Some((sampled_at, population, state)) = sample.last_complete() else {
        return;
    };
    append_population_sample_timestamps(output, sampled_at);
    append_population_file_categories(output, population, state);
    append_population_total_bytes(output, population, state);
    append_population_narinfo_counts(output, population, state);
    append_chunked_population_metrics(output, population.chunked.as_ref(), state);
}

#[derive(Clone, Copy)]
enum PopulationSampleView<'a> {
    NeverSampled,
    Unavailable,
    Measured {
        sampled_at: u64,
        population: &'a PopulationStats,
    },
    Stale {
        sampled_at: u64,
        population: &'a PopulationStats,
    },
}

impl<'a> From<&'a SampleState<PopulationStats>> for PopulationSampleView<'a> {
    fn from(sample: &'a SampleState<PopulationStats>) -> Self {
        match sample {
            SampleState::NeverSampled => Self::NeverSampled,
            SampleState::Unavailable { .. } => Self::Unavailable,
            SampleState::Measured {
                sampled_at_unix_seconds,
                value,
            } => Self::Measured {
                sampled_at: *sampled_at_unix_seconds,
                population: value,
            },
            SampleState::Stale {
                sampled_at_unix_seconds,
                value,
                ..
            } => Self::Stale {
                sampled_at: *sampled_at_unix_seconds,
                population: value,
            },
        }
    }
}

impl<'a> PopulationSampleView<'a> {
    const fn availability_label(self) -> Option<&'static str> {
        match self {
            Self::NeverSampled => None,
            Self::Unavailable => Some("unavailable"),
            Self::Measured { .. } => Some("measured"),
            Self::Stale { .. } => Some("stale"),
        }
    }

    const fn last_complete(self) -> Option<(u64, &'a PopulationStats, &'static str)> {
        match self {
            Self::Measured {
                sampled_at,
                population,
            } => Some((sampled_at, population, "measured")),
            Self::Stale {
                sampled_at,
                population,
            } => Some((sampled_at, population, "stale")),
            Self::NeverSampled | Self::Unavailable => None,
        }
    }
}

fn append_population_sample_timestamps(output: &mut String, sampled_at: u64) {
    output.push_str(&format!(
        "# HELP narjar_cache_population_sample_timestamp_seconds Completion time of the last complete population scan.\n# TYPE narjar_cache_population_sample_timestamp_seconds gauge\nnarjar_cache_population_sample_timestamp_seconds {sampled_at}\n\
         # HELP narjar_cache_population_sample_age_seconds Age of the last completed population scan.\n# TYPE narjar_cache_population_sample_age_seconds gauge\nnarjar_cache_population_sample_age_seconds {}\n",
        unix_seconds_now().saturating_sub(sampled_at),
    ));
}

fn append_population_file_categories(
    output: &mut String,
    population: &PopulationStats,
    state: &str,
) {
    output.push_str(
        "# HELP narjar_cache_population_files Observed files by fixed storage category.\n# TYPE narjar_cache_population_files gauge\n# HELP narjar_cache_population_apparent_bytes Sum of observed file lengths by category.\n# TYPE narjar_cache_population_apparent_bytes gauge\n",
    );
    for (kind, count, bytes) in [
        (
            "narinfo",
            population.narinfo_files,
            population.narinfo_bytes,
        ),
        ("raw", population.raw_files, population.raw_bytes),
        ("xz", population.xz_files, population.xz_bytes),
        ("zstd", population.zstd_files, population.zstd_bytes),
        (
            "malformed_nar",
            population.malformed_nar_files,
            population.malformed_nar_bytes,
        ),
        (
            "ingestion_receipt",
            population.ingestion_receipt_files,
            population.ingestion_receipt_bytes,
        ),
        (
            "egress_receipt",
            population.egress_receipt_files,
            population.egress_receipt_bytes,
        ),
        (
            "validation",
            population.validation_files,
            population.validation_bytes,
        ),
        (
            "transaction",
            population.transaction_files,
            population.transaction_bytes,
        ),
        (
            "temporary",
            population.temporary_files,
            population.temporary_bytes,
        ),
    ] {
        output.push_str(&format!(
            "narjar_cache_population_files{{kind=\"{kind}\",state=\"{state}\"}} {count}\nnarjar_cache_population_apparent_bytes{{kind=\"{kind}\",state=\"{state}\"}} {bytes}\n"
        ));
    }
}

fn append_population_total_bytes(output: &mut String, population: &PopulationStats, state: &str) {
    output.push_str(&format!(
        "narjar_cache_population_apparent_bytes{{kind=\"total\",state=\"{state}\"}} {}\nnarjar_cache_population_narinfo_claimed_nar_bytes{{state=\"{state}\"}} {}\n",
        population.apparent_file_bytes,
        population.narinfo_claimed_nar_bytes,
    ));
}

fn append_population_narinfo_counts(
    output: &mut String,
    population: &PopulationStats,
    state: &str,
) {
    output.push_str(
        "# HELP narjar_cache_population_narinfo_entries Narinfo pathname outcomes from the last complete population scan.\n# TYPE narjar_cache_population_narinfo_entries gauge\n# HELP narjar_cache_population_narinfo_claimed_nar_bytes Sum of valid narinfo NarSize claims, counted once per store path.\n# TYPE narjar_cache_population_narinfo_claimed_nar_bytes gauge\n",
    );
    for (kind, count) in [
        ("parsed", population.structurally_valid_narinfo_entries),
        ("malformed_filename", population.malformed_narinfo_filenames),
        ("malformed_contents", population.malformed_narinfo_contents),
        ("unreadable", population.narinfo_read_errors),
    ] {
        output.push_str(&format!(
            "narjar_cache_population_narinfo_entries{{kind=\"{kind}\",state=\"{state}\"}} {count}\n"
        ));
    }
}

fn append_chunked_population_metrics(
    output: &mut String,
    chunked: Option<&ChunkedPopulationStats>,
    state: &str,
) {
    if let Some(chunked) = chunked {
        output.push_str(
            "# HELP narjar_cache_population_logical_nars Distinct structurally valid canonical NAR manifests.\n# TYPE narjar_cache_population_logical_nars gauge\n# HELP narjar_cache_population_logical_nar_bytes Sum of logical NAR sizes in valid chunk manifests.\n# TYPE narjar_cache_population_logical_nar_bytes gauge\n",
        );
        output.push_str(&format!(
            "narjar_cache_population_logical_nars{{state=\"{state}\"}} {}\nnarjar_cache_population_logical_nar_bytes{{state=\"{state}\"}} {}\n",
            chunked.nars, chunked.logical_nar_bytes,
        ));
        for (kind, count, bytes) in [
            ("chunk", chunked.chunk_files, chunked.chunk_bytes),
            ("manifest", chunked.manifest_files, chunked.manifest_bytes),
        ] {
            output.push_str(&format!(
                "narjar_cache_population_files{{kind=\"{kind}\",state=\"{state}\"}} {count}\nnarjar_cache_population_apparent_bytes{{kind=\"{kind}\",state=\"{state}\"}} {bytes}\n"
            ));
        }
    }
}

fn append_population_attempt_metrics(output: &mut String, attempt: Option<&PopulationAttempt>) {
    output.push_str(
        "# HELP narjar_cache_population_scan_started_timestamp_seconds Unix time when the most recent population scan started.\n# TYPE narjar_cache_population_scan_started_timestamp_seconds gauge\n# HELP narjar_cache_population_scan_timestamp_seconds Unix time when the most recent population scan attempt ended.\n# TYPE narjar_cache_population_scan_timestamp_seconds gauge\n# HELP narjar_cache_population_scan_duration_seconds Monotonic duration of the most recent population scan attempt.\n# TYPE narjar_cache_population_scan_duration_seconds gauge\n# HELP narjar_cache_population_scan_quality Quality of the most recent population scan attempt.\n# TYPE narjar_cache_population_scan_quality gauge\n# HELP narjar_cache_population_scan_entries Directory entries visited during the most recent population scan attempt.\n# TYPE narjar_cache_population_scan_entries gauge\n# HELP narjar_cache_population_scan_ignored_entries Entries outside recognized cache categories.\n# TYPE narjar_cache_population_scan_ignored_entries gauge\n# HELP narjar_cache_population_scan_disappeared_entries Entries that disappeared during the scan.\n# TYPE narjar_cache_population_scan_disappeared_entries gauge\n# HELP narjar_cache_population_scan_errors Entries that could not be inspected during the scan.\n# TYPE narjar_cache_population_scan_errors gauge\n",
    );
    output.push_str(
        "# HELP narjar_cache_population_scan_narinfo_read_errors Narinfo entries unreadable during the most recent scan attempt.\n# TYPE narjar_cache_population_scan_narinfo_read_errors gauge\n",
    );
    let Some(attempt) = attempt else {
        return;
    };
    output.push_str(&format!(
        "narjar_cache_population_scan_started_timestamp_seconds {}\nnarjar_cache_population_scan_timestamp_seconds {}\nnarjar_cache_population_scan_duration_seconds {}\n",
        attempt.started_at_unix_seconds,
        attempt.completed_at_unix_seconds,
        attempt.elapsed_seconds,
    ));
    for quality in [
        PopulationQuality::Complete,
        PopulationQuality::ChangedDuringScan,
        PopulationQuality::EntryErrors,
        PopulationQuality::Failed,
    ] {
        let quality_name = match quality {
            PopulationQuality::Complete => "complete",
            PopulationQuality::ChangedDuringScan => "changed_during_scan",
            PopulationQuality::EntryErrors => "entry_errors",
            PopulationQuality::Failed => "failed",
        };
        output.push_str(&format!(
            "narjar_cache_population_scan_quality{{quality=\"{quality_name}\"}} {}\n",
            u8::from(attempt.quality == quality),
        ));
    }
    if let Some(coverage) = &attempt.coverage {
        output.push_str(&format!(
            "narjar_cache_population_scan_entries {}\nnarjar_cache_population_scan_ignored_entries {}\nnarjar_cache_population_scan_disappeared_entries {}\nnarjar_cache_population_scan_errors {}\n",
            coverage.scanned_entries,
            coverage.ignored_entries,
            coverage.disappeared_entries,
            coverage.errors,
        ));
        output.push_str(&format!(
            "narjar_cache_population_scan_narinfo_read_errors {}\n",
            coverage.narinfo_read_errors,
        ));
    }
}

fn next_sample_state<T: Clone>(
    previous: &SampleState<T>,
    sampled: Result<T, ()>,
    sampled_at_unix_seconds: u64,
    failure_reason: &'static str,
) -> SampleState<T> {
    match sampled {
        Ok(value) => SampleState::Measured {
            sampled_at_unix_seconds,
            value,
        },
        Err(()) => match previous {
            SampleState::Measured {
                sampled_at_unix_seconds,
                value,
            }
            | SampleState::Stale {
                sampled_at_unix_seconds,
                value,
                ..
            } => SampleState::Stale {
                sampled_at_unix_seconds: *sampled_at_unix_seconds,
                value: value.clone(),
                reason: failure_reason.to_owned(),
            },
            SampleState::NeverSampled | SampleState::Unavailable { .. } => {
                SampleState::Unavailable {
                    reason: failure_reason.to_owned(),
                }
            }
        },
    }
}

#[cfg(target_os = "linux")]
fn sample_process_resources() -> Result<ProcessResources, ()> {
    let status = read_bounded_text("/proc/self/status", 64 * 1024)?;
    let resident_bytes = status_value_kib(&status, "VmRSS:").ok_or(())?;
    let high_water_bytes = status_value_kib(&status, "VmHWM:");
    let threads = status_value(&status, "Threads:");
    let open_file_descriptors = process_open_file_descriptors();
    let (user_cpu_seconds, system_cpu_seconds) = process_cpu_seconds()?;
    Ok(ProcessResources {
        source: ProcessResourceSource::LinuxProcfs,
        resident_bytes,
        high_water_bytes,
        user_cpu_seconds,
        system_cpu_seconds,
        threads,
        open_file_descriptors,
    })
}

#[cfg(not(target_os = "linux"))]
fn sample_process_resources() -> Result<ProcessResources, ()> {
    Err(())
}

#[cfg(target_os = "linux")]
fn read_bounded_text(path: impl AsRef<Path>, limit: u64) -> Result<String, ()> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| ())?
        .take(limit.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|_| ())?;
    (text.len() as u64 <= limit).then_some(text).ok_or(())
}

#[cfg(target_os = "linux")]
fn status_value_kib(status: &str, name: &str) -> Option<u64> {
    status_value(status, name)?.checked_mul(1024)
}

#[cfg(target_os = "linux")]
fn status_value(status: &str, name: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn process_cpu_seconds() -> Result<(f64, f64), ()> {
    let stat = read_bounded_text("/proc/self/stat", 16 * 1024)?;
    let fields = stat
        .rsplit_once(')')
        .ok_or(())?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let user_ticks: u64 = fields.get(11).ok_or(())?.parse().map_err(|_| ())?;
    let system_ticks: u64 = fields.get(12).ok_or(())?.parse().map_err(|_| ())?;
    // SAFETY: sysconf reads a process-wide constant and takes no pointer arguments.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return Err(());
    }
    Ok((
        user_ticks as f64 / ticks_per_second as f64,
        system_ticks as f64 / ticks_per_second as f64,
    ))
}

#[cfg(target_os = "linux")]
fn process_open_file_descriptors() -> Option<u64> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    let observed = entries
        .take(MAX_PROCESS_FD_ENTRIES + 1)
        .try_fold(0_u64, |count, entry| {
            entry.ok()?;
            count.checked_add(1)
        })?;
    (observed <= MAX_PROCESS_FD_ENTRIES as u64).then_some(observed.saturating_sub(1))
}

fn lookup_snapshot(counters: &[AtomicU64; 3]) -> LookupStats {
    let hits = counters[CacheLookupOutcome::Hit.index()].load(Ordering::Relaxed);
    let misses = counters[CacheLookupOutcome::Miss.index()].load(Ordering::Relaxed);
    let failures = counters[CacheLookupOutcome::Failure.index()].load(Ordering::Relaxed);
    let eligible = hits.saturating_add(misses);
    let decisions = eligible.saturating_add(failures);
    LookupStats {
        hits,
        misses,
        failures,
        decisions,
        hit_ratio: ratio(hits, eligible),
        failure_ratio: ratio(failures, decisions),
    }
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

#[derive(Clone, Copy, Debug)]
struct TrafficSample {
    at: Instant,
    upload_bytes: u64,
    download_bytes: u64,
    process_cpu_seconds: Option<f64>,
    byte_counters_overflowed: bool,
}

#[derive(Debug)]
struct TrafficSamples {
    samples: [Option<TrafficSample>; TRAFFIC_SAMPLE_CAPACITY],
    next: usize,
    len: usize,
}

impl Default for TrafficSamples {
    fn default() -> Self {
        Self {
            samples: [None; TRAFFIC_SAMPLE_CAPACITY],
            next: 0,
            len: 0,
        }
    }
}

impl TrafficSamples {
    fn record(&mut self, sample: TrafficSample) {
        self.samples[self.next] = Some(sample);
        self.next = (self.next + 1) % TRAFFIC_SAMPLE_CAPACITY;
        self.len = (self.len + 1).min(TRAFFIC_SAMPLE_CAPACITY);
    }

    fn rates(&self) -> RecentTrafficRates {
        RecentTrafficRates {
            one_minute: self.rate_over(60),
            five_minutes: self.rate_over(300),
        }
    }

    fn rate_over(&self, window_seconds: u64) -> Option<TrafficRate> {
        let oldest_index =
            (self.next + TRAFFIC_SAMPLE_CAPACITY - self.len) % TRAFFIC_SAMPLE_CAPACITY;
        let samples = (0..self.len)
            .filter_map(|offset| self.samples[(oldest_index + offset) % TRAFFIC_SAMPLE_CAPACITY]);
        let mut samples = samples.peekable();
        let first = samples.next()?;
        let latest = samples.last().unwrap_or(first);
        if latest.byte_counters_overflowed {
            return None;
        }
        let cutoff = latest.at - Duration::from_secs(window_seconds);
        let first_in_window = (0..self.len)
            .filter_map(|offset| self.samples[(oldest_index + offset) % TRAFFIC_SAMPLE_CAPACITY])
            .find(|sample| sample.at >= cutoff)?;
        let coverage = latest.at.duration_since(first_in_window.at).as_secs_f64();
        let uploaded_bytes = latest
            .upload_bytes
            .checked_sub(first_in_window.upload_bytes)?;
        let downloaded_bytes = latest
            .download_bytes
            .checked_sub(first_in_window.download_bytes)?;
        (coverage > 0.0).then(|| TrafficRate {
            requested_window_seconds: window_seconds,
            coverage_seconds: coverage,
            upload_bytes_per_second: uploaded_bytes as f64 / coverage,
            artifact_bytes_per_second: downloaded_bytes as f64 / coverage,
            process_cpu_cores: match (
                first_in_window.process_cpu_seconds,
                latest.process_cpu_seconds,
            ) {
                (Some(first), Some(latest)) if latest >= first => Some((latest - first) / coverage),
                _ => None,
            },
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CacheLookupOutcome {
    Hit,
    Miss,
    Failure,
}

#[derive(Clone, Copy, Debug)]
pub enum ConnectionOutcome {
    Admitted,
    AdmissionRejected,
    RequestQueueFull,
    MalformedRequest,
    TimedOut,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestRecordingState {
    Pending,
    Finished,
}

#[derive(Clone, Copy, Debug)]
enum ResponseTransferFailureKind {
    TimedOut,
    Disconnected,
    Other,
}

impl ResponseTransferFailureKind {
    const fn index(self) -> usize {
        match self {
            Self::TimedOut => 0,
            Self::Disconnected => 1,
            Self::Other => 2,
        }
    }

    fn from_error(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::TimedOut,
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::WriteZero => Self::Disconnected,
            _ => Self::Other,
        }
    }
}

impl ConnectionOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Admitted => 0,
            Self::AdmissionRejected => 1,
            Self::RequestQueueFull => 2,
            Self::MalformedRequest => 3,
            Self::TimedOut => 4,
            Self::Disconnected => 5,
        }
    }
}

impl CacheLookupOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Hit => 0,
            Self::Miss => 1,
            Self::Failure => 2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CacheObject {
    Nar,
    NarInfo,
}

#[derive(Clone, Debug)]
pub struct StatsSnapshot {
    pub http_requests: Vec<HttpRequestCount>,
    pub connections: ConnectionStats,
    pub response_transfer_failures: ResponseTransferFailureStats,
    pub publication_outcomes: PublicationOutcomeStats,
    pub(crate) storage_activity: StorageActivitySnapshot,
    pub process: ProcessStats,
    pub cache: CacheStats,
    pub nar_range_requests: NarRangeStats,
    pub latency: LatencyStats,
    pub traffic: TrafficStats,
    pub reliability: ReliabilityStats,
    pub pressure: PressureStats,
    pub inventory: SampleState<PopulationStats>,
    pub(crate) inventory_attempt: Option<PopulationAttempt>,
    pub filesystem: SampleState<FilesystemStats>,
    pub maintenance: SampleState<maintenance::Snapshot>,
}

#[derive(Clone, Debug)]
pub struct HttpRequestCount {
    pub method: String,
    pub route: String,
    pub status_code: String,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct ConnectionStats {
    pub admitted: u64,
    pub admission_rejected: u64,
    pub request_queue_full: u64,
    pub malformed_requests: u64,
    pub timeouts: u64,
    pub disconnected: u64,
}

#[derive(Clone, Debug)]
pub struct ResponseTransferFailureStats {
    pub timed_out: u64,
    pub disconnected: u64,
    pub other: u64,
}

#[derive(Clone, Debug)]
pub struct PublicationOutcomeStats {
    pub created: u64,
    pub identical: u64,
    pub conflicts: u64,
    pub failures: u64,
}

#[derive(Clone, Debug)]
pub struct ReliabilityStats {
    pub auth_read_failures: u64,
    pub auth_write_failures: u64,
    pub validation_body_failures: u64,
    pub validation_nar_failures: u64,
    pub validation_narinfo_failures: u64,
    pub capacity_no_space: u64,
    pub capacity_quota: u64,
    pub capacity_inodes: u64,
    pub capacity_read_only: u64,
}

#[derive(Clone, Debug)]
pub struct LatencyStats {
    pub nar_lookup: DurationHistogramSnapshot,
    pub narinfo_lookup: DurationHistogramSnapshot,
    pub nar_delivery: DurationHistogramSnapshot,
    pub narinfo_delivery: DurationHistogramSnapshot,
    pub publication: DurationHistogramSnapshot,
    pub publication_queue_wait: DurationHistogramSnapshot,
}

#[derive(Clone, Debug)]
pub struct DurationHistogramSnapshot {
    pub count: u64,
    pub sum_seconds: f64,
    pub max_seconds: f64,
    pub upper_bounds_seconds: [f64; 13],
    pub bucket_counts: [u64; LATENCY_BUCKETS],
}

#[derive(Clone, Debug)]
pub struct ProcessStats {
    pub started_at_unix_seconds: u64,
    pub uptime_seconds: u64,
    pub resources: SampleState<ProcessResources>,
}

#[derive(Clone, Debug)]
pub enum SampleState<T> {
    NeverSampled,
    Measured {
        sampled_at_unix_seconds: u64,
        value: T,
    },
    Stale {
        sampled_at_unix_seconds: u64,
        value: T,
        reason: String,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug)]
struct PopulationSamples {
    last_complete: SampleState<PopulationStats>,
    last_attempt: Option<PopulationAttempt>,
}

impl Default for PopulationSamples {
    fn default() -> Self {
        Self {
            last_complete: SampleState::NeverSampled,
            last_attempt: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PopulationAttempt {
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
    elapsed_seconds: f64,
    quality: PopulationQuality,
    coverage: Option<PopulationScanCoverage>,
}

#[derive(Clone, Debug)]
struct PopulationScanCoverage {
    scanned_entries: u64,
    ignored_entries: u64,
    disappeared_entries: u64,
    errors: u64,
    narinfo_read_errors: u64,
}

impl PopulationScanCoverage {
    fn from_counts(counts: &PopulationCounts) -> Self {
        Self {
            scanned_entries: counts.scanned_entries,
            ignored_entries: counts.ignored_entries,
            disappeared_entries: counts.disappeared_entries,
            errors: counts.errors,
            narinfo_read_errors: counts.narinfo_read_errors,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessResources {
    pub source: ProcessResourceSource,
    pub resident_bytes: u64,
    pub high_water_bytes: Option<u64>,
    pub user_cpu_seconds: f64,
    pub system_cpu_seconds: f64,
    pub threads: Option<u64>,
    pub open_file_descriptors: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub enum ProcessResourceSource {
    LinuxProcfs,
}

#[derive(Clone, Debug)]
pub struct CacheStats {
    pub nar_get: LookupStats,
    pub nar_head: LookupStats,
    pub narinfo_get: LookupStats,
    pub narinfo_head: LookupStats,
}

impl CacheStats {
    fn lookups(&self) -> [(&'static str, &'static str, &LookupStats); 4] {
        [
            ("nar", "GET", &self.nar_get),
            ("nar", "HEAD", &self.nar_head),
            ("narinfo", "GET", &self.narinfo_get),
            ("narinfo", "HEAD", &self.narinfo_head),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct NarRangeStats {
    pub get: NarRangeMethodStats,
    pub head: NarRangeMethodStats,
}

#[derive(Clone, Debug)]
pub struct NarRangeMethodStats {
    pub full: u64,
    pub partial: u64,
    pub unsatisfiable: u64,
    pub invalid: u64,
}

impl NarRangeMethodStats {
    const fn count(&self, outcome: NarRangeOutcome) -> u64 {
        match outcome {
            NarRangeOutcome::Full => self.full,
            NarRangeOutcome::Partial => self.partial,
            NarRangeOutcome::Unsatisfiable => self.unsatisfiable,
            NarRangeOutcome::Invalid => self.invalid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LookupStats {
    pub hits: u64,
    pub misses: u64,
    pub failures: u64,
    pub decisions: u64,
    pub hit_ratio: Option<f64>,
    pub failure_ratio: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct TrafficStats {
    pub requests_in_flight: u64,
    pub uploads_in_flight: u64,
    pub declared_upload_bytes: u64,
    pub received_upload_body_bytes: u64,
    pub response_body_bytes: u64,
    pub completed_responses: u64,
    pub aborted_responses: u64,
    pub cumulative_byte_counters_overflowed: bool,
    pub recent_rates: RecentTrafficRates,
}

#[derive(Clone, Debug)]
pub struct RecentTrafficRates {
    pub one_minute: Option<TrafficRate>,
    pub five_minutes: Option<TrafficRate>,
}

#[derive(Clone, Debug)]
pub struct TrafficRate {
    pub requested_window_seconds: u64,
    pub coverage_seconds: f64,
    pub upload_bytes_per_second: f64,
    pub artifact_bytes_per_second: f64,
    pub process_cpu_cores: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct PressureStats {
    pub readiness: StorageReadiness,
    pub temporary_objects: u64,
    pub connections_in_flight: u64,
    pub connections_limit: u64,
    pub request_queue_depth: u64,
    pub request_queue_capacity: u64,
    pub active_publication_workers: u64,
    pub publication_worker_limit: u64,
    pub publication_queue_depth: u64,
    pub publication_queue_capacity: u64,
    pub capacity: Option<CapacityStats>,
}

#[derive(Clone, Debug)]
pub struct CapacityStats {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
    pub read_only: bool,
    pub configured_min_free_bytes: u64,
    pub outstanding_staging_bytes: u64,
    pub estimated_headroom_bytes: u64,
}

impl CapacityStats {
    fn from_storage(
        capacity: StorageCapacity,
        configured_min_free_bytes: u64,
        outstanding_staging_bytes: u64,
    ) -> Self {
        Self {
            total_bytes: capacity.total_bytes,
            available_bytes: capacity.available_bytes,
            total_inodes: capacity.total_inodes,
            available_inodes: capacity.available_inodes,
            read_only: capacity.read_only,
            configured_min_free_bytes,
            outstanding_staging_bytes,
            estimated_headroom_bytes: capacity
                .available_bytes
                .saturating_sub(configured_min_free_bytes)
                .saturating_sub(outstanding_staging_bytes),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FilesystemStats {
    pub used_bytes: u64,
    pub logical_used_bytes: u64,
    pub referenced_bytes: u64,
    pub logical_referenced_bytes: u64,
    pub used_by_dataset_bytes: u64,
    pub used_by_snapshots_bytes: u64,
    pub used_by_children_bytes: u64,
    pub used_by_refreservation_bytes: u64,
    pub available_bytes: u64,
    pub compression_ratio: String,
    pub referenced_compression_ratio: String,
    pub compression: String,
    pub record_size_bytes: u64,
    pub logical_to_used_ratio: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct PopulationStats {
    pub backend: StorageBackend,
    pub structurally_valid_narinfo_entries: u64,
    pub malformed_narinfo_filenames: u64,
    pub malformed_narinfo_contents: u64,
    pub narinfo_read_errors: u64,
    pub narinfo_files: u64,
    pub narinfo_bytes: u64,
    pub narinfo_claimed_nar_bytes: u64,
    pub malformed_nar_files: u64,
    pub malformed_nar_bytes: u64,
    pub raw_files: u64,
    pub raw_bytes: u64,
    pub xz_files: u64,
    pub xz_bytes: u64,
    pub zstd_files: u64,
    pub zstd_bytes: u64,
    pub chunked: Option<ChunkedPopulationStats>,
    pub ingestion_receipt_files: u64,
    pub ingestion_receipt_bytes: u64,
    pub egress_receipt_files: u64,
    pub egress_receipt_bytes: u64,
    pub validation_files: u64,
    pub validation_bytes: u64,
    pub transaction_files: u64,
    pub transaction_bytes: u64,
    pub temporary_files: u64,
    pub temporary_bytes: u64,
    pub apparent_file_bytes: u64,
}

impl PopulationStats {
    fn from_scan(backend: StorageBackend, counts: PopulationCounts) -> Self {
        Self {
            backend,
            structurally_valid_narinfo_entries: counts.structurally_valid_narinfo_entries,
            malformed_narinfo_filenames: counts.malformed_narinfo_filenames,
            malformed_narinfo_contents: counts.malformed_narinfo_contents,
            narinfo_read_errors: counts.narinfo_read_errors,
            narinfo_files: counts.narinfo_files,
            narinfo_bytes: counts.narinfo_bytes,
            narinfo_claimed_nar_bytes: counts.narinfo_claimed_nar_bytes,
            malformed_nar_files: counts.malformed_nar_files,
            malformed_nar_bytes: counts.malformed_nar_bytes,
            raw_files: counts.raw_files,
            raw_bytes: counts.raw_bytes,
            xz_files: counts.xz_files,
            xz_bytes: counts.xz_bytes,
            zstd_files: counts.zstd_files,
            zstd_bytes: counts.zstd_bytes,
            chunked: match backend {
                StorageBackend::Flat => None,
                StorageBackend::Chunked => Some(ChunkedPopulationStats {
                    chunk_files: counts.chunk_files,
                    chunk_bytes: counts.chunk_bytes,
                    manifest_files: counts.manifest_files,
                    manifest_bytes: counts.manifest_bytes,
                    nars: counts.chunked_nars,
                    logical_nar_bytes: counts.chunked_nar_bytes,
                }),
            },
            ingestion_receipt_files: counts.ingestion_receipt_files,
            ingestion_receipt_bytes: counts.ingestion_receipt_bytes,
            egress_receipt_files: counts.egress_receipt_files,
            egress_receipt_bytes: counts.egress_receipt_bytes,
            validation_files: counts.validation_files,
            validation_bytes: counts.validation_bytes,
            transaction_files: counts.transaction_files,
            transaction_bytes: counts.transaction_bytes,
            temporary_files: counts.temporary_files,
            temporary_bytes: counts.temporary_bytes,
            apparent_file_bytes: counts.apparent_file_bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChunkedPopulationStats {
    pub chunk_files: u64,
    pub chunk_bytes: u64,
    pub manifest_files: u64,
    pub manifest_bytes: u64,
    pub nars: u64,
    pub logical_nar_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PopulationQuality {
    Complete,
    ChangedDuringScan,
    EntryErrors,
    Failed,
}

impl PopulationQuality {
    fn from_counts(counts: &PopulationCounts) -> Self {
        match (counts.errors, counts.disappeared_entries) {
            (0, 0) => Self::Complete,
            (0, _) => Self::ChangedDuringScan,
            _ => Self::EntryErrors,
        }
    }
}

fn request_index(method: usize, route: usize, status: usize) -> usize {
    (method * ROUTES.len() + route) * STATUS_CODES.len() + status
}

fn status_index(status: u16) -> usize {
    STATUS_CODES
        .iter()
        .position(|(_, code)| *code == Some(status))
        .unwrap_or(STATUS_CODES.len() - 1)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ValidationClass {
    Body,
    Nar,
    NarInfo,
}

pub(crate) struct RequestGuard<'a> {
    metrics: &'a Metrics,
    method: RequestMethod,
    route: RequestRoute,
    recording: Cell<RequestRecordingState>,
}

impl RequestGuard<'_> {
    pub(crate) fn record_nar_range_request(&self, outcome: NarRangeOutcome) {
        let method_index = match self.method {
            RequestMethod::Get => 0,
            RequestMethod::Head => 1,
            RequestMethod::Put | RequestMethod::Other => return,
        };
        let counter_index = method_index * NAR_RANGE_OUTCOMES.len() + outcome.index();
        saturating_atomic_add(&self.metrics.nar_range_requests[counter_index], 1);
    }

    pub(crate) fn record_cache_lookup(
        &self,
        object: CacheObject,
        outcome: CacheLookupOutcome,
        elapsed: Duration,
    ) {
        self.metrics.cache_lookup(object, self.method, outcome);
        match object {
            CacheObject::Nar => self.metrics.nar_lookup_latency.observe(elapsed),
            CacheObject::NarInfo => self.metrics.narinfo_lookup_latency.observe(elapsed),
        }
    }

    pub(crate) fn record_completed_response(
        &self,
        status: StatusCode,
        body_bytes: u64,
        elapsed: Duration,
    ) {
        match self.recording.replace(RequestRecordingState::Finished) {
            RequestRecordingState::Pending => {}
            RequestRecordingState::Finished => return,
        }
        self.record_status(status);
        self.metrics
            .completed_responses
            .fetch_add(1, Ordering::Relaxed);
        self.record_artifact_bytes(body_bytes);
        self.record_delivery_latency(elapsed);
    }

    pub(crate) fn record_failed_response(
        &self,
        status: StatusCode,
        transfer: TransferFailure,
        elapsed: Duration,
    ) {
        match self.recording.replace(RequestRecordingState::Finished) {
            RequestRecordingState::Pending => {}
            RequestRecordingState::Finished => return,
        }
        self.record_status(status);
        self.metrics
            .aborted_responses
            .fetch_add(1, Ordering::Relaxed);
        self.metrics.record_response_transfer_failure(&transfer);
        self.record_artifact_bytes(transfer.body_bytes);
        self.record_delivery_latency(elapsed);
    }

    fn record_delivery_latency(&self, elapsed: Duration) {
        match self.route {
            RequestRoute::Nar => self.metrics.nar_delivery_latency.observe(elapsed),
            RequestRoute::NarInfo => self.metrics.narinfo_delivery_latency.observe(elapsed),
            _ => {}
        }
    }

    fn record_artifact_bytes(&self, body_bytes: u64) {
        if self.route.is_artifact() {
            self.metrics.bytes_out(body_bytes);
        }
    }

    fn record_status(&self, status: StatusCode) {
        self.metrics.requests[request_index(
            self.method.index(),
            self.route.index(),
            status_index(status.get()),
        )]
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_aborted_response(&self) {
        match self.recording.replace(RequestRecordingState::Finished) {
            RequestRecordingState::Pending => {}
            RequestRecordingState::Finished => return,
        }
        self.metrics.requests
            [request_index(self.method.index(), self.route.index(), status_index(0))]
        .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .aborted_responses
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        match self.recording.replace(RequestRecordingState::Finished) {
            RequestRecordingState::Pending => {
                self.metrics.requests
                    [request_index(self.method.index(), self.route.index(), status_index(0))]
                .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .aborted_responses
                    .fetch_add(1, Ordering::Relaxed);
            }
            RequestRecordingState::Finished => {}
        }
        self.metrics
            .requests_in_flight
            .fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct UploadGuard<'a>(&'a Metrics);

impl Drop for UploadGuard<'_> {
    fn drop(&mut self) {
        self.0.uploads_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CacheLookupOutcome, CacheObject, ConnectionOutcome, FilesystemStats, Metrics,
        NarRangeOutcome, PopulationScanFailure, RequestMethod, RequestRoute, SampleState,
        StorageActivitySnapshot, ValidationClass, append_storage_activity_metrics,
        render_prometheus,
    };
    use crate::http_server::{StatusCode, TransferFailure};
    use crate::maintenance::{Mode, Operation, Outcome, Recorder, RunValues};
    use crate::storage::{
        PopulationCounts, PublishOutcome, StorageBackend, StorageCapacity, StorageError,
        StorageReadiness,
    };
    use std::{
        os::unix::fs::symlink,
        path::Path,
        time::{Duration, Instant},
    };

    fn zfs_sample_document(storage_root: &Path, mountpoint: &Path) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "storage_root": storage_root,
            "dataset": "tank/narjar",
            "mountpoint": mountpoint,
            "sampled_at_unix_seconds": super::unix_seconds_now(),
            "used_bytes": 20,
            "logical_used_bytes": 50,
            "referenced_bytes": 18,
            "logical_referenced_bytes": 45,
            "used_by_dataset_bytes": 17,
            "used_by_snapshots_bytes": 2,
            "used_by_children_bytes": 1,
            "used_by_refreservation_bytes": 0,
            "available_bytes": 80,
            "compression_ratio": "2.50x",
            "referenced_compression_ratio": "2.25x",
            "compression": "off",
            "record_size_bytes": 1_048_576,
        })
    }

    #[test]
    fn process_lifetime_is_exported_with_unix_timestamps() {
        let snapshot = Metrics::default().snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        let exposition = render_prometheus(&snapshot);
        assert!(exposition.contains("narjar_stats_snapshot_timestamp_seconds "));
        assert!(exposition.contains("narjar_process_start_time_seconds "));
        assert!(exposition.contains("narjar_process_uptime_seconds "));
        assert!(exposition.contains("narjar_readiness{reason=\"available\"} 1"));
        assert!(!exposition.contains("narjar_chunks_total"));
    }

    #[test]
    fn readiness_exposition_identifies_the_actual_capacity_reason() {
        let snapshot = Metrics::default().snapshot(StorageReadiness::NoInodes, None, 0, 0, 0);
        let exposition = render_prometheus(&snapshot);
        assert!(exposition.contains("narjar_ready 0"));
        assert!(exposition.contains("narjar_readiness{reason=\"no_inodes\"} 1"));
        assert!(exposition.contains("narjar_readiness{reason=\"available\"} 0"));
    }

    #[test]
    fn nar_range_outcomes_are_counted_with_fixed_labels() {
        let metrics = Metrics::default();
        let guard = metrics.request(RequestMethod::Get, RequestRoute::Nar);
        for outcome in [
            NarRangeOutcome::Full,
            NarRangeOutcome::Partial,
            NarRangeOutcome::Partial,
            NarRangeOutcome::Unsatisfiable,
            NarRangeOutcome::Invalid,
        ] {
            guard.record_nar_range_request(outcome);
        }
        drop(guard);
        let head = metrics.request(RequestMethod::Head, RequestRoute::Nar);
        head.record_nar_range_request(NarRangeOutcome::Partial);
        drop(head);

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert_eq!(snapshot.nar_range_requests.get.full, 1);
        assert_eq!(snapshot.nar_range_requests.get.partial, 2);
        assert_eq!(snapshot.nar_range_requests.get.unsatisfiable, 1);
        assert_eq!(snapshot.nar_range_requests.get.invalid, 1);
        assert_eq!(snapshot.nar_range_requests.head.partial, 1);

        let exposition = render_prometheus(&snapshot);
        assert!(
            exposition
                .contains("narjar_nar_range_requests_total{method=\"GET\",outcome=\"full\"} 1")
        );
        assert!(
            exposition
                .contains("narjar_nar_range_requests_total{method=\"GET\",outcome=\"partial\"} 2")
        );
        assert!(exposition.contains(
            "narjar_nar_range_requests_total{method=\"GET\",outcome=\"unsatisfiable\"} 1"
        ));
        assert!(
            exposition
                .contains("narjar_nar_range_requests_total{method=\"GET\",outcome=\"invalid\"} 1")
        );
        assert!(
            exposition
                .contains("narjar_nar_range_requests_total{method=\"HEAD\",outcome=\"partial\"} 1")
        );
    }

    #[test]
    fn failed_population_refresh_keeps_the_last_complete_sample() {
        let metrics = Metrics::default();
        let counts = PopulationCounts {
            scanned_entries: 17,
            ignored_entries: 3,
            disappeared_entries: 0,
            errors: 0,
            structurally_valid_narinfo_entries: 4,
            malformed_narinfo_filenames: 2,
            malformed_narinfo_contents: 3,
            narinfo_read_errors: 0,
            narinfo_files: 10,
            narinfo_claimed_nar_bytes: 360,
            malformed_nar_files: 1,
            malformed_nar_bytes: 20,
            raw_bytes: 900,
            ..PopulationCounts::default()
        };
        let started_at = super::unix_seconds_now().saturating_sub(3);
        metrics.record_population_scan(StorageBackend::Flat, Ok(counts), started_at, 2.5);

        let first = metrics
            .snapshot(StorageReadiness::Ready, None, 0, 0, 0)
            .inventory;
        assert!(matches!(
            first,
            super::SampleState::Measured { ref value, .. }
                if value.structurally_valid_narinfo_entries == 4
                    && value.narinfo_claimed_nar_bytes == 360
                    && value.raw_bytes == 900
        ));
        let exposition = metrics.render(true, None, 0, 0);
        assert!(
            exposition.contains("narjar_cache_population_sample_available{state=\"measured\"} 1")
        );
        assert!(
            exposition.contains("narjar_cache_population_files{kind=\"raw\",state=\"measured\"} 0")
        );
        assert!(
            exposition.contains(
                "narjar_cache_population_narinfo_claimed_nar_bytes{state=\"measured\"} 360"
            )
        );
        assert!(exposition.contains("narjar_cache_population_scan_started_timestamp_seconds "));
        assert!(
            exposition.contains("narjar_cache_population_scan_quality{quality=\"complete\"} 1")
        );
        assert!(exposition.contains("narjar_cache_population_scan_entries 17"));
        assert!(exposition.contains("narjar_cache_population_scan_ignored_entries 3"));
        assert!(exposition.contains("narjar_cache_population_scan_disappeared_entries 0"));
        assert!(exposition.contains("narjar_cache_population_scan_errors 0"));
        assert!(exposition.contains(
            "narjar_cache_population_narinfo_entries{kind=\"parsed\",state=\"measured\"} 4"
        ));
        assert!(exposition.contains("narjar_cache_population_refresh_failed 0"));
        assert!(!exposition.contains("kind=\"chunk\""));

        metrics.record_population_scan(
            StorageBackend::Chunked,
            Err(PopulationScanFailure),
            started_at,
            0.0,
        );
        let refreshed = metrics
            .snapshot(StorageReadiness::Ready, None, 0, 0, 0)
            .inventory;
        assert!(matches!(
            refreshed,
            super::SampleState::Stale { ref value, .. }
                if value.backend == StorageBackend::Flat
                    && value.structurally_valid_narinfo_entries == 4
                    && value.raw_bytes == 900
        ));
        let exposition = metrics.render(true, None, 0, 0);
        assert!(exposition.contains("narjar_cache_population_sample_available{state=\"stale\"} 1"));
        assert!(exposition.contains("narjar_cache_population_refresh_failed 1"));
        assert!(exposition.contains("narjar_cache_population_scan_quality{quality=\"failed\"} 1"));
    }

    #[test]
    fn maximum_population_counts_keep_metrics_exposition_below_the_fixed_bound() {
        let metrics = Metrics::default();
        let counts = PopulationCounts {
            scanned_entries: u64::MAX,
            structurally_valid_narinfo_entries: u64::MAX,
            narinfo_files: u64::MAX,
            narinfo_bytes: u64::MAX,
            narinfo_claimed_nar_bytes: u64::MAX,
            raw_files: u64::MAX,
            raw_bytes: u64::MAX,
            chunk_files: u64::MAX,
            chunk_bytes: u64::MAX,
            manifest_files: u64::MAX,
            manifest_bytes: u64::MAX,
            chunked_nars: u64::MAX,
            chunked_nar_bytes: u64::MAX,
            apparent_file_bytes: u64::MAX,
            ..PopulationCounts::default()
        };
        metrics.record_population_scan(StorageBackend::Chunked, Ok(counts), 1, 300.0);

        let exposition = metrics.render(true, None, 0, 0);

        assert!(exposition.len() < 256 * 1024);
        assert!(exposition.contains("narjar_cache_population_files{kind=\"raw\""));
        assert!(exposition.contains("narjar_cache_population_logical_nars"));
    }

    #[test]
    fn incomplete_population_scan_keeps_last_complete_totals_and_reports_coverage() {
        let metrics = Metrics::default();
        let started_at = super::unix_seconds_now().saturating_sub(3);
        metrics.record_population_scan(
            StorageBackend::Flat,
            Ok(PopulationCounts {
                raw_files: 4,
                raw_bytes: 900,
                ..PopulationCounts::default()
            }),
            started_at,
            1.0,
        );
        metrics.record_population_scan(
            StorageBackend::Flat,
            Ok(PopulationCounts {
                scanned_entries: 12,
                ignored_entries: 2,
                errors: 1,
                narinfo_read_errors: 1,
                raw_files: 1,
                raw_bytes: 50,
                ..PopulationCounts::default()
            }),
            started_at + 1,
            2.0,
        );

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert!(matches!(
            &snapshot.inventory,
            super::SampleState::Stale { value, .. } if value.raw_bytes == 900
        ));
        let attempt = snapshot
            .inventory_attempt
            .as_ref()
            .expect("the latest scan attempt should be retained");
        assert_eq!(attempt.quality, super::PopulationQuality::EntryErrors);
        assert_eq!(
            attempt
                .coverage
                .as_ref()
                .map(|coverage| coverage.scanned_entries),
            Some(12)
        );

        let exposition = super::render_prometheus(&snapshot);
        assert!(
            exposition.contains(
                "narjar_cache_population_apparent_bytes{kind=\"raw\",state=\"stale\"} 900"
            )
        );
        assert!(exposition.contains("narjar_cache_population_scan_entries 12"));
        assert!(exposition.contains("narjar_cache_population_scan_errors 1"));
        assert!(exposition.contains("narjar_cache_population_scan_narinfo_read_errors 1"));
        assert!(
            exposition.contains("narjar_cache_population_scan_quality{quality=\"entry_errors\"} 1")
        );
    }

    #[test]
    fn lookup_snapshot_separates_hits_misses_and_failures() {
        let metrics = Metrics::default();
        let empty_exposition =
            render_prometheus(&metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0));
        assert!(
            !empty_exposition
                .contains("narjar_cache_lookup_hit_ratio{object=\"narinfo\",method=\"GET\"}")
        );
        assert_eq!(
            metrics
                .snapshot(StorageReadiness::Ready, None, 0, 0, 0)
                .cache
                .narinfo_get
                .hit_ratio,
            None
        );

        metrics.cache_lookup(
            CacheObject::NarInfo,
            RequestMethod::Get,
            CacheLookupOutcome::Hit,
        );
        metrics.cache_lookup(
            CacheObject::NarInfo,
            RequestMethod::Get,
            CacheLookupOutcome::Hit,
        );
        metrics.cache_lookup(
            CacheObject::NarInfo,
            RequestMethod::Get,
            CacheLookupOutcome::Miss,
        );
        metrics.cache_lookup(
            CacheObject::NarInfo,
            RequestMethod::Get,
            CacheLookupOutcome::Failure,
        );
        metrics.cache_lookup(
            CacheObject::NarInfo,
            RequestMethod::Head,
            CacheLookupOutcome::Miss,
        );

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        let get = &snapshot.cache.narinfo_get;
        assert_eq!(
            (get.hits, get.misses, get.failures, get.decisions),
            (2, 1, 1, 4)
        );
        assert_eq!(get.hit_ratio, Some(2.0 / 3.0));
        assert_eq!(get.failure_ratio, Some(0.25));
        assert_eq!(snapshot.cache.narinfo_head.misses, 1);
        assert_eq!(snapshot.cache.narinfo_head.hit_ratio, Some(0.0));
        let exposition = render_prometheus(&snapshot);
        assert!(
            exposition
                .contains("narjar_cache_lookup_hit_ratio{object=\"narinfo\",method=\"HEAD\"} 0")
        );
        assert!(exposition.contains(
            "narjar_cache_lookup_hit_ratio{object=\"narinfo\",method=\"GET\"} 0.6666666666666666"
        ));
    }

    #[test]
    fn maintenance_history_is_exported_from_bounded_local_records() {
        let directory = tempfile::tempdir().expect("maintenance directory should be created");
        let metrics = Metrics::default();
        let recorder = Recorder::begin(directory.path(), Operation::Gc, Mode::GcApply)
            .expect("started state should be stored");
        metrics.sample_maintenance_sidecar(directory.path());
        let exposition =
            render_prometheus(&metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0));
        assert!(exposition.contains(
            "narjar_maintenance_started_timestamp_seconds{operation=\"gc\",mode=\"gc_apply\"}"
        ));

        recorder
            .finish(
                Outcome::Success,
                RunValues {
                    objects_reclaimed: Some(2),
                    bytes_reclaimed: Some(8192),
                    ..RunValues::default()
                },
            )
            .expect("completion should be durably recorded");
        metrics.sample_maintenance_sidecar(directory.path());
        let exposition =
            render_prometheus(&metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0));
        assert!(exposition.contains("outcome=\"success\""));
        assert!(
            exposition
                .contains("narjar_maintenance_last_objects{operation=\"gc\",kind=\"reclaimed\"} 2")
        );
        assert!(
            exposition.contains(
                "narjar_maintenance_last_bytes{operation=\"gc\",kind=\"reclaimed\"} 8192"
            )
        );
        assert!(
            !exposition.contains("narjar_maintenance_started_timestamp_seconds{operation=\"gc\"")
        );

        std::fs::remove_file(directory.path().join(".narjar-maintenance-gc.last"))
            .expect("record should be replaceable for the failure case");
        std::os::unix::fs::symlink(
            directory.path().join("missing"),
            directory.path().join(".narjar-maintenance-gc.last"),
        )
        .expect("unsafe record should be creatable");
        metrics.sample_maintenance_sidecar(directory.path());
        let retained = render_prometheus(&metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0));
        assert!(
            retained.contains(
                "narjar_maintenance_last_bytes{operation=\"gc\",kind=\"reclaimed\"} 8192"
            )
        );
        assert!(retained.contains("narjar_maintenance_sample_available{state=\"stale\"} 1"));
    }

    #[test]
    fn zfs_metrics_report_physical_usage_compression_and_sample_freshness() {
        let mut exposition = String::new();
        super::append_filesystem_metrics(
            &mut exposition,
            &SampleState::Measured {
                sampled_at_unix_seconds: super::unix_seconds_now(),
                value: FilesystemStats {
                    used_bytes: 20,
                    logical_used_bytes: 50,
                    referenced_bytes: 18,
                    logical_referenced_bytes: 45,
                    used_by_dataset_bytes: 17,
                    used_by_snapshots_bytes: 2,
                    used_by_children_bytes: 1,
                    used_by_refreservation_bytes: 0,
                    available_bytes: 80,
                    compression_ratio: "2.50x".to_owned(),
                    referenced_compression_ratio: "2.25x".to_owned(),
                    compression: "zstd-19".to_owned(),
                    record_size_bytes: 1_048_576,
                    logical_to_used_ratio: Some(2.5),
                },
            },
        );

        for expected in [
            "narjar_zfs_sample_available{state=\"measured\"} 1",
            "narjar_zfs_bytes{kind=\"used\",state=\"measured\"} 20",
            "narjar_zfs_bytes{kind=\"logical_used\",state=\"measured\"} 50",
            "narjar_zfs_bytes{kind=\"used_by_snapshots\",state=\"measured\"} 2",
            "narjar_zfs_compression_ratio{kind=\"compression\",state=\"measured\"} 2.5",
            "narjar_zfs_logical_to_used_ratio{state=\"measured\"} 2.5",
            "narjar_zfs_record_size_bytes{state=\"measured\"} 1048576",
            "narjar_zfs_compression_info{algorithm=\"zstd\",state=\"measured\"} 1",
            "narjar_zfs_compression_level{algorithm=\"zstd\",state=\"measured\"} 19",
        ] {
            assert!(
                exposition.contains(expected),
                "missing {expected}: {exposition}"
            );
        }
    }

    #[test]
    fn zfs_compression_metrics_bound_labels_and_preserve_levels() {
        for (property, expected) in [
            ("gzip-9", ("gzip", Some(9))),
            ("zstd-fast-1000", ("zstd_fast", Some(1000))),
            ("future-codec-with-arbitrary-value", ("other", None)),
        ] {
            assert_eq!(super::zfs_compression_properties(property), expected);
        }
    }

    #[test]
    fn zfs_sidecar_is_root_bound_and_failed_refresh_never_looks_fresh() {
        let temporary = tempfile::tempdir().expect("temporary root should be created");
        let storage_root = temporary.path().join("cache");
        std::fs::create_dir(&storage_root).expect("storage root should be created");
        let mount_alias = temporary.path().join("mounted-cache");
        symlink(&storage_root, &mount_alias).expect("mount alias should be created");
        let sample_path = temporary.path().join("sample.json");
        let sample = zfs_sample_document(&storage_root, &mount_alias);
        std::fs::write(
            &sample_path,
            serde_json::to_vec(&sample).expect("sample should serialize"),
        )
        .expect("sample should be written");

        let metrics = Metrics::default();
        metrics.sample_filesystem_sidecar(&sample_path, &storage_root);
        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert!(matches!(
            snapshot.filesystem,
            SampleState::Measured { ref value, .. } if value.used_bytes == 20
        ));

        std::fs::remove_file(&sample_path).expect("sample should be removed");
        symlink(temporary.path().join("missing"), &sample_path)
            .expect("sample symlink should be created");
        metrics.sample_filesystem_sidecar(&sample_path, &storage_root);
        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert!(matches!(
            snapshot.filesystem,
            SampleState::Stale { ref value, .. } if value.used_bytes == 20
        ));
        assert!(
            render_prometheus(&snapshot).contains("narjar_zfs_sample_available{state=\"stale\"} 0")
        );
    }

    #[test]
    fn zfs_sample_rejects_malformed_oversized_future_and_wrong_root_files() {
        let temporary = tempfile::tempdir().expect("temporary root should be created");
        let storage_root = temporary.path().join("cache");
        std::fs::create_dir(&storage_root).expect("storage root should be created");
        let sample_path = temporary.path().join("sample.json");
        let mut sample = zfs_sample_document(&storage_root, &storage_root);
        let now = super::unix_seconds_now();

        sample["storage_root"] = serde_json::json!(temporary.path().join("other-cache"));
        std::fs::write(&sample_path, serde_json::to_vec(&sample).unwrap()).unwrap();
        assert_eq!(
            super::read_zfs_sample(&sample_path, &storage_root, now).unwrap_err(),
            "sample_wrong_storage_root"
        );

        sample["storage_root"] = serde_json::json!(&storage_root);
        sample["sampled_at_unix_seconds"] = serde_json::json!(now + 31);
        std::fs::write(&sample_path, serde_json::to_vec(&sample).unwrap()).unwrap();
        assert_eq!(
            super::read_zfs_sample(&sample_path, &storage_root, now).unwrap_err(),
            "sample_timestamp_in_future"
        );

        std::fs::write(&sample_path, b"not-json").unwrap();
        assert_eq!(
            super::read_zfs_sample(&sample_path, &storage_root, now).unwrap_err(),
            "sample_invalid"
        );

        std::fs::write(
            &sample_path,
            vec![b' '; (super::MAX_ZFS_SAMPLE_BYTES + 1) as usize],
        )
        .unwrap();
        assert_eq!(
            super::read_zfs_sample(&sample_path, &storage_root, now).unwrap_err(),
            "sample_too_large"
        );
    }

    #[test]
    fn zfs_sample_marks_old_values_stale_and_accepts_compression_off() {
        let temporary = tempfile::tempdir().expect("temporary root should be created");
        let storage_root = temporary.path().join("cache");
        std::fs::create_dir(&storage_root).expect("storage root should be created");
        let sample_path = temporary.path().join("sample.json");
        let metrics = Metrics::default();
        let sample = zfs_sample_document(&storage_root, &storage_root);
        std::fs::write(&sample_path, serde_json::to_vec(&sample).unwrap()).unwrap();

        metrics.sample_filesystem_sidecar(&sample_path, &storage_root);
        let exposition =
            render_prometheus(&metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0));
        assert!(
            exposition
                .contains("narjar_zfs_compression_info{algorithm=\"off\",state=\"measured\"} 1")
        );
        assert!(
            exposition.contains("narjar_zfs_bytes{kind=\"used_by_children\",state=\"measured\"} 1")
        );

        let mut stale_sample = sample;
        stale_sample["sampled_at_unix_seconds"] = serde_json::json!(
            super::unix_seconds_now().saturating_sub(super::ZFS_SAMPLE_MAX_AGE + 1)
        );
        std::fs::write(&sample_path, serde_json::to_vec(&stale_sample).unwrap()).unwrap();
        metrics.sample_filesystem_sidecar(&sample_path, &storage_root);
        let stale = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert!(matches!(
            stale.filesystem,
            SampleState::Stale { ref value, .. } if value.used_bytes == 20
        ));
        assert!(
            render_prometheus(&stale).contains("narjar_zfs_sample_available{state=\"stale\"} 0")
        );
    }

    #[test]
    fn traffic_rates_are_exported_with_real_window_coverage() {
        let mut exposition = String::new();
        super::append_traffic_rate_metrics(
            &mut exposition,
            &super::RecentTrafficRates {
                one_minute: Some(super::TrafficRate {
                    requested_window_seconds: 60,
                    coverage_seconds: 12.5,
                    upload_bytes_per_second: 3.0,
                    artifact_bytes_per_second: 8.0,
                    process_cpu_cores: Some(0.25),
                }),
                five_minutes: None,
            },
        );
        assert!(exposition.contains("narjar_http_upload_bytes_per_second{window=\"60\"} 3"));
        assert!(exposition.contains("narjar_http_artifact_bytes_per_second{window=\"60\"} 8"));
        assert!(
            exposition.contains("narjar_traffic_rate_window_coverage_seconds{window=\"60\"} 12.5")
        );
        assert!(exposition.contains("narjar_process_cpu_cores{window=\"60\"} 0.25"));
        assert!(!exposition.contains("window=\"300\""));
    }

    #[test]
    fn aborted_artifact_transfer_keeps_partial_bytes_not_expected_length() {
        let metrics = Metrics::default();
        let request = metrics.request(RequestMethod::Get, RequestRoute::Nar);
        request.record_failed_response(
            StatusCode::OK,
            TransferFailure {
                error: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
                body_bytes: 7,
            },
            Duration::from_millis(12),
        );
        request.record_completed_response(StatusCode::OK, 100, Duration::from_millis(1));
        drop(request);

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert_eq!(snapshot.traffic.response_body_bytes, 7);
        assert_eq!(snapshot.traffic.completed_responses, 0);
        assert_eq!(snapshot.traffic.aborted_responses, 1);
        assert_eq!(snapshot.response_transfer_failures.disconnected, 1);
        assert_eq!(snapshot.response_transfer_failures.timed_out, 0);
    }

    #[test]
    fn dropped_request_guard_records_an_abandoned_response_once() {
        let metrics = Metrics::default();
        let request = metrics.request(RequestMethod::Get, RequestRoute::NarInfo);
        drop(request);

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert_eq!(snapshot.traffic.requests_in_flight, 0);
        assert_eq!(snapshot.traffic.aborted_responses, 1);
        let exposition = render_prometheus(&snapshot);
        assert!(exposition.contains(
            "narjar_http_requests_total{method=\"GET\",route=\"narinfo\",status=\"other\"} 1"
        ));
        assert!(exposition.contains("narjar_response_transfer_failures_total{kind=\"timeout\"} 0"));
    }

    #[test]
    fn response_transfer_failures_use_bounded_timeout_and_other_classes() {
        let metrics = Metrics::default();
        for error_kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let request = metrics.request(RequestMethod::Get, RequestRoute::Nar);
            request.record_failed_response(
                StatusCode::OK,
                TransferFailure {
                    error: std::io::Error::from(error_kind),
                    body_bytes: 0,
                },
                Duration::from_millis(1),
            );
        }

        let exposition =
            render_prometheus(&metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0));
        assert!(exposition.contains("narjar_response_transfer_failures_total{kind=\"timeout\"} 1"));
        assert!(exposition.contains("narjar_response_transfer_failures_total{kind=\"other\"} 1"));
    }

    #[test]
    fn pressure_snapshot_shows_configured_limits_and_active_work() {
        let metrics = Metrics::default();
        metrics.configure_pressure_limits(8, 2);
        metrics.record_connection_outcome(ConnectionOutcome::AdmissionRejected);
        metrics.record_connection_outcome(ConnectionOutcome::MalformedRequest);
        metrics.connection_admitted();
        metrics.connection_queued();
        metrics.connection_dequeued();
        metrics.publication_worker_started();
        metrics.publication_enqueued();

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        let pressure = &snapshot.pressure;
        assert_eq!(pressure.connections_in_flight, 1);
        assert_eq!(pressure.connections_limit, 8);
        assert_eq!(pressure.request_queue_depth, 0);
        assert_eq!(pressure.request_queue_capacity, 8);
        assert_eq!(pressure.active_publication_workers, 1);
        assert_eq!(pressure.publication_worker_limit, 2);
        assert_eq!(pressure.publication_queue_depth, 1);
        assert_eq!(pressure.publication_queue_capacity, 8);
        assert_eq!(snapshot.connections.admitted, 1);
        assert_eq!(snapshot.connections.admission_rejected, 1);
        assert_eq!(snapshot.connections.malformed_requests, 1);
        assert!(
            render_prometheus(&snapshot)
                .contains("narjar_connections_total{outcome=\"admission_rejected\"} 1")
        );

        metrics.publication_dequeued(Instant::now());
        metrics.publication_worker_finished();
        metrics.connection_released();
    }

    #[test]
    fn publication_results_count_created_identical_conflict_and_failure_separately() {
        let metrics = Metrics::default();
        let created = Ok(PublishOutcome::Created);
        let identical = Ok(PublishOutcome::Identical);
        let conflict = Err(StorageError::Conflict);
        let failure = Err(StorageError::InsufficientSpace);

        for result in [&created, &identical, &conflict, &failure] {
            metrics.record_publication_result(result);
        }

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert_eq!(snapshot.publication_outcomes.created, 1);
        assert_eq!(snapshot.publication_outcomes.identical, 1);
        assert_eq!(snapshot.publication_outcomes.conflicts, 1);
        assert_eq!(snapshot.publication_outcomes.failures, 1);
        let exposition = render_prometheus(&snapshot);
        assert!(exposition.contains("narjar_publication_outcomes_total{outcome=\"identical\"} 1"));
    }

    #[test]
    fn storage_activity_exposes_validated_and_committed_nar_bytes() {
        let activity = StorageActivitySnapshot {
            upload_validated_logical_bytes: 200,
            upload_created_logical_bytes: 100,
            upload_identical_logical_bytes: 100,
            ..StorageActivitySnapshot::default()
        };
        let mut exposition = String::new();

        append_storage_activity_metrics(&mut exposition, activity);

        assert!(exposition.contains("narjar_nar_upload_validated_logical_bytes_total 200"));
        assert!(
            exposition.contains(
                "narjar_nar_upload_committed_logical_bytes_total{outcome=\"created\"} 100"
            )
        );
        assert!(exposition.contains(
            "narjar_nar_upload_committed_logical_bytes_total{outcome=\"identical\"} 100"
        ));
    }

    #[test]
    fn traffic_rate_reports_real_partial_window_coverage() {
        let start = Instant::now();
        let mut samples = super::TrafficSamples::default();
        samples.record(super::TrafficSample {
            at: start,
            upload_bytes: 100,
            download_bytes: 200,
            process_cpu_seconds: Some(1.0),
            byte_counters_overflowed: false,
        });
        samples.record(super::TrafficSample {
            at: start + Duration::from_secs(30),
            upload_bytes: 400,
            download_bytes: 800,
            process_cpu_seconds: Some(1.6),
            byte_counters_overflowed: false,
        });

        let rate = samples.rate_over(60).expect("two samples define a rate");
        assert_eq!(rate.requested_window_seconds, 60);
        assert_eq!(rate.coverage_seconds, 30.0);
        assert_eq!(rate.upload_bytes_per_second, 10.0);
        assert_eq!(rate.artifact_bytes_per_second, 20.0);
        assert!((rate.process_cpu_cores.expect("CPU sample is present") - 0.02).abs() < 1e-12);
    }

    #[test]
    fn traffic_rate_windows_include_both_endpoints_and_report_idle_zeroes() {
        let start = Instant::now();
        let mut samples = super::TrafficSamples::default();
        assert!(samples.rates().one_minute.is_none());
        assert!(samples.rates().five_minutes.is_none());

        (0..=60).for_each(|sample_index| {
            let elapsed_seconds = sample_index * 5;
            samples.record(super::TrafficSample {
                at: start + Duration::from_secs(elapsed_seconds),
                upload_bytes: 0,
                download_bytes: 0,
                process_cpu_seconds: Some(0.0),
                byte_counters_overflowed: false,
            });
        });

        let rates = samples.rates();
        let one_minute = rates.one_minute.expect("full one-minute coverage");
        assert_eq!(one_minute.coverage_seconds, 60.0);
        assert_eq!(one_minute.upload_bytes_per_second, 0.0);
        assert_eq!(one_minute.artifact_bytes_per_second, 0.0);

        let five_minutes = rates.five_minutes.expect("full five-minute coverage");
        assert_eq!(five_minutes.coverage_seconds, 300.0);
        assert_eq!(five_minutes.upload_bytes_per_second, 0.0);
        assert_eq!(five_minutes.artifact_bytes_per_second, 0.0);
    }

    #[test]
    fn traffic_rates_are_unavailable_after_counter_reset_or_overflow() {
        let start = Instant::now();
        let mut reset_samples = super::TrafficSamples::default();
        reset_samples.record(super::TrafficSample {
            at: start,
            upload_bytes: 100,
            download_bytes: 200,
            process_cpu_seconds: Some(1.0),
            byte_counters_overflowed: false,
        });
        reset_samples.record(super::TrafficSample {
            at: start + Duration::from_secs(30),
            upload_bytes: 50,
            download_bytes: 100,
            process_cpu_seconds: Some(1.5),
            byte_counters_overflowed: false,
        });
        assert!(reset_samples.rate_over(60).is_none());

        let mut overflowed_samples = super::TrafficSamples::default();
        overflowed_samples.record(super::TrafficSample {
            at: start,
            upload_bytes: 100,
            download_bytes: 200,
            process_cpu_seconds: Some(1.0),
            byte_counters_overflowed: false,
        });
        overflowed_samples.record(super::TrafficSample {
            at: start + Duration::from_secs(30),
            upload_bytes: u64::MAX,
            download_bytes: u64::MAX,
            process_cpu_seconds: Some(1.5),
            byte_counters_overflowed: true,
        });
        assert!(overflowed_samples.rate_over(60).is_none());
    }

    #[test]
    fn traffic_byte_counters_saturate_and_expose_overflow() {
        let metrics = Metrics::default();
        metrics
            .received_upload_bytes
            .store(u64::MAX - 1, std::sync::atomic::Ordering::Relaxed);

        metrics.received_upload_body_bytes(2);

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert_eq!(snapshot.traffic.received_upload_body_bytes, u64::MAX);
        assert!(snapshot.traffic.cumulative_byte_counters_overflowed);
        assert!(snapshot.traffic.recent_rates.one_minute.is_none());
        assert!(snapshot.traffic.recent_rates.five_minutes.is_none());
        assert!(render_prometheus(&snapshot).contains("narjar_traffic_byte_counters_overflowed 1"));
    }

    #[test]
    fn unavailable_process_sample_has_a_bounded_explicit_state() {
        let mut exposition = String::new();
        super::append_process_metrics(
            &mut exposition,
            &super::SampleState::<super::ProcessResources>::Unavailable {
                reason: "/private/path must not appear".to_owned(),
            },
        );

        assert!(exposition.contains("narjar_process_sample_available 0"));
        assert!(exposition.contains("narjar_process_sample_state{state=\"unavailable\"} 1"));
        assert!(!exposition.contains("/private/path"));
    }

    #[test]
    fn failed_resource_sample_keeps_the_original_sample_timestamp() {
        let measured = super::SampleState::Measured {
            sampled_at_unix_seconds: 10,
            value: 3_000_u64,
        };
        let stale = super::next_sample_state(&measured, Err(()), 20, "test_read_failed");
        assert!(matches!(
            stale,
            super::SampleState::Stale {
                sampled_at_unix_seconds: 10,
                value: 3_000,
                ..
            }
        ));

        let unavailable = super::next_sample_state(
            &super::SampleState::<u64>::NeverSampled,
            Err(()),
            20,
            "test_read_failed",
        );
        assert!(matches!(
            unavailable,
            super::SampleState::Unavailable { .. }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn periodic_linux_sample_reports_process_rss_without_request_path_io() {
        let metrics = Metrics::default();
        metrics.sample_periodic();

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        let super::SampleState::Measured { ref value, .. } = snapshot.process.resources else {
            panic!("Linux procfs sample should be available");
        };
        assert!(value.resident_bytes > 0);
        assert!(value.user_cpu_seconds.is_finite());
        assert!(value.system_cpu_seconds.is_finite());
        assert!(value.open_file_descriptors.is_some());
        let exposition = render_prometheus(&snapshot);
        assert!(!exposition.contains("cgroup"));
        assert!(
            exposition.contains("narjar_process_resource_source_info{source=\"linux_procfs\"} 1")
        );
        assert!(exposition.contains("narjar_process_sample_state{state=\"measured\"} 1"));
    }

    #[test]
    fn exposition_has_help_types_and_event_deltas() {
        let metrics = Metrics::default();
        let request = metrics.request(RequestMethod::Put, RequestRoute::Nar);
        let head = metrics.request(RequestMethod::Head, RequestRoute::Nar);
        let lookup = metrics.request(RequestMethod::Get, RequestRoute::NarInfo);
        lookup.record_cache_lookup(
            CacheObject::NarInfo,
            CacheLookupOutcome::Hit,
            Duration::from_millis(7),
        );
        let upload = metrics.upload(17);
        metrics.received_upload_body_bytes(5);
        assert!(
            metrics
                .render(true, None, 0, 0)
                .contains("narjar_uploads_in_flight 1")
        );

        metrics.validation_failure(ValidationClass::Nar);
        metrics.set_temp_objects(1);
        metrics.publication(Duration::from_millis(3));
        request.record_completed_response(StatusCode::CREATED, 23, Duration::from_millis(7));
        head.record_completed_response(StatusCode::OK, 0, Duration::from_millis(1));
        drop(upload);
        drop(request);
        drop(head);
        drop(lookup);

        let report = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        assert_eq!(report.latency.narinfo_lookup.count, 1);
        assert_eq!(report.latency.narinfo_lookup.bucket_counts[2], 1);
        assert_eq!(report.latency.nar_delivery.count, 2);
        let exposition = metrics.render(true, None, 0, 0);
        assert!(exposition.contains("# HELP narjar_http_requests_total"));
        assert!(exposition.contains("# TYPE narjar_http_requests_total counter"));
        assert!(
            exposition.contains(
                "narjar_http_requests_total{method=\"PUT\",route=\"nar\",status=\"201\"} 1"
            )
        );
        assert!(exposition.contains("narjar_http_upload_declared_bytes_total 17"));
        assert!(exposition.contains("narjar_http_upload_received_bytes_total 5"));
        assert!(exposition.contains("narjar_http_bytes_out_total 23"));
        assert!(exposition.contains("narjar_validation_failures_total{class=\"nar\"} 1"));
        assert!(exposition.contains("narjar_uploads_in_flight 0"));
        assert!(exposition.contains("narjar_requests_in_flight 0"));
        assert!(exposition.contains("narjar_temp_objects 1"));
        assert!(exposition.contains("narjar_publications_total 1"));
        assert!(exposition.contains("# TYPE narjar_operation_duration_seconds histogram"));
        assert!(exposition.contains(
            "narjar_operation_duration_seconds_bucket{operation=\"narinfo_lookup\",le=\"0.01\"} 1"
        ));
        assert!(exposition.contains("narjar_publication_queue_depth 0"));
        assert!(exposition.contains("narjar_ready 1"));
    }

    #[test]
    fn prometheus_render_includes_lookup_and_request_snapshot() {
        let metrics = Metrics::default();
        let hit = metrics.request(RequestMethod::Get, RequestRoute::NarInfo);
        hit.record_cache_lookup(
            CacheObject::NarInfo,
            CacheLookupOutcome::Hit,
            Duration::from_millis(4),
        );
        hit.record_completed_response(StatusCode::OK, 32, Duration::from_millis(5));
        drop(hit);

        let miss = metrics.request(RequestMethod::Get, RequestRoute::NarInfo);
        miss.record_cache_lookup(
            CacheObject::NarInfo,
            CacheLookupOutcome::Miss,
            Duration::from_millis(2),
        );
        miss.record_completed_response(StatusCode::NOT_FOUND, 0, Duration::from_millis(2));
        drop(miss);

        let snapshot = metrics.snapshot(StorageReadiness::Ready, None, 0, 0, 0);
        let prometheus = render_prometheus(&snapshot);

        assert_eq!(snapshot.cache.narinfo_get.hits, 1);
        assert_eq!(snapshot.cache.narinfo_get.misses, 1);
        assert_eq!(snapshot.cache.narinfo_get.hit_ratio, Some(0.5));
        assert_eq!(snapshot.http_requests.len(), 2);
        assert!(prometheus.contains(
            "narjar_http_requests_total{method=\"GET\",route=\"narinfo\",status=\"200\"} 1"
        ));
        assert!(prometheus.contains(
            "narjar_http_requests_total{method=\"GET\",route=\"narinfo\",status=\"404\"} 1"
        ));
        assert!(prometheus.contains(
            "narjar_cache_lookup_outcomes_total{object=\"narinfo\",method=\"GET\",outcome=\"hit\"} 1"
        ));
        assert!(prometheus.contains(
            "narjar_cache_lookup_outcomes_total{object=\"narinfo\",method=\"GET\",outcome=\"miss\"} 1"
        ));
        assert!(
            prometheus
                .contains("narjar_cache_lookup_hit_ratio{object=\"narinfo\",method=\"GET\"} 0.5")
        );
    }

    #[test]
    fn capacity_exposition_uses_destination_snapshot() {
        let metrics = Metrics::default();
        let exposition = metrics.render(
            false,
            Some(StorageCapacity {
                total_bytes: 100,
                available_bytes: 40,
                total_inodes: 10,
                available_inodes: 6,
                read_only: false,
            }),
            25,
            10,
        );

        assert!(exposition.contains("narjar_storage_capacity_bytes{kind=\"total\"} 100"));
        assert!(exposition.contains("narjar_storage_capacity_bytes{kind=\"available\"} 40"));
        assert!(exposition.contains("narjar_storage_capacity_inodes{kind=\"total\"} 10"));
        assert!(exposition.contains("narjar_storage_capacity_inodes{kind=\"available\"} 6"));
        assert!(exposition.contains("narjar_storage_read_only 0"));
        assert!(exposition.contains("narjar_staging_outstanding_bytes 25"));
        assert!(exposition.contains("narjar_staging_min_free_reserve_bytes 10"));
        assert!(exposition.contains("narjar_storage_estimated_headroom_bytes 5"));
    }
}
