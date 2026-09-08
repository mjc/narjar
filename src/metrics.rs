use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::{
    http_server::Method,
    storage::{CapacityErrorKind, StorageCapacity},
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
const STATUS_CLASSES: [&str; 5] = ["2xx", "3xx", "4xx", "5xx", "other"];
const REQUEST_SERIES: usize = METHODS.len() * ROUTES.len() * STATUS_CLASSES.len();

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
}

#[derive(Debug)]
pub struct Metrics {
    requests: [AtomicU64; REQUEST_SERIES],
    requests_in_flight: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
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
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            requests_in_flight: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
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
        }
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
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
        self.uploads_in_flight.fetch_add(1, Ordering::Relaxed);
        UploadGuard(self)
    }

    pub(crate) fn bytes_out(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn set_temp_objects(&self, count: u64) {
        self.temp_objects.store(count, Ordering::Relaxed);
    }

    pub(crate) fn publication(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.publications.fetch_add(1, Ordering::Relaxed);
        self.publication_count.fetch_add(1, Ordering::Relaxed);
        self.publication_micros.fetch_add(micros, Ordering::Relaxed);
        self.publication_max_micros
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

    pub(crate) fn render(&self, ready: bool, capacity: Option<StorageCapacity>) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let mut output = String::new();
        output.push_str("# HELP narjar_http_requests_total HTTP requests by method, route, and status class.\n# TYPE narjar_http_requests_total counter\n");
        for method in METHODS {
            for route in ROUTES {
                for (status_index, status) in STATUS_CLASSES.iter().enumerate() {
                    let value = load(
                        &self.requests[request_index(method.index(), route.index(), status_index)],
                    );
                    if value != 0 {
                        output.push_str(&format!(
                            "narjar_http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {}\n",
                            method.label(), route.label(), status, value
                        ));
                    }
                }
            }
        }
        output.push_str(&format!(
            "# HELP narjar_http_bytes_in_total Accepted upload body bytes.\n# TYPE narjar_http_bytes_in_total counter\nnarjar_http_bytes_in_total {}\n\
             # HELP narjar_http_bytes_out_total Served artifact bytes.\n# TYPE narjar_http_bytes_out_total counter\nnarjar_http_bytes_out_total {}\n\
             # HELP narjar_auth_failures_total Authentication failures by permission scope.\n# TYPE narjar_auth_failures_total counter\nnarjar_auth_failures_total{{scope=\"read\"}} {}\nnarjar_auth_failures_total{{scope=\"write\"}} {}\n\
             # HELP narjar_validation_failures_total Rejected request bodies by validation class.\n# TYPE narjar_validation_failures_total counter\nnarjar_validation_failures_total{{class=\"body\"}} {}\nnarjar_validation_failures_total{{class=\"nar\"}} {}\nnarjar_validation_failures_total{{class=\"narinfo\"}} {}\n\
             # HELP narjar_uploads_in_flight Accepted uploads currently being processed.\n# TYPE narjar_uploads_in_flight gauge\nnarjar_uploads_in_flight {}\n\
             # HELP narjar_requests_in_flight Requests currently being processed.\n# TYPE narjar_requests_in_flight gauge\nnarjar_requests_in_flight {}\n\
             # HELP narjar_temp_objects Temporary objects currently known by reconcile.\n# TYPE narjar_temp_objects gauge\nnarjar_temp_objects {}\n\
             # HELP narjar_disk_full_total No-space capacity failures.\n# TYPE narjar_disk_full_total counter\nnarjar_disk_full_total {}\n\
             # HELP narjar_capacity_failures_total Capacity failures by reason.\n# TYPE narjar_capacity_failures_total counter\nnarjar_capacity_failures_total{{reason=\"no_space\"}} {}\nnarjar_capacity_failures_total{{reason=\"quota\"}} {}\nnarjar_capacity_failures_total{{reason=\"inodes\"}} {}\nnarjar_capacity_failures_total{{reason=\"read_only\"}} {}\n\
             # HELP narjar_publications_total Publication attempts.\n# TYPE narjar_publications_total counter\nnarjar_publications_total {}\n\
             # HELP narjar_publication_duration_seconds Publication duration summary.\n# TYPE narjar_publication_duration_seconds summary\nnarjar_publication_duration_seconds_count {}\nnarjar_publication_duration_seconds_sum {}\nnarjar_publication_duration_seconds_max {}\n\
             # HELP narjar_ready Whether the configured destination is ready.\n# TYPE narjar_ready gauge\nnarjar_ready {}\n",
            load(&self.bytes_in), load(&self.bytes_out), load(&self.auth_read_failures),
            load(&self.auth_write_failures), load(&self.validation_body_failures),
            load(&self.validation_nar_failures), load(&self.validation_narinfo_failures),
            load(&self.uploads_in_flight), load(&self.requests_in_flight), load(&self.temp_objects),
            load(&self.disk_full), load(&self.capacity_no_space), load(&self.capacity_quota),
            load(&self.capacity_inodes), load(&self.capacity_read_only), load(&self.publications),
            load(&self.publication_count), load(&self.publication_micros) as f64 / 1_000_000.0,
            load(&self.publication_max_micros) as f64 / 1_000_000.0, u8::from(ready),
        ));
        if let Some(capacity) = capacity {
            output.push_str(&format!(
                "# HELP narjar_storage_capacity_bytes Destination filesystem bytes.\n# TYPE narjar_storage_capacity_bytes gauge\nnarjar_storage_capacity_bytes{{kind=\"total\"}} {}\nnarjar_storage_capacity_bytes{{kind=\"available\"}} {}\n\
                 # HELP narjar_storage_capacity_inodes Destination filesystem inodes.\n# TYPE narjar_storage_capacity_inodes gauge\nnarjar_storage_capacity_inodes{{kind=\"total\"}} {}\nnarjar_storage_capacity_inodes{{kind=\"available\"}} {}\n\
                 # HELP narjar_storage_read_only Whether the destination filesystem is read-only.\n# TYPE narjar_storage_read_only gauge\nnarjar_storage_read_only {}\n",
                capacity.total_bytes, capacity.available_bytes, capacity.total_inodes,
                capacity.available_inodes, u8::from(capacity.read_only),
            ));
        }
        output
    }
}

fn request_index(method: usize, route: usize, status: usize) -> usize {
    (method * ROUTES.len() + route) * STATUS_CLASSES.len() + status
}

fn status_index(status: u16) -> usize {
    match status / 100 {
        2 => 0,
        3 => 1,
        4 => 2,
        5 => 3,
        _ => 4,
    }
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
}

impl RequestGuard<'_> {
    pub(crate) fn record_response(&self, status: u16, bytes_out: u64) {
        self.metrics.requests[request_index(
            self.method.index(),
            self.route.index(),
            status_index(status),
        )]
        .fetch_add(1, Ordering::Relaxed);
        if !matches!(self.method, RequestMethod::Head) {
            self.metrics.bytes_out(bytes_out);
        }
    }
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
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
    use super::{Metrics, RequestMethod, RequestRoute, ValidationClass};
    use crate::storage::StorageCapacity;
    use std::time::Duration;

    #[test]
    fn exposition_has_help_types_and_event_deltas() {
        let metrics = Metrics::default();
        let request = metrics.request(RequestMethod::Put, RequestRoute::Nar);
        let head = metrics.request(RequestMethod::Head, RequestRoute::Nar);
        let upload = metrics.upload(17);
        assert!(
            metrics
                .render(true, None)
                .contains("narjar_uploads_in_flight 1")
        );

        metrics.validation_failure(ValidationClass::Nar);
        metrics.set_temp_objects(1);
        metrics.publication(Duration::from_millis(3));
        request.record_response(201, 23);
        head.record_response(200, 23);
        drop(upload);
        drop(request);
        drop(head);

        let exposition = metrics.render(true, None);
        assert!(exposition.contains("# HELP narjar_http_requests_total"));
        assert!(exposition.contains("# TYPE narjar_http_requests_total counter"));
        assert!(
            exposition.contains(
                "narjar_http_requests_total{method=\"PUT\",route=\"nar\",status=\"2xx\"} 1"
            )
        );
        assert!(exposition.contains("narjar_http_bytes_in_total 17"));
        assert!(exposition.contains("narjar_http_bytes_out_total 23"));
        assert!(exposition.contains("narjar_validation_failures_total{class=\"nar\"} 1"));
        assert!(exposition.contains("narjar_uploads_in_flight 0"));
        assert!(exposition.contains("narjar_requests_in_flight 0"));
        assert!(exposition.contains("narjar_temp_objects 1"));
        assert!(exposition.contains("narjar_publications_total 1"));
        assert!(exposition.contains("narjar_ready 1"));
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
        );

        assert!(exposition.contains("narjar_storage_capacity_bytes{kind=\"total\"} 100"));
        assert!(exposition.contains("narjar_storage_capacity_bytes{kind=\"available\"} 40"));
        assert!(exposition.contains("narjar_storage_capacity_inodes{kind=\"total\"} 10"));
        assert!(exposition.contains("narjar_storage_capacity_inodes{kind=\"available\"} 6"));
        assert!(exposition.contains("narjar_storage_read_only 0"));
    }
}
