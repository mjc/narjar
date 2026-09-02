use std::sync::atomic::{AtomicU64, Ordering};

use crate::storage::CapacityErrorKind;

#[derive(Debug, Default)]
pub struct Metrics {
    requests_total: AtomicU64,
    requests_in_flight: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    auth_failures: AtomicU64,
    validation_failures: AtomicU64,
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

impl Metrics {
    pub(crate) fn request(&self) -> RequestGuard<'_> {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.requests_in_flight.fetch_add(1, Ordering::Relaxed);
        RequestGuard(self)
    }

    pub(crate) fn auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
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
    }

    pub(crate) fn render(&self, ready: bool) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        format!(
            "narjar_http_requests_total {}\n\
             narjar_http_bytes_in_total {}\n\
             narjar_http_bytes_out_total {}\n\
             narjar_auth_failures_total {}\n\
             narjar_validation_failures_total {}\n\
             narjar_uploads_in_flight {}\n\
             narjar_requests_in_flight {}\n\
             narjar_temp_objects {}\n\
             narjar_disk_full_total {}\n\
             narjar_capacity_failures_total{{reason=\"no_space\"}} {}\n\
             narjar_capacity_failures_total{{reason=\"quota\"}} {}\n\
             narjar_capacity_failures_total{{reason=\"inodes\"}} {}\n\
             narjar_capacity_failures_total{{reason=\"read_only\"}} {}\n\
             narjar_publications_total {}\n\
             narjar_publication_duration_seconds_count {}\n\
             narjar_publication_duration_seconds_sum {}\n\
             narjar_publication_duration_seconds_max {}\n\
             narjar_ready {}\n",
            load(&self.requests_total),
            load(&self.bytes_in),
            load(&self.bytes_out),
            load(&self.auth_failures),
            load(&self.validation_failures),
            load(&self.uploads_in_flight),
            load(&self.requests_in_flight),
            load(&self.temp_objects),
            load(&self.disk_full),
            load(&self.capacity_no_space),
            load(&self.capacity_quota),
            load(&self.capacity_inodes),
            load(&self.capacity_read_only),
            load(&self.publications),
            load(&self.publication_count),
            load(&self.publication_micros) as f64 / 1_000_000.0,
            load(&self.publication_max_micros) as f64 / 1_000_000.0,
            u8::from(ready),
        )
    }
}

pub(crate) struct RequestGuard<'a>(&'a Metrics);

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        self.0.requests_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}
