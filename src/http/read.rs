use std::{
    io::{self, Read},
    net::TcpStream,
    time::Instant,
};

use crate::{
    auth::{Authorizer, Permission, ReadVisibility},
    http_server::{Method, Request, Response, ResponseHeader as Header, StatusCode, static_header},
    metrics::{
        CacheLookupOutcome, CacheObject, Metrics, NarRangeOutcome, RequestGuard, RequestMethod,
        RequestRoute, render_prometheus,
    },
    narinfo::{MAX_NARINFO_BYTES, TrustedPublicKeys},
    object::NarFileName,
    storage::{NarMatch, NarReadBody, Storage, StorageReadiness, StoreHash},
};

use super::write::unauthorized;

const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

pub(super) fn header(name: &'static str, value: &'static str) -> Header {
    static_header(name, value).expect("static response header is valid")
}

pub(super) fn send_response<R: Read>(
    guard: &RequestGuard<'_>,
    request: Request,
    response: Response<R>,
) -> Option<TcpStream> {
    let status = response.status();
    let transfer_started = Instant::now();
    match request.respond(response) {
        Ok(transfer) => {
            guard.record_completed_response(
                status,
                transfer.body_bytes,
                transfer_started.elapsed(),
            );
            transfer.connection
        }
        Err(transfer) => {
            guard.record_failed_response(status, transfer, transfer_started.elapsed());
            None
        }
    }
}

pub(super) fn not_found(guard: &RequestGuard<'_>, request: Request) -> Option<TcpStream> {
    send_response(guard, request, Response::empty(StatusCode::NOT_FOUND))
}

pub(super) fn internal_error(guard: &RequestGuard<'_>, request: Request) -> Option<TcpStream> {
    send_response(
        guard,
        request,
        Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
    )
}

fn nar_response<R>(
    status: StatusCode,
    content_length: usize,
    visibility: ReadVisibility,
    body: R,
) -> Response<R> {
    cache_policy(
        Response::new(status, body, content_length)
            .with_header(header("Content-Type", "application/x-nix-nar")),
        visibility,
        IMMUTABLE_CACHE_CONTROL,
    )
    .with_header(header("Accept-Ranges", "bytes"))
}

fn cache_policy<R>(
    response: Response<R>,
    visibility: ReadVisibility,
    public_control: &'static str,
) -> Response<R> {
    match visibility {
        ReadVisibility::Private => response
            .with_header(header("Cache-Control", "private, no-store"))
            .with_header(header("Vary", "Authorization")),
        ReadVisibility::Public => response.with_header(header("Cache-Control", public_control)),
    }
}

fn send_file_response(
    guard: &RequestGuard<'_>,
    request: Request,
    response: Response<io::Empty>,
    file: std::fs::File,
    offset: u64,
    length: u64,
) -> Option<TcpStream> {
    let status = response.status();
    let transfer_started = Instant::now();
    match request.respond_file(response, file, offset, length) {
        Ok(transfer) => {
            guard.record_completed_response(
                status,
                transfer.body_bytes,
                transfer_started.elapsed(),
            );
            transfer.connection
        }
        Err(transfer) => {
            guard.record_failed_response(status, transfer, transfer_started.elapsed());
            None
        }
    }
}

fn respond_narinfo(
    request: Request,
    storage: &Storage,
    store: &StoreHash,
    trusted: &TrustedPublicKeys,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
    let lookup_started = Instant::now();
    let narinfo = match storage.open_narinfo(store) {
        Ok(Some(narinfo)) => narinfo,
        Ok(None) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Miss, lookup_started);
            return not_found(guard, request);
        }
        Err(_) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return internal_error(guard, request);
        }
    };
    let mut bytes = Vec::new();
    if narinfo
        .take(MAX_NARINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_NARINFO_BYTES
    {
        record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
        return internal_error(guard, request);
    }
    let validated = match trusted.validate(store, bytes) {
        Ok(validated) => validated,
        Err(_) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return internal_error(guard, request);
        }
    };
    match storage.nar_matches(&validated) {
        Ok(NarMatch::Match) => {}
        Ok(NarMatch::Missing | NarMatch::Mismatch) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return not_found(guard, request);
        }
        Err(_) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return internal_error(guard, request);
        }
    }

    let bytes = match validated.into_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return internal_error(guard, request);
        }
    };
    record_narinfo_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
    let response = cache_policy(
        Response::from_data(bytes).with_header(header("Content-Type", "text/x-nix-narinfo")),
        visibility,
        IMMUTABLE_CACHE_CONTROL,
    );
    send_response(guard, request, response)
}

fn record_narinfo_lookup(
    guard: &RequestGuard<'_>,
    outcome: CacheLookupOutcome,
    lookup_started: Instant,
) {
    guard.record_cache_lookup(CacheObject::NarInfo, outcome, lookup_started.elapsed());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedRange {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
    Invalid,
}

impl RequestedRange {
    const fn metric_outcome(self) -> NarRangeOutcome {
        match self {
            Self::Full => NarRangeOutcome::Full,
            Self::Partial { .. } => NarRangeOutcome::Partial,
            Self::Unsatisfiable => NarRangeOutcome::Unsatisfiable,
            Self::Invalid => NarRangeOutcome::Invalid,
        }
    }
}

fn requested_range(request: &Request, length: u64) -> RequestedRange {
    let mut headers = request
        .headers()
        .iter()
        .filter(|header| header.field.equiv("Range"));
    let Some(header) = headers.next() else {
        return RequestedRange::Full;
    };
    if headers.next().is_some() {
        return RequestedRange::Invalid;
    }

    let Some(specification) = header.value.as_str().strip_prefix("bytes=") else {
        return RequestedRange::Invalid;
    };
    if specification.contains(',') {
        return RequestedRange::Invalid;
    }
    let Some((start, end)) = specification.split_once('-') else {
        return RequestedRange::Invalid;
    };
    if start.is_empty() {
        let Ok(suffix_length) = end.parse::<u64>() else {
            return RequestedRange::Invalid;
        };
        if suffix_length == 0 || length == 0 {
            return RequestedRange::Unsatisfiable;
        }
        let start = length.saturating_sub(suffix_length);
        return RequestedRange::Partial {
            start,
            end: length - 1,
        };
    }

    let Ok(start) = start.parse::<u64>() else {
        return RequestedRange::Invalid;
    };
    if start >= length {
        return RequestedRange::Unsatisfiable;
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        let Ok(end) = end.parse::<u64>() else {
            return RequestedRange::Invalid;
        };
        if start > end {
            return RequestedRange::Unsatisfiable;
        }
        end.min(length - 1)
    };
    RequestedRange::Partial { start, end }
}

fn respond_nar(
    request: Request,
    storage: &Storage,
    name: NarFileName,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
    let lookup_started = Instant::now();
    let length = match storage.nar_size(name) {
        Ok(Some(length)) => length,
        Ok(None) => {
            record_nar_lookup(guard, CacheLookupOutcome::Miss, lookup_started);
            return not_found(guard, request);
        }
        Err(_) => {
            record_nar_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return internal_error(guard, request);
        }
    };

    let range = requested_range(&request, length);
    guard.record_nar_range_request(range.metric_outcome());
    match range {
        RequestedRange::Full => {
            let Ok(content_length) = usize::try_from(length) else {
                record_nar_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
                return internal_error(guard, request);
            };
            let opened = storage.open_nar_range(name, 0..length);
            record_nar_open_outcome(guard, &opened, lookup_started);
            let opened = match opened {
                Ok(Some(opened)) => opened,
                Ok(None) => return not_found(guard, request),
                Err(_) => return internal_error(guard, request),
            };
            match opened.body {
                NarReadBody::File(file) => {
                    let response =
                        nar_response(StatusCode::OK, content_length, visibility, io::empty());
                    send_file_response(guard, request, response, file, 0, content_length as u64)
                }
                NarReadBody::Chunked(reader) => {
                    let response = nar_response(StatusCode::OK, content_length, visibility, reader);
                    send_response(guard, request, response)
                }
            }
        }
        RequestedRange::Partial { start, end } => {
            let response_length = end - start + 1;
            let Ok(content_length) = usize::try_from(response_length) else {
                record_nar_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
                return internal_error(guard, request);
            };
            let opened = storage.open_nar_range(name, start..end + 1);
            record_nar_open_outcome(guard, &opened, lookup_started);
            let opened = match opened {
                Ok(Some(opened)) => opened,
                Ok(None) => return not_found(guard, request),
                Err(_) => return internal_error(guard, request),
            };
            match opened.body {
                NarReadBody::File(file) => {
                    let response = nar_response(
                        StatusCode::PARTIAL_CONTENT,
                        content_length,
                        visibility,
                        io::empty(),
                    )
                    .with_header(
                        Header::owned("Content-Range", format!("bytes {start}-{end}/{length}"))
                            .expect("range response header is valid"),
                    );
                    send_file_response(guard, request, response, file, start, response_length)
                }
                NarReadBody::Chunked(reader) => {
                    let response = nar_response(
                        StatusCode::PARTIAL_CONTENT,
                        content_length,
                        visibility,
                        reader,
                    )
                    .with_header(
                        Header::owned("Content-Range", format!("bytes {start}-{end}/{length}"))
                            .expect("range response header is valid"),
                    );
                    send_response(guard, request, response)
                }
            }
        }
        RequestedRange::Unsatisfiable => {
            record_nar_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
            let response = Response::empty(StatusCode::RANGE_NOT_SATISFIABLE).with_header(
                Header::owned("Content-Range", format!("bytes */{length}"))
                    .expect("range response header is valid"),
            );
            send_response(guard, request, response)
        }
        RequestedRange::Invalid => {
            record_nar_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
            send_response(guard, request, Response::empty(StatusCode::BAD_REQUEST))
        }
    }
}

fn record_nar_open_outcome<T, E>(
    guard: &RequestGuard<'_>,
    opened: &Result<Option<T>, E>,
    lookup_started: Instant,
) {
    let outcome = match opened {
        Ok(Some(_)) => CacheLookupOutcome::Hit,
        Ok(None) | Err(_) => CacheLookupOutcome::Failure,
    };
    record_nar_lookup(guard, outcome, lookup_started);
}

fn record_nar_lookup(
    guard: &RequestGuard<'_>,
    outcome: CacheLookupOutcome,
    lookup_started: Instant,
) {
    guard.record_cache_lookup(CacheObject::Nar, outcome, lookup_started.elapsed());
}

#[derive(Debug)]
pub(super) enum CacheRoute {
    CacheInfo,
    Nar(NarFileName),
    NarInfo(StoreHash),
}

#[derive(Debug)]
pub(super) enum RouteMatch {
    Found(CacheRoute),
    InvalidNarPath,
    Invalid,
    Missing,
}

impl CacheRoute {
    pub(super) fn classify(url: &str) -> RouteMatch {
        normalize_main_alias(url).map_or_else(|route| route, Self::classify_normalized)
    }

    fn classify_normalized(url: &str) -> RouteMatch {
        if url.starts_with("//") || url.contains(['\\', '?', '#']) {
            return invalid_cache_route(url);
        }
        if url == "/nix-cache-info" {
            return RouteMatch::Found(Self::CacheInfo);
        }

        if let Some(path) = url.strip_prefix("/nar/") {
            return match NarFileName::parse(path) {
                Ok(name) => RouteMatch::Found(Self::Nar(name)),
                Err(_) => RouteMatch::InvalidNarPath,
            };
        }
        if url == "/nar" || url.starts_with("/nix-cache-info/") {
            return RouteMatch::Invalid;
        }

        if let Some(hash) = url
            .strip_prefix('/')
            .and_then(|path| path.strip_suffix(".narinfo"))
        {
            return match StoreHash::parse(hash) {
                Ok(store) => RouteMatch::Found(Self::NarInfo(store)),
                Err(_) => RouteMatch::Invalid,
            };
        }

        RouteMatch::Missing
    }
}

#[derive(Clone, Copy)]
enum OperatorRoute {
    Health,
    Protected(ProtectedOperatorRoute),
}

#[derive(Clone, Copy)]
enum ProtectedOperatorRoute {
    Readiness,
    Metrics,
}

enum ReadRoute {
    Operator(OperatorRoute),
    Cache(RouteMatch),
}

impl ReadRoute {
    fn classify(url: &str) -> Self {
        let url = match normalize_main_alias(url) {
            Ok(url) => url,
            Err(route) => return Self::Cache(route),
        };
        match url {
            "/healthz" => Self::Operator(OperatorRoute::Health),
            "/readyz" => {
                Self::Operator(OperatorRoute::Protected(ProtectedOperatorRoute::Readiness))
            }
            "/metrics" => Self::Operator(OperatorRoute::Protected(ProtectedOperatorRoute::Metrics)),
            _ => Self::Cache(CacheRoute::classify_normalized(url)),
        }
    }

    fn metrics_route(&self) -> RequestRoute {
        match self {
            Self::Operator(OperatorRoute::Health) => RequestRoute::Health,
            Self::Operator(OperatorRoute::Protected(ProtectedOperatorRoute::Readiness)) => {
                RequestRoute::Ready
            }
            Self::Operator(OperatorRoute::Protected(ProtectedOperatorRoute::Metrics)) => {
                RequestRoute::Metrics
            }
            Self::Cache(RouteMatch::Found(CacheRoute::CacheInfo)) => RequestRoute::CacheInfo,
            Self::Cache(RouteMatch::Found(CacheRoute::Nar(_))) => RequestRoute::Nar,
            Self::Cache(RouteMatch::Found(CacheRoute::NarInfo(_))) => RequestRoute::NarInfo,
            Self::Cache(RouteMatch::InvalidNarPath | RouteMatch::Invalid) => RequestRoute::Invalid,
            Self::Cache(RouteMatch::Missing) => RequestRoute::Missing,
        }
    }
}

fn normalize_main_alias(url: &str) -> Result<&str, RouteMatch> {
    match url.strip_prefix("/main") {
        Some("") => Err(RouteMatch::Invalid),
        Some(path) if path.starts_with('/') => Ok(path),
        Some(_) => Err(RouteMatch::Missing),
        None => Ok(url),
    }
}

fn invalid_cache_route(url: &str) -> RouteMatch {
    if url.starts_with("/nar/") {
        RouteMatch::InvalidNarPath
    } else {
        RouteMatch::Invalid
    }
}

fn method_not_allowed(
    guard: &RequestGuard<'_>,
    request: Request,
    allow: &'static str,
) -> Option<TcpStream> {
    let response =
        Response::empty(StatusCode::METHOD_NOT_ALLOWED).with_header(header("Allow", allow));
    send_response(guard, request, response)
}

pub(super) fn has_header(request: &Request, name: &'static str) -> bool {
    request
        .headers()
        .iter()
        .any(|header| header.field.equiv(name))
}

pub(super) fn request_route(url: &str) -> RequestRoute {
    ReadRoute::classify(url).metrics_route()
}

fn invalid_route_status(method: Method, route: &RouteMatch) -> StatusCode {
    match (route, method) {
        (RouteMatch::InvalidNarPath, Method::Get | Method::Head) => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    }
}

pub fn respond(
    request: Request,
    storage: &Storage,
    authorizer: &Authorizer,
    trusted: &TrustedPublicKeys,
    metrics: &Metrics,
    min_free_bytes: u64,
) -> Option<TcpStream> {
    let route = ReadRoute::classify(request.url());
    let guard = metrics.request(RequestMethod::from(request.method()), route.metrics_route());
    match route {
        ReadRoute::Operator(operator) => respond_operator_route(
            operator,
            request,
            storage,
            authorizer,
            metrics,
            min_free_bytes,
            &guard,
        ),
        ReadRoute::Cache(route) => respond_cache_route(
            route, request, storage, authorizer, trusted, metrics, &guard,
        ),
    }
}

fn respond_operator_route(
    operator: OperatorRoute,
    request: Request,
    storage: &Storage,
    authorizer: &Authorizer,
    metrics: &Metrics,
    min_free_bytes: u64,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    match operator {
        OperatorRoute::Health => match request.method() {
            Method::Get | Method::Head => send_response(
                guard,
                request,
                Response::from_string("ok\n")
                    .with_status_code(StatusCode::OK)
                    .with_header(header("Content-Type", "text/plain; charset=utf-8")),
            ),
            _ => method_not_allowed(guard, request, "GET, HEAD"),
        },
        OperatorRoute::Protected(operator) => {
            match request.method() {
                Method::Get | Method::Head => {}
                _ => return method_not_allowed(guard, request, "GET, HEAD"),
            }
            if !authorizer.allows(&request, Permission::Read) {
                metrics.auth_failure(false);
                return unauthorized(guard, request);
            }
            let readiness = storage
                .is_ready(min_free_bytes)
                .unwrap_or(StorageReadiness::ProbeFailed);
            match operator {
                ProtectedOperatorRoute::Readiness => {
                    let (status, body) = match readiness {
                        StorageReadiness::Ready => (StatusCode::OK, "ready\n"),
                        StorageReadiness::LowSpace
                        | StorageReadiness::NoInodes
                        | StorageReadiness::ReadOnly
                        | StorageReadiness::ProbeFailed => {
                            (StatusCode::SERVICE_UNAVAILABLE, "insufficient_space\n")
                        }
                    };
                    send_response(
                        guard,
                        request,
                        Response::from_string(body)
                            .with_status_code(status)
                            .with_header(header("Content-Type", "text/plain; charset=utf-8")),
                    )
                }
                ProtectedOperatorRoute::Metrics => {
                    metrics.set_temp_objects(storage.temporary_objects());
                    let (capacity, staging_bytes) = storage
                        .capacity_and_staging()
                        .map(|(capacity, staging_bytes)| (Some(capacity), staging_bytes))
                        .unwrap_or((None, 0));
                    let mut snapshot = metrics.snapshot(
                        readiness,
                        capacity,
                        storage.temporary_objects(),
                        min_free_bytes,
                        staging_bytes,
                    );
                    snapshot.storage_activity = storage.activity_snapshot();
                    send_response(
                        guard,
                        request,
                        Response::from_string(render_prometheus(&snapshot))
                            .with_status_code(StatusCode::OK)
                            .with_header(header(
                                "Content-Type",
                                "text/plain; version=0.0.4; charset=utf-8",
                            ))
                            .with_header(header("Cache-Control", "no-store"))
                            .with_header(header("Vary", "Authorization")),
                    )
                }
            }
        }
    }
}

fn respond_cache_route(
    route: RouteMatch,
    request: Request,
    storage: &Storage,
    authorizer: &Authorizer,
    trusted: &TrustedPublicKeys,
    metrics: &Metrics,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    if !authorizer.allows(&request, Permission::Read) {
        metrics.auth_failure(false);
        return unauthorized(guard, request);
    }
    match route {
        RouteMatch::InvalidNarPath | RouteMatch::Invalid => {
            let status = invalid_route_status(request.method(), &route);
            send_response(guard, request, Response::empty(status))
        }
        RouteMatch::Missing => not_found(guard, request),
        RouteMatch::Found(route) => {
            match request.method() {
                Method::Get | Method::Head => {}
                _ => return method_not_allowed(guard, request, "GET, HEAD, PUT"),
            }
            let visibility = authorizer.read_visibility();
            match route {
                CacheRoute::CacheInfo => {
                    let cache_info = match storage.cache_info() {
                        Ok(cache_info) => cache_info,
                        Err(_) => return internal_error(guard, request),
                    };
                    let response = cache_policy(
                        Response::from_data(cache_info)
                            .with_header(header("Content-Type", "text/x-nix-cache-info")),
                        visibility,
                        "public, max-age=3600",
                    );
                    send_response(guard, request, response)
                }
                CacheRoute::Nar(name) => respond_nar(request, storage, name, guard, visibility),
                CacheRoute::NarInfo(store) => {
                    respond_narinfo(request, storage, &store, trusted, guard, visibility)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::{
        CacheRoute, RouteMatch, invalid_route_status, record_nar_open_outcome, request_route,
    };
    use crate::{
        http_server::{Method, StatusCode},
        metrics::{Metrics, RequestMethod, RequestRoute as MetricsRoute},
        object::{CompressionCodec, WireEncoding},
        storage::StorageReadiness,
    };

    #[test]
    fn nar_open_failure_after_size_lookup_is_not_counted_as_a_hit() {
        let metrics = Metrics::default();
        let guard = metrics.request(RequestMethod::Get, MetricsRoute::Nar);
        let missing_after_size: Result<Option<()>, std::io::Error> = Ok(None);

        record_nar_open_outcome(&guard, &missing_after_size, Instant::now());
        drop(guard);

        let lookup = metrics
            .snapshot(StorageReadiness::Ready, None, 0, 0, 0)
            .cache
            .nar_get;
        assert_eq!(lookup.hits, 0);
        assert_eq!(lookup.failures, 1);
        assert_eq!(lookup.hit_ratio, None);
    }

    #[test]
    fn malformed_nar_reads_are_cache_misses() {
        assert_eq!(
            invalid_route_status(Method::Get, &RouteMatch::InvalidNarPath),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            invalid_route_status(Method::Put, &RouteMatch::InvalidNarPath),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn legacy_main_prefix_maps_to_cache_routes() {
        assert!(matches!(
            CacheRoute::classify("/main/nix-cache-info"),
            RouteMatch::Found(CacheRoute::CacheInfo)
        ));
        assert!(matches!(
            CacheRoute::classify("/main/00000000000000000000000000000000.narinfo"),
            RouteMatch::Found(CacheRoute::NarInfo(_))
        ));
        assert!(matches!(
            CacheRoute::classify(
                "/main/nar/0000000000000000000000000000000000000000000000000000.nar"
            ),
            RouteMatch::Found(CacheRoute::Nar(name)) if name.encoding() == WireEncoding::Raw
        ));
    }

    #[test]
    fn encoded_nar_routes_preserve_the_requested_encoding() {
        assert!(matches!(
            CacheRoute::classify("/nar/0000000000000000000000000000000000000000000000000000.nar.xz"),
            RouteMatch::Found(CacheRoute::Nar(name))
                if name.encoding() == WireEncoding::Compressed(CompressionCodec::Xz)
        ));
        assert!(matches!(
            CacheRoute::classify(
                "/nar/0000000000000000000000000000000000000000000000000000.nar.zst"
            ),
            RouteMatch::Found(CacheRoute::Nar(name))
                if name.encoding() == WireEncoding::Compressed(CompressionCodec::Zstd)
        ));
    }

    #[test]
    fn request_metrics_use_validated_routes_and_bound_unknown_paths() {
        let nar = "/nar/0000000000000000000000000000000000000000000000000000.nar";
        let narinfo = "/00000000000000000000000000000000.narinfo";

        assert!(matches!(request_route("/metrics"), MetricsRoute::Metrics));
        assert!(matches!(
            request_route("/main/metrics"),
            MetricsRoute::Metrics
        ));
        assert!(matches!(request_route(nar), MetricsRoute::Nar));
        assert!(matches!(
            request_route("/main/nar/0000000000000000000000000000000000000000000000000000.nar"),
            MetricsRoute::Nar
        ));
        assert!(matches!(request_route(narinfo), MetricsRoute::NarInfo));
        assert!(matches!(
            request_route("/nar/not-a-hash.nar"),
            MetricsRoute::Invalid
        ));
        assert!(matches!(request_route("/stats"), MetricsRoute::Missing));
        assert!(matches!(
            request_route("/unrecognized"),
            MetricsRoute::Missing
        ));
    }
}
