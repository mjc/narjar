use std::{
    io::{self, Read},
    net::TcpStream,
    time::Instant,
};

use crate::cache::{
    auth::{Authorizer, Permission, ReadVisibility},
    http_server::{Method, Request, Response, ResponseHeader as Header, StatusCode, static_header},
    metrics::{
        CacheLookupOutcome, CacheObject, Metrics, NarRangeOutcome, RequestGuard, RequestMethod,
        RequestRoute, render_prometheus,
    },
    object::NarFileName,
    storage::{NarReadBody, Storage, StorageReadiness, StoreHash},
};

use super::write::unauthorized;
#[cfg(unix)]
use crate::native_store::serving::{NativeReadError, NativeStoreSource};
use crate::read_through::ReadThroughSource;

pub(crate) enum ReadSource {
    FlatCache,
    #[cfg(unix)]
    NativeStore(Box<NativeStoreSource>),
    ReadThrough(Box<ReadThroughSource>),
}

#[derive(Clone, Copy)]
pub(crate) struct ReadContext<'a> {
    pub(crate) storage: &'a Storage,
    pub(crate) source: &'a ReadSource,
}

impl ReadSource {
    pub(crate) fn maintain(&self) {
        match self {
            Self::FlatCache => {}
            #[cfg(unix)]
            Self::NativeStore(source) => source.maintain(),
            Self::ReadThrough(source) => source.maintain(),
        }
    }

    fn allowed_methods(&self) -> &'static str {
        match self {
            Self::FlatCache => "GET, HEAD, PUT",
            #[cfg(unix)]
            Self::NativeStore(_) => "GET, HEAD",
            Self::ReadThrough(_) => "GET, HEAD",
        }
    }
}

impl ReadContext<'_> {
    fn readiness(self, min_free_bytes: u64) -> StorageReadiness {
        match self.source {
            ReadSource::FlatCache | ReadSource::ReadThrough(_) => self
                .storage
                .is_ready(min_free_bytes)
                .unwrap_or(StorageReadiness::ProbeFailed),
            #[cfg(unix)]
            ReadSource::NativeStore(source) => source
                .readiness(min_free_bytes)
                .unwrap_or(StorageReadiness::ProbeFailed),
        }
    }
}

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

pub(super) fn prevent_operator_and_auth_response_caching<R>(response: Response<R>) -> Response<R> {
    response
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("Vary", "Authorization"))
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
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
    public_control: &'static str,
) -> Option<TcpStream> {
    let lookup_started = Instant::now();
    let advertisement = match load_published_narinfo(storage, store) {
        Ok(advertisement) => advertisement,
        Err(NarInfoReadFailure::Missing) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Miss, lookup_started);
            return not_found(guard, request);
        }
        Err(NarInfoReadFailure::InvalidOrUnreadable) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
            return internal_error(guard, request);
        }
    };
    record_narinfo_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
    send_advertised_narinfo(request, advertisement, guard, visibility, public_control)
}

fn send_advertised_narinfo(
    request: Request,
    advertisement: crate::cache::storage::AdvertisedNarInfo<'_>,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
    public_control: &'static str,
) -> Option<TcpStream> {
    let crate::cache::storage::AdvertisedNarInfo { bytes, _activity } = advertisement;
    let response = cache_policy(
        Response::from_data(bytes).with_header(header("Content-Type", "text/x-nix-narinfo")),
        visibility,
        public_control,
    );
    send_response(guard, request, response)
}

fn respond_edge_narinfo(
    request: Request,
    storage: &Storage,
    source: &ReadThroughSource,
    store: &StoreHash,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
    let lookup_started = Instant::now();
    match source.advertise(storage, store) {
        Ok(advertisement) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
            send_advertised_narinfo(request, advertisement, guard, visibility, "no-store")
        }
        Err(_) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Miss, lookup_started);
            send_response(
                guard,
                request,
                cache_policy(
                    Response::empty(StatusCode::NOT_FOUND),
                    visibility,
                    "no-store",
                ),
            )
        }
    }
}

#[derive(Clone, Copy)]
enum NarInfoReadFailure {
    Missing,
    InvalidOrUnreadable,
}

fn load_published_narinfo<'storage>(
    storage: &'storage Storage,
    store: &StoreHash,
) -> Result<crate::cache::storage::AdvertisedNarInfo<'storage>, NarInfoReadFailure> {
    let narinfo = storage
        .read_advertised_narinfo(store)
        .map_err(|_| NarInfoReadFailure::InvalidOrUnreadable)?
        .ok_or(NarInfoReadFailure::Missing)?;
    Ok(narinfo)
}

fn record_narinfo_lookup(
    guard: &RequestGuard<'_>,
    outcome: CacheLookupOutcome,
    lookup_started: Instant,
) {
    guard.record_cache_lookup(CacheObject::NarInfo, outcome, lookup_started.elapsed());
}

#[cfg(unix)]
fn native_read_failure(
    request: Request,
    guard: &RequestGuard<'_>,
    error: NativeReadError,
) -> Option<TcpStream> {
    match error {
        NativeReadError::Missing | NativeReadError::Signature => not_found(guard, request),
        NativeReadError::Metadata(_) | NativeReadError::Lease(_) | NativeReadError::Delivery(_) => {
            eprintln!("narjar: {error}");
            send_response(
                guard,
                request,
                Response::empty(StatusCode::SERVICE_UNAVAILABLE),
            )
        }
    }
}

#[cfg(unix)]
fn native_lookup_outcome(error: &NativeReadError) -> CacheLookupOutcome {
    match error {
        NativeReadError::Missing | NativeReadError::Signature => CacheLookupOutcome::Miss,
        NativeReadError::Metadata(_) | NativeReadError::Lease(_) | NativeReadError::Delivery(_) => {
            CacheLookupOutcome::Failure
        }
    }
}

#[cfg(unix)]
fn respond_native_narinfo(
    request: Request,
    source: &NativeStoreSource,
    store: StoreHash,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
    let started = Instant::now();
    match source.advertise(store) {
        Ok(advertisement) => {
            record_narinfo_lookup(guard, CacheLookupOutcome::Hit, started);
            let response = cache_policy(
                Response::from_data(advertisement.bytes)
                    .with_header(header("Content-Type", "text/x-nix-narinfo")),
                visibility,
                "public, max-age=0, must-revalidate",
            );
            send_response(guard, request, response)
        }
        Err(error) => {
            record_narinfo_lookup(guard, native_lookup_outcome(&error), started);
            native_read_failure(request, guard, error)
        }
    }
}

#[cfg(unix)]
fn respond_native_nar(
    request: Request,
    source: &NativeStoreSource,
    name: NarFileName,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
    let started = Instant::now();
    let opened = name
        .raw_hash()
        .ok_or(NativeReadError::Missing)
        .and_then(|hash| source.resolve_nar(hash));
    let object = match opened {
        Ok(object) => object,
        Err(error) => {
            record_nar_lookup(guard, native_lookup_outcome(&error), started);
            return native_read_failure(request, guard, error);
        }
    };
    let length = object.identity().size().get();
    let requested = requested_range(&request, length);
    guard.record_nar_range_request(requested.metric_outcome());
    let range = match requested {
        RequestedRange::Full => NarResponseRange::Full { length },
        RequestedRange::Partial { start, end } => NarResponseRange::Partial {
            start,
            end,
            nar_length: length,
        },
        RequestedRange::Unsatisfiable => {
            return respond_unsatisfiable_nar_range(request, length, guard, started);
        }
        RequestedRange::Invalid => return respond_invalid_nar_range(request, guard, started),
    };
    let content_length = match usize::try_from(range.content_length()) {
        Ok(length) => length,
        Err(_) => return internal_error(guard, request),
    };
    match request.method() {
        Method::Head => {
            record_nar_lookup(guard, CacheLookupOutcome::Hit, started);
            send_response(
                guard,
                request,
                nar_range_response(range, content_length, visibility, io::empty()),
            )
        }
        Method::Get | Method::Put | Method::Other => {
            let reader = source.open_delivery(object).and_then(|delivery| {
                delivery
                    .into_range_reader(range.byte_range())
                    .map_err(Into::into)
            });
            match reader {
                Ok(reader) => {
                    record_nar_lookup(guard, CacheLookupOutcome::Hit, started);
                    send_response(
                        guard,
                        request,
                        nar_range_response(
                            range,
                            content_length,
                            visibility,
                            source.observe_delivery_reader(reader),
                        ),
                    )
                }
                Err(error) => {
                    record_nar_lookup(guard, CacheLookupOutcome::Failure, started);
                    native_read_failure(request, guard, error)
                }
            }
        }
    }
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
    match request.method() {
        Method::Get => {}
        Method::Head | Method::Put | Method::Other => return RequestedRange::Full,
    }
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

    parse_range_value(header.value.as_str(), length)
}

fn parse_range_value(value: &str, length: u64) -> RequestedRange {
    let Some(specification) = value.strip_prefix("bytes=") else {
        return RequestedRange::Invalid;
    };
    if specification.contains(',') {
        return RequestedRange::Invalid;
    }
    let Some((start, end)) = specification.split_once('-') else {
        return RequestedRange::Invalid;
    };

    if start.is_empty() {
        parse_suffix_range(end, length)
    } else {
        parse_starting_range(start, end, length)
    }
}

fn parse_suffix_range(suffix: &str, length: u64) -> RequestedRange {
    let Ok(suffix_length) = suffix.parse::<u64>() else {
        return RequestedRange::Invalid;
    };
    if suffix_length == 0 || length == 0 {
        return RequestedRange::Unsatisfiable;
    }
    RequestedRange::Partial {
        start: length.saturating_sub(suffix_length),
        end: length - 1,
    }
}

fn parse_starting_range(start: &str, end: &str, length: u64) -> RequestedRange {
    let Ok(start) = start.parse::<u64>() else {
        return RequestedRange::Invalid;
    };
    if start >= length {
        return RequestedRange::Unsatisfiable;
    }
    parse_range_end(start, end, length)
}

fn parse_range_end(start: u64, end: &str, length: u64) -> RequestedRange {
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
        RequestedRange::Full => respond_nar_bytes(
            request,
            storage,
            name,
            NarResponseRange::Full { length },
            NarResponseContext {
                guard,
                visibility,
                lookup_started,
            },
        ),
        RequestedRange::Partial { start, end } => respond_nar_bytes(
            request,
            storage,
            name,
            NarResponseRange::Partial {
                start,
                end,
                nar_length: length,
            },
            NarResponseContext {
                guard,
                visibility,
                lookup_started,
            },
        ),
        RequestedRange::Unsatisfiable => {
            respond_unsatisfiable_nar_range(request, length, guard, lookup_started)
        }
        RequestedRange::Invalid => respond_invalid_nar_range(request, guard, lookup_started),
    }
}

#[derive(Clone, Copy)]
enum NarResponseRange {
    Full {
        length: u64,
    },
    Partial {
        start: u64,
        end: u64,
        nar_length: u64,
    },
}

impl NarResponseRange {
    fn byte_range(self) -> std::ops::Range<u64> {
        match self {
            Self::Full { length } => 0..length,
            Self::Partial { start, end, .. } => start..end + 1,
        }
    }

    fn content_length(self) -> u64 {
        match self {
            Self::Full { length } => length,
            Self::Partial { start, end, .. } => end - start + 1,
        }
    }
}

#[derive(Clone, Copy)]
struct NarResponseContext<'guard, 'metrics> {
    guard: &'guard RequestGuard<'metrics>,
    visibility: ReadVisibility,
    lookup_started: Instant,
}

fn respond_nar_bytes(
    request: Request,
    storage: &Storage,
    name: NarFileName,
    response_range: NarResponseRange,
    context: NarResponseContext<'_, '_>,
) -> Option<TcpStream> {
    let NarResponseContext {
        guard,
        visibility,
        lookup_started,
    } = context;
    let range = response_range.byte_range();
    let range_length = response_range.content_length();
    let Ok(content_length) = usize::try_from(range_length) else {
        record_nar_lookup(guard, CacheLookupOutcome::Failure, lookup_started);
        return internal_error(guard, request);
    };
    let opened = storage.open_nar_range(name, range.clone());
    record_nar_open_outcome(guard, &opened, lookup_started);
    let opened = match opened {
        Ok(Some(opened)) => opened,
        Ok(None) => return not_found(guard, request),
        Err(_) => return internal_error(guard, request),
    };
    opened.record_served_access(storage, name);
    match opened.body {
        NarReadBody::File(file) => {
            let response =
                nar_range_response(response_range, content_length, visibility, io::empty());
            send_file_response(guard, request, response, file, range.start, range_length)
        }
        NarReadBody::Chunked { reader, _activity } => {
            let response = nar_range_response(response_range, content_length, visibility, reader);
            send_response(guard, request, response)
        }
    }
}

fn nar_range_response<R>(
    response_range: NarResponseRange,
    content_length: usize,
    visibility: ReadVisibility,
    body: R,
) -> Response<R> {
    match response_range {
        NarResponseRange::Full { .. } => {
            nar_response(StatusCode::OK, content_length, visibility, body)
        }
        NarResponseRange::Partial {
            start,
            end,
            nar_length,
        } => nar_response(
            StatusCode::PARTIAL_CONTENT,
            content_length,
            visibility,
            body,
        )
        .with_header(
            Header::owned("Content-Range", format!("bytes {start}-{end}/{nar_length}"))
                .expect("range response header is valid"),
        ),
    }
}

fn respond_unsatisfiable_nar_range(
    request: Request,
    nar_length: u64,
    guard: &RequestGuard<'_>,
    lookup_started: Instant,
) -> Option<TcpStream> {
    record_nar_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
    let response = Response::empty(StatusCode::RANGE_NOT_SATISFIABLE).with_header(
        Header::owned("Content-Range", format!("bytes */{nar_length}"))
            .expect("range response header is valid"),
    );
    send_response(guard, request, response)
}

fn respond_invalid_nar_range(
    request: Request,
    guard: &RequestGuard<'_>,
    lookup_started: Instant,
) -> Option<TcpStream> {
    record_nar_lookup(guard, CacheLookupOutcome::Hit, lookup_started);
    send_response(guard, request, Response::empty(StatusCode::BAD_REQUEST))
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
    context: ReadContext<'_>,
    authorizer: &Authorizer,
    metrics: &Metrics,
    min_free_bytes: u64,
) -> Option<TcpStream> {
    let route = ReadRoute::classify(request.url());
    let guard = metrics.request(RequestMethod::from(request.method()), route.metrics_route());
    match route {
        ReadRoute::Operator(operator) => respond_operator_route(
            operator,
            request,
            context,
            authorizer,
            metrics,
            min_free_bytes,
            &guard,
        ),
        ReadRoute::Cache(route) => {
            respond_cache_route(route, request, context, authorizer, metrics, &guard)
        }
    }
}

fn respond_operator_route(
    operator: OperatorRoute,
    request: Request,
    context: ReadContext<'_>,
    authorizer: &Authorizer,
    metrics: &Metrics,
    min_free_bytes: u64,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    match operator {
        OperatorRoute::Health => respond_health_request(request, guard),
        OperatorRoute::Protected(operator) => respond_protected_operator(
            operator,
            request,
            context,
            authorizer,
            metrics,
            min_free_bytes,
            guard,
        ),
    }
}

fn respond_health_request(request: Request, guard: &RequestGuard<'_>) -> Option<TcpStream> {
    match request.method() {
        Method::Get | Method::Head => send_response(
            guard,
            request,
            prevent_operator_and_auth_response_caching(
                Response::from_string("ok\n")
                    .with_status_code(StatusCode::OK)
                    .with_header(header("Content-Type", "text/plain; charset=utf-8")),
            ),
        ),
        _ => method_not_allowed(guard, request, "GET, HEAD"),
    }
}

fn respond_protected_operator(
    operator: ProtectedOperatorRoute,
    request: Request,
    context: ReadContext<'_>,
    authorizer: &Authorizer,
    metrics: &Metrics,
    min_free_bytes: u64,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    match request.method() {
        Method::Get | Method::Head => {}
        _ => return method_not_allowed(guard, request, "GET, HEAD"),
    }
    if !authorizer.allows(&request, Permission::Read) {
        metrics.auth_failure(false);
        return unauthorized(guard, request);
    }
    match operator {
        ProtectedOperatorRoute::Readiness => {
            respond_readiness(request, context.readiness(min_free_bytes), guard)
        }
        ProtectedOperatorRoute::Metrics => respond_metrics(request, context, metrics, guard),
    }
}

fn respond_readiness(
    request: Request,
    readiness: StorageReadiness,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    let (status, body) = readiness_response(readiness);
    send_response(
        guard,
        request,
        prevent_operator_and_auth_response_caching(
            Response::from_string(body)
                .with_status_code(status)
                .with_header(header("Content-Type", "text/plain; charset=utf-8")),
        ),
    )
}

fn readiness_response(readiness: StorageReadiness) -> (StatusCode, &'static str) {
    match readiness {
        StorageReadiness::Ready => (StatusCode::OK, "ready\n"),
        StorageReadiness::LowSpace => (StatusCode::SERVICE_UNAVAILABLE, "insufficient_space\n"),
        StorageReadiness::NoInodes => (StatusCode::SERVICE_UNAVAILABLE, "no_inodes\n"),
        StorageReadiness::ReadOnly => (StatusCode::SERVICE_UNAVAILABLE, "read_only\n"),
        StorageReadiness::ProbeFailed => (StatusCode::SERVICE_UNAVAILABLE, "probe_failed\n"),
    }
}

fn respond_metrics(
    request: Request,
    context: ReadContext<'_>,
    metrics: &Metrics,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    let storage = context.storage;
    let temporary_objects = storage.temporary_objects();
    metrics.set_temp_objects(temporary_objects);
    let mut snapshot = metrics.snapshot();
    snapshot.storage_activity = storage.activity_snapshot();
    let mut output = render_prometheus(&snapshot);
    match context.source {
        ReadSource::FlatCache => output.push_str(
            "# TYPE narjar_source_info gauge\nnarjar_source_info{source=\"flat-cache\"} 1\n",
        ),
        #[cfg(unix)]
        ReadSource::NativeStore(source) => {
            output.push_str(
                "# TYPE narjar_source_info gauge\nnarjar_source_info{source=\"native-store\"} 1\n",
            );
            source.append_metrics(&mut output);
        }
        ReadSource::ReadThrough(source) => {
            output.push_str(
                "# TYPE narjar_source_info gauge\nnarjar_source_info{source=\"read-through\"} 1\n",
            );
            source.append_metrics(&mut output);
        }
    }
    let response = prevent_operator_and_auth_response_caching(
        Response::from_string(output)
            .with_status_code(StatusCode::OK)
            .with_header(header(
                "Content-Type",
                "text/plain; version=0.0.4; charset=utf-8",
            )),
    );
    send_response(guard, request, response)
}

fn respond_cache_route(
    route: RouteMatch,
    request: Request,
    context: ReadContext<'_>,
    authorizer: &Authorizer,
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
                _ => return method_not_allowed(guard, request, context.source.allowed_methods()),
            }
            let visibility = authorizer.read_visibility();
            match route {
                CacheRoute::CacheInfo => {
                    let cache_info = match context.storage.cache_info() {
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
                CacheRoute::Nar(name) => match context.source {
                    ReadSource::FlatCache | ReadSource::ReadThrough(_) => {
                        respond_nar(request, context.storage, name, guard, visibility)
                    }
                    #[cfg(unix)]
                    ReadSource::NativeStore(source) => {
                        respond_native_nar(request, source, name, guard, visibility)
                    }
                },
                CacheRoute::NarInfo(store) => match context.source {
                    ReadSource::FlatCache => respond_narinfo(
                        request,
                        context.storage,
                        &store,
                        guard,
                        visibility,
                        IMMUTABLE_CACHE_CONTROL,
                    ),
                    #[cfg(unix)]
                    ReadSource::NativeStore(source) => {
                        respond_native_narinfo(request, source, store, guard, visibility)
                    }
                    ReadSource::ReadThrough(source) => respond_edge_narinfo(
                        request,
                        context.storage,
                        source,
                        &store,
                        guard,
                        visibility,
                    ),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::{
        CacheRoute, RequestedRange, RouteMatch, invalid_route_status, parse_range_value,
        readiness_response, record_nar_open_outcome, request_route,
    };
    use crate::cache::{
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

        let lookup = metrics.snapshot().cache.nar_get;
        assert_eq!(lookup.hits, 0);
        assert_eq!(lookup.failures, 1);
        assert_eq!(lookup.hit_ratio, None);
    }

    #[test]
    fn byte_range_forms_have_explicit_valid_invalid_and_unsatisfiable_results() {
        let cases = [
            ("bytes=2-5", RequestedRange::Partial { start: 2, end: 5 }),
            ("bytes=2-", RequestedRange::Partial { start: 2, end: 9 }),
            ("bytes=-3", RequestedRange::Partial { start: 7, end: 9 }),
            ("bytes=-0", RequestedRange::Unsatisfiable),
            ("bytes=10-", RequestedRange::Unsatisfiable),
            ("bytes=5-2", RequestedRange::Unsatisfiable),
            ("items=2-5", RequestedRange::Invalid),
            ("bytes=2-5,7-8", RequestedRange::Invalid),
            ("bytes=two-five", RequestedRange::Invalid),
        ];

        for (header_value, expected) in cases {
            assert_eq!(
                parse_range_value(header_value, 10),
                expected,
                "{header_value}"
            );
        }
        assert_eq!(
            parse_range_value("bytes=-3", 0),
            RequestedRange::Unsatisfiable
        );
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
    #[test]
    fn readiness_responses_preserve_each_bounded_failure_reason() {
        let responses = [
            (StorageReadiness::Ready, StatusCode::OK, "ready\n"),
            (
                StorageReadiness::LowSpace,
                StatusCode::SERVICE_UNAVAILABLE,
                "insufficient_space\n",
            ),
            (
                StorageReadiness::NoInodes,
                StatusCode::SERVICE_UNAVAILABLE,
                "no_inodes\n",
            ),
            (
                StorageReadiness::ReadOnly,
                StatusCode::SERVICE_UNAVAILABLE,
                "read_only\n",
            ),
            (
                StorageReadiness::ProbeFailed,
                StatusCode::SERVICE_UNAVAILABLE,
                "probe_failed\n",
            ),
        ];

        for (readiness, expected_status, expected_body) in responses {
            assert_eq!(
                readiness_response(readiness),
                (expected_status, expected_body),
                "{readiness:?}"
            );
        }
    }
}
