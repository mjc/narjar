use std::{
    io::{self, Read, Seek, SeekFrom},
    time::Instant,
};

use crate::{
    auth::{Authorizer, Permission},
    http_server::{Method, Request, Response, ResponseHeader as Header, StatusCode, static_header},
    metrics::{Metrics, RequestGuard, RequestMethod, RequestRoute, ValidationClass},
    narinfo::{MAX_NARINFO_BYTES, NarEncoding, TrustedPublicKeys},
    storage::{
        CapacityErrorKind, NarObjectId, NarUploadPolicy, PublishOutcome, Storage, StorageError,
        StoreHash, capacity_error_kind,
    },
};

const NIX_CACHE_INFO: &[u8] = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

fn header(name: &'static str, value: &'static str) -> Header {
    static_header(name, value)
}

fn send_response<R: Read>(
    guard: &RequestGuard<'_>,
    request: Request,
    status: u16,
    response: Response<R>,
    bytes_out: u64,
) {
    guard.record_response(status, bytes_out);
    let _ = request.respond(response);
}

fn not_found(guard: &RequestGuard<'_>, request: Request) {
    send_response(guard, request, 404, Response::empty(StatusCode(404)), 0);
}

fn internal_error(guard: &RequestGuard<'_>, request: Request) {
    send_response(guard, request, 500, Response::empty(StatusCode(500)), 0);
}

fn nar_response<R: Read>(status: StatusCode, reader: R, content_length: usize) -> Response<R> {
    Response::new(status, reader, content_length)
        .with_header(header("Content-Type", "application/x-nix-nar"))
        .with_header(header("Cache-Control", IMMUTABLE_CACHE_CONTROL))
        .with_header(header("Accept-Ranges", "bytes"))
}

fn respond_narinfo(
    request: Request,
    storage: &Storage,
    store: &StoreHash,
    trusted: &TrustedPublicKeys,
    guard: &RequestGuard<'_>,
) {
    let narinfo = match storage.open_narinfo(store) {
        Ok(Some(narinfo)) => narinfo,
        Ok(None) => return not_found(guard, request),
        Err(_) => return internal_error(guard, request),
    };
    let mut bytes = Vec::new();
    if narinfo
        .take(MAX_NARINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_NARINFO_BYTES
    {
        return internal_error(guard, request);
    }
    let validated = match trusted.validate(store, bytes) {
        Ok(validated) => validated,
        Err(_) => return internal_error(guard, request),
    };
    match storage.nar_matches(&validated) {
        Ok(true) => {}
        Ok(false) => return not_found(guard, request),
        Err(_) => return internal_error(guard, request),
    }

    let bytes = validated.into_bytes();
    let bytes_out = bytes.len() as u64;
    let response = Response::from_data(bytes)
        .with_header(header("Content-Type", "text/x-nix-narinfo"))
        .with_header(header("Cache-Control", IMMUTABLE_CACHE_CONTROL));
    send_response(guard, request, 200, response, bytes_out);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedRange {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
    Invalid,
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
    nar: &NarObjectId,
    encoding: NarEncoding,
    guard: &RequestGuard<'_>,
) {
    let mut file = match storage.open_nar_encoded(nar, encoding) {
        Ok(Some(file)) => file,
        Ok(None) => return not_found(guard, request),
        Err(_) => return internal_error(guard, request),
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return internal_error(guard, request);
    };

    match requested_range(&request, length) {
        RequestedRange::Full => {
            let Ok(content_length) = usize::try_from(length) else {
                return internal_error(guard, request);
            };
            let response = nar_response(StatusCode(200), file, content_length);
            send_response(guard, request, 200, response, content_length as u64);
        }
        RequestedRange::Partial { start, end } => {
            if file.seek(SeekFrom::Start(start)).is_err() {
                return internal_error(guard, request);
            }
            let response_length = end - start + 1;
            let Ok(content_length) = usize::try_from(response_length) else {
                return internal_error(guard, request);
            };
            let response =
                nar_response(StatusCode(206), file.take(response_length), content_length)
                    .with_header(Header::owned(
                        "Content-Range",
                        format!("bytes {start}-{end}/{length}"),
                    ));
            send_response(guard, request, 206, response, response_length);
        }
        RequestedRange::Unsatisfiable => {
            let response = Response::empty(StatusCode(416))
                .with_header(Header::owned("Content-Range", format!("bytes */{length}")));
            send_response(guard, request, 416, response, 0);
        }
        RequestedRange::Invalid => {
            send_response(guard, request, 400, Response::empty(StatusCode(400)), 0);
        }
    }
}

#[derive(Debug)]
enum ReadRoute {
    CacheInfo,
    Nar(NarObjectId, NarEncoding),
    NarInfo(StoreHash),
}

#[derive(Debug)]
enum RouteMatch {
    Found(ReadRoute),
    UnsupportedEncoding,
    Invalid,
    Missing,
}

impl ReadRoute {
    fn classify(url: &str) -> RouteMatch {
        if url.starts_with("//") || url.contains(['\\', '?', '#']) {
            return RouteMatch::Invalid;
        }
        let url = match url.strip_prefix("/main") {
            Some("") => return RouteMatch::Invalid,
            Some(path) if path.starts_with('/') => path,
            Some(_) => return RouteMatch::Missing,
            None => url,
        };

        if url == "/nix-cache-info" {
            return RouteMatch::Found(Self::CacheInfo);
        }

        if let Some(path) = url.strip_prefix("/nar/") {
            if path
                .strip_suffix(".nar.zst")
                .is_some_and(|id| NarObjectId::parse(id).is_ok())
            {
                return RouteMatch::UnsupportedEncoding;
            }
            if let Some(id) = path
                .strip_suffix(NarEncoding::Xz.suffix())
                .and_then(|id| NarObjectId::parse(id).ok())
            {
                return RouteMatch::Found(Self::Nar(id, NarEncoding::Xz));
            }
            return match path
                .strip_suffix(NarEncoding::None.suffix())
                .and_then(|id| NarObjectId::parse(id).ok())
            {
                Some(id) => RouteMatch::Found(Self::Nar(id, NarEncoding::None)),
                None => RouteMatch::Invalid,
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

fn method_not_allowed(guard: &RequestGuard<'_>, request: Request, allow: &'static str) {
    let response = Response::empty(StatusCode(405)).with_header(header("Allow", allow));
    send_response(guard, request, 405, response, 0);
}

fn has_header(request: &Request, name: &'static str) -> bool {
    request
        .headers()
        .iter()
        .any(|header| header.field.equiv(name))
}

fn request_route(url: &str) -> RequestRoute {
    match url {
        "/healthz" => RequestRoute::Health,
        "/readyz" => RequestRoute::Ready,
        "/metrics" => RequestRoute::Metrics,
        "/nix-cache-info" | "/main/nix-cache-info" => RequestRoute::CacheInfo,
        _ if url.starts_with("/nar/") => RequestRoute::Nar,
        _ if url.ends_with(".narinfo") => RequestRoute::NarInfo,
        _ => RequestRoute::Other,
    }
}

struct UploadRequest {
    request: Request,
    length: usize,
}

impl UploadRequest {
    fn accept(request: Request, guard: &RequestGuard<'_>, metrics: &Metrics) -> Option<Self> {
        let length = if has_header(&request, "Transfer-Encoding") {
            Err(400)
        } else if has_header(&request, "Content-Encoding") {
            Err(415)
        } else {
            request.body_length().ok_or(411)
        };
        match length {
            Ok(length) => Some(Self { request, length }),
            Err(status) => {
                metrics.validation_failure(ValidationClass::Body);
                send_response(
                    guard,
                    request,
                    status,
                    Response::empty(StatusCode(status)),
                    0,
                );
                None
            }
        }
    }

    const fn length(&self) -> usize {
        self.length
    }

    fn body_complete(&self) -> bool {
        self.request.body_complete()
    }

    fn reader(&mut self) -> impl Read + '_ {
        self.request.as_reader()
    }

    fn read_body(&mut self, max_bytes: usize) -> Result<Vec<u8>, u16> {
        if self.length > max_bytes {
            return Err(413);
        }
        let length = self.length;
        let mut bytes = Vec::with_capacity(length);
        let read = self
            .reader()
            .take(length as u64 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() != length {
            return Err(422);
        }
        Ok(bytes)
    }

    fn respond(self, guard: &RequestGuard<'_>, status: u16) {
        send_response(
            guard,
            self.request,
            status,
            Response::empty(StatusCode(status)),
            0,
        );
    }
}

fn capacity_status(error: &io::Error) -> Option<u16> {
    match error.raw_os_error().map(capacity_error_kind) {
        Some(CapacityErrorKind::NoSpace | CapacityErrorKind::Quota) => Some(507),
        Some(CapacityErrorKind::ReadOnly) => Some(503),
        Some(CapacityErrorKind::Inodes | CapacityErrorKind::Other) | None => None,
    }
}

fn record_capacity_error(metrics: &Metrics, error: &StorageError) {
    let kind = match error {
        StorageError::InsufficientSpace => CapacityErrorKind::NoSpace,
        StorageError::InsufficientInodes => CapacityErrorKind::Inodes,
        StorageError::Io(error) => error
            .raw_os_error()
            .map(capacity_error_kind)
            .unwrap_or(CapacityErrorKind::Other),
        _ => CapacityErrorKind::Other,
    };
    metrics.capacity_failure(kind);
}

fn respond_cache_info_put(
    request: Request,
    storage: &Storage,
    metrics: &Metrics,
    guard: &RequestGuard<'_>,
) {
    let Some(mut upload) = UploadRequest::accept(request, guard, metrics) else {
        return;
    };
    let _upload = metrics.upload(upload.length() as u64);
    if upload.length() != NIX_CACHE_INFO.len() {
        metrics.validation_failure(ValidationClass::Body);
        upload.respond(guard, 409);
        return;
    }
    let bytes = match upload.read_body(NIX_CACHE_INFO.len()) {
        Ok(bytes) => bytes,
        Err(status) => {
            metrics.validation_failure(ValidationClass::Body);
            return upload.respond(guard, status);
        }
    };
    if bytes != NIX_CACHE_INFO {
        metrics.validation_failure(ValidationClass::Body);
        upload.respond(guard, 409);
        return;
    }

    let started = Instant::now();
    let result = storage.publish_cache_info(bytes.as_slice());
    metrics.publication(started.elapsed());
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => 201,
        Ok(PublishOutcome::Identical) => 200,
        Err(StorageError::Conflict) => 409,
        Err(StorageError::Io(error)) => capacity_status(&error).unwrap_or(500),
        Err(_) => 500,
    };
    upload.respond(guard, status);
}

fn respond_nar_put(
    request: Request,
    storage: &Storage,
    id: &NarObjectId,
    encoding: NarEncoding,
    policy: NarUploadPolicy,
    metrics: &Metrics,
    guard: &RequestGuard<'_>,
) {
    let Some(mut upload) = UploadRequest::accept(request, guard, metrics) else {
        return;
    };
    let length = upload.length();
    let _upload = metrics.upload(length as u64);
    let started = Instant::now();
    let result = storage.publish_nar(id, encoding, upload.reader(), length as u64, policy);
    metrics.publication(started.elapsed());
    if !upload.body_complete() {
        metrics.validation_failure(ValidationClass::Nar);
        guard.record_response(0, 0);
        return;
    }
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => 201,
        Ok(PublishOutcome::Identical) => 200,
        Err(StorageError::Conflict) => 409,
        Err(StorageError::UploadTooLarge) => 413,
        Err(StorageError::InsufficientSpace) => 507,
        Err(StorageError::InsufficientInodes) => 507,
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => 422,
        Err(StorageError::Io(error)) => capacity_status(&error).unwrap_or(500),
        Err(_) => 500,
    };
    upload.respond(guard, status);
}

fn respond_narinfo_put(
    request: Request,
    storage: &Storage,
    store: &StoreHash,
    trusted: &TrustedPublicKeys,
    metrics: &Metrics,
    guard: &RequestGuard<'_>,
) {
    let Some(mut upload) = UploadRequest::accept(request, guard, metrics) else {
        return;
    };
    let _upload = metrics.upload(upload.length() as u64);
    let bytes = match upload.read_body(MAX_NARINFO_BYTES as usize) {
        Ok(bytes) => bytes,
        Err(status) => {
            metrics.validation_failure(ValidationClass::Body);
            return upload.respond(guard, status);
        }
    };
    let validated = match trusted.validate(store, bytes) {
        Ok(validated) => validated,
        Err(_) => {
            metrics.validation_failure(ValidationClass::NarInfo);
            upload.respond(guard, 422);
            return;
        }
    };
    let started = Instant::now();
    let result = storage.publish_narinfo(store, validated);
    metrics.publication(started.elapsed());
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => 201,
        Ok(PublishOutcome::Identical) => 200,
        Err(StorageError::Conflict) => 409,
        Err(StorageError::MissingNar | StorageError::NarMismatch) => 422,
        Err(StorageError::Io(error)) => capacity_status(&error).unwrap_or(500),
        Err(_) => 500,
    };
    upload.respond(guard, status);
}

fn unauthorized(guard: &RequestGuard<'_>, request: Request) {
    let challenge = header("WWW-Authenticate", "Basic realm=\"narjar\"");
    send_response(
        guard,
        request,
        401,
        Response::empty(StatusCode(401)).with_header(challenge),
        0,
    );
}

pub fn respond(
    request: Request,
    storage: &Storage,
    authorizer: &Authorizer,
    trusted: &TrustedPublicKeys,
    policy: NarUploadPolicy,
    metrics: &Metrics,
    min_free_bytes: u64,
) {
    let guard = metrics.request(
        RequestMethod::from(request.method()),
        request_route(request.url()),
    );
    if request.url() == "/healthz" {
        if !matches!(request.method(), Method::Get | Method::Head) {
            method_not_allowed(&guard, request, "GET, HEAD");
            return;
        }
        send_response(
            &guard,
            request,
            200,
            Response::from_string("ok\n")
                .with_status_code(StatusCode(200))
                .with_header(header("Content-Type", "text/plain; charset=utf-8")),
            3,
        );
        return;
    }
    if matches!(request.url(), "/readyz" | "/metrics") {
        if !matches!(request.method(), Method::Get | Method::Head) {
            method_not_allowed(&guard, request, "GET, HEAD");
            return;
        }
        if !authorizer.allows(&request, Permission::Read) {
            metrics.auth_failure(false);
            unauthorized(&guard, request);
            return;
        }
        let ready = storage.is_ready(min_free_bytes).unwrap_or(false);
        if request.url() == "/readyz" {
            let (status, body) = if ready {
                (200, "ready\n")
            } else {
                (503, "insufficient_space\n")
            };
            send_response(
                &guard,
                request,
                status,
                Response::from_string(body)
                    .with_status_code(StatusCode(status))
                    .with_header(header("Content-Type", "text/plain; charset=utf-8")),
                body.len() as u64,
            );
        } else {
            metrics.set_temp_objects(storage.temporary_objects());
            let body = metrics.render(ready, storage.capacity().ok());
            send_response(
                &guard,
                request,
                200,
                Response::from_string(body.clone())
                    .with_status_code(StatusCode(200))
                    .with_header(header(
                        "Content-Type",
                        "text/plain; version=0.0.4; charset=utf-8",
                    )),
                body.len() as u64,
            );
        }
        return;
    }

    let permission = if matches!(request.method(), Method::Put) {
        Permission::Write
    } else {
        Permission::Read
    };
    if !authorizer.allows(&request, permission) {
        metrics.auth_failure(matches!(permission, Permission::Write));
        unauthorized(&guard, request);
        return;
    }

    let route = match ReadRoute::classify(request.url()) {
        RouteMatch::Found(route) => route,
        RouteMatch::UnsupportedEncoding => {
            let status = if matches!(request.method(), Method::Put) {
                415
            } else {
                400
            };
            send_response(
                &guard,
                request,
                status,
                Response::empty(StatusCode(status)),
                0,
            );
            return;
        }
        RouteMatch::Invalid => {
            send_response(&guard, request, 400, Response::empty(StatusCode(400)), 0);
            return;
        }
        RouteMatch::Missing => return not_found(&guard, request),
    };

    if matches!(request.method(), Method::Put) {
        return match route {
            ReadRoute::Nar(id, encoding) => {
                respond_nar_put(request, storage, &id, encoding, policy, metrics, &guard)
            }
            ReadRoute::NarInfo(store) => {
                respond_narinfo_put(request, storage, &store, trusted, metrics, &guard)
            }
            ReadRoute::CacheInfo => respond_cache_info_put(request, storage, metrics, &guard),
        };
    }

    if !matches!(request.method(), Method::Get | Method::Head) {
        method_not_allowed(&guard, request, "GET, HEAD, PUT");
        return;
    }

    match route {
        ReadRoute::CacheInfo => {
            let response = Response::from_data(NIX_CACHE_INFO.to_vec())
                .with_header(header("Content-Type", "text/x-nix-cache-info"))
                .with_header(header("Cache-Control", "public, max-age=3600"));
            send_response(&guard, request, 200, response, NIX_CACHE_INFO.len() as u64);
        }
        ReadRoute::Nar(id, encoding) => respond_nar(request, storage, &id, encoding, &guard),
        ReadRoute::NarInfo(store) => respond_narinfo(request, storage, &store, trusted, &guard),
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadRoute, RouteMatch};
    use crate::narinfo::NarEncoding;

    #[test]
    fn legacy_main_prefix_maps_to_cache_routes() {
        assert!(matches!(
            ReadRoute::classify("/main/nix-cache-info"),
            RouteMatch::Found(ReadRoute::CacheInfo)
        ));
        assert!(matches!(
            ReadRoute::classify("/main/00000000000000000000000000000000.narinfo"),
            RouteMatch::Found(ReadRoute::NarInfo(_))
        ));
        assert!(matches!(
            ReadRoute::classify(
                "/main/nar/0000000000000000000000000000000000000000000000000000.nar"
            ),
            RouteMatch::Found(ReadRoute::Nar(_, NarEncoding::None))
        ));
    }

    #[test]
    fn xz_nar_routes_preserve_the_requested_encoding() {
        assert!(matches!(
            ReadRoute::classify("/nar/0000000000000000000000000000000000000000000000000000.nar.xz"),
            RouteMatch::Found(ReadRoute::Nar(_, NarEncoding::Xz))
        ));
    }
}
