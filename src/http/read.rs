use std::{
    io::{self, Read},
    net::TcpStream,
};

use crate::{
    auth::{Authorizer, Permission, ReadVisibility},
    http_server::{Method, Request, Response, ResponseHeader as Header, StatusCode, static_header},
    metrics::{Metrics, RequestGuard, RequestMethod, RequestRoute},
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
    bytes_out: u64,
) -> Option<TcpStream> {
    guard.record_response(response.status(), bytes_out);
    request.respond(response).ok().flatten()
}

pub(super) fn not_found(guard: &RequestGuard<'_>, request: Request) -> Option<TcpStream> {
    send_response(guard, request, Response::empty(StatusCode::NOT_FOUND), 0)
}

pub(super) fn internal_error(guard: &RequestGuard<'_>, request: Request) -> Option<TcpStream> {
    send_response(
        guard,
        request,
        Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
        0,
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
    guard.record_response(response.status(), length);
    request
        .respond_file(response, file, offset, length)
        .ok()
        .flatten()
}

fn respond_narinfo(
    request: Request,
    storage: &Storage,
    store: &StoreHash,
    trusted: &TrustedPublicKeys,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
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
        Ok(NarMatch::Match) => {}
        Ok(NarMatch::Missing | NarMatch::Mismatch) => return not_found(guard, request),
        Err(_) => return internal_error(guard, request),
    }

    let bytes = match validated.into_bytes() {
        Ok(bytes) => bytes,
        Err(_) => return internal_error(guard, request),
    };
    let bytes_out = bytes.len() as u64;
    let response = cache_policy(
        Response::from_data(bytes).with_header(header("Content-Type", "text/x-nix-narinfo")),
        visibility,
        IMMUTABLE_CACHE_CONTROL,
    );
    send_response(guard, request, response, bytes_out)
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
    name: NarFileName,
    guard: &RequestGuard<'_>,
    visibility: ReadVisibility,
) -> Option<TcpStream> {
    let length = match storage.nar_size(name) {
        Ok(Some(length)) => length,
        Ok(None) => return not_found(guard, request),
        Err(_) => return internal_error(guard, request),
    };

    match requested_range(&request, length) {
        RequestedRange::Full => {
            let Ok(content_length) = usize::try_from(length) else {
                return internal_error(guard, request);
            };
            let opened = match storage.open_nar_range(name, 0..length) {
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
                    send_response(guard, request, response, length)
                }
            }
        }
        RequestedRange::Partial { start, end } => {
            let response_length = end - start + 1;
            let Ok(content_length) = usize::try_from(response_length) else {
                return internal_error(guard, request);
            };
            let opened = match storage.open_nar_range(name, start..end + 1) {
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
                    send_response(guard, request, response, response_length)
                }
            }
        }
        RequestedRange::Unsatisfiable => {
            let response = Response::empty(StatusCode::RANGE_NOT_SATISFIABLE).with_header(
                Header::owned("Content-Range", format!("bytes */{length}"))
                    .expect("range response header is valid"),
            );
            send_response(guard, request, response, 0)
        }
        RequestedRange::Invalid => {
            send_response(guard, request, Response::empty(StatusCode::BAD_REQUEST), 0)
        }
    }
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
    Invalid,
    Missing,
}

impl CacheRoute {
    pub(super) fn classify(url: &str) -> RouteMatch {
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
            return match NarFileName::parse(path) {
                Ok(name) => RouteMatch::Found(Self::Nar(name)),
                Err(_) => RouteMatch::Invalid,
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

fn method_not_allowed(
    guard: &RequestGuard<'_>,
    request: Request,
    allow: &'static str,
) -> Option<TcpStream> {
    let response =
        Response::empty(StatusCode::METHOD_NOT_ALLOWED).with_header(header("Allow", allow));
    send_response(guard, request, response, 0)
}

pub(super) fn has_header(request: &Request, name: &'static str) -> bool {
    request
        .headers()
        .iter()
        .any(|header| header.field.equiv(name))
}

pub(super) fn request_route(url: &str) -> RequestRoute {
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

pub fn respond(
    request: Request,
    storage: &Storage,
    authorizer: &Authorizer,
    trusted: &TrustedPublicKeys,
    metrics: &Metrics,
    min_free_bytes: u64,
) -> Option<TcpStream> {
    let guard = metrics.request(
        RequestMethod::from(request.method()),
        request_route(request.url()),
    );
    if request.url() == "/healthz" {
        if !matches!(request.method(), Method::Get | Method::Head) {
            return method_not_allowed(&guard, request, "GET, HEAD");
        }
        return send_response(
            &guard,
            request,
            Response::from_string("ok\n")
                .with_status_code(StatusCode::OK)
                .with_header(header("Content-Type", "text/plain; charset=utf-8")),
            3,
        );
    }
    if matches!(request.url(), "/readyz" | "/metrics") {
        if !matches!(request.method(), Method::Get | Method::Head) {
            return method_not_allowed(&guard, request, "GET, HEAD");
        }
        if !authorizer.allows(&request, Permission::Read) {
            metrics.auth_failure(false);
            return unauthorized(&guard, request);
        }
        let ready = storage
            .is_ready(min_free_bytes)
            .unwrap_or(StorageReadiness::Insufficient);
        if request.url() == "/readyz" {
            let (status, body) = match ready {
                StorageReadiness::Ready => (StatusCode::OK, "ready\n"),
                StorageReadiness::Insufficient => {
                    (StatusCode::SERVICE_UNAVAILABLE, "insufficient_space\n")
                }
            };
            return send_response(
                &guard,
                request,
                Response::from_string(body)
                    .with_status_code(status)
                    .with_header(header("Content-Type", "text/plain; charset=utf-8")),
                body.len() as u64,
            );
        } else {
            metrics.set_temp_objects(storage.temporary_objects());
            let body = metrics.render(ready.is_ready(), storage.capacity().ok());
            return send_response(
                &guard,
                request,
                Response::from_string(body.clone())
                    .with_status_code(StatusCode::OK)
                    .with_header(header(
                        "Content-Type",
                        "text/plain; version=0.0.4; charset=utf-8",
                    )),
                body.len() as u64,
            );
        }
    }

    let permission = if matches!(request.method(), Method::Put) {
        Permission::Write
    } else {
        Permission::Read
    };
    if !authorizer.allows(&request, permission) {
        metrics.auth_failure(matches!(permission, Permission::Write));
        return unauthorized(&guard, request);
    }
    let visibility = authorizer.read_visibility();

    let route = match CacheRoute::classify(request.url()) {
        RouteMatch::Found(route) => route,
        RouteMatch::Invalid => {
            return send_response(&guard, request, Response::empty(StatusCode::BAD_REQUEST), 0);
        }
        RouteMatch::Missing => return not_found(&guard, request),
    };

    if !matches!(request.method(), Method::Get | Method::Head) {
        return method_not_allowed(&guard, request, "GET, HEAD, PUT");
    }

    match route {
        CacheRoute::CacheInfo => {
            let cache_info = match storage.cache_info() {
                Ok(cache_info) => cache_info,
                Err(_) => return internal_error(&guard, request),
            };
            let cache_info_length = cache_info.len() as u64;
            let response = cache_policy(
                Response::from_data(cache_info)
                    .with_header(header("Content-Type", "text/x-nix-cache-info")),
                visibility,
                "public, max-age=3600",
            );
            send_response(&guard, request, response, cache_info_length)
        }
        CacheRoute::Nar(name) => respond_nar(request, storage, name, &guard, visibility),
        CacheRoute::NarInfo(store) => {
            respond_narinfo(request, storage, &store, trusted, &guard, visibility)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheRoute, RouteMatch};
    use crate::object::{CompressionCodec, WireEncoding};

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
}
