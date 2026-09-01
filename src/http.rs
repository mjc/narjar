use std::io::{Read, Seek, SeekFrom};

use tiny_http::{Header, Method, Response, StatusCode};

use crate::storage::{NarObjectId, Storage, StoreHash};

const NIX_CACHE_INFO: &[u8] = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
const MAX_NARINFO_BYTES: usize = 1024 * 1024;
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("static response header is valid")
}

fn not_found(request: tiny_http::Request) {
    let _ = request.respond(Response::empty(StatusCode(404)));
}

fn referenced_nar(bytes: &[u8]) -> Option<NarObjectId> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut urls = text.lines().filter_map(|line| line.strip_prefix("URL: "));
    let url = urls.next()?;
    if urls.next().is_some() {
        return None;
    }
    let id = url.strip_prefix("nar/")?.strip_suffix(".nar")?;
    NarObjectId::parse(id).ok()
}

fn respond_narinfo(request: tiny_http::Request, storage: &Storage, store: &StoreHash) {
    let Ok(Some(narinfo)) = storage.open_narinfo(store) else {
        return not_found(request);
    };
    let mut bytes = Vec::new();
    if narinfo
        .take((MAX_NARINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_NARINFO_BYTES
    {
        return not_found(request);
    }
    let Some(nar) = referenced_nar(&bytes) else {
        return not_found(request);
    };
    let Ok(Some(_nar)) = storage.open_nar(&nar) else {
        return not_found(request);
    };

    let response = Response::from_data(bytes)
        .with_header(header("Content-Type", "text/x-nix-narinfo"))
        .with_header(header("Cache-Control", IMMUTABLE_CACHE_CONTROL));
    let _ = request.respond(response);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedRange {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
    Invalid,
}

fn requested_range(request: &tiny_http::Request, length: u64) -> RequestedRange {
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

fn respond_nar(request: tiny_http::Request, storage: &Storage, nar: &NarObjectId) {
    let Ok(Some(mut file)) = storage.open_nar(nar) else {
        return not_found(request);
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return not_found(request);
    };

    match requested_range(&request, length) {
        RequestedRange::Full => {
            let Ok(content_length) = usize::try_from(length) else {
                return not_found(request);
            };
            let response = Response::new(
                StatusCode(200),
                Vec::new(),
                file,
                Some(content_length),
                None,
            )
            .with_chunked_threshold(usize::MAX)
            .with_header(header("Content-Type", "application/x-nix-nar"))
            .with_header(header("Cache-Control", IMMUTABLE_CACHE_CONTROL))
            .with_header(header("Accept-Ranges", "bytes"));
            let _ = request.respond(response);
        }
        RequestedRange::Partial { start, end } => {
            if file.seek(SeekFrom::Start(start)).is_err() {
                return not_found(request);
            }
            let response_length = end - start + 1;
            let Ok(content_length) = usize::try_from(response_length) else {
                return not_found(request);
            };
            let response = Response::new(
                StatusCode(206),
                Vec::new(),
                file.take(response_length),
                Some(content_length),
                None,
            )
            .with_chunked_threshold(usize::MAX)
            .with_header(header("Content-Type", "application/x-nix-nar"))
            .with_header(header("Cache-Control", IMMUTABLE_CACHE_CONTROL))
            .with_header(header("Accept-Ranges", "bytes"))
            .with_header(header(
                "Content-Range",
                &format!("bytes {start}-{end}/{length}"),
            ));
            let _ = request.respond(response);
        }
        RequestedRange::Unsatisfiable => {
            let response = Response::empty(StatusCode(416))
                .with_header(header("Content-Range", &format!("bytes */{length}")));
            let _ = request.respond(response);
        }
        RequestedRange::Invalid => {
            let _ = request.respond(Response::empty(StatusCode(400)));
        }
    }
}

#[derive(Debug)]
enum ReadRoute {
    CacheInfo,
    Nar(NarObjectId),
    NarInfo(StoreHash),
}

#[derive(Debug)]
enum RouteMatch {
    Found(ReadRoute),
    Invalid,
    Missing,
}

impl ReadRoute {
    fn classify(url: &str) -> RouteMatch {
        if url == "/nix-cache-info" {
            return RouteMatch::Found(Self::CacheInfo);
        }
        if url.starts_with("//") || url.contains(['\\', '?', '#']) {
            return RouteMatch::Invalid;
        }

        if let Some(path) = url.strip_prefix("/nar/") {
            return match path
                .strip_suffix(".nar")
                .and_then(|id| NarObjectId::parse(id).ok())
            {
                Some(id) => RouteMatch::Found(Self::Nar(id)),
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

pub fn respond(request: tiny_http::Request, storage: &Storage) {
    let route = match ReadRoute::classify(request.url()) {
        RouteMatch::Found(route) => route,
        RouteMatch::Invalid => {
            let _ = request.respond(Response::empty(StatusCode(400)));
            return;
        }
        RouteMatch::Missing => return not_found(request),
    };

    if !matches!(request.method(), Method::Get | Method::Head) {
        let response = Response::empty(StatusCode(405)).with_header(header("Allow", "GET, HEAD"));
        let _ = request.respond(response);
        return;
    }

    match route {
        ReadRoute::CacheInfo => {
            let response = Response::from_data(NIX_CACHE_INFO)
                .with_header(header("Content-Type", "text/x-nix-cache-info"))
                .with_header(header("Cache-Control", "public, max-age=3600"));
            let _ = request.respond(response);
        }
        ReadRoute::Nar(id) => respond_nar(request, storage, &id),
        ReadRoute::NarInfo(store) => respond_narinfo(request, storage, &store),
    }
}
