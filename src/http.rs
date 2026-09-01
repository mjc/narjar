use std::io::Read;

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

fn respond_nar(request: tiny_http::Request, storage: &Storage, nar: &NarObjectId) {
    let Ok(Some(file)) = storage.open_nar(nar) else {
        return not_found(request);
    };
    let response = Response::from_file(file)
        .with_header(header("Content-Type", "application/x-nix-nar"))
        .with_header(header("Cache-Control", IMMUTABLE_CACHE_CONTROL))
        .with_header(header("Accept-Ranges", "bytes"));
    let _ = request.respond(response);
}

#[derive(Debug)]
enum ReadRoute {
    CacheInfo,
    Nar(NarObjectId),
    NarInfo(StoreHash),
}

impl ReadRoute {
    fn parse(url: &str) -> Option<Self> {
        if url == "/nix-cache-info" {
            return Some(Self::CacheInfo);
        }

        if let Some(id) = url
            .strip_prefix("/nar/")
            .and_then(|path| path.strip_suffix(".nar"))
            .and_then(|id| NarObjectId::parse(id).ok())
        {
            return Some(Self::Nar(id));
        }

        url.strip_prefix('/')
            .and_then(|path| path.strip_suffix(".narinfo"))
            .and_then(|hash| StoreHash::parse(hash).ok())
            .map(Self::NarInfo)
    }
}

pub fn respond(request: tiny_http::Request, storage: &Storage) {
    if !matches!(request.method(), Method::Get | Method::Head) {
        return not_found(request);
    }

    match ReadRoute::parse(request.url()) {
        Some(ReadRoute::CacheInfo) => {
            let response = Response::from_data(NIX_CACHE_INFO)
                .with_header(header("Content-Type", "text/x-nix-cache-info"))
                .with_header(header("Cache-Control", "public, max-age=3600"));
            let _ = request.respond(response);
        }
        Some(ReadRoute::Nar(id)) => respond_nar(request, storage, &id),
        Some(ReadRoute::NarInfo(store)) => respond_narinfo(request, storage, &store),
        None => not_found(request),
    }
}
