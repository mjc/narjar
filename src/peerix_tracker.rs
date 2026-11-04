//! Peerix tracker routes on the `narjar serve` listener.
//!
//! The routes exist only when the server enables the tracker. Learned rows come
//! from upstream GETs. Local announcements stay here and are not posted back.

use std::{
    collections::{HashMap, HashSet},
    io::Read,
    net::IpAddr,
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

use crate::{
    cache::{
        http_server::{Request, Response, ResponseHeader, StatusCode, static_header},
        storage::StoreHash,
    },
    http_client::idle_agent_allowing_status,
    http_url::HttpUrl,
};

pub(crate) const PEER_TTL: Duration = Duration::from_secs(120);
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const DEFAULT_UPSTREAM: &str = "https://sophronesis.dev/peerix";

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_HASHES: usize = 200_000;
const MAX_TRACKED_ROWS: usize = 10_000;
const MAX_TOKEN_LEN: usize = 256;
const MAX_RELAY_URL_LEN: usize = 512;
const MAX_DIRECT_ADDR_LEN: usize = 256;
const MAX_DIRECT_ADDRS: usize = 32;
const UPSTREAM_BODY_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct TrackerSettings {
    pub(crate) upstream: HttpUrl,
    pub(crate) timeout: Duration,
}

pub(crate) struct Tracker {
    state: Mutex<State>,
    upstream: HttpUrl,
    timeout: Duration,
}

#[derive(Default)]
struct State {
    local_peers: HashMap<String, PeerRow>,
    learned_peers: HashMap<String, PeerRow>,
    local_packages: HashMap<String, HashSet<String>>,
    learned_providers: HashMap<String, Vec<ProviderRow>>,
    local_iroh: HashMap<String, IrohRow>,
    learned_iroh: HashMap<String, IrohRow>,
}

#[derive(Clone)]
struct PeerRow {
    addr: String,
    port: u16,
    last_seen: SystemTime,
    libp2p_peer_id: Option<String>,
}

#[derive(Clone)]
struct ProviderRow {
    peer_id: String,
    row: PeerRow,
}

#[derive(Clone)]
struct IrohRow {
    peer_id: String,
    relay_url: Option<String>,
    direct_addrs: Vec<String>,
    addr: String,
    last_seen: SystemTime,
}

enum Action {
    Announce,
    IrohAnnounce,
    Peers,
    IrohPeers,
    Batch,
    Delta,
    Find(String),
    Method(&'static str),
    Query,
    Missing,
}

enum Outcome {
    Json(StatusCode, Value),
    Method(&'static str),
}

impl Tracker {
    pub(crate) fn new(settings: TrackerSettings) -> Self {
        Self {
            state: Mutex::new(State::default()),
            upstream: settings.upstream,
            timeout: settings.timeout,
        }
    }

    pub(crate) fn refresh(&self) -> Result<(), String> {
        let peers_url = self.upstream.endpoint(&["peers"]);
        let iroh_url = self.upstream.endpoint(&["iroh", "peers"]);
        let timeout = self.timeout;
        self.refresh_with(
            |url| fetch_get(url, timeout),
            SystemTime::now(),
            peers_url.as_str(),
            iroh_url.as_str(),
        )
    }

    fn refresh_with(
        &self,
        mut get: impl FnMut(&str) -> Result<Vec<u8>, String>,
        now: SystemTime,
        peers_url: &str,
        iroh_url: &str,
    ) -> Result<(), String> {
        let peers = get(peers_url);
        let iroh = get(iroh_url);
        let mut errors = Vec::new();
        let mut state = self.lock();
        match peers {
            Ok(bytes) => match parse_peer_list(&bytes, now) {
                Ok(rows) => state.learned_peers = rows,
                Err(error) => errors.push(error),
            },
            Err(error) => errors.push(error),
        }
        match iroh {
            Ok(bytes) => match parse_iroh_list(&bytes, now) {
                Ok(rows) => state.learned_iroh = rows,
                Err(error) => errors.push(error),
            },
            Err(error) => errors.push(error),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn find_document(&self, hash: &str, now: SystemTime) -> Value {
        let url = self.upstream.endpoint(&["find", hash]);
        if let Ok(bytes) = fetch_get(url.as_str(), self.timeout) {
            self.store_learned_providers(hash, &bytes, now);
        }
        self.providers_document(hash, now)
    }

    fn store_learned_providers(&self, hash: &str, bytes: &[u8], now: SystemTime) {
        let Ok(providers) = parse_providers(bytes, now) else {
            return;
        };
        let mut state = self.lock();
        let known = state.learned_providers.contains_key(hash);
        if known || state.learned_providers.len() < MAX_TRACKED_ROWS {
            state.learned_providers.insert(hash.to_owned(), providers);
        }
    }

    pub(crate) fn respond(&self, mut request: Request) -> Option<std::net::TcpStream> {
        let action = classify(request.http_method(), request.url());
        let outcome = match action {
            Action::Announce => self.post_json(&mut request, |tracker, request, body| {
                tracker.announce(request, &body, SystemTime::now())
            }),
            Action::IrohAnnounce => self.post_json(&mut request, |tracker, request, body| {
                tracker.announce_iroh(request, &body, SystemTime::now())
            }),
            Action::Batch => self.post_json(&mut request, |tracker, _, body| tracker.batch(&body)),
            Action::Delta => self.post_json(&mut request, |tracker, _, body| tracker.delta(&body)),
            Action::Peers => Outcome::Json(StatusCode::OK, self.peers_document(SystemTime::now())),
            Action::IrohPeers => {
                Outcome::Json(StatusCode::OK, self.iroh_document(SystemTime::now()))
            }
            Action::Find(hash) => {
                if StoreHash::parse(&hash).is_err() {
                    Outcome::Json(StatusCode::BAD_REQUEST, error_json("invalid store hash"))
                } else {
                    Outcome::Json(StatusCode::OK, self.find_document(&hash, SystemTime::now()))
                }
            }
            Action::Method(allow) => Outcome::Method(allow),
            Action::Query => Outcome::Json(
                StatusCode::BAD_REQUEST,
                error_json("query string is not allowed"),
            ),
            Action::Missing => Outcome::Json(StatusCode::NOT_FOUND, error_json("not found")),
        };
        finish(request, outcome)
    }

    fn post_json(
        &self,
        request: &mut Request,
        handle: impl FnOnce(&Self, &Request, Value) -> Result<Value, (StatusCode, &'static str)>,
    ) -> Outcome {
        match read_json(request) {
            Ok(body) => match handle(self, request, body) {
                Ok(body) => Outcome::Json(StatusCode::OK, body),
                Err((status, message)) => Outcome::Json(status, error_json(message)),
            },
            Err((status, message)) => Outcome::Json(status, error_json(message)),
        }
    }

    fn announce(
        &self,
        request: &Request,
        body: &Value,
        now: SystemTime,
    ) -> Result<Value, (StatusCode, &'static str)> {
        let peer_id = required_token(body.get("peer_id"))
            .ok_or((StatusCode::BAD_REQUEST, "peer_id and port required"))?;
        let port = body
            .get("port")
            .and_then(parse_port)
            .ok_or((StatusCode::BAD_REQUEST, "peer_id and port required"))?;
        let addr =
            client_addr(request).ok_or((StatusCode::BAD_REQUEST, "peer_id and port required"))?;
        let packages = optional_hash_list(body.get("packages"))?;
        let libp2p = optional_token(body.get("libp2p_peer_id"));
        self.record_announce(peer_id, addr, port, packages, libp2p, now)?;
        Ok(json!({"status": "ok"}))
    }

    fn record_announce(
        &self,
        peer_id: String,
        addr: String,
        port: u16,
        packages: Option<Vec<String>>,
        libp2p_peer_id: Option<String>,
        now: SystemTime,
    ) -> Result<(), (StatusCode, &'static str)> {
        let mut state = self.lock();
        if !state.local_peers.contains_key(&peer_id) && state.local_peers.len() >= MAX_TRACKED_ROWS
        {
            return Err((StatusCode::BAD_REQUEST, "tracker is full"));
        }
        let replacing_packages = packages.as_ref().is_some_and(|hashes| !hashes.is_empty());
        if replacing_packages
            && !state.local_packages.contains_key(&peer_id)
            && state.local_packages.len() >= MAX_TRACKED_ROWS
        {
            return Err((StatusCode::BAD_REQUEST, "tracker is full"));
        }
        state.local_peers.insert(
            peer_id.clone(),
            PeerRow {
                addr,
                port,
                last_seen: now,
                libp2p_peer_id,
            },
        );
        if let Some(hashes) = packages.filter(|hashes| !hashes.is_empty()) {
            state
                .local_packages
                .insert(peer_id, hashes.into_iter().collect());
        }
        Ok(())
    }

    fn announce_iroh(
        &self,
        request: &Request,
        body: &Value,
        now: SystemTime,
    ) -> Result<Value, (StatusCode, &'static str)> {
        let node_id = required_token(body.get("node_id"))
            .ok_or((StatusCode::BAD_REQUEST, "node_id and peer_id required"))?;
        let peer_id = required_token(body.get("peer_id"))
            .ok_or((StatusCode::BAD_REQUEST, "node_id and peer_id required"))?;
        let relay_url = parse_relay(body.get("relay_url"))?;
        let direct_addrs = parse_direct_addrs(body.get("direct_addrs"))?;
        let addr = client_addr(request)
            .ok_or((StatusCode::BAD_REQUEST, "node_id and peer_id required"))?;
        let mut state = self.lock();
        if !state.local_iroh.contains_key(&node_id) && state.local_iroh.len() >= MAX_TRACKED_ROWS {
            return Err((StatusCode::BAD_REQUEST, "tracker is full"));
        }
        state.local_iroh.insert(
            node_id,
            IrohRow {
                peer_id,
                relay_url,
                direct_addrs,
                addr,
                last_seen: now,
            },
        );
        Ok(json!({"status": "ok"}))
    }

    fn batch(&self, body: &Value) -> Result<Value, (StatusCode, &'static str)> {
        let peer_id = required_token(body.get("peer_id"))
            .ok_or((StatusCode::BAD_REQUEST, "peer_id required"))?;
        let hashes = match body.get("hashes") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => parse_hash_list(value)?,
        };
        let count = hashes.len();
        let mut state = self.lock();
        if !state.local_packages.contains_key(&peer_id)
            && state.local_packages.len() >= MAX_TRACKED_ROWS
        {
            return Err((StatusCode::BAD_REQUEST, "tracker is full"));
        }
        state
            .local_packages
            .insert(peer_id, hashes.into_iter().collect());
        Ok(json!({"status": "ok", "count": count}))
    }

    fn delta(&self, body: &Value) -> Result<Value, (StatusCode, &'static str)> {
        let peer_id = required_token(body.get("peer_id"))
            .ok_or((StatusCode::BAD_REQUEST, "peer_id required"))?;
        let added = match body.get("added") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => parse_hash_list(value)?,
        };
        let removed = match body.get("removed") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => parse_hash_list(value)?,
        };
        let added_count = added.len();
        let removed_count = removed.len();
        let mut state = self.lock();
        if !state.local_packages.contains_key(&peer_id)
            && state.local_packages.len() >= MAX_TRACKED_ROWS
        {
            return Err((StatusCode::BAD_REQUEST, "tracker is full"));
        }
        let packages = state.local_packages.entry(peer_id).or_default();
        for hash in &removed {
            packages.remove(hash);
        }
        for hash in added {
            packages.insert(hash);
        }
        Ok(json!({
            "status": "ok",
            "added": added_count,
            "removed": removed_count,
        }))
    }

    fn peers_document(&self, now: SystemTime) -> Value {
        let state = self.lock();
        let mut peers = Vec::new();
        let mut local_ids = HashSet::new();
        for (peer_id, row) in &state.local_peers {
            if !is_fresh(row.last_seen, now) {
                continue;
            }
            local_ids.insert(peer_id.clone());
            peers.push(peer_json(peer_id, row));
        }
        for (peer_id, row) in &state.learned_peers {
            if local_ids.contains(peer_id) || !is_fresh(row.last_seen, now) {
                continue;
            }
            peers.push(peer_json(peer_id, row));
        }
        peers.sort_by(|left, right| peer_field(left).cmp(peer_field(right)));
        json!({"peers": peers})
    }

    fn iroh_document(&self, now: SystemTime) -> Value {
        let state = self.lock();
        let mut peers = Vec::new();
        let mut local_nodes = HashSet::new();
        let mut local_peers = HashSet::new();
        for (node_id, row) in &state.local_iroh {
            if !is_fresh(row.last_seen, now) {
                continue;
            }
            local_nodes.insert(node_id.clone());
            local_peers.insert(row.peer_id.clone());
            peers.push(iroh_json(node_id, row));
        }
        for (node_id, row) in &state.learned_iroh {
            if local_nodes.contains(node_id)
                || local_peers.contains(&row.peer_id)
                || !is_fresh(row.last_seen, now)
            {
                continue;
            }
            peers.push(iroh_json(node_id, row));
        }
        peers.sort_by(|left, right| node_field(left).cmp(node_field(right)));
        let count = peers.len();
        json!({"peers": peers, "count": count})
    }

    fn providers_document(&self, hash: &str, now: SystemTime) -> Value {
        let state = self.lock();
        let mut providers = HashMap::new();
        if let Some(learned) = state.learned_providers.get(hash) {
            for provider in learned {
                let mut row = provider.row.clone();
                if let Some(local) = state.local_peers.get(&provider.peer_id)
                    && is_fresh(local.last_seen, now)
                {
                    row.addr.clone_from(&local.addr);
                    row.port = local.port;
                    row.last_seen = local.last_seen;
                    if let Some(libp2p) = &local.libp2p_peer_id {
                        row.libp2p_peer_id = Some(libp2p.clone());
                    }
                }
                if is_fresh(row.last_seen, now) {
                    providers.insert(
                        provider.peer_id.clone(),
                        provider_json(&provider.peer_id, &row),
                    );
                }
            }
        }
        for (peer_id, hashes) in &state.local_packages {
            if !hashes.contains(hash) {
                continue;
            }
            let Some(row) = state.local_peers.get(peer_id) else {
                continue;
            };
            if !is_fresh(row.last_seen, now) {
                continue;
            }
            providers.insert(peer_id.clone(), provider_json(peer_id, row));
        }
        let mut providers: Vec<_> = providers.into_values().collect();
        providers.sort_by(|left, right| peer_field(left).cmp(peer_field(right)));
        json!({"hash": hash, "providers": providers})
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

pub(crate) fn is_mount(url: &str) -> bool {
    match url.strip_prefix("/peerix") {
        Some(rest) => {
            rest.is_empty()
                || rest.starts_with('/')
                || rest.starts_with('?')
                || rest.starts_with('#')
        }
        None => false,
    }
}

fn classify(method: &str, url: &str) -> Action {
    if url.contains('?') || url.contains('#') {
        return Action::Query;
    }
    let Some(rest) = url.strip_prefix("/peerix") else {
        return Action::Missing;
    };
    if let Some(hash) = rest.strip_prefix("/find/") {
        if hash.is_empty() || hash.contains('/') {
            return Action::Missing;
        }
        if method == "GET" {
            return Action::Find(hash.to_owned());
        }
        return Action::Method("GET");
    }
    match (method, rest) {
        ("POST", "/announce") => Action::Announce,
        ("POST", "/iroh/announce") => Action::IrohAnnounce,
        ("GET", "/peers") => Action::Peers,
        ("GET", "/iroh/peers") => Action::IrohPeers,
        ("POST", "/packages/batch") => Action::Batch,
        ("POST", "/packages/delta") => Action::Delta,
        (_, "/announce" | "/iroh/announce" | "/packages/batch" | "/packages/delta") => {
            Action::Method("POST")
        }
        (_, "/peers" | "/iroh/peers") => Action::Method("GET"),
        _ => Action::Missing,
    }
}

fn finish(request: Request, outcome: Outcome) -> Option<std::net::TcpStream> {
    let (status, body, allow) = match outcome {
        Outcome::Json(status, body) => (status, body, None),
        Outcome::Method(allow) => (
            StatusCode::METHOD_NOT_ALLOWED,
            error_json("method not allowed"),
            Some(allow),
        ),
    };
    let mut response = Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(json_header("Content-Type", "application/json"))
        .with_header(json_header("Cache-Control", "no-store"));
    if let Some(allow) = allow {
        response = response.with_header(json_header("Allow", allow));
    }
    match request.respond(response) {
        Ok(transfer) => transfer.connection,
        Err(_) => None,
    }
}

fn json_header(name: &'static str, value: &'static str) -> ResponseHeader {
    static_header(name, value).expect("tracker response header is static")
}

fn error_json(message: &str) -> Value {
    json!({"error": message})
}

fn read_json(request: &mut Request) -> Result<Value, (StatusCode, &'static str)> {
    let Some(length) = request.body_length() else {
        return Err((StatusCode::LENGTH_REQUIRED, "content length required"));
    };
    if length > MAX_BODY_BYTES {
        request.close_after_response();
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"));
    }
    let mut bytes = vec![0; length];
    let read = request
        .as_reader()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid json"))?
        .read_exact(&mut bytes);
    if read.is_err() {
        return Err((StatusCode::BAD_REQUEST, "invalid json"));
    }
    serde_json::from_slice(&bytes).map_err(|_| (StatusCode::BAD_REQUEST, "invalid json"))
}

fn fetch_get(url: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let agent = idle_agent_allowing_status(timeout);
    let mut response = agent.get(url).call().map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(UPSTREAM_BODY_LIMIT)
        .read_to_vec()
        .map_err(|error| error.to_string())?;
    if status == 200 {
        Ok(body)
    } else {
        Err(format!("HTTP {status}"))
    }
}

fn parse_peer_list(bytes: &[u8], now: SystemTime) -> Result<HashMap<String, PeerRow>, String> {
    let peers = json_array(bytes, "peers")?;
    if peers.len() > MAX_TRACKED_ROWS {
        return Err("too many peers".to_owned());
    }
    let mut rows = HashMap::new();
    for peer in peers {
        if let Some((peer_id, row)) = learned_peer(&peer, now) {
            rows.insert(peer_id, row);
        }
    }
    Ok(rows)
}

fn parse_iroh_list(bytes: &[u8], now: SystemTime) -> Result<HashMap<String, IrohRow>, String> {
    let peers = json_array(bytes, "peers")?;
    if peers.len() > MAX_TRACKED_ROWS {
        return Err("too many peers".to_owned());
    }
    let mut rows = HashMap::new();
    for peer in peers {
        if let Some((node_id, row)) = learned_iroh(&peer, now) {
            rows.insert(node_id, row);
        }
    }
    Ok(rows)
}

fn parse_providers(bytes: &[u8], now: SystemTime) -> Result<Vec<ProviderRow>, String> {
    let providers = json_array(bytes, "providers")?;
    if providers.len() > MAX_TRACKED_ROWS {
        return Err("too many providers".to_owned());
    }
    let mut rows = Vec::new();
    for provider in providers {
        if let Some(row) = learned_provider(&provider, now) {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn json_array(bytes: &[u8], field: &str) -> Result<Vec<Value>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| format!("{field} list missing"))
}

fn learned_peer(value: &Value, now: SystemTime) -> Option<(String, PeerRow)> {
    let peer_id = required_token(value.get("peer_id"))?;
    let addr = required_token(value.get("addr"))?;
    let port = value.get("port").and_then(parse_port)?;
    Some((
        peer_id,
        PeerRow {
            addr,
            port,
            last_seen: parse_last_seen(value.get("last_seen"), now),
            libp2p_peer_id: optional_token(value.get("libp2p_peer_id")),
        },
    ))
}

fn learned_provider(value: &Value, now: SystemTime) -> Option<ProviderRow> {
    let (peer_id, row) = learned_peer(value, now)?;
    Some(ProviderRow { peer_id, row })
}

fn learned_iroh(value: &Value, now: SystemTime) -> Option<(String, IrohRow)> {
    let node_id = required_token(value.get("node_id"))?;
    let peer_id = required_token(value.get("peer_id"))?;
    let addr = required_token(value.get("addr"))?;
    let direct_addrs = learned_direct_addrs(value.get("direct_addrs"));
    Some((
        node_id,
        IrohRow {
            peer_id,
            relay_url: optional_token(value.get("relay_url")),
            direct_addrs,
            addr,
            last_seen: parse_last_seen(value.get("last_seen"), now),
        },
    ))
}

fn learned_direct_addrs(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .filter(|addr| valid_token(addr, MAX_DIRECT_ADDR_LEN))
        .take(MAX_DIRECT_ADDRS)
        .map(str::to_owned)
        .collect()
}

fn optional_hash_list(
    value: Option<&Value>,
) -> Result<Option<Vec<String>>, (StatusCode, &'static str)> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_hash_list(value).map(Some),
    }
}

fn parse_hash_list(value: &Value) -> Result<Vec<String>, (StatusCode, &'static str)> {
    let Some(list) = value.as_array() else {
        return Err((StatusCode::BAD_REQUEST, "hashes must be a list"));
    };
    if list.len() > MAX_HASHES {
        return Err((StatusCode::BAD_REQUEST, "too many hashes"));
    }
    let mut hashes = Vec::with_capacity(list.len());
    for item in list {
        let Some(text) = item.as_str() else {
            return Err((StatusCode::BAD_REQUEST, "invalid store hash"));
        };
        let hash =
            StoreHash::parse(text).map_err(|_| (StatusCode::BAD_REQUEST, "invalid store hash"))?;
        hashes.push(hash.as_str().to_owned());
    }
    Ok(hashes)
}

fn parse_direct_addrs(value: Option<&Value>) -> Result<Vec<String>, (StatusCode, &'static str)> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) if items.len() > MAX_DIRECT_ADDRS => {
            Err((StatusCode::BAD_REQUEST, "too many direct addresses"))
        }
        Some(Value::Array(items)) => {
            let mut addrs = Vec::with_capacity(items.len());
            for item in items {
                let Some(text) = item
                    .as_str()
                    .filter(|text| valid_token(text, MAX_DIRECT_ADDR_LEN))
                else {
                    return Err((StatusCode::BAD_REQUEST, "invalid direct address"));
                };
                addrs.push(text.to_owned());
            }
            Ok(addrs)
        }
        Some(_) => Err((StatusCode::BAD_REQUEST, "direct_addrs must be a list")),
    }
}

fn parse_relay(value: Option<&Value>) -> Result<Option<String>, (StatusCode, &'static str)> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) if valid_token(text, MAX_RELAY_URL_LEN) => Ok(Some(text.clone())),
        Some(_) => Err((StatusCode::BAD_REQUEST, "invalid relay_url")),
    }
}

fn required_token(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    valid_token(text, MAX_TOKEN_LEN).then(|| text.to_owned())
}

fn optional_token(value: Option<&Value>) -> Option<String> {
    required_token(value)
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_control())
}

fn parse_port(value: &Value) -> Option<u16> {
    let port = value.as_u64()?;
    u16::try_from(port).ok()
}

fn parse_last_seen(value: Option<&Value>, now: SystemTime) -> SystemTime {
    value
        .and_then(Value::as_f64)
        .and_then(system_time_from_unix)
        .unwrap_or(now)
}

fn system_time_from_unix(seconds: f64) -> Option<SystemTime> {
    if !seconds.is_finite() {
        return None;
    }
    if seconds >= 0.0 {
        let duration = Duration::try_from_secs_f64(seconds).ok()?;
        UNIX_EPOCH.checked_add(duration)
    } else {
        let duration = Duration::try_from_secs_f64(-seconds).ok()?;
        UNIX_EPOCH.checked_sub(duration)
    }
}

fn unix_seconds(time: SystemTime) -> f64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    }
}

fn is_fresh(last_seen: SystemTime, now: SystemTime) -> bool {
    match now.duration_since(last_seen) {
        Ok(age) => age <= PEER_TTL,
        Err(_) => true,
    }
}

fn client_addr(request: &Request) -> Option<String> {
    header_ip(request, "X-Real-IP")
        .or_else(|| forwarded_for(request))
        .or_else(|| {
            request
                .peer_ip()
                .filter(|addr| addr.parse::<IpAddr>().is_ok())
        })
}

fn header_ip(request: &Request, name: &str) -> Option<String> {
    request.headers().iter().find_map(|header| {
        header
            .field
            .equiv(name)
            .then(|| parse_ip_token(header.value.as_str()))
            .flatten()
    })
}

fn forwarded_for(request: &Request) -> Option<String> {
    request.headers().iter().find_map(|header| {
        if !header.field.equiv("X-Forwarded-For") {
            return None;
        }
        header
            .value
            .as_str()
            .split(',')
            .next()
            .and_then(parse_ip_token)
    })
}

fn parse_ip_token(value: &str) -> Option<String> {
    let addr = value.trim().parse::<IpAddr>().ok()?;
    Some(addr.to_string())
}

fn peer_json(peer_id: &str, row: &PeerRow) -> Value {
    json!({
        "peer_id": peer_id,
        "addr": row.addr,
        "port": row.port,
        "last_seen": unix_seconds(row.last_seen),
    })
}

fn provider_json(peer_id: &str, row: &PeerRow) -> Value {
    let mut value = peer_json(peer_id, row);
    if let Some(libp2p) = &row.libp2p_peer_id {
        value
            .as_object_mut()
            .expect("provider object")
            .insert("libp2p_peer_id".to_owned(), json!(libp2p));
    }
    value
}

fn iroh_json(node_id: &str, row: &IrohRow) -> Value {
    json!({
        "node_id": node_id,
        "peer_id": row.peer_id,
        "relay_url": row.relay_url,
        "direct_addrs": row.direct_addrs,
        "addr": row.addr,
        "last_seen": unix_seconds(row.last_seen),
    })
}

fn peer_field(value: &Value) -> &str {
    value.get("peer_id").and_then(Value::as_str).unwrap_or("")
}

fn node_field(value: &Value) -> &str {
    value.get("node_id").and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use serde_json::{Value, json};

    use super::{
        MAX_HASHES, MAX_TRACKED_ROWS, PEER_TTL, Tracker, TrackerSettings, is_fresh, unix_seconds,
    };
    use crate::http_url::HttpUrl;

    const HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    const OTHER: &str = "11111111111111111111111111111111";

    fn tracker(upstream: &str) -> Tracker {
        Tracker::new(TrackerSettings {
            upstream: upstream.parse().expect("tracker upstream"),
            timeout: Duration::from_secs(2),
        })
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn exchange(tracker: &Tracker, raw: &str) -> (u16, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(raw.as_bytes()).unwrap();
        let request = crate::cache::http_server::Request::read(server).unwrap();
        assert!(tracker.respond(request).is_none());
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, body.to_owned())
    }

    fn post(path: &str, headers: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
    }

    fn json_body(body: &str) -> Value {
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn learned_rows_follow_upstream_last_seen_and_local_announce_replaces_them() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        let seen = at(1_700_000_000);
        let peers_url = tracker.upstream.endpoint(&["peers"]);
        let iroh_url = tracker.upstream.endpoint(&["iroh", "peers"]);
        let peers = serde_json::to_vec(&json!({
            "peers": [{
                "peer_id": "same",
                "addr": "198.51.100.8",
                "port": 9,
                "last_seen": unix_seconds(seen),
                "libp2p_peer_id": "12D3KooWlearned",
            }]
        }))
        .unwrap();
        let iroh = serde_json::to_vec(&json!({
            "peers": [{
                "node_id": "node-old",
                "peer_id": "same",
                "relay_url": "https://relay.example/old",
                "direct_addrs": ["198.51.100.8:9"],
                "addr": "198.51.100.8",
                "last_seen": unix_seconds(seen),
            }, {
                "node_id": "node-other",
                "peer_id": "other",
                "addr": "198.51.100.9",
                "last_seen": unix_seconds(seen),
            }]
        }))
        .unwrap();
        tracker
            .refresh_with(
                |url| {
                    if url == iroh_url.as_str() {
                        Ok(iroh.clone())
                    } else if url == peers_url.as_str() {
                        Ok(peers.clone())
                    } else {
                        Err(format!("unexpected {url}"))
                    }
                },
                seen,
                peers_url.as_str(),
                iroh_url.as_str(),
            )
            .unwrap();
        let find_url = tracker.upstream.endpoint(&["find", HASH]);
        let providers = serde_json::to_vec(&json!({
            "hash": HASH,
            "providers": [{
                "peer_id": "same",
                "addr": "198.51.100.8",
                "port": 9,
                "last_seen": unix_seconds(seen),
                "libp2p_peer_id": "12D3KooWlearned",
            }]
        }))
        .unwrap();
        tracker.store_learned_providers(HASH, &providers, seen);
        assert!(find_url.as_str().ends_with(&format!("/find/{HASH}")));

        let listed = tracker.peers_document(seen);
        assert_eq!(listed["peers"][0]["addr"], "198.51.100.8");
        let found = tracker.providers_document(HASH, seen);
        assert_eq!(found["providers"][0]["addr"], "198.51.100.8");
        assert_eq!(found["providers"][0]["libp2p_peer_id"], "12D3KooWlearned");
        let iroh_list = tracker.iroh_document(seen);
        assert_eq!(iroh_list["count"], 2);

        tracker
            .record_announce(
                "same".to_owned(),
                "203.0.113.8".to_owned(),
                5102,
                None,
                Some("12D3KooWlocal".to_owned()),
                seen + Duration::from_secs(60),
            )
            .unwrap();
        tracker
            .announce_iroh(
                &exchange_request(&post(
                    "/peerix/iroh/announce",
                    "X-Real-IP: 203.0.113.8\r\nContent-Type: application/json\r\n",
                    &json!({"node_id":"node-new","peer_id":"same","relay_url":"https://relay.example/new","direct_addrs":["203.0.113.8:5102"]}).to_string(),
                )),
                &json!({"node_id":"node-new","peer_id":"same","relay_url":"https://relay.example/new","direct_addrs":["203.0.113.8:5102"]}),
                seen + Duration::from_secs(60),
            )
            .unwrap();

        let replaced = tracker.peers_document(seen + Duration::from_secs(60));
        assert_eq!(replaced["peers"][0]["peer_id"], "same");
        assert_eq!(replaced["peers"][0]["addr"], "203.0.113.8");
        assert_eq!(replaced["peers"][0]["port"], 5102);
        let found = tracker.providers_document(HASH, seen + Duration::from_secs(60));
        assert_eq!(found["providers"][0]["addr"], "203.0.113.8");
        assert_eq!(found["providers"][0]["port"], 5102);
        assert_eq!(found["providers"][0]["libp2p_peer_id"], "12D3KooWlocal");
        let iroh_list = tracker.iroh_document(seen + Duration::from_secs(60));
        let node_ids: Vec<_> = iroh_list["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|peer| peer["node_id"].as_str().unwrap())
            .collect();
        assert_eq!(node_ids, vec!["node-new", "node-other"]);
        assert_eq!(iroh_list["peers"][0]["addr"], "203.0.113.8");

        tracker
            .refresh_with(
                |_| Err("upstream down".to_owned()),
                seen + Duration::from_secs(60),
                peers_url.as_str(),
                iroh_url.as_str(),
            )
            .unwrap_err();
        assert_eq!(
            tracker.peers_document(seen + Duration::from_secs(120))["peers"][0]["addr"],
            "203.0.113.8"
        );
        assert!(
            tracker.providers_document(HASH, seen + Duration::from_secs(120))["providers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|provider| provider["peer_id"] == "same")
        );
        assert!(is_fresh(seen, seen + PEER_TTL));
        assert!(!is_fresh(seen, seen + Duration::from_secs(121)));
        let expired = seen + Duration::from_secs(121);
        let peers = tracker.peers_document(expired);
        assert_eq!(peers["peers"].as_array().unwrap().len(), 1);
        assert_eq!(peers["peers"][0]["addr"], "203.0.113.8");
        assert!(
            tracker.providers_document(HASH, expired)["providers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|provider| provider["addr"] == "203.0.113.8")
        );
        let iroh_list = tracker.iroh_document(expired);
        assert_eq!(iroh_list["count"], 1);
        assert_eq!(iroh_list["peers"][0]["node_id"], "node-new");
        let behind = tracker.iroh_document(seen - Duration::from_secs(10));
        assert!(
            behind["peers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|peer| peer["node_id"] == "node-other")
        );
    }

    fn exchange_request(raw: &str) -> crate::cache::http_server::Request {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(raw.as_bytes()).unwrap();
        crate::cache::http_server::Request::read(server).unwrap()
    }

    #[test]
    fn unreachable_upstream_keeps_local_rows_and_drops_learned_rows_after_120_seconds() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        let seen = at(1_700_000_000);
        let peers_url = "http://127.0.0.1:9/peerix/peers";
        let iroh_url = "http://127.0.0.1:9/peerix/iroh/peers";
        let peers = serde_json::to_vec(&json!({
            "peers": [{
                "peer_id": "learned",
                "addr": "198.51.100.20",
                "port": 9,
                "last_seen": unix_seconds(seen),
            }]
        }))
        .unwrap();
        let iroh = serde_json::to_vec(&json!({
            "peers": [{
                "node_id": "node-learned",
                "peer_id": "learned-iroh",
                "addr": "198.51.100.21",
                "direct_addrs": [],
                "last_seen": unix_seconds(seen),
            }]
        }))
        .unwrap();
        tracker
            .refresh_with(
                |url| {
                    if url.ends_with("/iroh/peers") {
                        Ok(iroh.clone())
                    } else {
                        assert!(url.ends_with("/peers"));
                        Ok(peers.clone())
                    }
                },
                seen,
                peers_url,
                iroh_url,
            )
            .unwrap();
        let providers = serde_json::to_vec(&json!({
            "providers": [{
                "peer_id": "learned",
                "addr": "198.51.100.20",
                "port": 9,
                "last_seen": unix_seconds(seen),
            }]
        }))
        .unwrap();
        tracker.store_learned_providers(HASH, &providers, seen);
        tracker
            .record_announce(
                "local".to_owned(),
                "203.0.113.10".to_owned(),
                1,
                Some(vec![HASH.to_owned()]),
                None,
                seen + Duration::from_secs(60),
            )
            .unwrap();
        tracker
            .refresh_with(
                |_| Err("down".to_owned()),
                seen + Duration::from_secs(60),
                peers_url,
                iroh_url,
            )
            .unwrap_err();

        let within = seen + Duration::from_secs(120);
        assert_eq!(
            tracker.peers_document(within)["peers"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(tracker.iroh_document(within)["count"], 1);
        assert_eq!(
            tracker.providers_document(HASH, within)["providers"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let expired = seen + Duration::from_secs(121);
        let peers = tracker.peers_document(expired);
        assert_eq!(peers["peers"].as_array().unwrap().len(), 1);
        assert_eq!(peers["peers"][0]["peer_id"], "local");
        assert_eq!(tracker.iroh_document(expired)["count"], 0);
        let providers = tracker.providers_document(HASH, expired);
        assert_eq!(providers["providers"].as_array().unwrap().len(), 1);
        assert_eq!(providers["providers"][0]["peer_id"], "local");
        assert_eq!(providers["providers"][0]["addr"], "203.0.113.10");

        let behind = seen - Duration::from_secs(5);
        tracker
            .refresh_with(|_| Err("down".to_owned()), behind, peers_url, iroh_url)
            .unwrap_err();
        assert!(
            tracker.peers_document(behind)["peers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|peer| peer["peer_id"] == "learned")
        );
    }

    #[test]
    fn batch_and_delta_replace_the_local_hash_set_after_announce() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        let (status, _) = exchange(
            &tracker,
            &post(
                "/peerix/packages/batch",
                "Content-Type: application/json\r\n",
                &json!({"peer_id":"peer","hashes":[HASH]}).to_string(),
            ),
        );
        assert_eq!(status, 200);
        assert!(
            tracker.providers_document(HASH, SystemTime::now())["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        let (status, body) = exchange(
            &tracker,
            &post(
                "/peerix/announce",
                "Content-Type: application/json\r\n",
                &json!({"peer_id":"peer","port":5102}).to_string(),
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(json_body(&body)["status"], "ok");
        assert_eq!(
            tracker.providers_document(HASH, SystemTime::now())["providers"][0]["peer_id"],
            "peer"
        );

        let (status, body) = exchange(
            &tracker,
            &post(
                "/peerix/packages/delta",
                "Content-Type: application/json\r\n",
                &json!({"peer_id":"peer","added":[OTHER],"removed":[HASH]}).to_string(),
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(json_body(&body)["added"], 1);
        assert_eq!(json_body(&body)["removed"], 1);
        assert!(
            tracker.providers_document(HASH, SystemTime::now())["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            tracker.providers_document(OTHER, SystemTime::now())["providers"][0]["peer_id"],
            "peer"
        );

        let (status, _) = exchange(
            &tracker,
            &post(
                "/peerix/announce",
                "Content-Type: application/json\r\n",
                &json!({"peer_id":"peer","port":5102,"packages":[]}).to_string(),
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(
            tracker.providers_document(OTHER, SystemTime::now())["providers"][0]["peer_id"],
            "peer"
        );

        let (status, _) = exchange(
            &tracker,
            &post(
                "/peerix/packages/batch",
                "Content-Type: application/json\r\n",
                &json!({"peer_id":"peer","hashes":["not-a-hash", HASH]}).to_string(),
            ),
        );
        assert_eq!(status, 400);
        assert_eq!(
            tracker.providers_document(OTHER, SystemTime::now())["providers"][0]["peer_id"],
            "peer"
        );

        let (status, body) = exchange(
            &tracker,
            &post(
                "/peerix/packages/batch",
                "Content-Type: application/json\r\n",
                &json!({"peer_id":"peer","hashes":[]}).to_string(),
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(json_body(&body)["count"], 0);
        assert!(
            tracker.providers_document(OTHER, SystemTime::now())["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn hash_list_rejects_one_past_the_cap_without_a_partial_update() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        tracker
            .record_announce(
                "peer".to_owned(),
                "203.0.113.4".to_owned(),
                1,
                Some(vec![HASH.to_owned()]),
                None,
                SystemTime::now(),
            )
            .unwrap();
        let mut hashes = vec![Value::from(HASH); MAX_HASHES];
        hashes.push(Value::from(OTHER));
        let error = tracker
            .batch(&json!({"peer_id":"peer","hashes":hashes}))
            .unwrap_err();
        assert_eq!(error.1, "too many hashes");
        assert_eq!(
            tracker.providers_document(HASH, SystemTime::now())["providers"][0]["peer_id"],
            "peer"
        );
        assert!(
            tracker.providers_document(OTHER, SystemTime::now())["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn direct_announce_records_the_peerix_client_address() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        let body = json!({"peer_id":"peer","port":5102}).to_string();
        let (status, _) = exchange(
            &tracker,
            &post(
                "/peerix/announce",
                "X-Real-IP: 192.0.2.8\r\nX-Forwarded-For: 203.0.113.4, 10.0.0.1\r\nContent-Type: application/json\r\n",
                &body,
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(
            tracker.peers_document(SystemTime::now())["peers"][0]["addr"],
            "192.0.2.8"
        );

        let (status, _) = exchange(
            &tracker,
            &post(
                "/peerix/announce",
                "X-Forwarded-For:  203.0.113.4, 10.0.0.1\r\nContent-Type: application/json\r\n",
                &body,
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(
            tracker.peers_document(SystemTime::now())["peers"][0]["addr"],
            "203.0.113.4"
        );

        let (status, _) = exchange(
            &tracker,
            &post(
                "/peerix/announce",
                "Content-Type: application/json\r\n",
                &body,
            ),
        );
        assert_eq!(status, 200);
        assert_eq!(
            tracker.peers_document(SystemTime::now())["peers"][0]["addr"],
            "127.0.0.1"
        );
    }

    #[test]
    fn tracker_routes_reject_the_wrong_method_query_and_unknown_path() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        let (status, body) = exchange(
            &tracker,
            "GET /peerix/announce HTTP/1.0\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(status, 405);
        assert_eq!(json_body(&body)["error"], "method not allowed");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client
            .write_all(
                b"POST /peerix/peers HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        let request = crate::cache::http_server::Request::read(server).unwrap();
        assert!(tracker.respond(request).is_none());
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        assert!(raw.contains("Allow: GET"));

        let (status, _) = exchange(
            &tracker,
            "POST /peerix/peers?x=1 HTTP/1.0\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert_eq!(status, 400);
        let (status, _) = exchange(
            &tracker,
            "GET /peerix/missing HTTP/1.0\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(status, 404);
        let (status, _) = exchange(
            &tracker,
            "DELETE /peerix/iroh/peer/node HTTP/1.0\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(status, 404);
        assert!(!is_mount_path("/peer"));
        assert!(is_mount_path("/peerix"));
        assert!(is_mount_path("/peerix/peers"));
        assert!(is_mount_path("/peerix?x=1"));
    }

    fn is_mount_path(url: &str) -> bool {
        super::is_mount(url)
    }

    #[test]
    fn upstream_stand_in_is_only_read_and_supplies_find_and_iroh_peers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let recorded = Arc::clone(&calls);
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                answer(stream, &recorded);
            }
        });
        let tracker = tracker(&format!("http://{address}/peerix"));
        tracker.refresh().unwrap();
        let (status, body) = exchange(
            &tracker,
            &format!("GET /peerix/find/{HASH} HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        );
        assert_eq!(status, 200);
        let found = json_body(&body);
        assert_eq!(found["providers"][0]["peer_id"], "learned");
        assert_eq!(found["providers"][0]["addr"], "198.51.100.20");
        let (status, body) = exchange(
            &tracker,
            "GET /peerix/iroh/peers HTTP/1.0\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(status, 200);
        let iroh = json_body(&body);
        assert_eq!(iroh["count"], 1);
        assert_eq!(iroh["peers"][0]["node_id"], "node-learned");
        server.join().unwrap();
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|call: &String| call.starts_with("GET ")));
        assert!(calls.iter().any(|call| call.contains("/peerix/peers")));
        assert!(calls.iter().any(|call| call.contains("/peerix/iroh/peers")));
        assert!(
            calls
                .iter()
                .any(|call| call.contains(&format!("/peerix/find/{HASH}")))
        );
        assert!(calls.iter().all(|call| !call.starts_with("POST ")));
    }

    fn answer(mut stream: TcpStream, calls: &Mutex<Vec<String>>) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    bytes.extend_from_slice(&chunk[..count]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        let line = text.lines().next().unwrap_or("").to_owned();
        calls.lock().unwrap().push(line.clone());
        let path = line.split_whitespace().nth(1).unwrap_or("");
        let seen = unix_seconds(SystemTime::now());
        let body = if path.contains("/iroh/peers") {
            json!({
                "peers": [{
                    "node_id": "node-learned",
                    "peer_id": "learned-iroh",
                    "relay_url": "https://relay.example",
                    "direct_addrs": ["198.51.100.21:9"],
                    "addr": "198.51.100.21",
                    "last_seen": seen,
                }],
                "count": 1
            })
            .to_string()
        } else if path.contains("/find/") {
            json!({
                "hash": HASH,
                "providers": [{
                    "peer_id": "learned",
                    "addr": "198.51.100.20",
                    "port": 9,
                    "last_seen": seen,
                }]
            })
            .to_string()
        } else if path.contains("/peers") {
            json!({
                "peers": [{
                    "peer_id": "learned",
                    "addr": "198.51.100.20",
                    "port": 9,
                    "last_seen": seen,
                }]
            })
            .to_string()
        } else {
            json!({"error":"unexpected"}).to_string()
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    #[test]
    fn garbage_upstream_keeps_the_previous_learned_rows() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        let seen = at(1_700_000_000);
        let peers = serde_json::to_vec(&json!({
            "peers": [{
                "peer_id": "learned",
                "addr": "198.51.100.20",
                "port": 9,
                "last_seen": unix_seconds(seen),
            }]
        }))
        .unwrap();
        tracker
            .refresh_with(|_| Ok(br"not-json".to_vec()), seen, "peers", "iroh")
            .unwrap_err();
        assert!(
            tracker.peers_document(seen)["peers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        tracker
            .refresh_with(
                |url| {
                    if url == "peers" {
                        Ok(peers.clone())
                    } else {
                        Ok(br#"{"peers":[]}"#.to_vec())
                    }
                },
                seen,
                "peers",
                "iroh",
            )
            .unwrap();
        assert_eq!(
            tracker.peers_document(seen)["peers"][0]["peer_id"],
            "learned"
        );
        tracker
            .refresh_with(
                |url| {
                    if url == "peers" {
                        Ok(br"not-json".to_vec())
                    } else {
                        Ok(br#"{"nope":true}"#.to_vec())
                    }
                },
                seen,
                "peers",
                "iroh",
            )
            .unwrap_err();
        assert_eq!(
            tracker.peers_document(seen)["peers"][0]["peer_id"],
            "learned"
        );
        tracker
            .refresh_with(|_| Ok(br#"{"peers":[]}"#.to_vec()), seen, "peers", "iroh")
            .unwrap();
        assert!(
            tracker.peers_document(seen)["peers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            tracker.iroh_document(seen)["peers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tracked_row_cap_rejects_a_new_peer_id() {
        let tracker = tracker("http://127.0.0.1:9/peerix");
        for index in 0..MAX_TRACKED_ROWS {
            tracker
                .record_announce(
                    format!("peer-{index}"),
                    "203.0.113.4".to_owned(),
                    1,
                    None,
                    None,
                    SystemTime::now(),
                )
                .unwrap();
        }
        let error = tracker
            .record_announce(
                "overflow".to_owned(),
                "203.0.113.4".to_owned(),
                1,
                None,
                None,
                SystemTime::now(),
            )
            .unwrap_err();
        assert_eq!(error.1, "tracker is full");
        tracker
            .record_announce(
                "peer-0".to_owned(),
                "203.0.113.9".to_owned(),
                2,
                None,
                None,
                SystemTime::now(),
            )
            .unwrap();
        assert_eq!(
            tracker.peers_document(SystemTime::now())["peers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["peer_id"] == "peer-0")
                .unwrap()["addr"],
            "203.0.113.9"
        );
    }

    #[test]
    fn settings_keep_the_configured_upstream() {
        let upstream: HttpUrl = "https://example.test/peerix".parse().unwrap();
        let settings = TrackerSettings {
            upstream: upstream.clone(),
            timeout: Duration::from_secs(3),
        };
        assert_eq!(settings.upstream.as_str(), "https://example.test/peerix");
        assert_eq!(settings.timeout, Duration::from_secs(3));
    }
}
