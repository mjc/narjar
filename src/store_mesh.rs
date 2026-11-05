//! HTTP exchange with nix-store-mesh peers.
//!
//! The integration stays down until serve has a host map or a listen address.
//! A host map makes `127.0.0.1:9740` a loopback substituter: Nix asks for a
//! narinfo, and the NAR request goes back to the host that answered. Outbound
//! requests are HTTP/2 and are dialed only when the address is inside the
//! Tailscale ranges. A listen address publishes shareable paths over HTTP/2.
//! A client is accepted only when its source address is a Tailscale address of
//! a host in the map. mDNS advertisement and browse are left alone.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::poll_fn,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

use crate::{cache::narinfo::MAX_NARINFO_BYTES, cache::storage::StoreHash, peer_share::ShareIndex};

pub(crate) const DEFAULT_PORT: u16 = 9722;
pub(crate) const SUBSTITUTER_PORT: u16 = 9740;
const NAR_CHUNK: usize = 16 * 1024;
const CACHE_INFO: &[u8] = b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 50\n";
const OUTSIDE_TAILSCALE: &str = "mesh address is outside the tailscale ranges";
const ALLOW_REFRESH: Duration = Duration::from_secs(60);
const ALLOW_RETRY: Duration = Duration::from_secs(5);

pub(crate) fn substituter_socket() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), SUBSTITUTER_PORT)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MeshHost {
    name: String,
    target: HostTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostTarget {
    Socket(SocketAddr),
    Name { host: String, port: u16 },
}

#[derive(Clone, Debug)]
pub(crate) struct MeshSettings {
    pub(crate) hosts: Vec<MeshHost>,
    pub(crate) listen: Option<SocketAddr>,
    pub(crate) stall_timeout: Duration,
    pub(crate) substituter: SocketAddr,
}

impl MeshHost {
    fn literal_ip(&self) -> Option<IpAddr> {
        match self.target {
            HostTarget::Socket(addr) => Some(addr.ip()),
            HostTarget::Name { .. } => None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn socket(&self) -> Option<SocketAddr> {
        match self.target {
            HostTarget::Socket(addr) => Some(addr),
            HostTarget::Name { .. } => None,
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) fn settings_from_cli(
    hosts: &[String],
    listen: Option<&str>,
    stall_timeout: Duration,
) -> Result<Option<MeshSettings>, String> {
    if hosts.is_empty() && listen.is_none() {
        return Ok(None);
    }
    if stall_timeout.is_zero() {
        return Err("store mesh stall timeout must be non-zero".to_owned());
    }
    let mut parsed = Vec::with_capacity(hosts.len());
    let mut seen = BTreeSet::new();
    for spec in hosts {
        let host = parse_host(spec)?;
        if !seen.insert(host.name().to_owned()) {
            return Err(format!("store mesh host {} is listed twice", host.name()));
        }
        parsed.push(host);
    }
    let listen = listen.map(parse_listen).transpose()?;
    Ok(Some(MeshSettings {
        hosts: parsed,
        listen,
        stall_timeout,
        substituter: substituter_socket(),
    }))
}

pub(crate) fn parse_host(spec: &str) -> Result<MeshHost, String> {
    let Some((name, target)) = spec.split_once('=') else {
        return Err(format!("store mesh host must be NAME=TARGET: {spec}"));
    };
    if !valid_token(name) {
        return Err(format!("store mesh host name is invalid: {name}"));
    }
    Ok(MeshHost {
        name: name.to_owned(),
        target: parse_target(target)?,
    })
}

fn parse_listen(value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("store mesh listen address is invalid: {value}"))
}

fn parse_target(target: &str) -> Result<HostTarget, String> {
    if target.is_empty() {
        return Err("store mesh target is empty".to_owned());
    }
    if let Some(rest) = target.strip_prefix('[') {
        let (addr, port) = split_bracket(rest)?;
        let ip = addr
            .parse()
            .map_err(|_| format!("store mesh address is invalid: {target}"))?;
        return Ok(HostTarget::Socket(SocketAddr::new(ip, port)));
    }
    if target.matches(':').count() > 1 {
        return Err(format!("store mesh IPv6 address needs brackets: {target}"));
    }
    if let Some((host, port_text)) = target.rsplit_once(':')
        && let Ok(port) = port_text.parse::<u16>()
        && port != 0
    {
        return host_target(host, port);
    }
    host_target(target, DEFAULT_PORT)
}

fn split_bracket(rest: &str) -> Result<(&str, u16), String> {
    let Some((addr, after)) = rest.split_once(']') else {
        return Err("store mesh IPv6 address needs brackets".to_owned());
    };
    if addr.is_empty() {
        return Err("store mesh address is invalid".to_owned());
    }
    if after.is_empty() {
        return Ok((addr, DEFAULT_PORT));
    }
    let Some(port_text) = after.strip_prefix(':') else {
        return Err("store mesh address is invalid".to_owned());
    };
    let port = port_text
        .parse::<u16>()
        .map_err(|_| "store mesh port is invalid".to_owned())?;
    if port == 0 {
        return Err("store mesh port is invalid".to_owned());
    }
    Ok((addr, port))
}

fn host_target(host: &str, port: u16) -> Result<HostTarget, String> {
    if host.is_empty() {
        return Err("store mesh target is empty".to_owned());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(HostTarget::Socket(SocketAddr::new(ip, port)));
    }
    if !valid_token(host) {
        return Err(format!("store mesh target is invalid: {host}"));
    }
    Ok(HostTarget::Name {
        host: host.to_owned(),
        port,
    })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

pub(crate) fn is_tailscale(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            octets[0] == 100 && (octets[1] & 0xc0) == 0x40
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}

pub(crate) fn choose_addr(addrs: &[SocketAddr]) -> Result<SocketAddr, String> {
    addrs
        .iter()
        .copied()
        .find(|addr| is_tailscale(addr.ip()))
        .ok_or_else(|| OUTSIDE_TAILSCALE.to_owned())
}

/// Dial only after [`choose_addr`] accepts the address.
///
/// The closure is the dial. An address outside the Tailscale ranges returns
/// before the closure runs.
pub(crate) fn dial_resolved<T>(
    addrs: &[SocketAddr],
    connect: impl FnOnce(SocketAddr) -> Result<T, String>,
) -> Result<T, String> {
    connect(choose_addr(addrs)?)
}

pub(crate) fn source_allowed(ip: IpAddr, hosts: &[MeshHost]) -> bool {
    is_tailscale(ip) && hosts.iter().any(|host| host.literal_ip() == Some(ip))
}

pub(crate) fn fetch_targets<'a>(hosts: &'a [MeshHost], own: &[u8]) -> Vec<&'a MeshHost> {
    hosts
        .iter()
        .filter(|host| host.name().as_bytes() != own)
        .collect()
}

fn own_hostname() -> Vec<u8> {
    rustix::system::uname().nodename().to_bytes().to_vec()
}

fn substituter_line(addr: SocketAddr) -> String {
    format!("narjar: store mesh substituter http://{addr}")
}

enum FetchMode {
    Http,
    #[cfg(test)]
    Script(HostScript),
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScriptReply {
    Miss,
    Body(Vec<u8>),
}

#[cfg(test)]
type HostScript = Arc<dyn Fn(&MeshHost, &str) -> Result<ScriptReply, String> + Send + Sync>;

struct NameAllow {
    by_host: BTreeMap<String, Vec<IpAddr>>,
    refreshed: Instant,
    retry_soon: bool,
}

struct MeshState {
    hosts: Vec<MeshHost>,
    own: Vec<u8>,
    allow: Mutex<NameAllow>,
    usable: Mutex<BTreeSet<String>>,
    routes: Mutex<BTreeMap<String, MeshHost>>,
    fetch: FetchMode,
    stall: Duration,
    index: Option<Arc<ShareIndex>>,
}

pub(crate) struct StoreMesh {
    runtime: Option<tokio::runtime::Runtime>,
    shutdown: Option<watch::Sender<bool>>,
    substituter_addr: SocketAddr,
    listen_addr: Option<SocketAddr>,
}

impl StoreMesh {
    pub(crate) fn start(
        settings: &MeshSettings,
        share: Option<Arc<ShareIndex>>,
    ) -> Result<Self, String> {
        Self::spawn(settings, share, FetchMode::Http)
    }

    #[cfg(test)]
    pub(crate) fn start_scripted(
        settings: MeshSettings,
        script: HostScript,
    ) -> Result<Self, String> {
        Self::spawn(&settings, None, FetchMode::Script(script))
    }

    pub(crate) fn substituter_addr(&self) -> SocketAddr {
        self.substituter_addr
    }

    pub(crate) fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }

    fn spawn(
        settings: &MeshSettings,
        share: Option<Arc<ShareIndex>>,
        fetch: FetchMode,
    ) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .thread_name("narjar-mesh")
            .build()
            .map_err(|error| format!("cannot start store mesh runtime: {error}"))?;
        let (substituter, listen, allow) = runtime.block_on(bind_listeners(settings))?;
        let substituter_addr = substituter
            .local_addr()
            .map_err(|error| format!("cannot inspect store mesh substituter: {error}"))?;
        let listen_addr = listen
            .as_ref()
            .map(|listener| listener.local_addr())
            .transpose()
            .map_err(|error| format!("cannot inspect store mesh listener: {error}"))?;
        let (shutdown, watch_rx) = watch::channel(false);
        let state = Arc::new(MeshState {
            hosts: settings.hosts.clone(),
            own: own_hostname(),
            allow: Mutex::new(allow),
            usable: Mutex::new(BTreeSet::new()),
            routes: Mutex::new(BTreeMap::new()),
            fetch,
            stall: settings.stall_timeout,
            index: share,
        });
        runtime.spawn(serve_substituter(
            substituter,
            Arc::clone(&state),
            watch_rx.clone(),
        ));
        if let Some(listener) = listen {
            runtime.spawn(serve_listener(listener, Arc::clone(&state), watch_rx));
        }
        let mesh = Self {
            runtime: Some(runtime),
            shutdown: Some(shutdown),
            substituter_addr,
            listen_addr,
        };
        eprintln!("{}", substituter_line(mesh.substituter_addr()));
        if let Some(addr) = mesh.listen_addr() {
            eprintln!("narjar: store mesh listening {addr}");
        }
        Ok(mesh)
    }
}

impl Drop for StoreMesh {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

async fn bind_listeners(
    settings: &MeshSettings,
) -> Result<(TcpListener, Option<TcpListener>, NameAllow), String> {
    let substituter = TcpListener::bind(settings.substituter)
        .await
        .map_err(|error| format!("cannot listen for the store mesh substituter: {error}"))?;
    let listen = match settings.listen {
        Some(addr) => Some(
            TcpListener::bind(addr)
                .await
                .map_err(|error| format!("cannot listen for the store mesh: {error}"))?,
        ),
        None => None,
    };
    let allow = resolve_names(&settings.hosts, &BTreeMap::new(), settings.stall_timeout).await;
    Ok((substituter, listen, allow))
}

fn allow_due(allow: &NameAllow) -> bool {
    let age = allow.refreshed.elapsed();
    if allow.retry_soon {
        age >= ALLOW_RETRY
    } else {
        age >= ALLOW_REFRESH
    }
}

/// Keep the last addresses when a lookup fails. A new answer replaces them.
fn apply_resolution(
    previous: Option<&Vec<IpAddr>>,
    result: Result<Vec<IpAddr>, String>,
) -> Option<Vec<IpAddr>> {
    match result {
        Ok(ips) => Some(ips),
        Err(_) => previous.cloned(),
    }
}

async fn resolve_names(
    hosts: &[MeshHost],
    previous: &BTreeMap<String, Vec<IpAddr>>,
    stall: Duration,
) -> NameAllow {
    let mut by_host = BTreeMap::new();
    let mut retry_soon = false;
    for host in hosts {
        let HostTarget::Name { host: name, port } = &host.target else {
            continue;
        };
        let result = resolve_name(name, *port, stall)
            .await
            .map(|addrs| addrs.into_iter().map(|addr| addr.ip()).collect::<Vec<_>>());
        if let Err(error) = &result {
            eprintln!(
                "narjar: store mesh host {} is not on the allow list: {error}",
                host.name()
            );
            if !previous.contains_key(host.name()) {
                retry_soon = true;
            }
        }
        if let Some(ips) = apply_resolution(previous.get(host.name()), result) {
            by_host.insert(host.name().to_owned(), ips);
        }
    }
    NameAllow {
        by_host,
        refreshed: Instant::now(),
        retry_soon,
    }
}

async fn current_allow(state: &MeshState) -> Vec<IpAddr> {
    if allow_due(&locked(&state.allow)) {
        let previous = locked(&state.allow).by_host.clone();
        let next = resolve_names(&state.hosts, &previous, state.stall).await;
        *locked(&state.allow) = next;
    }
    locked(&state.allow)
        .by_host
        .values()
        .flatten()
        .copied()
        .collect()
}

async fn resolve_name(host: &str, port: u16, stall: Duration) -> Result<Vec<SocketAddr>, String> {
    let label = host.to_owned();
    let lookup = label.clone();
    tokio::time::timeout(
        stall,
        tokio::task::spawn_blocking(move || {
            (lookup.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
                .map_err(|error| error.to_string())
        }),
    )
    .await
    .map_err(|_| format!("mesh resolve stalled for {label}"))?
    .map_err(|_| format!("mesh resolve failed for {label}"))?
}

async fn resolve_host(host: &MeshHost, stall: Duration) -> Result<Vec<SocketAddr>, String> {
    match &host.target {
        HostTarget::Socket(addr) => Ok(vec![*addr]),
        HostTarget::Name { host, port } => resolve_name(host, *port, stall).await,
    }
}

async fn connect_host(host: &MeshHost, stall: Duration) -> Result<TcpStream, String> {
    let addrs = resolve_host(host, stall).await?;
    let name = host.name().to_owned();
    let dial_name = name.clone();
    let std_stream = tokio::task::spawn_blocking(move || {
        dial_resolved(&addrs, |addr| {
            std::net::TcpStream::connect_timeout(&addr, stall)
                .map_err(|error| format!("cannot dial {dial_name}: {error}"))
        })
    })
    .await
    .map_err(|_| format!("cannot dial {name}"))??;
    std_stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let stream = TcpStream::from_std(std_stream).map_err(|error| error.to_string())?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn client_allowed(ip: IpAddr, hosts: &[MeshHost], resolved: &[IpAddr]) -> bool {
    source_allowed(ip, hosts) || (is_tailscale(ip) && resolved.contains(&ip))
}

async fn serve_listener(
    listener: TcpListener,
    state: Arc<MeshState>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { break };
                let allow = current_allow(&state).await;
                if !client_allowed(peer.ip(), &state.hosts, &allow) {
                    drop(stream);
                    continue;
                }
                let index = state.index.clone();
                let stall = state.stall;
                let connection_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    serve_connection(stream, index, stall, connection_shutdown).await;
                });
            }
        }
    }
}

async fn serve_connection(
    io: TcpStream,
    index: Option<Arc<ShareIndex>>,
    stall: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connection = match tokio::time::timeout(stall, h2::server::handshake(io)).await {
        Ok(Ok(connection)) => connection,
        _ => return,
    };
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = connection.accept() => {
                match accepted {
                    Some(Ok((request, respond))) => {
                        let index = index.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_request(index, request, respond, stall).await {
                                eprintln!("narjar: store mesh request failed: {error}");
                            }
                        });
                    }
                    _ => break,
                }
            }
        }
    }
}

async fn handle_request(
    index: Option<Arc<ShareIndex>>,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    stall: Duration,
) -> Result<(), String> {
    let (parts, _body) = request.into_parts();
    if parts.method != http::Method::GET || parts.uri.query().is_some() {
        return send_status(&mut respond, http::StatusCode::NOT_FOUND).await;
    }
    let path = parts.uri.path();
    if path == "/nix-cache-info" {
        return send_bytes(
            &mut respond,
            http::StatusCode::OK,
            "text/x-nix-cache-info",
            CACHE_INFO,
            stall,
        )
        .await;
    }
    if let Some(hash) = narinfo_hash(path) {
        let body = index
            .as_ref()
            .and_then(|index| index.narinfo(&hash))
            .filter(|body| mesh_shaped(body));
        return match body {
            Some(body) => {
                send_bytes(
                    &mut respond,
                    http::StatusCode::OK,
                    "text/x-nix-narinfo",
                    &body,
                    stall,
                )
                .await
            }
            None => send_status(&mut respond, http::StatusCode::NOT_FOUND).await,
        };
    }
    if let Some(query) = offered_nar_query(path) {
        return serve_nar(index, &query, &mut respond, stall).await;
    }
    send_status(&mut respond, http::StatusCode::NOT_FOUND).await
}

fn narinfo_hash(path: &str) -> Option<StoreHash> {
    let name = path.strip_prefix('/')?.strip_suffix(".narinfo")?;
    StoreHash::parse(name).ok()
}

fn offered_nar_query(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/nar/")?;
    if rest.is_empty()
        || rest.contains('\\')
        || rest
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(format!("nar/{rest}"))
}

fn mesh_shaped(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let mut urls = text.lines().filter_map(|line| {
        let value = line.strip_prefix("URL:")?.trim();
        (!value.is_empty()).then_some(value)
    });
    let Some(url) = urls.next() else {
        return false;
    };
    urls.next().is_none()
        && url.starts_with("nar/")
        && !url.contains('?')
        && !url.contains(' ')
        && raw_nar_claim(text)
}

/// The listener streams a raw NAR, so the narinfo has to describe those bytes.
fn raw_nar_claim(text: &str) -> bool {
    if single_field(text, "Compression") != Some("none") {
        return false;
    }
    match (
        single_field(text, "FileHash"),
        single_field(text, "FileSize"),
    ) {
        (None, None) => true,
        (Some(file_hash), Some(file_size)) => {
            single_field(text, "NarHash") == Some(file_hash)
                && single_field(text, "NarSize") == Some(file_size)
        }
        _ => false,
    }
}

fn single_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut found = None;
    let header = format!("{name}:");
    for line in text.lines() {
        let Some(value) = line.strip_prefix(&header) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(value.trim());
    }
    found
}

async fn serve_nar(
    index: Option<Arc<ShareIndex>>,
    query: &str,
    respond: &mut h2::server::SendResponse<Bytes>,
    stall: Duration,
) -> Result<(), String> {
    let Some(index) = index else {
        return send_status(respond, http::StatusCode::NOT_FOUND).await;
    };
    let Some(hash) = index.hash_for_nar_request(query) else {
        return send_status(respond, http::StatusCode::NOT_FOUND).await;
    };
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/x-nix-nar")
        .body(())
        .map_err(|error| error.to_string())?;
    let mut stream = respond
        .send_response(response, false)
        .map_err(|error| error.to_string())?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let writing = Arc::clone(&index);
    let joined = tokio::task::spawn_blocking(move || {
        let writer = ChanWriter { tx };
        writing.write_nar(&hash, writer)
    });
    let mut forward_error = None;
    while let Some(chunk) = rx.recv().await {
        if let Err(error) = write_data(&mut stream, chunk, false, stall).await {
            forward_error = Some(error);
            break;
        }
    }
    drop(rx);
    let wrote = joined
        .await
        .map_err(|_| "mesh nar task panicked".to_owned())?;
    if forward_error.is_none() && wrote.is_ok() {
        return write_data(&mut stream, Bytes::new(), true, stall).await;
    }
    stream.send_reset(h2::Reason::INTERNAL_ERROR);
    Err(forward_error.unwrap_or_else(|| wrote.unwrap_err().to_string()))
}

struct ChanWriter {
    tx: tokio::sync::mpsc::Sender<Bytes>,
}

impl Write for ChanWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.chunks(NAR_CHUNK) {
            self.tx
                .blocking_send(Bytes::copy_from_slice(chunk))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mesh client stopped"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn send_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: http::StatusCode,
) -> Result<(), String> {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .map_err(|error| error.to_string())?;
    respond
        .send_response(response, true)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

async fn send_bytes(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: http::StatusCode,
    content_type: &str,
    body: &[u8],
    stall: Duration,
) -> Result<(), String> {
    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(|error| error.to_string())?;
    let mut stream = respond
        .send_response(response, false)
        .map_err(|error| error.to_string())?;
    if body.is_empty() {
        return write_data(&mut stream, Bytes::new(), true, stall).await;
    }
    let mut offset = 0;
    while offset < body.len() {
        let end = offset.saturating_add(NAR_CHUNK).min(body.len());
        write_data(
            &mut stream,
            Bytes::copy_from_slice(&body[offset..end]),
            end == body.len(),
            stall,
        )
        .await?;
        offset = end;
    }
    Ok(())
}

async fn write_data(
    stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end: bool,
    stall: Duration,
) -> Result<(), String> {
    let needed = data.len();
    if needed > 0 {
        stream.reserve_capacity(needed);
        while stream.capacity() < needed {
            let available = tokio::time::timeout(stall, poll_fn(|cx| stream.poll_capacity(cx)))
                .await
                .map_err(|_| "mesh send stalled".to_owned())?
                .ok_or_else(|| "mesh send closed".to_owned())?
                .map_err(|error| error.to_string())?;
            if available == 0 {
                return Err("mesh send closed".to_owned());
            }
        }
    }
    stream
        .send_data(data, end)
        .map_err(|error| error.to_string())
}

async fn serve_substituter(
    listener: TcpListener,
    state: Arc<MeshState>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { break };
                if !peer.ip().is_loopback() {
                    drop(stream);
                    continue;
                }
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    if let Err(error) = handle_substituter(stream, &state).await {
                        eprintln!("narjar: store mesh substituter failed: {error}");
                    }
                });
            }
        }
    }
}

async fn handle_substituter(mut stream: TcpStream, state: &MeshState) -> Result<(), String> {
    let asked = match read_substituter_path(&mut stream, state.stall).await {
        Ok(path) => path,
        Err(error) => {
            let _ = write_fixed(
                &mut stream,
                400,
                "Bad Request",
                "text/plain",
                error.as_bytes(),
            )
            .await;
            return Ok(());
        }
    };
    if asked == "/nix-cache-info" {
        return write_fixed(&mut stream, 200, "OK", "text/x-nix-cache-info", CACHE_INFO).await;
    }
    if narinfo_hash(&asked).is_some() {
        return substituter_narinfo(&mut stream, state, &asked).await;
    }
    if asked.starts_with("/nar/") {
        return substituter_nar(&mut stream, state, &asked).await;
    }
    write_fixed(&mut stream, 404, "Not Found", "text/plain", b"").await
}

async fn read_substituter_path(stream: &mut TcpStream, stall: Duration) -> Result<String, String> {
    let mut buf = vec![0_u8; 4096];
    let mut filled = 0usize;
    loop {
        let read = tokio::time::timeout(stall, stream.read(&mut buf[filled..]))
            .await
            .map_err(|_| "mesh substituter read stalled".to_owned())?
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("mesh substituter client closed".to_owned());
        }
        filled += read;
        let mut headers = [httparse::EMPTY_HEADER; 48];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&buf[..filled]) {
            Ok(httparse::Status::Complete(_)) => {
                if request.method != Some("GET") {
                    return Err("mesh substituter method is not GET".to_owned());
                }
                let path = request.path.unwrap_or("");
                if path.is_empty() || path.contains('?') {
                    return Err("mesh substituter path is invalid".to_owned());
                }
                return Ok(path.to_owned());
            }
            Ok(httparse::Status::Partial) if filled == buf.len() => {
                return Err("mesh substituter request is too large".to_owned());
            }
            Ok(httparse::Status::Partial) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

async fn substituter_narinfo(
    stream: &mut TcpStream,
    state: &MeshState,
    path: &str,
) -> Result<(), String> {
    let mut saw_miss = false;
    let mut last_error = None;
    for host in fetch_targets(&state.hosts, &state.own) {
        if let Err(error) = ensure_usable(state, host).await {
            last_error = Some(error);
            continue;
        }
        match fetch_bytes(state, host, path, narinfo_limit()).await {
            Ok(Some(body)) => {
                if let Some(nar_path) = nar_request_path(&body) {
                    locked(&state.routes).insert(nar_path, (*host).clone());
                }
                return write_fixed(stream, 200, "OK", "text/x-nix-narinfo", &body).await;
            }
            Ok(None) => saw_miss = true,
            Err(error) => last_error = Some(error),
        }
    }
    if saw_miss {
        return write_fixed(stream, 404, "Not Found", "text/plain", b"").await;
    }
    let message = last_error.unwrap_or_else(|| "store mesh has no hosts to ask".to_owned());
    eprintln!("narjar: store mesh narinfo failed: {message}");
    write_fixed(stream, 500, "Internal Server Error", "text/plain", b"").await
}

async fn substituter_nar(
    stream: &mut TcpStream,
    state: &MeshState,
    path: &str,
) -> Result<(), String> {
    let Some(host) = locked(&state.routes).get(path).cloned() else {
        return write_fixed(stream, 404, "Not Found", "text/plain", b"").await;
    };
    match proxy_nar(state, &host, path, stream).await {
        Ok(Proxied::Missing) => write_fixed(stream, 404, "Not Found", "text/plain", b"").await,
        Ok(Proxied::Sent) => Ok(()),
        Ok(Proxied::Failed(error)) => {
            eprintln!("narjar: store mesh nar failed: {error}");
            Ok(())
        }
        Err(error) => {
            eprintln!("narjar: store mesh nar failed: {error}");
            write_fixed(stream, 500, "Internal Server Error", "text/plain", b"").await
        }
    }
}

enum Proxied {
    Missing,
    Sent,
    Failed(String),
}

async fn proxy_nar(
    state: &MeshState,
    host: &MeshHost,
    path: &str,
    stream: &mut TcpStream,
) -> Result<Proxied, String> {
    match &state.fetch {
        FetchMode::Http => {
            let mut opened = http2_open(host, path, state.stall).await?;
            if opened.status == 404 {
                return Ok(Proxied::Missing);
            }
            if opened.status != 200 {
                return Err(format!(
                    "mesh host {} returned {} for {path}",
                    host.name(),
                    opened.status
                ));
            }
            write_chunked_headers(stream).await?;
            if let Err(error) = write_h2_body(&mut opened, stream, state.stall).await {
                return Ok(Proxied::Failed(error));
            }
            if let Err(error) = write_chunk_end(stream).await {
                return Ok(Proxied::Failed(error));
            }
            Ok(Proxied::Sent)
        }
        #[cfg(test)]
        FetchMode::Script(script) => match script(host, path)? {
            ScriptReply::Miss => Ok(Proxied::Missing),
            ScriptReply::Body(body) => {
                write_fixed(stream, 200, "OK", "application/x-nix-nar", &body).await?;
                Ok(Proxied::Sent)
            }
        },
    }
}

async fn ensure_usable(state: &MeshState, host: &MeshHost) -> Result<(), String> {
    if locked(&state.usable).contains(host.name()) {
        return Ok(());
    }
    match fetch_bytes(state, host, "/nix-cache-info", 64 * 1024).await? {
        Some(_) => {
            locked(&state.usable).insert(host.name().to_owned());
            Ok(())
        }
        None => Err(format!("mesh host {} has no cache info", host.name())),
    }
}

async fn fetch_bytes(
    state: &MeshState,
    host: &MeshHost,
    path: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, String> {
    match &state.fetch {
        FetchMode::Http => {
            let mut opened = http2_open(host, path, state.stall).await?;
            if opened.status == 404 {
                return Ok(None);
            }
            if opened.status != 200 {
                return Err(format!(
                    "mesh host {} returned {} for {path}",
                    host.name(),
                    opened.status
                ));
            }
            let body = read_limited(&mut opened, limit, state.stall).await?;
            Ok(Some(body))
        }
        #[cfg(test)]
        FetchMode::Script(script) => match script(host, path)? {
            ScriptReply::Miss => Ok(None),
            ScriptReply::Body(body) if body.len() > limit => {
                Err("mesh response is too large".to_owned())
            }
            ScriptReply::Body(body) => Ok(Some(body)),
        },
    }
}

struct H2Response {
    status: u16,
    body: h2::RecvStream,
    flow: h2::FlowControl,
}

async fn http2_open(host: &MeshHost, path: &str, stall: Duration) -> Result<H2Response, String> {
    let stream = connect_host(host, stall).await?;
    http2_exchange(stream, path, stall).await
}

async fn http2_exchange(
    stream: TcpStream,
    path: &str,
    stall: Duration,
) -> Result<H2Response, String> {
    let (client, connection) = tokio::time::timeout(stall, h2::client::handshake(stream))
        .await
        .map_err(|_| "mesh handshake stalled".to_owned())?
        .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = tokio::time::timeout(stall, client.ready())
        .await
        .map_err(|_| "mesh request stalled".to_owned())?
        .map_err(|error| error.to_string())?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_2)
        .uri(mesh_uri(path)?)
        .body(())
        .map_err(|error| error.to_string())?;
    let (response, _send) = client
        .send_request(request, true)
        .map_err(|error| error.to_string())?;
    let response = tokio::time::timeout(stall, response)
        .await
        .map_err(|_| "mesh response stalled".to_owned())?
        .map_err(|error| error.to_string())?;
    let (parts, mut body) = response.into_parts();
    let flow = body.flow_control().clone();
    Ok(H2Response {
        status: parts.status.as_u16(),
        body,
        flow,
    })
}

fn mesh_uri(path: &str) -> Result<http::Uri, String> {
    if !path.starts_with('/') {
        return Err(format!("mesh path is invalid: {path}"));
    }
    format!("https://mesh{path}")
        .parse()
        .map_err(|error| format!("mesh path is invalid: {error}"))
}

async fn read_limited(
    got: &mut H2Response,
    limit: usize,
    stall: Duration,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let next = tokio::time::timeout(stall, got.body.data())
            .await
            .map_err(|_| "mesh body stalled".to_owned())?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|error| error.to_string())?;
        if out.len().saturating_add(chunk.len()) > limit {
            return Err("mesh response is too large".to_owned());
        }
        out.extend_from_slice(&chunk);
        got.flow
            .release_capacity(chunk.len())
            .map_err(|error| error.to_string())?;
    }
    Ok(out)
}

async fn write_h2_body(
    got: &mut H2Response,
    sink: &mut TcpStream,
    stall: Duration,
) -> Result<(), String> {
    loop {
        let next = tokio::time::timeout(stall, got.body.data())
            .await
            .map_err(|_| "mesh body stalled".to_owned())?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|error| error.to_string())?;
        write_http_chunk(sink, &chunk).await?;
        got.flow
            .release_capacity(chunk.len())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn nar_request_path(narinfo: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(narinfo).ok()?;
    let url = text.lines().find_map(|line| {
        let value = line.strip_prefix("URL:")?.trim();
        (!value.is_empty()).then_some(value)
    })?;
    let rest = url.strip_prefix("nar/")?;
    if rest.is_empty() || rest.contains('?') || rest.contains(' ') {
        return None;
    }
    Some(format!("/nar/{rest}"))
}

fn narinfo_limit() -> usize {
    usize::try_from(MAX_NARINFO_BYTES).unwrap_or(1024 * 1024)
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn write_fixed(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(body)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn write_chunked_headers(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/x-nix-nar\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
        )
        .await
        .map_err(|error| error.to_string())
}

async fn write_http_chunk(stream: &mut TcpStream, chunk: &[u8]) -> Result<(), String> {
    let header = format!("{:x}\r\n", chunk.len());
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(chunk)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(b"\r\n")
        .await
        .map_err(|error| error.to_string())
}

async fn write_chunk_end(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::Read,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use tokio::{
        net::{TcpListener, TcpStream},
        sync::watch,
    };

    use super::*;
    use crate::{cache::storage::StoreHash, peer_share::ShareIndex};

    fn host(spec: &str) -> MeshHost {
        parse_host(spec).expect("host")
    }

    #[test]
    fn host_map_accepts_ports_brackets_and_names() {
        let plain = host("other=100.64.0.2");
        assert_eq!(plain.name(), "other");
        assert_eq!(
            plain.socket(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
                9722
            ))
        );
        let port = host("other=100.64.0.2:9733");
        assert_eq!(port.socket().expect("socket").port(), 9733);
        let v6 = host("other=[fd7a:115c:a1e0::8]");
        assert_eq!(v6.socket().expect("socket").port(), 9722);
        assert!(is_tailscale(v6.socket().expect("socket").ip()));
        let v6_port = host("other=[fd7a:115c:a1e0::8]:9730");
        assert_eq!(v6_port.socket().expect("socket").port(), 9730);
        let name = host("other=machine.tail.ts.net");
        assert!(name.socket().is_none());
        let named_port = host("other=machine.tail.ts.net:9731");
        assert!(named_port.socket().is_none());
        assert!(parse_host("bad name=100.64.0.2").is_err());
        assert!(parse_host("other=").is_err());
        assert!(parse_host("other=fd7a:115c:a1e0::8").is_err());
        assert!(
            settings_from_cli(&[], None, Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        let settings = settings_from_cli(
            &["self=100.64.0.1".to_owned(), "other=100.64.0.2".to_owned()],
            Some("100.64.0.1:9722"),
            Duration::from_secs(5),
        )
        .expect("settings");
        let settings = settings.expect("on");
        assert_eq!(settings.substituter, substituter_socket());
        assert_eq!(settings.listen, Some("100.64.0.1:9722".parse().unwrap()));
        let targets = fetch_targets(&settings.hosts, b"self");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name(), "other");
        assert!(source_allowed(
            Ipv4Addr::new(100, 64, 0, 1).into(),
            &settings.hosts
        ));
        assert!(
            settings_from_cli(
                &["other=100.64.0.2".to_owned(), "other=100.64.0.3".to_owned()],
                None,
                Duration::from_secs(1),
            )
            .is_err()
        );
    }

    #[test]
    fn tailscale_ranges_are_the_cgnat_and_mesh_prefixes() {
        assert!(is_tailscale(Ipv4Addr::new(100, 64, 0, 1).into()));
        assert!(is_tailscale(Ipv4Addr::new(100, 127, 255, 255).into()));
        assert!(!is_tailscale(Ipv4Addr::new(100, 128, 0, 1).into()));
        assert!(!is_tailscale(Ipv4Addr::new(100, 63, 255, 255).into()));
        assert!(!is_tailscale(Ipv4Addr::new(203, 0, 113, 5).into()));
        assert!(!is_tailscale(Ipv4Addr::LOCALHOST.into()));
        assert!(is_tailscale(
            "fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap().into()
        ));
        assert!(!is_tailscale(
            "fd7a:115c:a1e1::1".parse::<Ipv6Addr>().unwrap().into()
        ));
    }

    #[test]
    fn a_resolved_address_outside_the_tailscale_ranges_is_not_dialed() {
        let outside: SocketAddr = "203.0.113.5:9722".parse().unwrap();
        let mut dials = 0;
        let error = dial_resolved(&[outside], |_| {
            dials += 1;
            Ok(())
        })
        .expect_err("outside");
        assert_eq!(dials, 0);
        assert_eq!(error, OUTSIDE_TAILSCALE);
        let inside: SocketAddr = "100.64.0.2:9722".parse().unwrap();
        let chosen = dial_resolved(&[outside, inside], Ok).expect("inside");
        assert_eq!(chosen, inside);
    }

    #[test]
    fn source_allowed_requires_a_mapped_tailscale_address() {
        let hosts = vec![
            host("other=100.64.0.2"),
            host("public=203.0.113.5"),
            host("named=machine.tail.ts.net"),
        ];
        assert!(source_allowed(Ipv4Addr::new(100, 64, 0, 2).into(), &hosts));
        assert!(!source_allowed(Ipv4Addr::new(100, 64, 0, 3).into(), &hosts));
        assert!(!source_allowed(
            Ipv4Addr::new(203, 0, 113, 5).into(),
            &hosts
        ));
        assert!(!source_allowed(Ipv4Addr::LOCALHOST.into(), &hosts));
    }

    #[test]
    fn mesh_shaped_narinfo_has_one_relative_nar_url() {
        assert!(mesh_shaped(
            b"URL: nar/abc.nar\nCompression: none\nSig: cache.example:AAAA\n"
        ));
        assert!(mesh_shaped(
            b"URL: nar/abc.nar\nCompression: none\nFileHash: sha256:abc\nFileSize: 4\nNarHash: sha256:abc\nNarSize: 4\n"
        ));
        assert!(!mesh_shaped(b"URL: nar/abc.nar\nSig: cache.example:AAAA\n"));
        assert!(!mesh_shaped(b"URL: nar/abc.nar.xz\nCompression: xz\n"));
        assert!(!mesh_shaped(
            b"URL: nar/abc.nar\nCompression: none\nCompression: none\n"
        ));
        assert!(!mesh_shaped(
            b"URL: nar/abc.nar\nCompression: none\nFileHash: sha256:abc\nFileSize: 4\nNarHash: sha256:other\nNarSize: 4\n"
        ));
        assert!(!mesh_shaped(
            b"URL: nar/abc.nar\nCompression: none\nFileHash: sha256:abc\n"
        ));
        assert!(!mesh_shaped(
            b"URL: nar/abc.nar?peer=a\nCompression: none\n"
        ));
        assert!(!mesh_shaped(
            b"URL: https://cache.example/nar/abc.nar\nCompression: none\n"
        ));
        assert!(!mesh_shaped(
            b"URL: nar/one.nar\nURL: nar/two.nar\nCompression: none\n"
        ));
        assert!(!mesh_shaped(b"Sig: cache.example:AAAA\n"));
    }

    #[test]
    fn a_name_keeps_its_last_addresses_until_a_new_answer() {
        let hosts = vec![host("named=machine.tail.ts.net")];
        let previous = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3));
        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        assert!(apply_resolution(None, Err("dns".into())).is_none());
        assert!(!client_allowed(previous, &hosts, &[]));

        let first = apply_resolution(None, Ok(vec![previous])).expect("first");
        assert!(client_allowed(previous, &hosts, &first));
        assert!(!client_allowed(moved, &hosts, &first));
        assert!(!client_allowed(public, &hosts, &[public]));

        let next = apply_resolution(Some(&first), Ok(vec![moved])).expect("moved");
        assert!(!client_allowed(previous, &hosts, &next));
        assert!(client_allowed(moved, &hosts, &next));

        let kept = apply_resolution(Some(&next), Err("dns".into())).expect("kept");
        assert_eq!(kept, vec![moved]);
        assert!(client_allowed(moved, &hosts, &kept));
        assert!(!client_allowed(previous, &hosts, &kept));
    }

    #[test]
    fn an_unresolved_name_is_retried_before_a_resolved_one() {
        let now = Instant::now();
        let unresolved = NameAllow {
            by_host: BTreeMap::new(),
            refreshed: now,
            retry_soon: true,
        };
        assert!(!allow_due(&unresolved));
        let retry = NameAllow {
            by_host: BTreeMap::new(),
            refreshed: now.checked_sub(ALLOW_RETRY).expect("clock"),
            retry_soon: true,
        };
        assert!(allow_due(&retry));
        let fresh = NameAllow {
            by_host: BTreeMap::new(),
            refreshed: now.checked_sub(ALLOW_RETRY).expect("clock"),
            retry_soon: false,
        };
        assert!(!allow_due(&fresh));
        let stale = NameAllow {
            by_host: BTreeMap::new(),
            refreshed: now.checked_sub(ALLOW_REFRESH).expect("clock"),
            retry_soon: false,
        };
        assert!(allow_due(&stale));
    }

    #[test]
    fn the_local_hostname_is_nonempty() {
        assert!(!own_hostname().is_empty());
    }

    #[test]
    fn a_fake_host_returns_narinfo_and_nar_to_the_substituter() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let narinfo = b"\
StorePath: /nix/store/0123456789abcdfghijklmnpqrsvwxyz-package\n\
URL: nar/abc.nar\n\
Compression: none\n\
Sig: cache.example:AAAA\n";
        let script = Arc::new(move |host: &MeshHost, path: &str| {
            recorded
                .lock()
                .expect("calls")
                .push((host.name().to_owned(), path.to_owned()));
            if path == "/nix-cache-info" {
                return Ok(ScriptReply::Body(CACHE_INFO.to_vec()));
            }
            if host.name() == "miss" {
                return Ok(ScriptReply::Miss);
            }
            if path.ends_with(".narinfo") {
                return Ok(ScriptReply::Body(narinfo.to_vec()));
            }
            if path == "/nar/abc.nar" && host.name() == "hit" {
                return Ok(ScriptReply::Body(b"nar-bytes".to_vec()));
            }
            Err(format!("unexpected {} {path}", host.name()))
        });
        let mut settings = settings_from_cli(
            &["miss=100.64.0.9".to_owned(), "hit=100.64.0.8".to_owned()],
            None,
            Duration::from_secs(2),
        )
        .expect("settings")
        .expect("on");
        settings.substituter = "127.0.0.1:0".parse().unwrap();
        let mesh = StoreMesh::start_scripted(settings, script).expect("mesh");
        let line = substituter_line(mesh.substituter_addr());
        assert!(line.starts_with("narjar: store mesh substituter http://127.0.0.1:"));
        assert!(!line.contains("trusted"));
        let info = http1(
            &mesh,
            "GET /nix-cache-info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(info.starts_with("HTTP/1.1 200"));
        assert!(info.contains("Priority: 50"));
        let body = http1(
            &mesh,
            "GET /0123456789abcdfghijklmnpqrsvwxyz.narinfo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(body.starts_with("HTTP/1.1 200"));
        assert!(body.contains("Sig: cache.example:AAAA"));
        assert!(body.contains("URL: nar/abc.nar"));
        let nar = http1(
            &mesh,
            "GET /nar/abc.nar HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(nar.starts_with("HTTP/1.1 200"));
        assert!(nar.contains("nar-bytes"));
        let log = http1(
            &mesh,
            "GET /log/abc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(log.starts_with("HTTP/1.1 404"));
        let seen = calls.lock().expect("calls");
        assert!(
            seen.iter()
                .any(|(name, path)| name == "hit" && path == "/nar/abc.nar")
        );
        assert!(
            !seen
                .iter()
                .any(|(name, path)| name == "miss" && path.starts_with("/nar/"))
        );
        drop(mesh);
    }

    fn http1(mesh: &StoreMesh, request: &str) -> String {
        let mut stream = std::net::TcpStream::connect(mesh.substituter_addr()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        std::io::Write::write_all(&mut stream, request.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        String::from_utf8(response).expect("utf-8")
    }

    #[test]
    fn a_configured_peer_fetches_a_shareable_path() {
        let (root, index, hash, narinfo) = offered_hello();
        let bad = StoreHash::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        index.insert_offered_for_test(
            bad,
            b"URL: https://cache.example/nar/abc.nar\nSig: cache.example:AAAA\n".to_vec(),
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .thread_name("narjar-mesh-test")
            .build()
            .unwrap();
        runtime.block_on(exchange_share(
            &index,
            &hash,
            &narinfo,
            Duration::from_secs(3),
        ));
        drop(root);
    }

    #[test]
    fn a_wide_narinfo_arrives_and_a_compressed_one_is_a_miss() {
        let (root, index, _hash, _narinfo) = offered_hello();
        let wide_hash = StoreHash::parse("cccccccccccccccccccccccccccccccc").unwrap();
        let mut wide = b"URL: nar/wide.nar\nCompression: none\n".to_vec();
        wide.resize(wide.len() + 70_000, b'x');
        wide.push(b'\n');
        assert!(wide.len() > 65_535);
        index.insert_offered_for_test(wide_hash, wide.clone());
        let compressed = StoreHash::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        index.insert_offered_for_test(
            compressed,
            b"URL: nar/abc.nar.xz\nCompression: xz\n".to_vec(),
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .thread_name("narjar-mesh-test")
            .build()
            .unwrap();
        let stall = Duration::from_secs(3);
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let shared = Arc::clone(&index);
            let (_shutdown, rx) = watch::channel(false);
            tokio::spawn(async move {
                for _ in 0..2 {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let shared = Arc::clone(&shared);
                    let rx = rx.clone();
                    tokio::spawn(async move {
                        serve_connection(stream, Some(shared), stall, rx).await;
                    });
                }
            });
            let (status, body) = read_exchange(
                TcpStream::connect(addr).await.unwrap(),
                &format!("/{}.narinfo", wide_hash.as_str()),
                stall,
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(body, wide);
            let (status, body) = read_exchange(
                TcpStream::connect(addr).await.unwrap(),
                &format!("/{}.narinfo", compressed.as_str()),
                stall,
            )
            .await;
            assert_eq!(status, 404);
            assert!(body.is_empty());
        });
        drop(root);
    }

    async fn exchange_share(
        index: &Arc<ShareIndex>,
        hash: &StoreHash,
        narinfo: &[u8],
        stall: Duration,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = Arc::clone(index);
        let (shutdown, rx) = watch::channel(false);
        tokio::spawn(async move {
            for _ in 0..6 {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let shared = Arc::clone(&shared);
                let rx = rx.clone();
                tokio::spawn(async move {
                    serve_connection(stream, Some(shared), stall, rx).await;
                });
            }
        });
        let (status, info) = read_exchange(
            TcpStream::connect(addr).await.unwrap(),
            "/nix-cache-info",
            stall,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(info, CACHE_INFO);
        let (status, info) = read_exchange(
            TcpStream::connect(addr).await.unwrap(),
            &format!("/{}.narinfo", hash.as_str()),
            stall,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(info, narinfo);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("URL: nar/"));
        assert!(!text.contains('?'));
        assert!(text.contains("Sig: cache.example:AAAA"));
        let url = text
            .lines()
            .find_map(|line| line.strip_prefix("URL:"))
            .unwrap()
            .trim();
        let (status, nar) = read_exchange(
            TcpStream::connect(addr).await.unwrap(),
            &format!("/{url}"),
            stall,
        )
        .await;
        assert_eq!(status, 200);
        let mut direct = Vec::new();
        index.write_nar(hash, &mut direct).unwrap();
        assert_eq!(nar, direct);
        let (status, _) = read_exchange(
            TcpStream::connect(addr).await.unwrap(),
            "/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.narinfo",
            stall,
        )
        .await;
        assert_eq!(status, 404);
        let (status, _) = read_exchange(
            TcpStream::connect(addr).await.unwrap(),
            "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo",
            stall,
        )
        .await;
        assert_eq!(status, 404);
        let (status, _) =
            read_exchange(TcpStream::connect(addr).await.unwrap(), "/log/abc", stall).await;
        assert_eq!(status, 404);
        drop(shutdown);
    }

    async fn read_exchange(stream: TcpStream, path: &str, stall: Duration) -> (u16, Vec<u8>) {
        let mut opened = http2_exchange(stream, path, stall).await.expect("exchange");
        let body = read_limited(&mut opened, 1024 * 1024, stall)
            .await
            .expect("body");
        (opened.status, body)
    }

    fn offered_hello() -> (tempfile::TempDir, Arc<ShareIndex>, StoreHash, Vec<u8>) {
        let root = tempfile::tempdir().unwrap();
        let hash = "0123456789abcdfghijklmnpqrsvwxyz";
        let basename = format!("{hash}-package");
        std::fs::write(root.path().join(&basename), b"hello").unwrap();
        let (digest, nar_size) = crate::push::hash_store_nar(&root.path().join(&basename)).unwrap();
        let identity = narjar::object::NarIdentity::new(
            narjar::object::NarHash::from_digest(digest),
            narjar::object::NarSize::new(nar_size),
        );
        let metadata = crate::cache::narinfo::NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{basename}"),
            None,
            None,
            identity,
            Vec::new(),
            vec!["cache.example:AAAA".to_owned()],
        )
        .unwrap();
        let narinfo = metadata
            .serialize(narjar::object::NarRepresentation::Raw(identity))
            .unwrap();
        let index = Arc::new(ShareIndex::new(crate::peer_share::PeerShareSettings {
            store_root: root.path().to_path_buf(),
            upstream: "https://cache.nixos.org".parse().unwrap(),
            publish_all: false,
            signing_key: None,
            state_dir: None,
            refresh_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
        }));
        let parsed = StoreHash::parse(hash).unwrap();
        index.insert_offered_for_test(parsed, narinfo.clone());
        (root, index, parsed, narinfo)
    }

    #[test]
    fn a_client_outside_the_host_map_is_refused() {
        let mut settings = settings_from_cli(
            &["other=100.64.0.2".to_owned()],
            Some("127.0.0.1:0"),
            Duration::from_secs(2),
        )
        .unwrap()
        .unwrap();
        settings.substituter = "127.0.0.1:0".parse().unwrap();
        let mesh = StoreMesh::start(&settings, None).expect("mesh");
        let addr = mesh.listen_addr().expect("listen");
        let mut client = std::net::TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0_u8; 8];
        let read = client.read(&mut buf).expect("eof");
        assert_eq!(read, 0);
        drop(mesh);
    }
}
