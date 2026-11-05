//! Iroh endpoint for the peerix narinfo and NAR protocols.
//!
//! The endpoint stays down until serve is configured with it. A configured
//! endpoint keeps a 32-byte secret so its id survives restart, accepts
//! `peerix/narinfo/1` and `peerix/nar/1`, and answers from the share index.
//! Direct addresses are used when the peer has them. The public relay is only
//! a fallback, and tests bind loopback with that fallback removed.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{cache::storage::StoreHash, peer_share::ShareIndex};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{Connection, SendStream, presets},
};

pub(crate) const NARINFO_ALPN: &[u8] = b"peerix/narinfo/1";
pub(crate) const NAR_ALPN: &[u8] = b"peerix/nar/1";
pub(crate) const SECRET_FILE_NAME: &str = "iroh_secret.key";
const NOT_FOUND: &[u8] = b"NOTFOUND";
const NARINFO_QUERY_LIMIT: usize = 64;
const NAR_QUERY_LIMIT: usize = 1024;
#[cfg_attr(not(test), allow(dead_code))]
const NARINFO_RESPONSE_LIMIT: usize = 65_536;
const NAR_CHUNK: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct EndpointSettings {
    pub(crate) state_dir: PathBuf,
    pub(crate) stall_timeout: Duration,
}

#[cfg_attr(not(test), allow(dead_code))]
struct Backoff {
    failures: u32,
    until: Instant,
}

pub(crate) struct PeerEndpoint {
    runtime: tokio::runtime::Runtime,
    endpoint: Endpoint,
    shutdown: Option<tokio::sync::watch::Sender<bool>>,
    #[cfg_attr(not(test), allow(dead_code))]
    backoff: Mutex<BTreeMap<EndpointId, Backoff>>,
    #[cfg_attr(not(test), allow(dead_code))]
    stall_timeout: Duration,
}

impl PeerEndpoint {
    /// Bind with direct connections first and the public relay as fallback.
    pub(crate) fn start(
        settings: &EndpointSettings,
        share: Option<Arc<ShareIndex>>,
    ) -> Result<Self, String> {
        Self::bind(settings, share, false)
    }
}

/// Client calls used by tests now and by the loopback substituter once it exists.
#[cfg_attr(not(test), allow(dead_code))]
impl PeerEndpoint {
    /// Bind on loopback with relays and address lookup removed.
    pub(crate) fn start_local(
        settings: &EndpointSettings,
        share: Option<Arc<ShareIndex>>,
    ) -> Result<Self, String> {
        Self::bind(settings, share, true)
    }

    pub(crate) fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub(crate) fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub(crate) fn fetch_narinfo(
        &self,
        addr: &EndpointAddr,
        hash: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        if self.is_backed_off(addr.id) {
            return Err(format!("peer {} is backed off", addr.id));
        }
        match self.runtime.block_on(fetch_narinfo(
            &self.endpoint,
            addr,
            hash,
            self.stall_timeout,
        )) {
            Ok(body) => {
                self.clear_backoff(addr.id);
                Ok(body)
            }
            Err(error) => {
                self.record_failure(addr.id);
                Err(error)
            }
        }
    }

    /// Ask peers until one returns a narinfo. A backed-off peer is skipped.
    /// `Ok(None)` means a peer answered and none of them have the path.
    pub(crate) fn fetch_narinfo_from_peers(
        &self,
        peers: &[EndpointAddr],
        hash: &str,
    ) -> Result<Option<(EndpointId, Vec<u8>)>, String> {
        if peers.is_empty() {
            return Err("no peerix peers".to_owned());
        }
        let mut saw_miss = false;
        let mut last_error = None;
        let mut skipped = 0usize;
        for peer in peers {
            if self.is_backed_off(peer.id) {
                skipped += 1;
                continue;
            }
            match self.fetch_narinfo(peer, hash) {
                Ok(Some(body)) => return Ok(Some((peer.id, body))),
                Ok(None) => saw_miss = true,
                Err(error) => last_error = Some(error),
            }
        }
        if saw_miss {
            return Ok(None);
        }
        Err(last_error.unwrap_or_else(|| {
            if skipped == peers.len() {
                "peerix peers are backed off".to_owned()
            } else {
                "peerix narinfo lookup failed".to_owned()
            }
        }))
    }

    pub(crate) fn fetch_nar<W: Write + Send>(
        &self,
        addr: &EndpointAddr,
        query: &str,
        output: W,
    ) -> Result<(), String> {
        if self.is_backed_off(addr.id) {
            return Err(format!("peer {} is backed off", addr.id));
        }
        match self.runtime.block_on(fetch_nar(
            &self.endpoint,
            addr,
            query,
            output,
            self.stall_timeout,
        )) {
            Ok(()) => {
                self.clear_backoff(addr.id);
                Ok(())
            }
            Err(error) => {
                self.record_failure(addr.id);
                Err(error)
            }
        }
    }

    fn bind(
        settings: &EndpointSettings,
        share: Option<Arc<ShareIndex>>,
        local_only: bool,
    ) -> Result<Self, String> {
        if settings.stall_timeout.is_zero() {
            return Err("peerix stall timeout must be non-zero".to_owned());
        }
        let secret = SecretKey::from_bytes(&load_or_create_secret(&settings.state_dir)?);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .thread_name("narjar-peerix")
            .build()
            .map_err(|error| format!("cannot start peerix endpoint runtime: {error}"))?;
        let endpoint = runtime
            .block_on(bind_endpoint(secret, local_only))
            .map_err(|error| format!("cannot bind peerix endpoint: {error}"))?;
        let (shutdown, watch) = tokio::sync::watch::channel(false);
        let stall_timeout = settings.stall_timeout;
        let accepting = endpoint.clone();
        runtime.spawn(accept_loop(accepting, share, stall_timeout, watch));
        let id = endpoint.id();
        eprintln!("narjar: peerix endpoint {id}");
        Ok(Self {
            runtime,
            endpoint,
            shutdown: Some(shutdown),
            backoff: Mutex::new(BTreeMap::new()),
            stall_timeout,
        })
    }

    fn is_backed_off(&self, id: EndpointId) -> bool {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .is_some_and(|backoff| Instant::now() < backoff.until)
    }

    fn clear_backoff(&self, id: EndpointId) {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }

    fn record_failure(&self, id: EndpointId) {
        let mut peers = self
            .backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let backoff = peers.entry(id).or_insert(Backoff {
            failures: 0,
            until: Instant::now(),
        });
        backoff.failures = backoff.failures.saturating_add(1);
        backoff.until = Instant::now() + backoff_delay(backoff.failures);
    }
}

impl Drop for PeerEndpoint {
    fn drop(&mut self) {
        self.shutdown.take();
        self.runtime.block_on(self.endpoint.close());
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn backoff_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    Duration::from_secs(1_u64 << shift).min(Duration::from_secs(60))
}

fn load_or_create_secret(state_dir: &Path) -> Result<[u8; 32], String> {
    fs::create_dir_all(state_dir).map_err(|error| {
        format!(
            "cannot create peerix endpoint state directory {}: {error}",
            state_dir.display()
        )
    })?;
    let path = state_dir.join(SECRET_FILE_NAME);
    if let Some(secret) = read_secret(&path)? {
        restrict_secret(&path)?;
        return Ok(secret);
    }
    if path.exists() {
        fs::remove_file(&path).map_err(|error| {
            format!(
                "cannot replace invalid peerix endpoint secret {}: {error}",
                path.display()
            )
        })?;
    }
    let secret = SecretKey::generate().to_bytes();
    write_secret(&path, &secret)?;
    Ok(secret)
}

fn read_secret(path: &Path) -> Result<Option<[u8; 32]>, String> {
    match fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut secret = [0_u8; 32];
            secret.copy_from_slice(&bytes);
            Ok(Some(secret))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot read peerix endpoint secret {}: {error}",
            path.display()
        )),
    }
}

fn write_secret(path: &Path, secret: &[u8; 32]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot create peerix endpoint secret {}: {error}",
                path.display()
            )
        })?;
    file.write_all(secret).map_err(|error| {
        format!(
            "cannot write peerix endpoint secret {}: {error}",
            path.display()
        )
    })?;
    restrict_secret(path)
}

fn restrict_secret(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        format!(
            "cannot restrict peerix endpoint secret {}: {error}",
            path.display()
        )
    })
}

async fn bind_endpoint(secret: SecretKey, local_only: bool) -> Result<Endpoint, String> {
    let alpns = vec![NARINFO_ALPN.to_vec(), NAR_ALPN.to_vec()];
    let builder = if local_only {
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .clear_relay_transports()
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .map_err(|error| error.to_string())?
    } else {
        Endpoint::builder(presets::N0)
    };
    builder
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .map_err(|error| error.to_string())
}

async fn accept_loop(
    endpoint: Endpoint,
    share: Option<Arc<ShareIndex>>,
    stall_timeout: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let share = share.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    serve_connection(connection, share, stall_timeout).await;
                });
            }
        }
    }
}

async fn serve_connection(
    connection: Connection,
    share: Option<Arc<ShareIndex>>,
    stall_timeout: Duration,
) {
    let alpn = connection.alpn().to_vec();
    let served = if alpn.as_slice() == NARINFO_ALPN {
        serve_narinfo(connection, share.as_deref(), stall_timeout).await
    } else if alpn.as_slice() == NAR_ALPN {
        serve_nar(connection, share, stall_timeout).await
    } else {
        Err("peerix connection used an unknown protocol".to_owned())
    };
    if let Err(error) = served {
        eprintln!("narjar: peerix request failed: {error}");
    }
}

async fn wait_for<T, E: std::fmt::Display>(
    timeout: Duration,
    what: &str,
    work: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_elapsed) => Err(format!("peerix {what} stalled")),
    }
}

async fn serve_narinfo(
    connection: Connection,
    share: Option<&ShareIndex>,
    stall_timeout: Duration,
) -> Result<(), String> {
    let (mut send, mut recv) =
        wait_for(stall_timeout, "narinfo accept", connection.accept_bi()).await?;
    let query = wait_for(
        stall_timeout,
        "narinfo read",
        recv.read_to_end(NARINFO_QUERY_LIMIT),
    )
    .await?;
    let hash = std::str::from_utf8(&query)
        .map_err(|_| "peerix narinfo query is not UTF-8".to_owned())?
        .trim();
    let body = StoreHash::parse(hash)
        .ok()
        .and_then(|hash| share.and_then(|share| share.narinfo(&hash)));
    let response = body.as_deref().unwrap_or(NOT_FOUND);
    wait_for(stall_timeout, "narinfo write", send.write_all(response)).await?;
    finish_response(&mut send, &connection, stall_timeout).await
}

async fn serve_nar(
    connection: Connection,
    share: Option<Arc<ShareIndex>>,
    stall_timeout: Duration,
) -> Result<(), String> {
    let (mut send, mut recv) =
        wait_for(stall_timeout, "NAR accept", connection.accept_bi()).await?;
    let query = wait_for(stall_timeout, "NAR read", recv.read_to_end(NAR_QUERY_LIMIT)).await?;
    let query = std::str::from_utf8(&query)
        .map_err(|_| "peerix NAR query is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    let Some(share) = share else {
        return Err("peerix NAR request has no share index".to_owned());
    };
    let Some(hash) = share.hash_for_nar_request(&query) else {
        return Err("peerix NAR request is not offered".to_owned());
    };
    let share_for_size = Arc::clone(&share);
    let size = tokio::task::spawn_blocking(move || share_for_size.measured_nar(&hash))
        .await
        .map_err(|error| format!("peerix NAR measurement task failed: {error}"))?
        .map_err(|error| error.to_string())?;
    wait_for(
        stall_timeout,
        "NAR length",
        send.write_all(&size.to_be_bytes()),
    )
    .await?;

    let (chunks, mut incoming) = tokio::sync::mpsc::channel(4);
    let share_for_body = Arc::clone(&share);
    let body = tokio::task::spawn_blocking(move || {
        let mut writer = ChunkWriter { chunks };
        share_for_body.write_nar(&hash, &mut writer)
    });
    let forwarded: Result<(), String> = async {
        while let Some(chunk) = incoming.recv().await {
            wait_for(stall_timeout, "NAR write", send.write_all(&chunk)).await?;
        }
        Ok(())
    }
    .await;
    let streamed = body
        .await
        .map_err(|error| format!("peerix NAR stream task failed: {error}"))?;
    forwarded?;
    streamed.map_err(|error| error.to_string())?;
    finish_response(&mut send, &connection, stall_timeout).await
}

/// Finish the response and keep the connection until the peer has read it.
///
/// Dropping the connection sends CONNECTION_CLOSE, and the peer may discard
/// stream bytes it has not delivered to the application yet.
async fn finish_response(
    send: &mut SendStream,
    connection: &Connection,
    stall_timeout: Duration,
) -> Result<(), String> {
    send.finish().map_err(|error| error.to_string())?;
    match tokio::time::timeout(stall_timeout, connection.closed()).await {
        Ok(_reason) => Ok(()),
        Err(_elapsed) => Err("peerix peer did not finish reading the response".to_owned()),
    }
}

struct ChunkWriter {
    chunks: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl Write for ChunkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let size = buf.len().min(NAR_CHUNK);
        self.chunks
            .blocking_send(buf[..size].to_vec())
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg_attr(not(test), allow(dead_code))]
async fn fetch_narinfo(
    endpoint: &Endpoint,
    addr: &EndpointAddr,
    hash: &str,
    stall_timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    let connection =
        tokio::time::timeout(stall_timeout, endpoint.connect(addr.clone(), NARINFO_ALPN))
            .await
            .map_err(|_| format!("peerix narinfo connection to {} stalled", addr.id))?
            .map_err(|error| format!("cannot connect to {} for narinfo: {error}", addr.id))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    send.write_all(hash.trim().as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    let response = tokio::time::timeout(stall_timeout, recv.read_to_end(NARINFO_RESPONSE_LIMIT))
        .await
        .map_err(|_| format!("peerix narinfo read from {} stalled", addr.id))?
        .map_err(|error| format!("cannot read narinfo from {}: {error}", addr.id))?;
    if response.is_empty() {
        return Err(format!("peer {} closed narinfo without a body", addr.id));
    }
    if response.as_slice() == NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(response))
}

#[cfg_attr(not(test), allow(dead_code))]
async fn fetch_nar<W: Write + Send>(
    endpoint: &Endpoint,
    addr: &EndpointAddr,
    query: &str,
    mut output: W,
    stall_timeout: Duration,
) -> Result<(), String> {
    let connection = tokio::time::timeout(stall_timeout, endpoint.connect(addr.clone(), NAR_ALPN))
        .await
        .map_err(|_| format!("peerix NAR connection to {} stalled", addr.id))?
        .map_err(|error| format!("cannot connect to {} for a NAR: {error}", addr.id))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    send.write_all(query.trim().as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    let mut length = [0_u8; 8];
    tokio::time::timeout(stall_timeout, recv.read_exact(&mut length))
        .await
        .map_err(|_| format!("peerix NAR length from {} stalled", addr.id))?
        .map_err(|error| format!("peer {} closed the NAR stream: {error}", addr.id))?;
    let mut remaining = u64::from_be_bytes(length);
    let mut buffer = vec![0_u8; NAR_CHUNK];
    while remaining > 0 {
        let size = usize::try_from(remaining)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        tokio::time::timeout(stall_timeout, recv.read_exact(&mut buffer[..size]))
            .await
            .map_err(|_| format!("peerix NAR body from {} stalled", addr.id))?
            .map_err(|error| format!("peer {} ended the NAR early: {error}", addr.id))?;
        output
            .write_all(&buffer[..size])
            .map_err(|error| format!("cannot write peerix NAR: {error}"))?;
        remaining -= size as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use super::*;
    use crate::{
        cache::narinfo::NarInfoMetadata,
        peer_share::{PeerShareSettings, ShareIndex},
        push::hash_store_nar,
    };
    use narjar::object::{NarHash, NarIdentity, NarRepresentation, NarSize};

    const HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";

    fn settings(dir: &Path, stall: Duration) -> EndpointSettings {
        EndpointSettings {
            state_dir: dir.to_path_buf(),
            stall_timeout: stall,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime")
    }

    fn offered_share(bytes: &[u8]) -> (tempfile::TempDir, Arc<ShareIndex>, Vec<u8>) {
        let root = tempfile::tempdir().expect("store root");
        let basename = format!("{HASH}-package");
        fs::write(root.path().join(&basename), bytes).expect("store file");
        let (digest, nar_size) =
            hash_store_nar(&root.path().join(&basename)).expect("hash store file");
        let identity = NarIdentity::new(NarHash::from_digest(digest), NarSize::new(nar_size));
        let narinfo = NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{basename}"),
            None,
            None,
            identity,
            Vec::new(),
            Vec::new(),
        )
        .expect("narinfo")
        .serialize(NarRepresentation::Raw(identity))
        .expect("serialize narinfo");
        let index = ShareIndex::new(PeerShareSettings {
            store_root: root.path().to_path_buf(),
            upstream: "https://cache.nixos.org".parse().expect("upstream"),
            publish_all: false,
            signing_key: None,
            state_dir: None,
            refresh_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
        });
        index.insert_offered_for_test(StoreHash::parse(HASH).expect("hash"), narinfo.clone());
        (root, Arc::new(index), narinfo)
    }

    #[test]
    fn the_endpoint_secret_stays_private_and_the_id_survives_restart() {
        let state = tempfile::tempdir().expect("state");
        let first =
            PeerEndpoint::start_local(&settings(state.path(), Duration::from_secs(2)), None)
                .expect("first endpoint");
        let id = first.id();
        let addr = first.addr();
        assert!(addr.relay_urls().next().is_none());
        assert!(addr.ip_addrs().any(|socket| socket.ip().is_loopback()));
        let path = state.path().join(SECRET_FILE_NAME);
        let secret = fs::read(&path).expect("secret");
        assert_eq!(secret.len(), 32);
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(first);

        let second =
            PeerEndpoint::start_local(&settings(state.path(), Duration::from_secs(2)), None)
                .expect("second endpoint");
        assert_eq!(second.id(), id);
        assert_eq!(fs::read(path).expect("reused secret"), secret);
    }

    #[test]
    fn backoff_grows_and_then_caps_at_one_minute() {
        assert_eq!(backoff_delay(1), Duration::from_secs(1));
        assert_eq!(backoff_delay(2), Duration::from_secs(2));
        assert_eq!(backoff_delay(3), Duration::from_secs(4));
        assert_eq!(backoff_delay(6), Duration::from_secs(32));
        assert_eq!(backoff_delay(7), Duration::from_secs(60));
        assert_eq!(backoff_delay(30), Duration::from_secs(60));
    }

    #[test]
    fn a_peerix_peer_and_a_narjar_endpoint_exchange_narinfo_and_nar() {
        let (_root, share, narinfo) = offered_share(b"hello peer");
        let state = tempfile::tempdir().expect("state");
        let server = PeerEndpoint::start_local(
            &settings(state.path(), Duration::from_secs(2)),
            Some(Arc::clone(&share)),
        )
        .expect("server");
        let server_addr = server.addr();

        let runtime = runtime();
        let peer = runtime
            .block_on(bind_endpoint(SecretKey::generate(), true))
            .expect("raw peer");
        let answer = narinfo.clone();
        let body = {
            let mut direct = Vec::new();
            share
                .write_nar(&StoreHash::parse(HASH).unwrap(), &mut direct)
                .unwrap();
            direct
        };
        let peer_body = body.clone();
        let accepting = peer.clone();
        runtime.spawn(async move {
            let peer = accepting;
            while let Some(incoming) = peer.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                let answer = answer.clone();
                let peer_body = peer_body.clone();
                tokio::spawn(async move {
                    let alpn = connection.alpn().to_vec();
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let Ok(query) = recv.read_to_end(1024).await else {
                        return;
                    };
                    if alpn.as_slice() == NARINFO_ALPN {
                        let hash = String::from_utf8_lossy(&query);
                        let response = if hash.trim() == HASH {
                            answer
                        } else {
                            NOT_FOUND.to_vec()
                        };
                        if send.write_all(&response).await.is_err() {
                            return;
                        }
                    } else if alpn.as_slice() == NAR_ALPN {
                        if send
                            .write_all(&peer_body.len().to_be_bytes())
                            .await
                            .is_err()
                            || send.write_all(&peer_body).await.is_err()
                        {
                            return;
                        }
                    } else {
                        return;
                    }
                    if send.finish().is_err() {
                        return;
                    }
                    // Stay up until the Narjar client has read the bytes.
                    connection.closed().await;
                });
            }
        });
        let peer_addr = peer.addr();

        let client_state = tempfile::tempdir().expect("client state");
        let client =
            PeerEndpoint::start_local(&settings(client_state.path(), Duration::from_secs(2)), None)
                .expect("client");
        let fetched = client
            .fetch_narinfo(&peer_addr, HASH)
            .expect("narinfo from raw peer");
        assert_eq!(fetched.as_deref(), Some(narinfo.as_slice()));
        assert!(
            client
                .fetch_narinfo(&peer_addr, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .expect("missing hash")
                .is_none()
        );
        let mut nar = Vec::new();
        client
            .fetch_nar(&peer_addr, HASH, &mut nar)
            .expect("nar from raw peer");
        assert_eq!(nar, body);

        let raw_narinfo = runtime.block_on(async {
            let connection = peer
                .connect(server_addr.clone(), NARINFO_ALPN)
                .await
                .expect("raw client narinfo");
            let (mut send, mut recv) = connection.open_bi().await.expect("open");
            send.write_all(HASH.as_bytes()).await.expect("write hash");
            send.finish().expect("finish");
            recv.read_to_end(NARINFO_RESPONSE_LIMIT)
                .await
                .expect("read narinfo")
        });
        assert_eq!(raw_narinfo, narinfo);
        let raw_missing = runtime.block_on(async {
            let connection = peer
                .connect(server_addr.clone(), NARINFO_ALPN)
                .await
                .expect("raw client miss");
            let (mut send, mut recv) = connection.open_bi().await.expect("open");
            send.write_all(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .await
                .expect("write");
            send.finish().expect("finish");
            recv.read_to_end(NARINFO_RESPONSE_LIMIT)
                .await
                .expect("read")
        });
        assert_eq!(raw_missing, NOT_FOUND);
        let raw_nar = runtime.block_on(async {
            let connection = peer
                .connect(server_addr.clone(), NAR_ALPN)
                .await
                .expect("raw client nar");
            let (mut send, mut recv) = connection.open_bi().await.expect("open");
            let url = std::str::from_utf8(&narinfo)
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("URL:"))
                .expect("url")
                .trim()
                .to_owned();
            send.write_all(url.as_bytes()).await.expect("write url");
            send.finish().expect("finish");
            let mut length = [0_u8; 8];
            recv.read_exact(&mut length).await.expect("length");
            let size = u64::from_be_bytes(length) as usize;
            let mut received = vec![0_u8; size];
            recv.read_exact(&mut received).await.expect("body");
            received
        });
        assert_eq!(raw_nar, body);
    }

    #[test]
    fn a_stalled_peer_is_backed_off_and_the_next_peer_answers() {
        let runtime = runtime();
        let attempts = Arc::new(AtomicUsize::new(0));
        let hang = runtime
            .block_on(bind_endpoint(SecretKey::generate(), true))
            .expect("hang peer");
        let hang_addr = hang.addr();
        let seen = Arc::clone(&attempts);
        runtime.spawn(async move {
            while let Some(incoming) = hang.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                seen.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok((_send, _recv)) = connection.accept_bi().await else {
                        return;
                    };
                    std::future::pending::<()>().await;
                });
            }
        });

        let (_root, share, narinfo) = offered_share(b"next");
        let good_state = tempfile::tempdir().expect("good state");
        let good = PeerEndpoint::start_local(
            &settings(good_state.path(), Duration::from_secs(2)),
            Some(share),
        )
        .expect("good peer");
        let good_addr = good.addr();
        let client_state = tempfile::tempdir().expect("client state");
        let stall = Duration::from_millis(300);
        let client =
            PeerEndpoint::start_local(&settings(client_state.path(), stall), None).expect("client");
        let started = Instant::now();
        let found = client
            .fetch_narinfo_from_peers(&[hang_addr.clone(), good_addr.clone()], HASH)
            .expect("lookup");
        assert_eq!(
            found.map(|(_peer, body)| body).as_deref(),
            Some(narinfo.as_slice())
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() >= stall);

        let started = Instant::now();
        let again = client
            .fetch_narinfo_from_peers(&[hang_addr, good_addr], HASH)
            .expect("second lookup");
        assert_eq!(
            again.map(|(_peer, body)| body).as_deref(),
            Some(narinfo.as_slice())
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < stall);
    }
}
