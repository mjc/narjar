//! Decide which local Nix store paths this daemon may offer to a peer.
//!
//! The index is off until a store root is configured. A refresh examines at
//! most [`MAX_SCANNED_PATHS`] paths, one at a time ([`SCAN_CONCURRENCY`]), and
//! keeps at most [`MAX_OFFERED_PATHS`] narinfo documents or
//! [`MAX_OFFERED_BYTES`] of those documents. It does not retain NAR bytes. The
//! default refresh interval is one hour. An upstream lookup failure, or a path
//! whose narinfo cannot be built, omits that path and leaves the rest of the
//! refresh intact.

use std::{
    collections::{BTreeMap, BinaryHeap},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::{
        RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use sqlite::{Connection, ConnectionThreadSafe, OpenFlags, State};

use crate::{
    cache::narinfo::{MAX_NARINFO_BYTES, NarInfoClaims, NarInfoMetadata, NixStorePath},
    cache::storage::StoreHash,
    http_client::idle_agent_allowing_status,
    http_url::HttpUrl,
    narinfo_signing::NixSigningKey,
    push::hash_store_nar,
};
use narjar::object::{NarHash, NarIdentity, NarRepresentation, NarSize};

/// Paths examined in one refresh. The scan keeps the lexicographically first
/// names and leaves the rest unoffered.
pub(crate) const MAX_SCANNED_PATHS: usize = 100_000;
/// Narinfo documents retained. Each document is at most [`MAX_NARINFO_BYTES`].
pub(crate) const MAX_OFFERED_PATHS: usize = 100_000;
/// Narinfo bytes retained by one refresh.
pub(crate) const MAX_OFFERED_BYTES: usize = 256 * 1024 * 1024;
/// Store paths hashed at once. Refresh is synchronous, so this stays one.
pub(crate) const SCAN_CONCURRENCY: usize = 1;
/// Time between refreshes when the caller does not ask for one.
pub(crate) const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub(crate) struct PeerShareSettings {
    pub(crate) store_root: PathBuf,
    pub(crate) upstream: HttpUrl,
    pub(crate) publish_all: bool,
    pub(crate) signing_key: Option<NixSigningKey>,
    pub(crate) state_dir: Option<PathBuf>,
    pub(crate) refresh_interval: Duration,
    pub(crate) request_timeout: Duration,
}

impl std::fmt::Debug for PeerShareSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerShareSettings")
            .field("store_root", &self.store_root)
            .field("upstream", &self.upstream)
            .field("publish_all", &self.publish_all)
            .field("has_signing_key", &self.signing_key.is_some())
            .field("state_dir", &self.state_dir)
            .field("refresh_interval", &self.refresh_interval)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

struct Offered(BTreeMap<StoreHash, Vec<u8>>);

pub(crate) struct ShareIndex {
    offered: RwLock<Offered>,
    settings: PeerShareSettings,
}

#[derive(Clone)]
struct LocalPath {
    store_path: NixStorePath,
    nar_hash: NarHash,
    nar_size: u64,
    references: Option<Vec<String>>,
}

trait PathSource {
    /// `None` means the scan stopped before finishing. The caller keeps the previous index.
    fn list(&self, stopping: &AtomicBool) -> Result<Option<Vec<LocalPath>>, String>;
}

trait UpstreamNarinfo {
    fn fetch(&self, hash: &StoreHash) -> Result<Option<Vec<u8>>, String>;
}

impl ShareIndex {
    pub(crate) fn new(settings: PeerShareSettings) -> Self {
        Self {
            offered: RwLock::new(Offered(BTreeMap::new())),
            settings,
        }
    }

    pub(crate) fn refresh_interval(&self) -> Duration {
        self.settings.refresh_interval
    }

    // Nothing in the daemon asks for a peer narinfo yet. The index still has to answer.
    #[allow(dead_code)]
    pub(crate) fn narinfo(&self, hash: &StoreHash) -> Option<Vec<u8>> {
        self.offered
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
            .get(hash)
            .cloned()
    }

    pub(crate) fn refresh(&self, stopping: &AtomicBool) -> Result<(), String> {
        let settings = &self.settings;
        let source = FilesystemSource {
            store_root: &settings.store_root,
            state_dir: settings.state_dir.as_deref(),
            publish_all: settings.publish_all,
        };
        let upstream = HttpUpstream {
            upstream: &settings.upstream,
            agent: idle_agent_allowing_status(settings.request_timeout),
        };
        match self.refresh_from(&source, &upstream, stopping, MAX_OFFERED_BYTES)? {
            RefreshOutcome::Stopped => Ok(()),
            RefreshOutcome::Complete(Some(warning)) => {
                eprintln!("narjar: {warning}");
                Ok(())
            }
            RefreshOutcome::Complete(None) => Ok(()),
        }
    }

    fn refresh_from(
        &self,
        source: &impl PathSource,
        upstream: &impl UpstreamNarinfo,
        stopping: &AtomicBool,
        offered_byte_limit: usize,
    ) -> Result<RefreshOutcome, String> {
        let settings = &self.settings;
        let Some(locals) = source.list(stopping)? else {
            return Ok(RefreshOutcome::Stopped);
        };
        let mut offered = BTreeMap::new();
        let mut offered_bytes = 0usize;
        let mut upstream_failure = None;
        let mut signing_failure = None;
        let mut limit_reached = false;
        for local in locals {
            if stopping.load(Ordering::Acquire) {
                return Ok(RefreshOutcome::Stopped);
            }
            if offered.len() >= MAX_OFFERED_PATHS {
                limit_reached = true;
                break;
            }
            let hash = *local.store_path.store();
            let fetched = match upstream.fetch(&hash) {
                Ok(bytes) => bytes,
                Err(error) => {
                    upstream_failure.get_or_insert(error);
                    continue;
                }
            };
            let narinfo = match offer_narinfo(&local, fetched.as_deref(), settings) {
                Ok(Some(narinfo)) => narinfo,
                Ok(None) => continue,
                Err(error) => {
                    signing_failure.get_or_insert(error);
                    continue;
                }
            };
            if offered_bytes.saturating_add(narinfo.len()) > offered_byte_limit {
                limit_reached = true;
                break;
            }
            offered_bytes += narinfo.len();
            offered.insert(hash, narinfo);
        }
        *self
            .offered
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Offered(offered);
        Ok(RefreshOutcome::Complete(refresh_warning(
            upstream_failure,
            signing_failure,
            limit_reached,
        )))
    }
}

fn refresh_warning(
    upstream_failure: Option<String>,
    signing_failure: Option<String>,
    limit_reached: bool,
) -> Option<String> {
    let mut warnings = Vec::new();
    if let Some(error) = upstream_failure {
        warnings.push(format!(
            "peer share upstream lookup failed; unmatched paths stay unoffered: {error}"
        ));
    }
    if let Some(error) = signing_failure {
        warnings.push(format!(
            "peer share left a path unoffered because its narinfo could not be built: {error}"
        ));
    }
    if limit_reached {
        warnings.push("peer share offer limit reached; later paths stay unoffered".to_owned());
    }
    (!warnings.is_empty()).then(|| warnings.join(" "))
}

#[derive(Debug)]
enum RefreshOutcome {
    Complete(Option<String>),
    Stopped,
}

/// Fail before the daemon reports ready when the configured store cannot be listed.
pub(crate) fn ensure_store_readable(store_root: &Path) -> Result<(), String> {
    fs::read_dir(store_root)
        .map_err(|error| format!("cannot read Nix store {}: {error}", store_root.display()))?;
    Ok(())
}

const _: () = assert!(SCAN_CONCURRENCY == 1);

fn offer_narinfo(
    local: &LocalPath,
    upstream: Option<&[u8]>,
    settings: &PeerShareSettings,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = upstream
        && upstream_matches(local, bytes)
    {
        return Ok(Some(bytes.to_vec()));
    }
    if !settings.publish_all {
        return Ok(None);
    }
    let Some(signing_key) = &settings.signing_key else {
        return Ok(None);
    };
    let Some(references) = &local.references else {
        return Ok(None);
    };
    signed_narinfo(local, references, signing_key).map(Some)
}

fn upstream_matches(local: &LocalPath, bytes: &[u8]) -> bool {
    NarInfoClaims::parse_external_logical_claims(local.store_path.store(), bytes).is_ok_and(
        |claims| {
            claims.store_path() == local.store_path.as_str()
                && claims.identity().hash() == local.nar_hash
        },
    )
}

fn signed_narinfo(
    local: &LocalPath,
    references: &[String],
    signing_key: &NixSigningKey,
) -> Result<Vec<u8>, String> {
    let identity = NarIdentity::new(local.nar_hash, NarSize::new(local.nar_size));
    let mut metadata = NarInfoMetadata::from_store_metadata(
        local.store_path.as_str().to_owned(),
        None,
        None,
        identity,
        references.to_vec(),
        Vec::new(),
    )
    .map_err(|_| "peer share narinfo claims are invalid".to_owned())?;
    metadata.add_signature(signing_key.sign_fingerprint(&metadata.claims().fingerprint()));
    metadata
        .serialize(NarRepresentation::Raw(identity))
        .map_err(|_| "peer share narinfo is too large".to_owned())
}

struct FilesystemSource<'a> {
    store_root: &'a Path,
    state_dir: Option<&'a Path>,
    publish_all: bool,
}

impl PathSource for FilesystemSource<'_> {
    fn list(&self, stopping: &AtomicBool) -> Result<Option<Vec<LocalPath>>, String> {
        self.list_limited(stopping, MAX_SCANNED_PATHS)
    }
}

impl FilesystemSource<'_> {
    fn list_limited(
        &self,
        stopping: &AtomicBool,
        limit: usize,
    ) -> Result<Option<Vec<LocalPath>>, String> {
        if stopping.load(Ordering::Acquire) {
            return Ok(None);
        }
        let references = self
            .publish_all
            .then(|| self.state_dir.and_then(ReferenceDatabase::open))
            .flatten();
        let entries = fs::read_dir(self.store_root)
            .map_err(|error| format!("reading {}: {error}", self.store_root.display()))?
            .map(|entry| {
                entry
                    .map_err(|error| format!("reading {}: {error}", self.store_root.display()))
                    .map(|entry| entry.file_name())
            });
        let Some(names) = bounded_directory_names(entries, limit, stopping)? else {
            return Ok(None);
        };
        let mut paths = Vec::new();
        for name in names {
            if stopping.load(Ordering::Acquire) {
                return Ok(None);
            }
            if let Some(path) = local_path(self.store_root, &name, references.as_ref())? {
                paths.push(path);
            }
        }
        Ok(Some(paths))
    }
}

/// Keeps at most `limit` names while the iterator is consumed. `None` means
/// shutdown was requested and the caller should keep the previous index.
fn bounded_directory_names(
    mut entries: impl Iterator<Item = Result<OsString, String>>,
    limit: usize,
    stopping: &AtomicBool,
) -> Result<Option<Vec<OsString>>, String> {
    let mut selected = BinaryHeap::new();
    loop {
        if stopping.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Some(entry) = entries.next() else {
            break;
        };
        let name = entry?;
        if selected.len() < limit {
            selected.push(name);
        } else if selected.peek().is_some_and(|largest| &name < largest) {
            selected.pop();
            selected.push(name);
        }
    }
    let mut names = Vec::from(selected);
    names.sort();
    Ok(Some(names))
}

fn local_path(
    store_root: &Path,
    name: &std::ffi::OsStr,
    references: Option<&ReferenceDatabase>,
) -> Result<Option<LocalPath>, String> {
    let Some(basename) = name.to_str() else {
        return Ok(None);
    };
    let Ok(store_path) = NixStorePath::from_basename(basename) else {
        return Ok(None);
    };
    let path = store_root.join(name);
    let (digest, nar_size) = match hash_store_nar(&path) {
        Ok(hashed) => hashed,
        Err(_) => return Ok(None),
    };
    Ok(Some(LocalPath {
        references: references.and_then(|database| database.references(store_path.as_str())),
        store_path,
        nar_hash: NarHash::from_digest(digest),
        nar_size,
    }))
}

struct ReferenceDatabase {
    connection: ConnectionThreadSafe,
}

impl ReferenceDatabase {
    fn open(state_dir: &Path) -> Option<Self> {
        let path = state_dir.join("db/db.sqlite");
        Connection::open_thread_safe_with_flags(&path, OpenFlags::new().with_read_only())
            .ok()
            .map(|connection| Self { connection })
    }

    fn references(&self, store_path: &str) -> Option<Vec<String>> {
        let mut identity = self
            .connection
            .prepare("SELECT id FROM ValidPaths WHERE path = ?")
            .ok()?;
        identity.bind((1, store_path)).ok()?;
        let id = match identity.next().ok()? {
            State::Row => identity.read::<i64, _>("id").ok()?,
            State::Done => return None,
        };
        let mut references = self
            .connection
            .prepare(
                "SELECT reference.path FROM Refs \
                 JOIN ValidPaths AS reference ON reference.id = Refs.reference \
                 WHERE Refs.referrer = ? ORDER BY reference.path",
            )
            .ok()?;
        references.bind((1, id)).ok()?;
        let mut paths = Vec::new();
        loop {
            match references.next().ok()? {
                State::Row => paths.push(references.read::<String, _>("path").ok()?),
                State::Done => return Some(paths),
            }
        }
    }
}

struct HttpUpstream<'a> {
    upstream: &'a HttpUrl,
    agent: ureq::Agent,
}

impl UpstreamNarinfo for HttpUpstream<'_> {
    fn fetch(&self, hash: &StoreHash) -> Result<Option<Vec<u8>>, String> {
        let url = format!(
            "{}/{}.narinfo",
            self.upstream.as_str().trim_end_matches('/'),
            hash.as_str()
        );
        let response = self
            .agent
            .get(&url)
            .call()
            .map_err(|error| format!("GET {url} failed: {error}"))?;
        match response.status().as_u16() {
            200 => read_narinfo(response, &url).map(Some),
            404 => Ok(None),
            status => Err(format!("GET {url} returned {status}")),
        }
    }
}

fn read_narinfo(response: ureq::http::Response<ureq::Body>, url: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_NARINFO_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading GET {url} failed: {error}"))?;
    if bytes.len() as u64 > MAX_NARINFO_BYTES {
        return Err(format!(
            "GET {url} narinfo exceeds {MAX_NARINFO_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn refresh(
        index: &ShareIndex,
        source: &impl PathSource,
        upstream: &impl UpstreamNarinfo,
    ) -> RefreshOutcome {
        index
            .refresh_from(source, upstream, &AtomicBool::new(false), MAX_OFFERED_BYTES)
            .expect("peer share refresh")
    }

    const HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    const OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Listed(Vec<LocalPath>);

    impl PathSource for Listed {
        fn list(&self, _: &AtomicBool) -> Result<Option<Vec<LocalPath>>, String> {
            Ok(Some(self.0.clone()))
        }
    }

    struct MapUpstream(BTreeMap<String, Vec<u8>>);

    impl UpstreamNarinfo for MapUpstream {
        fn fetch(&self, hash: &StoreHash) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.get(hash.as_str()).cloned())
        }
    }

    fn settings(publish_all: bool, signing_key: Option<NixSigningKey>) -> PeerShareSettings {
        PeerShareSettings {
            store_root: PathBuf::from("/nix/store"),
            upstream: "https://cache.nixos.org".parse().unwrap(),
            publish_all,
            signing_key,
            state_dir: None,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            request_timeout: Duration::from_secs(1),
        }
    }

    fn local(
        hash: &str,
        nar_hash: NarHash,
        nar_size: u64,
        references: Option<Vec<String>>,
    ) -> LocalPath {
        LocalPath {
            store_path: NixStorePath::parse(format!("/nix/store/{hash}-package")).unwrap(),
            nar_hash,
            nar_size,
            references,
        }
    }

    fn signing_key() -> NixSigningKey {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut secret = [0; 64];
        secret[..32].copy_from_slice(&key.to_bytes());
        secret[32..].copy_from_slice(key.verifying_key().as_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, format!("test:{}", BASE64.encode(&secret))).unwrap();
        NixSigningKey::read(&path).unwrap()
    }

    fn upstream_narinfo(path: &LocalPath) -> Vec<u8> {
        let identity = NarIdentity::new(path.nar_hash, NarSize::new(path.nar_size));
        NarInfoMetadata::from_store_metadata(
            path.store_path.as_str().to_owned(),
            None,
            None,
            identity,
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
        .serialize(NarRepresentation::Raw(identity))
        .unwrap()
    }

    #[test]
    fn a_matching_upstream_narinfo_is_offered_unchanged() {
        let path = local(HASH, NarHash::from_digest([1; 32]), 32, None);
        let narinfo = upstream_narinfo(&path);
        let index = ShareIndex::new(settings(false, None));
        let mut upstream = BTreeMap::new();
        upstream.insert(HASH.to_owned(), narinfo.clone());
        refresh(&index, &Listed(vec![path]), &MapUpstream(upstream));
        assert_eq!(
            index.narinfo(&StoreHash::parse(HASH).unwrap()).as_deref(),
            Some(narinfo.as_slice())
        );
    }

    #[test]
    fn a_path_missing_upstream_is_not_offered() {
        let path = local(OTHER, NarHash::from_digest([2; 32]), 8, Some(Vec::new()));
        let index = ShareIndex::new(settings(false, Some(signing_key())));
        refresh(&index, &Listed(vec![path]), &MapUpstream(BTreeMap::new()));
        assert!(index.narinfo(&StoreHash::parse(OTHER).unwrap()).is_none());
    }

    #[test]
    fn publish_all_signs_a_path_the_upstream_does_not_have() {
        let path = local(OTHER, NarHash::from_digest([3; 32]), 8, Some(Vec::new()));
        let index = ShareIndex::new(settings(true, Some(signing_key())));
        refresh(&index, &Listed(vec![path]), &MapUpstream(BTreeMap::new()));
        let narinfo = index.narinfo(&StoreHash::parse(OTHER).unwrap()).unwrap();
        let text = String::from_utf8(narinfo).unwrap();
        assert!(text.contains("Sig: test:"));
        assert!(text.contains(&format!("/nix/store/{OTHER}-package")));
    }

    #[test]
    fn publish_all_without_a_signing_key_omits_the_path() {
        let path = local(OTHER, NarHash::from_digest([4; 32]), 8, Some(Vec::new()));
        let index = ShareIndex::new(settings(true, None));
        refresh(&index, &Listed(vec![path]), &MapUpstream(BTreeMap::new()));
        assert!(index.narinfo(&StoreHash::parse(OTHER).unwrap()).is_none());
    }

    #[test]
    fn publish_all_without_known_references_omits_the_path() {
        let path = local(OTHER, NarHash::from_digest([5; 32]), 8, None);
        let index = ShareIndex::new(settings(true, Some(signing_key())));
        refresh(&index, &Listed(vec![path]), &MapUpstream(BTreeMap::new()));
        assert!(index.narinfo(&StoreHash::parse(OTHER).unwrap()).is_none());
    }

    #[test]
    fn an_upstream_lookup_error_omits_the_path() {
        let path = local(OTHER, NarHash::from_digest([6; 32]), 8, Some(Vec::new()));
        let index = ShareIndex::new(settings(true, Some(signing_key())));
        let outcome = refresh(&index, &Listed(vec![path]), &FailingUpstream);
        assert!(index.narinfo(&StoreHash::parse(OTHER).unwrap()).is_none());
        match outcome {
            RefreshOutcome::Complete(Some(warning)) => {
                assert!(warning.contains("upstream lookup failed"));
            }
            other => panic!("expected an upstream warning, got {other:?}"),
        }
    }

    #[test]
    fn publish_all_signs_references_from_the_nix_database() {
        let root = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let basename = format!("{OTHER}-package");
        std::fs::write(root.path().join(&basename), b"world").unwrap();
        let db_dir = state.path().join("db");
        std::fs::create_dir(&db_dir).unwrap();
        let database = sqlite::Connection::open(db_dir.join("db.sqlite")).unwrap();
        database
            .execute("CREATE TABLE ValidPaths (id INTEGER PRIMARY KEY, path TEXT)")
            .unwrap();
        database
            .execute("CREATE TABLE Refs (referrer INTEGER, reference INTEGER)")
            .unwrap();
        let store_path = format!("/nix/store/{basename}");
        let reference = format!("/nix/store/{HASH}-dep");
        database
            .execute(format!(
                "INSERT INTO ValidPaths (id, path) VALUES (1, '{store_path}'), (2, '{reference}')"
            ))
            .unwrap();
        database
            .execute("INSERT INTO Refs (referrer, reference) VALUES (1, 2)")
            .unwrap();
        let mut configured = settings(true, Some(signing_key()));
        configured.store_root = root.path().to_path_buf();
        configured.state_dir = Some(state.path().to_path_buf());
        let index = ShareIndex::new(configured);
        let source = FilesystemSource {
            store_root: root.path(),
            state_dir: Some(state.path()),
            publish_all: true,
        };
        refresh(&index, &source, &MapUpstream(BTreeMap::new()));
        let text =
            String::from_utf8(index.narinfo(&StoreHash::parse(OTHER).unwrap()).unwrap()).unwrap();
        assert!(text.contains(&format!("References: {HASH}-dep\n")));
        assert!(text.contains("Sig: test:"));
    }

    #[test]
    fn a_store_file_whose_nar_matches_upstream_is_offered() {
        let root = tempfile::tempdir().unwrap();
        let basename = format!("{HASH}-package");
        std::fs::write(root.path().join(&basename), b"hello").unwrap();
        let (digest, nar_size) = hash_store_nar(&root.path().join(&basename)).unwrap();
        let path = local(HASH, NarHash::from_digest(digest), nar_size, None);
        let narinfo = upstream_narinfo(&path);
        let mut settings = settings(false, None);
        settings.store_root = root.path().to_path_buf();
        let reads = AtomicUsize::new(0);
        let index = ShareIndex::new(settings);
        let source = CountingSource {
            inner: FilesystemSource {
                store_root: root.path(),
                state_dir: None,
                publish_all: false,
            },
            reads: &reads,
        };
        let mut upstream = BTreeMap::new();
        upstream.insert(HASH.to_owned(), narinfo.clone());
        refresh(&index, &source, &MapUpstream(upstream));
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert_eq!(
            index.narinfo(&StoreHash::parse(HASH).unwrap()).as_deref(),
            Some(narinfo.as_slice())
        );
    }

    struct CountingSource<'a> {
        inner: FilesystemSource<'a>,
        reads: &'a AtomicUsize,
    }

    impl PathSource for CountingSource<'_> {
        fn list(&self, stopping: &AtomicBool) -> Result<Option<Vec<LocalPath>>, String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.list(stopping)
        }
    }

    struct FailingUpstream;

    impl UpstreamNarinfo for FailingUpstream {
        fn fetch(&self, hash: &StoreHash) -> Result<Option<Vec<u8>>, String> {
            Err(format!("GET {} failed", hash.as_str()))
        }
    }

    #[test]
    fn a_matching_upstream_narinfo_with_another_url_layout_is_offered_unchanged() {
        let nar_hash =
            NarHash::parse("0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl").unwrap();
        let path = local(HASH, nar_hash, 32, Some(Vec::new()));
        let narinfo = format!(
            "StorePath: {}\n\
             URL: https://cache.example/objects/package.nar.xz\n\
             Compression: xz\n\
             FileHash: sha256:1111111111111111111111111111111111111111111111111111\n\
             FileSize: 12\n\
             NarHash: sha256:0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl\n\
             NarSize: 32\n\
             Sig: cache.example:AAAA\n",
            path.store_path.as_str(),
        )
        .into_bytes();
        let index = ShareIndex::new(settings(true, Some(signing_key())));
        let mut upstream = BTreeMap::new();
        upstream.insert(HASH.to_owned(), narinfo.clone());
        refresh(&index, &Listed(vec![path]), &MapUpstream(upstream));
        assert_eq!(
            index.narinfo(&StoreHash::parse(HASH).unwrap()).as_deref(),
            Some(narinfo.as_slice())
        );
    }

    #[test]
    fn publish_all_signs_when_the_upstream_returns_not_found() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let upstream_url: HttpUrl = format!("http://{address}").parse().unwrap();
        let mut configured = settings(true, Some(signing_key()));
        configured.upstream = upstream_url.clone();
        configured.request_timeout = Duration::from_secs(5);
        let index = ShareIndex::new(configured);
        let path = local(OTHER, NarHash::from_digest([8; 32]), 8, Some(Vec::new()));
        let outcome = refresh(
            &index,
            &Listed(vec![path]),
            &HttpUpstream {
                upstream: &upstream_url,
                agent: idle_agent_allowing_status(Duration::from_secs(5)),
            },
        );
        server.join().unwrap();
        assert!(
            matches!(outcome, RefreshOutcome::Complete(None)),
            "{outcome:?}"
        );
        let text =
            String::from_utf8(index.narinfo(&StoreHash::parse(OTHER).unwrap()).unwrap()).unwrap();
        assert!(text.contains("Sig: test:"));
        assert!(text.contains(&format!("/nix/store/{OTHER}-package")));
    }

    #[test]
    fn a_directory_scan_keeps_the_lexicographically_first_names() {
        let names = ["m", "a", "z", "b", "c"]
            .into_iter()
            .map(|name| Ok(OsString::from(name)));
        let selected = bounded_directory_names(names, 2, &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        let selected: Vec<_> = selected
            .iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        assert_eq!(selected, ["a", "b"]);
    }

    #[test]
    fn a_directory_scan_stops_before_reading_every_name() {
        let stopping = AtomicBool::new(false);
        let mut reads = 0usize;
        let names = ["m", "a", "z", "b", "c"].into_iter().map(|name| {
            reads += 1;
            if reads == 3 {
                stopping.store(true, Ordering::Release);
            }
            Ok(OsString::from(name))
        });
        let selected = bounded_directory_names(names, 2, &stopping).unwrap();
        assert!(selected.is_none());
        assert_eq!(reads, 3);
    }

    #[test]
    fn a_store_scan_hashes_only_the_first_paths_within_the_limit() {
        let root = tempfile::tempdir().unwrap();
        let kept = [format!("{HASH}-a"), format!("{OTHER}-b")];
        let skipped = [
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-c".to_owned(),
            "cccccccccccccccccccccccccccccccc-d".to_owned(),
        ];
        for name in kept.iter().chain(skipped.iter()) {
            std::fs::write(root.path().join(name), b"x").unwrap();
        }
        let source = FilesystemSource {
            store_root: root.path(),
            state_dir: None,
            publish_all: false,
        };
        let paths = source
            .list_limited(&AtomicBool::new(false), 2)
            .unwrap()
            .unwrap();
        let mut offered: Vec<_> = paths
            .into_iter()
            .map(|path| path.store_path.as_str().to_owned())
            .collect();
        offered.sort();
        assert_eq!(
            offered,
            vec![
                format!("/nix/store/{HASH}-a"),
                format!("/nix/store/{OTHER}-b"),
            ]
        );
    }

    #[test]
    fn an_offer_stops_before_the_byte_limit_and_keeps_earlier_paths() {
        let first = local(HASH, NarHash::from_digest([1; 32]), 32, None);
        let second = local(OTHER, NarHash::from_digest([2; 32]), 32, None);
        let first_narinfo = upstream_narinfo(&first);
        let second_narinfo = upstream_narinfo(&second);
        let index = ShareIndex::new(settings(false, None));
        let mut upstream = BTreeMap::new();
        upstream.insert(HASH.to_owned(), first_narinfo.clone());
        upstream.insert(OTHER.to_owned(), second_narinfo);
        let outcome = index
            .refresh_from(
                &Listed(vec![first, second]),
                &MapUpstream(upstream),
                &AtomicBool::new(false),
                first_narinfo.len(),
            )
            .expect("peer share refresh");
        assert_eq!(
            index.narinfo(&StoreHash::parse(HASH).unwrap()).as_deref(),
            Some(first_narinfo.as_slice())
        );
        assert!(index.narinfo(&StoreHash::parse(OTHER).unwrap()).is_none());
        match outcome {
            RefreshOutcome::Complete(Some(warning)) => {
                assert!(warning.contains("offer limit reached"));
            }
            other => panic!("expected the offer limit warning, got {other:?}"),
        }
    }

    #[test]
    fn a_path_whose_narinfo_cannot_be_built_does_not_abort_the_refresh() {
        let invalid = local(
            OTHER,
            NarHash::from_digest([3; 32]),
            8,
            Some(vec!["not-a-store-path".to_owned()]),
        );
        let valid = local(HASH, NarHash::from_digest([4; 32]), 8, Some(Vec::new()));
        let index = ShareIndex::new(settings(true, Some(signing_key())));
        let outcome = refresh(
            &index,
            &Listed(vec![invalid, valid]),
            &MapUpstream(BTreeMap::new()),
        );
        assert!(index.narinfo(&StoreHash::parse(OTHER).unwrap()).is_none());
        let text =
            String::from_utf8(index.narinfo(&StoreHash::parse(HASH).unwrap()).unwrap()).unwrap();
        assert!(text.contains("Sig: test:"));
        match outcome {
            RefreshOutcome::Complete(Some(warning)) => {
                assert!(warning.contains("could not be built"));
                assert!(warning.contains("claims are invalid"));
            }
            other => panic!("expected a signing warning, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_store_root_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let error = ensure_store_readable(&missing).unwrap_err();
        assert!(error.contains("cannot read Nix store"));
        assert!(error.contains("missing"));
        ensure_store_readable(root.path()).unwrap();
    }
}
