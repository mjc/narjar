use super::*;

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Barrier, Condvar, atomic::AtomicBool},
    thread::{self, JoinHandle},
};

use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use narjar::nar_encode::{Encoder, Event};
use tempfile::TempDir;

use crate::cache::{
    nar_compression::encode_and_measure_nar,
    narinfo::NarInfoMetadata,
    object::{CompressionCodec, EncodedIdentity, FileHash, NarHash, NarIdentity, NarSize},
    storage::{CacheCreation, Directory, SupportedStorageBackend},
};

const STORE: &str = "00000000000000000000000000000000";
const ALIAS: &str = "11111111111111111111111111111111";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture {
    raw: Vec<u8>,
    compressed: Vec<u8>,
    identity: NarIdentity,
    encoded: EncodedIdentity,
}

impl Fixture {
    fn new() -> Self {
        let mut encoder = Encoder::new(Vec::new()).unwrap();
        encoder.push(Event::BeginDirectory).unwrap();
        encoder.push(Event::EndDirectory).unwrap();
        let (raw, summary) = encoder.finish().unwrap();
        let identity = NarIdentity::new(
            NarHash::from_digest(summary.raw_sha256),
            NarSize::new(summary.raw_size),
        );
        let mut compressed = Vec::new();
        let encoded = encode_and_measure_nar(CompressionCodec::Zstd, &mut compressed, |writer| {
            writer.write_all(&raw)
        })
        .unwrap();
        Self {
            raw,
            compressed,
            identity,
            encoded,
        }
    }

    fn metadata(&self, store: &str, payload: NarRepresentation, signer: &SigningKey) -> Vec<u8> {
        let mut metadata = NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{store}-fixture"),
            None,
            None,
            payload.identity(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let signature = signer.sign(metadata.claims().fingerprint().as_bytes());
        metadata.add_signature(format!("fixture:{}", BASE64.encode(&signature.to_bytes())));
        metadata.serialize(payload).unwrap()
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn trusted_keys() -> Arc<TrustedPublicKeys> {
    Arc::new(
        TrustedPublicKeys::parse(&format!(
            "fixture:{}",
            BASE64.encode(signing_key().verifying_key().as_bytes())
        ))
        .unwrap(),
    )
}

fn settings(upstream: HttpUrl) -> EdgeSettings {
    EdgeSettings {
        upstream,
        lease_seconds: NonZeroU64::new(60).unwrap(),
        max_fills: NonZeroUsize::new(8).unwrap(),
        request_workers: NonZeroUsize::new(16).unwrap(),
        max_in_flight: NonZeroUsize::new(64).unwrap(),
        timeout: TEST_TIMEOUT,
        fill_timeout: TEST_TIMEOUT,
        negative_ttl: Duration::from_secs(1),
    }
}

fn storage() -> (TempDir, Storage) {
    let directory = tempfile::tempdir().unwrap();
    let mut storage = CacheCreation::prepare(
        &Directory::open(directory.path()).unwrap(),
        SupportedStorageBackend::FLAT,
    )
    .unwrap()
    .create_or_complete()
    .unwrap();
    storage
        .configure_advertisement_leases(NonZeroU64::new(60).unwrap(), 0)
        .unwrap();
    (directory, storage)
}

fn source(upstream: &Upstream) -> ReadThroughSource {
    ReadThroughSource::new(
        settings(upstream.url()),
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap()
}

struct Upstream {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Upstream {
    fn new(handler: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let stopping = stopping.clone();
            let requests = requests.clone();
            let handler = Arc::new(handler);
            thread::spawn(move || {
                let mut workers = Vec::new();
                for accepted in listener.incoming() {
                    let mut stream = accepted.unwrap();
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let handler = handler.clone();
                    let requests = requests.clone();
                    workers.push(thread::spawn(move || {
                        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
                        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
                        let mut request = BufReader::new(&mut stream);
                        let mut line = String::new();
                        request.read_line(&mut line).unwrap();
                        let route = line.split_ascii_whitespace().nth(1).unwrap().to_owned();
                        loop {
                            let mut header = String::new();
                            if request.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                                break;
                            }
                        }
                        requests.lock().unwrap().push(route.clone());
                        handler(&route, &mut stream);
                    }));
                }
                workers
                    .into_iter()
                    .for_each(|worker| worker.join().unwrap());
            })
        };
        Self {
            address,
            stopping,
            requests,
            thread: Some(thread),
        }
    }

    fn url(&self) -> HttpUrl {
        format!("http://{}/cache", self.address).parse().unwrap()
    }

    fn count(&self, suffix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|route| route.ends_with(suffix))
            .count()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, TEST_TIMEOUT);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn reply(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|()| stream.write_all(body));
}

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let (open, _) = self
            .changed
            .wait_timeout_while(self.open.lock().unwrap(), TEST_TIMEOUT, |open| !*open)
            .unwrap();
        assert!(*open, "test did not release the upstream gate");
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

fn wait_for(condition: impl Fn() -> bool) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !condition() {
        assert!(Instant::now() < deadline, "expected overlap did not occur");
        thread::yield_now();
    }
}

#[test]
fn empty_trust_is_rejected_before_any_fill() {
    let result = ReadThroughSource::new(
        EdgeSettings {
            upstream: "http://127.0.0.1:1".parse().unwrap(),
            lease_seconds: NonZeroU64::new(60).unwrap(),
            max_fills: NonZeroUsize::new(1).unwrap(),
            request_workers: NonZeroUsize::new(2).unwrap(),
            max_in_flight: NonZeroUsize::new(64).unwrap(),
            timeout: Duration::from_secs(1),
            fill_timeout: TEST_TIMEOUT,
            negative_ttl: Duration::from_secs(1),
        },
        Arc::new(TrustedPublicKeys::default()),
        NarUploadPolicy::new(1024, 0),
    );
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn offline_repair_rejects_compressed_publications_in_a_raw_only_edge() {
    let fixture = Fixture::new();
    let (directory, storage) = storage();
    storage
        .publish_nar(
            crate::cache::object::NarFileName::raw(fixture.identity.hash()),
            fixture.raw.as_slice(),
            fixture.raw.len() as u64,
            NarUploadPolicy::new(1024 * 1024, 0),
        )
        .unwrap();
    let compressed = fixture.metadata(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
    );
    let store = StoreHash::parse(STORE).unwrap();
    fs::write(
        directory.path().join(format!("{STORE}.narinfo")),
        &compressed,
    )
    .unwrap();
    let source = ReadThroughSource::new(
        settings("http://127.0.0.1:1".parse().unwrap()),
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(EdgeFailure::Invalid)
    );
    assert!(matches!(
        storage.advertisement_evidence(store).unwrap(),
        AdvertisementEvidence::Missing
    ));
    assert_eq!(
        fs::read(directory.path().join(format!("{STORE}.narinfo"))).unwrap(),
        compressed,
        "raw-only mode must not overwrite immutable metadata"
    );
}

#[test]
fn recorded_leases_do_not_make_compressed_metadata_a_raw_edge_advertisement() {
    use crate::cache::object::{NarFileName, WireEncoding};
    let fixture = Fixture::new();
    let (_directory, storage) = storage();
    let policy = NarUploadPolicy::new(1024 * 1024, 0);
    storage
        .publish_nar(
            NarFileName::raw(fixture.identity.hash()),
            fixture.raw.as_slice(),
            fixture.raw.len() as u64,
            policy,
        )
        .unwrap();
    let store = StoreHash::parse(STORE).unwrap();
    let metadata = trusted_keys()
        .validate(
            &store,
            fixture.metadata(
                STORE,
                NarRepresentation::Raw(fixture.identity),
                &signing_key(),
            ),
        )
        .unwrap();
    storage
        .bind_narinfo(
            metadata,
            WireEncoding::Compressed(CompressionCodec::Zstd),
            policy,
        )
        .unwrap()
        .publish()
        .unwrap();
    let source = ReadThroughSource::new(
        settings("http://127.0.0.1:1".parse().unwrap()),
        trusted_keys(),
        policy,
    )
    .unwrap();
    assert!(matches!(
        storage.advertisement_evidence(store).unwrap(),
        AdvertisementEvidence::Recorded
    ));
    assert_eq!(
        source.advertise(&storage, &store).err(),
        Some(EdgeFailure::Invalid)
    );
}

#[test]
fn overlapping_store_requests_make_one_upstream_generation_and_local_hits_stay_offline() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let gate = Arc::new(Gate::default());
    let upstream = {
        let gate = gate.clone();
        let raw = fixture.raw.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                gate.wait();
                reply(stream, 200, &metadata);
            } else {
                reply(stream, 200, &raw);
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    let start = Barrier::new(9);
    thread::scope(|scope| {
        let calls = (0..8)
            .map(|_| {
                let (source, storage, start) = (&source, &storage, &start);
                scope.spawn(move || {
                    start.wait();
                    source.ensure_local(storage, &store)
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        wait_for(|| source.counters.followers.load(Ordering::Relaxed) == 7);
        assert!(storage.open_narinfo(&store).unwrap().is_none());
        gate.release();
        calls
            .into_iter()
            .for_each(|call| assert_eq!(call.join().unwrap(), EdgeLookup::Ready));
    });
    assert_eq!(upstream.count(".narinfo"), 1);
    assert_eq!(upstream.count(".nar"), 1);
    drop(upstream);
    // Even a cached upstream failure cannot hide a durable local hit.
    source.state.lock().unwrap().remember(
        Key::Store(store),
        EdgeFailure::Transient,
        Instant::now(),
        Duration::from_secs(1),
    );
    assert_eq!(source.ensure_local(&storage, &store), EdgeLookup::Ready);
    let mut bytes = Vec::new();
    storage
        .open_nar(crate::cache::object::NarFileName::raw(
            fixture.identity.hash(),
        ))
        .unwrap()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, fixture.raw);
}

#[test]
fn aliases_with_different_encodings_share_one_logical_payload_fill() {
    let fixture = Fixture::new();
    let raw_metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let compressed_metadata = fixture.metadata(
        ALIAS,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
    );
    let metadata_overlap = Arc::new(Barrier::new(2));
    let gate = Arc::new(Gate::default());
    let upstream = {
        let (metadata_overlap, gate) = (metadata_overlap.clone(), gate.clone());
        let (raw, compressed) = (fixture.raw.clone(), fixture.compressed.clone());
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                metadata_overlap.wait();
                let metadata = if route.contains(STORE) {
                    &raw_metadata
                } else {
                    &compressed_metadata
                };
                reply(stream, 200, metadata);
            } else {
                gate.wait();
                reply(
                    stream,
                    200,
                    if route.ends_with(".zst") {
                        &compressed
                    } else {
                        &raw
                    },
                );
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    thread::scope(|scope| {
        let calls = [STORE, ALIAS]
            .into_iter()
            .map(|hash| {
                let (source, storage) = (&source, &storage);
                scope.spawn(move || source.ensure_local(storage, &StoreHash::parse(hash).unwrap()))
            })
            .collect::<Vec<_>>();
        wait_for(|| source.counters.followers.load(Ordering::Relaxed) == 1);
        gate.release();
        calls
            .into_iter()
            .for_each(|call| assert_eq!(call.join().unwrap(), EdgeLookup::Ready));
    });
    let requests = upstream.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|route| route.ends_with(".narinfo"))
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|route| route.contains("/nar/"))
            .count(),
        1
    );
    drop(requests);
    [STORE, ALIAS].into_iter().for_each(|hash| {
        let store = StoreHash::parse(hash).unwrap();
        let advertised = storage.read_advertised_narinfo(&store).unwrap().unwrap();
        let verified = trusted_keys().validate(&store, advertised.bytes).unwrap();
        assert_eq!(verified.payload(), NarRepresentation::Raw(fixture.identity));
    });
}

#[test]
fn active_limit_rejects_unrelated_keys_while_same_store_followers_wait() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let gate = Arc::new(Gate::default());
    let upstream = {
        let gate = gate.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                gate.wait();
                reply(stream, 200, &metadata);
            } else {
                reply(stream, 200, &fixture.raw);
            }
        })
    };
    let mut settings = settings(upstream.url());
    settings.max_fills = NonZeroUsize::new(1).unwrap();
    settings.request_workers = NonZeroUsize::new(3).unwrap();
    let source = ReadThroughSource::new(
        settings,
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    thread::scope(|scope| {
        let source = &source;
        let storage = &storage;
        let leader = scope.spawn(move || source.ensure_local(storage, &store));
        wait_for(|| upstream.count(".narinfo") == 1);
        let follower = scope.spawn(move || source.ensure_local(storage, &store));
        wait_for(|| source.counters.followers.load(Ordering::Relaxed) == 1);
        assert_eq!(source.blocked_requests.load(Ordering::Relaxed), 2);
        assert_eq!(
            source.ensure_local(storage, &store),
            EdgeLookup::Miss(EdgeFailure::Capacity),
            "a third blocked request must leave the last HTTP worker available"
        );
        assert_eq!(
            source.ensure_local(storage, &StoreHash::parse(ALIAS).unwrap()),
            EdgeLookup::Miss(EdgeFailure::Capacity)
        );
        assert_eq!(upstream.count(".narinfo"), 1);
        gate.release();
        assert_eq!(leader.join().unwrap(), EdgeLookup::Ready);
        assert_eq!(follower.join().unwrap(), EdgeLookup::Ready);
    });
    assert_eq!(source.blocked_requests.load(Ordering::Relaxed), 0);
}

#[test]
fn blocked_requests_leave_both_worker_and_connection_admission_capacity() {
    let mut settings = settings("http://127.0.0.1:1".parse().unwrap());
    settings.request_workers = NonZeroUsize::new(8).unwrap();
    settings.max_in_flight = NonZeroUsize::new(2).unwrap();
    let source =
        ReadThroughSource::new(settings, trusted_keys(), NarUploadPolicy::new(1024, 0)).unwrap();
    assert_eq!(source.max_blocked_requests, 1);
}

#[test]
fn a_failed_compressed_alias_does_not_poison_a_valid_raw_alias() {
    let fixture = Fixture::new();
    let compressed_metadata = fixture.metadata(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
    );
    let raw_metadata = fixture.metadata(
        ALIAS,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let gate = Arc::new(Gate::default());
    let upstream = {
        let gate = gate.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                reply(
                    stream,
                    200,
                    if route.contains(STORE) {
                        &compressed_metadata
                    } else {
                        &raw_metadata
                    },
                );
            } else if route.ends_with(".zst") {
                gate.wait();
                let mut corrupt = fixture.compressed.clone();
                corrupt[0] ^= 1;
                reply(stream, 200, &corrupt);
            } else {
                reply(stream, 200, &fixture.raw);
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    thread::scope(|scope| {
        let leader =
            scope.spawn(|| source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()));
        wait_for(|| upstream.count(".zst") == 1);
        let follower =
            scope.spawn(|| source.ensure_local(&storage, &StoreHash::parse(ALIAS).unwrap()));
        wait_for(|| source.counters.followers.load(Ordering::Relaxed) == 1);
        gate.release();
        assert_eq!(
            leader.join().unwrap(),
            EdgeLookup::Miss(EdgeFailure::Invalid)
        );
        assert_eq!(follower.join().unwrap(), EdgeLookup::Ready);
    });
    assert_eq!(upstream.count(".zst"), 1);
    assert_eq!(upstream.count(".nar"), 1);
}

#[test]
fn progressing_payload_can_outlive_the_network_idle_timeout() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                fixture.raw.len()
            )
            .unwrap();
            for chunk in fixture.raw.chunks(fixture.raw.len().div_ceil(8)) {
                if stream.write_all(chunk).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(400));
            }
        }
    });
    let mut options = settings(upstream.url());
    options.timeout = Duration::from_secs(2);
    options.fill_timeout = Duration::from_secs(20);
    let source = ReadThroughSource::new(
        options,
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    let (_directory, storage) = storage();
    let started = Instant::now();
    assert_eq!(
        source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()),
        EdgeLookup::Ready
    );
    assert!(started.elapsed() > Duration::from_secs(2));
}

#[test]
fn transient_negative_expires_and_allows_a_healthy_fill() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let healthy = Arc::new(AtomicBool::new(false));
    let upstream = {
        let healthy = healthy.clone();
        Upstream::new(move |route, stream| {
            if !healthy.load(Ordering::Acquire) {
                reply(stream, 503, b"");
            } else {
                reply(
                    stream,
                    200,
                    if route.ends_with(".narinfo") {
                        &metadata
                    } else {
                        &fixture.raw
                    },
                );
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(EdgeFailure::Transient)
    );
    healthy.store(true, Ordering::Release);
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(EdgeFailure::Transient)
    );
    assert_eq!(upstream.count(".narinfo"), 1);
    // Advance maintenance time rather than sleeping through the negative TTL.
    source
        .state
        .lock()
        .unwrap()
        .prune(Instant::now() + Duration::from_secs(2));
    assert_eq!(source.ensure_local(&storage, &store), EdgeLookup::Ready);
    assert_eq!(upstream.count(".narinfo"), 2);
    assert_eq!(upstream.count(".nar"), 1);
}

#[derive(Clone, Copy, Debug)]
enum FailureCase {
    InvalidSignature,
    WrongEncodedHash,
    WrongDecodedHash,
    WrongDecodedSize,
    TruncatedBody,
    TrailingCompressedBytes,
    OversizedMetadata,
    OversizedStreamingMetadata,
    OversizedEncoded,
    OversizedDecoded,
    Redirect,
    ArbitraryPayloadUrl,
    RateLimited,
    Unavailable,
    NotFound,
    Timeout,
    MidstreamDrop,
}

impl FailureCase {
    fn expected(self) -> EdgeFailure {
        match self {
            Self::InvalidSignature
            | Self::WrongEncodedHash
            | Self::WrongDecodedHash
            | Self::WrongDecodedSize
            | Self::TruncatedBody
            | Self::TrailingCompressedBytes
            | Self::OversizedMetadata
            | Self::OversizedStreamingMetadata
            | Self::OversizedEncoded
            | Self::OversizedDecoded
            | Self::Redirect
            | Self::ArbitraryPayloadUrl => EdgeFailure::Invalid,
            Self::RateLimited | Self::Unavailable | Self::Timeout | Self::MidstreamDrop => {
                EdgeFailure::Transient
            }
            Self::NotFound => EdgeFailure::Authoritative404,
        }
    }

    fn payload_requests(self) -> usize {
        match self {
            Self::WrongEncodedHash
            | Self::WrongDecodedHash
            | Self::WrongDecodedSize
            | Self::TruncatedBody
            | Self::TrailingCompressedBytes
            | Self::MidstreamDrop => 1,
            Self::InvalidSignature
            | Self::OversizedMetadata
            | Self::OversizedStreamingMetadata
            | Self::OversizedEncoded
            | Self::OversizedDecoded
            | Self::Redirect
            | Self::ArbitraryPayloadUrl
            | Self::RateLimited
            | Self::Unavailable
            | Self::NotFound
            | Self::Timeout => 0,
        }
    }
}

#[test]
fn upstream_failure_matrix_never_publishes_metadata() {
    [
        FailureCase::InvalidSignature,
        FailureCase::WrongEncodedHash,
        FailureCase::WrongDecodedHash,
        FailureCase::WrongDecodedSize,
        FailureCase::TruncatedBody,
        FailureCase::TrailingCompressedBytes,
        FailureCase::OversizedMetadata,
        FailureCase::OversizedStreamingMetadata,
        FailureCase::OversizedEncoded,
        FailureCase::OversizedDecoded,
        FailureCase::Redirect,
        FailureCase::ArbitraryPayloadUrl,
        FailureCase::RateLimited,
        FailureCase::Unavailable,
        FailureCase::NotFound,
        FailureCase::Timeout,
        FailureCase::MidstreamDrop,
    ]
    .into_iter()
    .for_each(assert_failed_fill);
}

fn assert_failed_fill(case: FailureCase) {
    let fixture = Fixture::new();
    let mut compressed = fixture.compressed.clone();
    let (encoded, identity) = match case {
        FailureCase::WrongEncodedHash => (
            EncodedIdentity::new(
                CompressionCodec::Zstd,
                FileHash::from_digest([9; 32]),
                fixture.encoded.size(),
            ),
            fixture.identity,
        ),
        FailureCase::WrongDecodedHash => (
            fixture.encoded,
            NarIdentity::new(NarHash::from_digest([9; 32]), fixture.identity.size()),
        ),
        FailureCase::WrongDecodedSize => (
            fixture.encoded,
            NarIdentity::new(
                fixture.identity.hash(),
                NarSize::new(fixture.identity.size().get() + 1),
            ),
        ),
        FailureCase::TrailingCompressedBytes => {
            compressed.extend_from_slice(b"trailing");
            use sha2::{Digest, Sha256};
            (
                EncodedIdentity::new(
                    CompressionCodec::Zstd,
                    FileHash::from_digest(Sha256::digest(&compressed).into()),
                    crate::cache::object::EncodedSize::new(compressed.len() as u64),
                ),
                fixture.identity,
            )
        }
        _ => (fixture.encoded, fixture.identity),
    };
    let signer = match case {
        FailureCase::InvalidSignature => SigningKey::from_bytes(&[4; 32]),
        _ => signing_key(),
    };
    let mut metadata = fixture.metadata(
        STORE,
        NarRepresentation::compressed(encoded, identity),
        &signer,
    );
    if let FailureCase::ArbitraryPayloadUrl = case {
        let original = format!("URL: nar/{}", encoded.file_name());
        metadata = String::from_utf8(metadata)
            .unwrap()
            .replace(&original, "URL: http://127.0.0.1:1/forbidden")
            .into_bytes();
    }
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            match case {
                FailureCase::OversizedMetadata => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        MAX_NARINFO_BYTES + 1
                    );
                }
                FailureCase::OversizedStreamingMetadata => {
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                        .is_ok()
                    {
                        for _ in 0..=MAX_NARINFO_BYTES / 1024 {
                            if stream.write_all(&[b'x'; 1024]).is_err() {
                                break;
                            }
                        }
                    }
                }
                FailureCase::Redirect => {
                    let _ = stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
                FailureCase::RateLimited => reply(stream, 429, b""),
                FailureCase::Unavailable => reply(stream, 503, b""),
                FailureCase::NotFound => reply(stream, 404, b""),
                FailureCase::Timeout => {
                    let _ = stream.read(&mut [0]);
                }
                _ => reply(stream, 200, &metadata),
            }
        } else {
            match case {
                FailureCase::TruncatedBody => {
                    reply(stream, 200, &compressed[..compressed.len() / 2])
                }
                FailureCase::MidstreamDrop => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        compressed.len()
                    )
                    .and_then(|()| stream.write_all(&compressed[..compressed.len() / 2]));
                }
                _ => reply(stream, 200, &compressed),
            }
        }
    });
    let mut settings = settings(upstream.url());
    if let FailureCase::Timeout = case {
        settings.timeout = Duration::from_millis(50);
    }
    let policy = match case {
        FailureCase::OversizedEncoded => {
            NarUploadPolicy::with_limits(1, 1024 * 1024, 128 * 1024 * 1024, 0)
        }
        FailureCase::OversizedDecoded => {
            NarUploadPolicy::with_limits(1024 * 1024, 1, 128 * 1024 * 1024, 0)
        }
        _ => NarUploadPolicy::new(1024 * 1024, 0),
    };
    let source = ReadThroughSource::new(settings, trusted_keys(), policy).unwrap();
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(case.expected()),
        "{case:?}"
    );
    assert!(storage.open_narinfo(&store).unwrap().is_none(), "{case:?}");
    assert_eq!(
        upstream
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|route| route.contains("/nar/"))
            .count(),
        case.payload_requests(),
        "{case:?}"
    );
    assert_eq!(source.active.load(Ordering::Relaxed), 0);
}

#[test]
fn refused_connection_is_a_transient_negative_and_caches_are_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    drop(listener);
    let source = ReadThroughSource::new(
        settings(upstream),
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(EdgeFailure::Transient)
    );
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(EdgeFailure::Transient)
    );
    assert_eq!(source.counters.started.load(Ordering::Relaxed), 1);
    assert_eq!(source.counters.negative_hits.load(Ordering::Relaxed), 1);
}

#[test]
fn missing_advertisement_evidence_is_repaired_offline_after_reopen() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let upstream = Upstream::new(move |route, stream| {
        reply(
            stream,
            200,
            if route.ends_with(".narinfo") {
                &metadata
            } else {
                &fixture.raw
            },
        );
    });
    let source = source(&upstream);
    let (directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    assert_eq!(source.ensure_local(&storage, &store), EdgeLookup::Ready);
    drop(upstream);
    drop(storage);
    let lease = directory
        .path()
        .join(".narjar-advertisements")
        .join(format!("{STORE}.lease"));
    fs::remove_file(&lease).unwrap();
    let storage = Storage::open(
        &Directory::open(directory.path()).unwrap(),
        SupportedStorageBackend::FLAT,
    )
    .unwrap();
    assert!(matches!(
        storage.advertisement_evidence(store).unwrap(),
        AdvertisementEvidence::Missing
    ));
    assert_eq!(source.ensure_local(&storage, &store), EdgeLookup::Ready);
    assert!(matches!(
        storage.advertisement_evidence(store).unwrap(),
        AdvertisementEvidence::Recorded
    ));
    assert!(lease.exists());
    assert_eq!(source.counters.started.load(Ordering::Relaxed), 1);
}

#[test]
fn missing_evidence_does_not_bless_untrusted_local_metadata() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let invalid_metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &SigningKey::from_bytes(&[4; 32]),
    );
    let upstream = Upstream::new(move |route, stream| {
        reply(
            stream,
            200,
            if route.ends_with(".narinfo") {
                &metadata
            } else {
                &fixture.raw
            },
        );
    });
    let source = source(&upstream);
    let (directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();
    assert_eq!(source.ensure_local(&storage, &store), EdgeLookup::Ready);
    drop(upstream);
    let lease = directory
        .path()
        .join(".narjar-advertisements")
        .join(format!("{STORE}.lease"));
    fs::remove_file(&lease).unwrap();
    fs::write(
        directory.path().join(format!("{STORE}.narinfo")),
        invalid_metadata,
    )
    .unwrap();
    assert_eq!(
        source.ensure_local(&storage, &store),
        EdgeLookup::Miss(EdgeFailure::Invalid)
    );
    assert!(!lease.exists());
    assert_eq!(source.counters.started.load(Ordering::Relaxed), 1);
}

#[test]
fn deadline_reader_does_not_read_after_the_total_deadline() {
    struct UnexpectedRead;
    impl Read for UnexpectedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("expired reader performed I/O")
        }
    }
    let deadline = Deadline(Instant::now() - Duration::from_secs(1));
    let error = DeadlineReader::new(UnexpectedRead, deadline)
        .read(&mut [0])
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn metrics_use_fixed_labels_and_do_not_expose_upstream_or_store_paths() {
    let source = ReadThroughSource::new(
        settings("http://127.0.0.1:1/private-upstream".parse().unwrap()),
        trusted_keys(),
        NarUploadPolicy::new(1024, 0),
    )
    .unwrap();
    let mut metrics = String::new();
    source.append_metrics(&mut metrics);
    assert!(metrics.contains("narjar_edge_failures_total{reason=\"transient\"} 0"));
    assert!(!metrics.contains("127.0.0.1"));
    assert!(!metrics.contains("private-upstream"));
    assert!(!metrics.contains("/nix/store"));
    assert_eq!(source.negative_ttl, Duration::from_secs(1));
}
