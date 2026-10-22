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
use lzma_rust2::{XzOptions, XzWriter};
use narjar::nar_encode::{Encoder, Event};
use sha2::{Digest, Sha256};
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};
use tempfile::TempDir;

use crate::cache::{
    nar_compression::encode_and_measure_nar,
    narinfo::NarInfoMetadata,
    object::{
        CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarFileName, NarHash,
        NarIdentity, NarSize,
    },
    storage::{CacheCreation, Directory, EGRESS_RECEIPT_DIRECTORY, SupportedStorageBackend},
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
        Self::with_file_data(&[])
    }

    fn with_file_data(data: &[u8]) -> Self {
        let mut encoder = Encoder::new(Vec::new()).unwrap();
        encoder.push(Event::BeginDirectory).unwrap();
        if !data.is_empty() {
            encoder.push(Event::Entry(b"payload")).unwrap();
            encoder
                .push(Event::BeginFile {
                    executable: false,
                    size: data.len() as u64,
                })
                .unwrap();
            for chunk in data.chunks(64 * 1024) {
                encoder.push(Event::FileChunk(chunk)).unwrap();
            }
            encoder.push(Event::EndFile).unwrap();
        }
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

    fn metadata_with_download_url(
        &self,
        store: &str,
        payload: NarRepresentation,
        signer: &SigningKey,
        url: &str,
    ) -> Vec<u8> {
        let metadata = String::from_utf8(self.metadata(store, payload, signer)).unwrap();
        let old_url = format!("URL: nar/{}\n", payload.file_name());
        metadata
            .replace(&old_url, &format!("URL: {url}\n"))
            .into_bytes()
    }

    fn metadata_with_claimed_identity(
        store: &str,
        claimed: NarIdentity,
        payload: NarRepresentation,
        signer: &SigningKey,
    ) -> Vec<u8> {
        let mut metadata = NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{store}-fixture"),
            None,
            None,
            claimed,
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
    settings_with_egress(upstream, WireEncoding::Raw)
}

fn settings_with_egress(upstream: HttpUrl, egress_compression: WireEncoding) -> EdgeSettings {
    EdgeSettings {
        upstream,
        egress_compression,
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
    source_with_egress(upstream, WireEncoding::Raw)
}

fn source_with_egress(upstream: &Upstream, egress_compression: WireEncoding) -> ReadThroughSource {
    ReadThroughSource::new(
        settings_with_egress(upstream.url(), egress_compression),
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap()
}

fn nondefault_upstream_encoding(raw: &[u8], codec: CompressionCodec) -> (Vec<u8>, EncodedIdentity) {
    let mut encoded = Vec::new();
    match codec {
        CompressionCodec::Xz => {
            let mut encoder = XzWriter::new(&mut encoded, XzOptions::with_preset(6)).unwrap();
            encoder.write_all(raw).unwrap();
            encoder.finish().unwrap();
        }
        CompressionCodec::Zstd => {
            let mut encoder = StreamingEncoder::new(&mut encoded, CompressionLevel::Best);
            encoder.write_all(raw).unwrap();
            encoder.finish().unwrap();
        }
    }
    let identity = EncodedIdentity::new(
        codec,
        FileHash::from_digest(Sha256::digest(&encoded).into()),
        EncodedSize::new(encoded.len() as u64),
    );
    (encoded, identity)
}

fn zstd_upstream_encoding(
    raw: &[u8],
    level: structured_zstd::encoding::CompressionLevel,
) -> (Vec<u8>, EncodedIdentity) {
    let mut encoded = Vec::new();
    let mut encoder = StreamingEncoder::new(&mut encoded, level);
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap();
    let identity = EncodedIdentity::new(
        CompressionCodec::Zstd,
        FileHash::from_digest(Sha256::digest(&encoded).into()),
        EncodedSize::new(encoded.len() as u64),
    );
    (encoded, identity)
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
                        match route.strip_prefix(&upstream_fixture_prefix()) {
                            Some(_) => {
                                requests.lock().unwrap().push(route.clone());
                                handler(&route, &mut stream);
                            }
                            None => reply(&mut stream, 404, b""),
                        }
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
        format!("http://{}{}", self.address, upstream_fixture_prefix())
            .parse()
            .unwrap()
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

fn upstream_fixture_prefix() -> String {
    format!("/cache/{}/", std::process::id())
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

#[test]
fn upstream_fixture_rejects_foreign_requests_to_a_reused_port() {
    let handled = Arc::new(AtomicUsize::new(0));
    let upstream = {
        let handled = handled.clone();
        Upstream::new(move |_, stream| {
            handled.fetch_add(1, Ordering::Relaxed);
            reply(stream, 200, b"fixture");
        })
    };
    let mut stream = TcpStream::connect(upstream.address).unwrap();
    stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    write!(
        stream,
        "GET /{STORE}.narinfo HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    assert_eq!(upstream.count(".narinfo"), 0);
    assert_eq!(handled.load(Ordering::Relaxed), 0);
    let response = idle_agent(TEST_TIMEOUT)
        .get(
            upstream
                .url()
                .endpoint(&[&format!("{STORE}.narinfo")])
                .as_str(),
        )
        .call()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(upstream.count(".narinfo"), 1);
    assert_eq!(handled.load(Ordering::Relaxed), 1);
}

#[test]
fn identity_content_encoding_accepts_mixed_case_without_accepting_other_codings() {
    for coding in ["identity", "Identity", "IDENTITY", "gzip"] {
        let fixture = Fixture::new();
        let metadata = fixture.metadata(
            STORE,
            NarRepresentation::Raw(fixture.identity),
            &signing_key(),
        );
        let upstream = Upstream::new(move |route, stream| {
            let body = if route.ends_with(".narinfo") {
                &metadata
            } else {
                &fixture.raw
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .and_then(|()| stream.write_all(body))
            .unwrap();
        });
        let source = source(&upstream);
        let (_directory, storage) = storage();
        let result = source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap());
        let expected = if coding == "gzip" {
            Err(EdgeMiss::Failed(EdgeFailure::Invalid))
        } else {
            Ok(EdgeHit::Filled)
        };
        assert_eq!(result, expected, "Content-Encoding: {coding}");
    }
}

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        self.wait_until_released(TEST_TIMEOUT);
    }

    fn wait_until_released(&self, timeout: Duration) {
        let (open, _) = self
            .changed
            .wait_timeout_while(self.open.lock().unwrap(), timeout, |open| !*open)
            .unwrap();
        assert!(*open, "test did not release the upstream gate");
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

fn wait_for(condition: impl Fn() -> bool) {
    wait_for_within(TEST_TIMEOUT, condition);
}

fn wait_for_within(timeout: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
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
            egress_compression: WireEncoding::Raw,
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
fn offline_repair_preserves_the_existing_compressed_output() {
    let fixture = Fixture::new();
    let (directory, storage) = storage();
    let policy = NarUploadPolicy::new(1024 * 1024, 0);
    storage
        .publish_nar(
            crate::cache::object::NarFileName::raw(fixture.identity.hash()),
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
    let bound = storage
        .bind_narinfo(
            metadata,
            WireEncoding::Compressed(fixture.encoded.codec()),
            policy,
        )
        .unwrap();
    let output = bound.output();
    bound.publish().unwrap();
    let compressed = fs::read(directory.path().join(format!("{STORE}.narinfo"))).unwrap();
    fs::remove_file(
        directory
            .path()
            .join(".narjar-advertisements")
            .join(format!("{STORE}.lease")),
    )
    .unwrap();
    let source = ReadThroughSource::new(
        settings("http://127.0.0.1:1".parse().unwrap()),
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Local));
    assert!(matches!(
        storage.advertisement_evidence(store).unwrap(),
        AdvertisementEvidence::Recorded
    ));
    assert_eq!(
        fs::read(directory.path().join(format!("{STORE}.narinfo"))).unwrap(),
        compressed,
        "repair must preserve the representation already published"
    );
    let output_file = match output {
        NarRepresentation::Compressed(compressed) => compressed.encoded().file_name(),
        NarRepresentation::Raw(_) => panic!("test selected compressed egress"),
    };
    assert!(storage.open_nar(output_file).unwrap().is_some());
}

#[test]
fn recovery_uses_the_recorded_upstream_url_to_repair_a_corrupt_canonical_nar() {
    let fixture = Fixture::new();
    let compressed = NarRepresentation::compressed(fixture.encoded, fixture.identity);
    let expected_resource = "objects/fixture.zst?token=keep-this-query";
    let metadata = fixture.metadata(STORE, compressed, &signing_key());
    let metadata = String::from_utf8(metadata)
        .unwrap()
        .replace(
            &format!("URL: nar/{}", fixture.encoded.file_name()),
            &format!("URL: {expected_resource}"),
        )
        .into_bytes();
    let compressed_bytes = fixture.compressed.clone();
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else if route.ends_with(expected_resource) {
            reply(stream, 200, &compressed_bytes);
        } else {
            reply(stream, 404, b"");
        }
    });
    let source = source_with_egress(&upstream, WireEncoding::Raw);
    let (directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
    assert_eq!(
        storage.read_through_source(store).unwrap().unwrap().url(),
        upstream
            .url()
            .resolve_trusted_cache_resource(expected_resource)
            .unwrap()
            .as_str()
    );

    fs::write(
        directory
            .path()
            .join("nar")
            .join(NarFileName::raw(fixture.identity.hash()).to_string()),
        b"corrupt canonical NAR",
    )
    .unwrap();
    source.repair_recovery_blockers(&storage).unwrap();

    let mut repaired = storage
        .open_nar(NarFileName::raw(fixture.identity.hash()))
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    repaired.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, fixture.raw);
    assert_eq!(upstream.count(".narinfo"), 1);
    assert_eq!(upstream.count(expected_resource), 2);
}

#[test]
fn recovery_refreshes_a_stale_recorded_upstream_url() {
    let fixture = Fixture::new();
    let compressed = NarRepresentation::compressed(fixture.encoded, fixture.identity);
    let old_resource = "objects/fixture.zst?token=expired";
    let new_resource = "objects/fixture.zst?token=current";
    let old_metadata =
        fixture.metadata_with_download_url(STORE, compressed, &signing_key(), old_resource);
    let current_metadata =
        fixture.metadata_with_download_url(STORE, compressed, &signing_key(), new_resource);
    let metadata_requests = Arc::new(AtomicUsize::new(0));
    let expired_downloads = Arc::new(AtomicUsize::new(0));
    let compressed_bytes = fixture.compressed.clone();
    let upstream = {
        let metadata_requests = metadata_requests.clone();
        let expired_downloads = expired_downloads.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                let metadata = if metadata_requests.fetch_add(1, Ordering::AcqRel) == 0 {
                    &old_metadata
                } else {
                    &current_metadata
                };
                reply(stream, 200, metadata);
            } else if route.ends_with(old_resource) {
                if expired_downloads.fetch_add(1, Ordering::AcqRel) == 0 {
                    reply(stream, 200, &compressed_bytes);
                } else {
                    reply(stream, 403, b"");
                }
            } else if route.ends_with(new_resource) {
                reply(stream, 200, &compressed_bytes);
            } else {
                reply(stream, 404, b"");
            }
        })
    };
    let source = source_with_egress(&upstream, WireEncoding::Raw);
    let (directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
    fs::write(
        directory
            .path()
            .join("nar")
            .join(NarFileName::raw(fixture.identity.hash()).to_string()),
        b"corrupt canonical NAR",
    )
    .unwrap();

    source.repair_recovery_blockers(&storage).unwrap();

    let mut repaired = storage
        .open_nar(NarFileName::raw(fixture.identity.hash()))
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    repaired.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, fixture.raw);
    assert_eq!(upstream.count(".narinfo"), 2);
    assert_eq!(upstream.count(old_resource), 2);
    assert_eq!(upstream.count(new_resource), 1);
    assert_eq!(
        storage.read_through_source(store).unwrap().unwrap().url(),
        upstream
            .url()
            .resolve_trusted_cache_resource(new_resource)
            .unwrap()
            .as_str()
    );
}

#[test]
fn recovery_rejects_a_fresh_url_for_a_different_compressed_identity() {
    let fixture = Fixture::new();
    let (old_bytes, old_identity) = zstd_upstream_encoding(&fixture.raw, CompressionLevel::Fastest);
    let (current_bytes, current_identity) =
        zstd_upstream_encoding(&fixture.raw, CompressionLevel::Best);
    assert_ne!(old_identity, current_identity);
    let old_payload = NarRepresentation::compressed(old_identity, fixture.identity);
    let current_payload = NarRepresentation::compressed(current_identity, fixture.identity);
    let old_resource = "objects/fixture.zst?token=expired";
    let current_resource = "objects/fixture.zst?token=current";
    let old_metadata =
        fixture.metadata_with_download_url(STORE, old_payload, &signing_key(), old_resource);
    let current_metadata = fixture.metadata_with_download_url(
        STORE,
        current_payload,
        &signing_key(),
        current_resource,
    );
    let metadata_requests = Arc::new(AtomicUsize::new(0));
    let expired_downloads = Arc::new(AtomicUsize::new(0));
    let upstream = {
        let metadata_requests = metadata_requests.clone();
        let expired_downloads = expired_downloads.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                let metadata = if metadata_requests.fetch_add(1, Ordering::AcqRel) == 0 {
                    &old_metadata
                } else {
                    &current_metadata
                };
                reply(stream, 200, metadata);
            } else if route.ends_with(old_resource) {
                if expired_downloads.fetch_add(1, Ordering::AcqRel) == 0 {
                    reply(stream, 200, &old_bytes);
                } else {
                    reply(stream, 403, b"");
                }
            } else if route.ends_with(current_resource) {
                reply(stream, 200, &current_bytes);
            } else {
                reply(stream, 404, b"");
            }
        })
    };
    let source = source_with_egress(&upstream, WireEncoding::Compressed(CompressionCodec::Zstd));
    let (directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
    fs::write(
        directory
            .path()
            .join("nar")
            .join(NarFileName::raw(fixture.identity.hash()).to_string()),
        b"corrupt canonical NAR",
    )
    .unwrap();

    assert_eq!(
        source.repair_recovery_blockers(&storage),
        Err(EdgeFailure::Invalid)
    );
    assert_eq!(upstream.count(".narinfo"), 2);
    assert_eq!(upstream.count(old_resource), 2);
    assert_eq!(upstream.count(current_resource), 0);
}

#[test]
fn recorded_leases_serve_compressed_metadata_without_upstream_access() {
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
    let (advertisement, hit) = source.advertise(&storage, &store).unwrap();
    assert_eq!(hit, EdgeHit::Local);
    assert!(
        std::str::from_utf8(&advertisement.bytes)
            .unwrap()
            .contains("Compression: zstd\n")
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
        let outcomes = calls
            .into_iter()
            .map(|call| call.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Ok(EdgeHit::Filled))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Ok(EdgeHit::Coalesced))
                .count(),
            7
        );
    });
    assert_eq!(upstream.count(".narinfo"), 1);
    assert_eq!(upstream.count(".nar"), 1);
    drop(upstream);
    // Return a locally stored object even if an earlier upstream failure is cached.
    source.state.lock().unwrap().remember(
        Key::Store(store),
        EdgeFailure::Transient,
        Instant::now(),
        Duration::from_secs(1),
    );
    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Local));
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
fn compressed_egress_preserves_exact_matching_upstream_bytes() {
    for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
        let data = (0..512 * 1024)
            .map(|index| ((index * 31 + index / 251) % 251) as u8)
            .collect::<Vec<_>>();
        let fixture = Fixture::with_file_data(&data);
        let (encoded_bytes, encoded_identity) = nondefault_upstream_encoding(&fixture.raw, codec);
        let payload = NarRepresentation::compressed(encoded_identity, fixture.identity);
        let metadata = fixture.metadata_with_download_url(
            STORE,
            payload,
            &signing_key(),
            "objects/source.nar?token=one",
        );
        let upstream = {
            let encoded_bytes = encoded_bytes.clone();
            Upstream::new(move |route, stream| {
                if route.ends_with(".narinfo") {
                    reply(stream, 200, &metadata);
                } else if route.ends_with("/objects/source.nar?token=one") {
                    reply(stream, 200, &encoded_bytes);
                } else {
                    reply(stream, 404, b"");
                }
            })
        };
        let source = source_with_egress(&upstream, WireEncoding::Compressed(codec));
        let (directory, storage) = storage();
        let store = StoreHash::parse(STORE).unwrap();

        assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
        let published = {
            let advertisement = storage.read_advertised_narinfo(&store).unwrap().unwrap();
            String::from_utf8(advertisement.bytes).unwrap()
        };
        let verified = trusted_keys()
            .verify_external_narinfo_for_transfer(&store, published.as_bytes().to_vec())
            .unwrap()
            .into_publication();
        assert_eq!(verified.claims().identity(), fixture.identity);
        assert_eq!(
            verified.payload(),
            NarRepresentation::compressed(encoded_identity, fixture.identity)
        );
        assert!(published.contains(&format!(
            "Compression: {}\n",
            WireEncoding::from(codec).compression()
        )));
        assert!(published.contains(&format!("FileHash: sha256:{}\n", encoded_identity.hash())));
        assert!(published.contains(&format!("FileSize: {}\n", encoded_identity.size().get())));

        let mut stored = storage
            .open_nar(encoded_identity.file_name())
            .unwrap()
            .unwrap();
        let mut stored_bytes = Vec::new();
        stored.read_to_end(&mut stored_bytes).unwrap();
        assert_eq!(stored_bytes, encoded_bytes);
        assert_eq!(storage.egress_generations(), 0);

        fs::remove_file(
            directory
                .path()
                .join(EGRESS_RECEIPT_DIRECTORY)
                .join(format!(
                    "{}{}.receipt",
                    fixture.identity.hash(),
                    codec.suffix()
                )),
        )
        .unwrap();
        fs::remove_file(
            directory
                .path()
                .join(".narjar-advertisements")
                .join(format!("{STORE}.lease")),
        )
        .unwrap();
        fs::remove_file(
            directory
                .path()
                .join("nar")
                .join(encoded_identity.file_name().to_string()),
        )
        .unwrap();

        drop(storage);
        let storage = Storage::open(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Local));
        assert_eq!(
            storage.egress_generations(),
            1,
            "the local encoder is checked before fetching a non-reproducible derivative"
        );
        let mut stored = storage
            .open_nar(encoded_identity.file_name())
            .unwrap()
            .unwrap();
        let mut stored_bytes = Vec::new();
        stored.read_to_end(&mut stored_bytes).unwrap();
        assert_eq!(stored_bytes, encoded_bytes);

        stored_bytes[0] ^= 0x01;
        fs::write(
            directory
                .path()
                .join("nar")
                .join(encoded_identity.file_name().to_string()),
            &stored_bytes,
        )
        .unwrap();
        drop(storage);
        let storage = Storage::open(
            &Directory::open(directory.path()).unwrap(),
            SupportedStorageBackend::FLAT,
        )
        .unwrap();
        assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Local));
        assert_eq!(storage.egress_generations(), 1);
        let mut stored = storage
            .open_nar(encoded_identity.file_name())
            .unwrap()
            .unwrap();
        stored_bytes.clear();
        stored.read_to_end(&mut stored_bytes).unwrap();
        assert_eq!(stored_bytes, encoded_bytes);
        assert_eq!(upstream.count("objects/source.nar?token=one"), 3);
    }
}

#[test]
fn cached_raw_nar_still_fetches_the_exact_upstream_compressed_output() {
    for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
        let fixture = Fixture::new();
        let (encoded_bytes, encoded_identity) = nondefault_upstream_encoding(&fixture.raw, codec);
        let payload = NarRepresentation::compressed(encoded_identity, fixture.identity);
        let metadata = fixture.metadata(STORE, payload, &signing_key());
        let upstream = {
            let encoded_bytes = encoded_bytes.clone();
            Upstream::new(move |route, stream| {
                if route.ends_with(".narinfo") {
                    reply(stream, 200, &metadata);
                } else if route.ends_with(codec.suffix()) {
                    reply(stream, 200, &encoded_bytes);
                } else {
                    reply(stream, 404, b"");
                }
            })
        };
        let source = source_with_egress(&upstream, WireEncoding::Compressed(codec));
        let (_directory, storage) = storage();
        storage
            .publish_nar(
                crate::cache::object::NarFileName::raw(fixture.identity.hash()),
                fixture.raw.as_slice(),
                fixture.raw.len() as u64,
                NarUploadPolicy::new(1024 * 1024, 0),
            )
            .unwrap();

        assert_eq!(
            source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()),
            Ok(EdgeHit::Filled)
        );
        assert_eq!(upstream.count(codec.suffix()), 1);
        let mut stored = storage
            .open_nar(encoded_identity.file_name())
            .unwrap()
            .unwrap();
        let mut actual = Vec::new();
        stored.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, encoded_bytes);
        assert_eq!(storage.egress_generations(), 0);
    }
}

#[test]
fn decoded_identity_mismatch_publishes_neither_raw_nar_nor_retained_encoding() {
    let fixture = Fixture::new();
    let (encoded_bytes, encoded_identity) =
        nondefault_upstream_encoding(&fixture.raw, CompressionCodec::Zstd);
    let claimed_identity =
        NarIdentity::new(NarHash::from_digest([0x91; 32]), fixture.identity.size());
    let payload = NarRepresentation::compressed(encoded_identity, claimed_identity);
    let metadata =
        Fixture::metadata_with_claimed_identity(STORE, claimed_identity, payload, &signing_key());
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else if route.ends_with(".nar.zst") {
            reply(stream, 200, &encoded_bytes);
        } else {
            reply(stream, 404, b"");
        }
    });
    let source = source_with_egress(&upstream, WireEncoding::Compressed(CompressionCodec::Zstd));
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Failed(EdgeFailure::Invalid))
    );
    assert!(
        storage
            .open_nar(NarFileName::raw(fixture.identity.hash()))
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .open_nar(encoded_identity.file_name())
            .unwrap()
            .is_none()
    );
    assert!(storage.open_narinfo(&store).unwrap().is_none());
    assert!(matches!(
        storage.advertisement_evidence(store).unwrap(),
        AdvertisementEvidence::Missing
    ));
}

#[test]
fn changing_egress_policy_does_not_strand_an_existing_advertisement() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
    );
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else if route.ends_with(".nar") {
            reply(stream, 200, &fixture.raw);
        } else {
            reply(stream, 404, b"");
        }
    });
    let raw_source = source(&upstream);
    let compressed_source =
        source_with_egress(&upstream, WireEncoding::Compressed(CompressionCodec::Zstd));
    let (directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(
        raw_source.ensure_local(&storage, &store),
        Ok(EdgeHit::Filled)
    );
    let original = storage
        .read_advertised_narinfo(&store)
        .unwrap()
        .unwrap()
        .bytes;
    let (advertisement, hit) = compressed_source.advertise(&storage, &store).unwrap();
    assert_eq!(hit, EdgeHit::Local);
    assert_eq!(advertisement.bytes, original);

    fs::remove_file(
        directory
            .path()
            .join(".narjar-advertisements")
            .join(format!("{STORE}.lease")),
    )
    .unwrap();
    assert_eq!(
        compressed_source.ensure_local(&storage, &store),
        Ok(EdgeHit::Local)
    );
    let repaired = storage
        .read_advertised_narinfo(&store)
        .unwrap()
        .unwrap()
        .bytes;
    assert_eq!(repaired, original);
    assert_eq!(storage.egress_generations(), 0);
}

#[test]
fn external_transport_url_with_a_query_selects_the_download_without_changing_local_output() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata_with_download_url(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
        "objects/not-a-hash.nar?token=one",
    );
    let upstream = {
        let compressed = fixture.compressed.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                reply(stream, 200, &metadata);
            } else if route.ends_with("/objects/not-a-hash.nar?token=one") {
                reply(stream, 200, &compressed);
            } else {
                reply(stream, 404, b"");
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
    assert!(
        upstream
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|route| route.ends_with("/objects/not-a-hash.nar?token=one"))
    );

    let published = storage.read_advertised_narinfo(&store).unwrap().unwrap();
    let published = String::from_utf8(published.bytes).unwrap();
    assert!(published.contains(&format!("URL: nar/{}.nar\n", fixture.identity.hash())));
    assert!(published.contains("Compression: none\n"));
}

#[test]
fn same_scope_redirects_are_followed_and_the_final_bytes_are_still_verified() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata_with_download_url(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
        "objects/start.nar?token=one",
    );
    let upstream = {
        let compressed = fixture.compressed.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                reply(stream, 200, &metadata);
            } else if route.ends_with("/objects/start.nar?token=one") {
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: final.nar?token=two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            } else if route.ends_with("/objects/final.nar?token=two") {
                reply(stream, 200, &compressed);
            } else {
                reply(stream, 404, b"");
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
    assert!(
        upstream
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|route| route.ends_with("/objects/final.nar?token=two"))
    );
}

#[test]
fn a_redirect_outside_the_configured_path_is_not_requested() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata_with_download_url(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
        "objects/start.nar",
    );
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else {
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: ../../../outside.nar\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
    });
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Failed(EdgeFailure::Invalid))
    );
    assert_eq!(upstream.count(".narinfo"), 1);
    assert_eq!(upstream.count(".nar"), 1);
}

#[test]
fn a_valid_logical_signature_does_not_authorize_an_upstream_path_escape() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata_with_download_url(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
        "../outside.nar?token=one",
    );
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else {
            panic!("untrusted metadata URL was requested: {route}");
        }
    });
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Failed(EdgeFailure::Invalid))
    );
    assert_eq!(upstream.count(".narinfo"), 1);
}

#[test]
fn raw_upstream_metadata_can_omit_encoded_identity_and_include_system() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata_with_download_url(
        STORE,
        NarRepresentation::Raw(fixture.identity),
        &signing_key(),
        "objects/raw-without-hash?token=one",
    );
    let metadata = without_encoded_file_identity(metadata)
        .replace(
            "Compression: none\n",
            "Compression: none\nSystem: x86_64-linux\n",
        )
        .into_bytes();
    let upstream = {
        let raw = fixture.raw.clone();
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                reply(stream, 200, &metadata);
            } else if route.ends_with("/objects/raw-without-hash?token=one") {
                reply(stream, 200, &raw);
            } else {
                reply(stream, 404, b"");
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
    let published = storage.read_advertised_narinfo(&store).unwrap().unwrap();
    let published = String::from_utf8(published.bytes).unwrap();
    assert!(published.contains("Compression: none\n"));
    assert!(published.contains("FileHash: sha256:"));
    assert!(!published.contains("System:"));
}

#[test]
fn compressed_upstream_metadata_without_encoded_identity_is_rejected() {
    let fixture = Fixture::new();
    let metadata = fixture.metadata_with_download_url(
        STORE,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
        "objects/compressed-without-hash?token=one",
    );
    let metadata = without_encoded_file_identity(metadata).into_bytes();
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(stream, 200, &metadata);
        } else {
            panic!("download started without encoded identity: {route}");
        }
    });
    let source = source(&upstream);
    let (_directory, storage) = storage();
    let store = StoreHash::parse(STORE).unwrap();

    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Failed(EdgeFailure::Invalid))
    );
    assert_eq!(upstream.count(".narinfo"), 1);
}

fn without_encoded_file_identity(metadata: Vec<u8>) -> String {
    let metadata = String::from_utf8(metadata).unwrap();
    format!(
        "{}\n",
        metadata
            .lines()
            .filter(|line| !line.starts_with("FileHash: ") && !line.starts_with("FileSize: "))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[test]
fn cached_raw_nars_satisfy_aliases_whose_encoded_download_would_exceed_the_limit() {
    let fixture = Fixture::new();
    assert!(fixture.raw.len() as u64 > fixture.encoded.size().get());
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
    let compressed = fixture.compressed.clone();
    let upstream = Upstream::new(move |route, stream| {
        let body = if route.ends_with(&format!("/{STORE}.narinfo")) {
            &compressed_metadata
        } else if route.ends_with(&format!("/{ALIAS}.narinfo")) {
            &raw_metadata
        } else if route.ends_with(".zst") {
            &compressed
        } else {
            reply(stream, 404, b"raw download must not be needed");
            return;
        };
        reply(stream, 200, body);
    });
    let policy = NarUploadPolicy::with_limits(
        fixture.encoded.size().get(),
        fixture.identity.size().get(),
        128 * 1024 * 1024,
        0,
    );
    let source = ReadThroughSource::new(settings(upstream.url()), trusted_keys(), policy).unwrap();
    let (_directory, storage) = storage();
    for hash in [STORE, ALIAS] {
        let store = StoreHash::parse(hash).unwrap();
        assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
        let metadata = storage.read_advertised_narinfo(&store).unwrap().unwrap();
        assert_eq!(
            trusted_keys()
                .validate(&store, metadata.bytes)
                .unwrap()
                .payload(),
            NarRepresentation::Raw(fixture.identity)
        );
    }
    assert_eq!(upstream.count(".narinfo"), 2);
    assert_eq!(upstream.count(".zst"), 1);
    assert_eq!(upstream.count(".nar"), 0);
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
            .for_each(|call| assert_eq!(call.join().unwrap(), Ok(EdgeHit::Filled)));
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
fn compressed_aliases_share_one_exact_retained_download() {
    let data = (0..256 * 1024)
        .map(|index| ((index * 17 + index / 193) % 251) as u8)
        .collect::<Vec<_>>();
    let fixture = Fixture::with_file_data(&data);
    let encoded = nondefault_upstream_encoding(&fixture.raw, CompressionCodec::Zstd);
    let payload = NarRepresentation::compressed(encoded.1, fixture.identity);
    let primary_metadata = fixture.metadata(STORE, payload, &signing_key());
    let alias_metadata = fixture.metadata(ALIAS, payload, &signing_key());
    let metadata_overlap = Arc::new(Barrier::new(2));
    let gate = Arc::new(Gate::default());
    let upstream = {
        let (metadata_overlap, gate) = (metadata_overlap.clone(), gate.clone());
        let (primary, alias, encoded_bytes) = (primary_metadata, alias_metadata, encoded.0.clone());
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                metadata_overlap.wait();
                reply(
                    stream,
                    200,
                    if route.contains(STORE) {
                        &primary
                    } else {
                        &alias
                    },
                );
            } else {
                gate.wait();
                reply(stream, 200, &encoded_bytes);
            }
        })
    };
    let source = source_with_egress(&upstream, WireEncoding::Compressed(CompressionCodec::Zstd));
    let (_directory, storage) = storage();
    thread::scope(|scope| {
        let calls = [STORE, ALIAS]
            .into_iter()
            .map(|hash| {
                let (source, storage) = (&source, &storage);
                scope.spawn(move || source.ensure_local(storage, &StoreHash::parse(hash).unwrap()))
            })
            .collect::<Vec<_>>();
        wait_for(|| upstream.count(".narinfo") == 2);
        wait_for(|| source.counters.followers.load(Ordering::Relaxed) == 1);
        gate.release();
        calls
            .into_iter()
            .for_each(|call| assert!(call.join().unwrap().is_ok()));
    });

    assert_eq!(upstream.count(".nar.zst"), 1);
    assert_eq!(storage.egress_generations(), 0);
    for hash in [STORE, ALIAS] {
        let store = StoreHash::parse(hash).unwrap();
        let advertisement = storage.read_advertised_narinfo(&store).unwrap().unwrap();
        let verified = trusted_keys()
            .verify_external_narinfo_for_transfer(&store, advertisement.bytes)
            .unwrap()
            .into_publication();
        assert_eq!(verified.payload(), payload);
    }
    let mut stored = storage.open_nar(encoded.1.file_name()).unwrap().unwrap();
    let mut actual = Vec::new();
    stored.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, encoded.0);
}

#[test]
fn aliases_with_distinct_compressed_encodings_retain_each_requested_identity() {
    let data = (0..512 * 1024)
        .map(|index| ((index * 31 + index / 127) % 251) as u8)
        .collect::<Vec<_>>();
    let fixture = Fixture::with_file_data(&data);
    let (primary_bytes, primary_encoded) =
        zstd_upstream_encoding(&fixture.raw, CompressionLevel::Best);
    let (alias_bytes, alias_encoded) =
        zstd_upstream_encoding(&fixture.raw, CompressionLevel::Fastest);
    assert_ne!(primary_encoded, alias_encoded);
    let primary_payload = NarRepresentation::compressed(primary_encoded, fixture.identity);
    let alias_payload = NarRepresentation::compressed(alias_encoded, fixture.identity);
    let primary_metadata = fixture.metadata(STORE, primary_payload, &signing_key());
    let alias_metadata = fixture.metadata(ALIAS, alias_payload, &signing_key());
    let metadata_overlap = Arc::new(Barrier::new(2));
    let gate = Arc::new(Gate::default());
    let upstream = {
        let (metadata_overlap, gate) = (metadata_overlap.clone(), gate.clone());
        let (primary_name, alias_name) = (
            primary_encoded.file_name().to_string(),
            alias_encoded.file_name().to_string(),
        );
        let (primary_bytes, alias_bytes) = (primary_bytes.clone(), alias_bytes.clone());
        Upstream::new(move |route, stream| {
            if route.ends_with(".narinfo") {
                metadata_overlap.wait();
                reply(
                    stream,
                    200,
                    if route.contains(STORE) {
                        &primary_metadata
                    } else {
                        &alias_metadata
                    },
                );
            } else {
                gate.wait_until_released(Duration::from_secs(30));
                let encoded = if route.ends_with(&primary_name) {
                    &primary_bytes
                } else if route.ends_with(&alias_name) {
                    &alias_bytes
                } else {
                    reply(stream, 404, b"");
                    return;
                };
                reply(stream, 200, encoded);
            }
        })
    };
    let mut edge_settings = settings_with_egress(
        upstream.url(),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    );
    edge_settings.fill_timeout = Duration::from_secs(30);
    let source = ReadThroughSource::new(
        edge_settings,
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    let (_directory, storage) = storage();

    thread::scope(|scope| {
        let primary =
            scope.spawn(|| source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()));
        wait_for(|| upstream.count(".narinfo") == 1);
        let alias =
            scope.spawn(|| source.ensure_local(&storage, &StoreHash::parse(ALIAS).unwrap()));
        wait_for(|| upstream.count(".narinfo") == 2);
        wait_for_within(Duration::from_secs(30), || {
            source.counters.followers.load(Ordering::Relaxed) == 1
        });
        gate.release();
        let primary_result = primary.join().unwrap();
        let alias_result = alias.join().unwrap();
        assert_eq!(
            primary_result,
            Ok(EdgeHit::Filled),
            "primary failed; requests: {:?}",
            upstream.requests.lock().unwrap()
        );
        assert_eq!(
            alias_result,
            Ok(EdgeHit::Filled),
            "alias failed; requests: {:?}",
            upstream.requests.lock().unwrap()
        );
    });

    assert_eq!(upstream.count(".nar.zst"), 2);
    assert_eq!(storage.egress_generations(), 0);
    for (hash, expected) in [(STORE, primary_payload), (ALIAS, alias_payload)] {
        let store = StoreHash::parse(hash).unwrap();
        let advertisement = storage.read_advertised_narinfo(&store).unwrap().unwrap();
        let verified = trusted_keys()
            .verify_external_narinfo_for_transfer(&store, advertisement.bytes)
            .unwrap()
            .into_publication();
        assert_eq!(verified.payload(), expected);
    }
    for (encoded, expected) in [
        (primary_encoded, primary_bytes),
        (alias_encoded, alias_bytes),
    ] {
        let mut stored = storage.open_nar(encoded.file_name()).unwrap().unwrap();
        let mut actual = Vec::new();
        stored.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
    }
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
            Err(EdgeMiss::Failed(EdgeFailure::Capacity)),
            "a third blocked request must leave the last HTTP worker available"
        );
        assert_eq!(
            source.ensure_local(storage, &StoreHash::parse(ALIAS).unwrap()),
            Err(EdgeMiss::Failed(EdgeFailure::Capacity))
        );
        assert_eq!(upstream.count(".narinfo"), 1);
        gate.release();
        assert_eq!(leader.join().unwrap(), Ok(EdgeHit::Filled));
        assert_eq!(follower.join().unwrap(), Ok(EdgeHit::Coalesced));
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
            Err(EdgeMiss::Failed(EdgeFailure::Invalid))
        );
        assert_eq!(follower.join().unwrap(), Ok(EdgeHit::Filled));
    });
    assert_eq!(upstream.count(".zst"), 1);
    assert_eq!(upstream.count(".nar"), 1);
}

#[test]
fn a_wrong_decoded_claim_cannot_poison_a_valid_claim_sharing_the_encoded_payload() {
    let fixture = Fixture::new();
    let wrong_identity = NarIdentity::new(NarHash::from_digest([42; 32]), fixture.identity.size());
    let wrong = fixture.metadata(
        STORE,
        NarRepresentation::compressed(fixture.encoded, wrong_identity),
        &signing_key(),
    );
    let valid = fixture.metadata(
        ALIAS,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
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
                        &wrong
                    } else {
                        &valid
                    },
                );
            } else {
                gate.wait();
                reply(stream, 200, &fixture.compressed);
            }
        })
    };
    let source = source(&upstream);
    let (_directory, storage) = storage();
    thread::scope(|scope| {
        let invalid =
            scope.spawn(|| source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()));
        wait_for(|| upstream.count(".zst") == 1);
        let valid =
            scope.spawn(|| source.ensure_local(&storage, &StoreHash::parse(ALIAS).unwrap()));
        wait_for(|| upstream.count(".zst") == 2);
        gate.release();
        assert_eq!(
            invalid.join().unwrap(),
            Err(EdgeMiss::Failed(EdgeFailure::Invalid))
        );
        assert_eq!(valid.join().unwrap(), Ok(EdgeHit::Filled));
    });
    assert_eq!(upstream.count(".zst"), 2);
    assert!(
        storage
            .open_narinfo(&StoreHash::parse(STORE).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .open_narinfo(&StoreHash::parse(ALIAS).unwrap())
            .unwrap()
            .is_some()
    );
}

#[test]
fn an_incorrect_encoded_size_cannot_poison_a_valid_alias_before_negative_expiry() {
    let fixture = Fixture::new();
    let wrong_encoded = EncodedIdentity::new(
        fixture.encoded.codec(),
        fixture.encoded.hash(),
        (fixture.encoded.size().get() + 1).into(),
    );
    let wrong = fixture.metadata(
        STORE,
        NarRepresentation::compressed(wrong_encoded, fixture.identity),
        &signing_key(),
    );
    let valid = fixture.metadata(
        ALIAS,
        NarRepresentation::compressed(fixture.encoded, fixture.identity),
        &signing_key(),
    );
    let upstream = Upstream::new(move |route, stream| {
        let body = if route.ends_with(".narinfo") {
            if route.contains(STORE) {
                &wrong
            } else {
                &valid
            }
        } else {
            &fixture.compressed
        };
        reply(stream, 200, body);
    });
    let mut settings = settings(upstream.url());
    settings.negative_ttl = Duration::from_secs(60);
    let source = ReadThroughSource::new(
        settings,
        trusted_keys(),
        NarUploadPolicy::new(1024 * 1024, 0),
    )
    .unwrap();
    let (_directory, storage) = storage();
    assert_eq!(
        source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()),
        Err(EdgeMiss::Failed(EdgeFailure::Invalid))
    );
    assert!(source.state.lock().unwrap().negative_entries() > 0);
    assert_eq!(
        source.ensure_local(&storage, &StoreHash::parse(ALIAS).unwrap()),
        Ok(EdgeHit::Filled)
    );
    assert_eq!(upstream.count(".zst"), 2);
}

#[test]
fn a_cached_representation_failure_stays_negative_for_another_store_path() {
    let fixture = Fixture::new();
    let representation = NarRepresentation::compressed(fixture.encoded, fixture.identity);
    let first_metadata = fixture.metadata(STORE, representation, &signing_key());
    let alias_metadata = fixture.metadata(ALIAS, representation, &signing_key());
    let upstream = Upstream::new(move |route, stream| {
        if route.ends_with(".narinfo") {
            reply(
                stream,
                200,
                if route.contains(STORE) {
                    &first_metadata
                } else {
                    &alias_metadata
                },
            );
        } else {
            reply(stream, 503, b"");
        }
    });
    let source = source(&upstream);
    let (_directory, storage) = storage();

    assert_eq!(
        source.ensure_local(&storage, &StoreHash::parse(STORE).unwrap()),
        Err(EdgeMiss::Failed(EdgeFailure::Transient))
    );
    assert_eq!(
        source.ensure_local(&storage, &StoreHash::parse(ALIAS).unwrap()),
        Err(EdgeMiss::Cached(EdgeFailure::Transient))
    );
    assert_eq!(upstream.count(".narinfo"), 2);
    assert_eq!(upstream.count(".zst"), 1);
}

#[test]
fn followers_keep_the_local_hit_outcome_from_a_shared_flight() {
    let upstream = Upstream::new(|_, _| panic!("offline repair must not contact upstream"));
    let source = source(&upstream);
    let key = Key::Store(StoreHash::parse(STORE).unwrap());
    let flight = match source
        .state
        .lock()
        .unwrap()
        .join(key, Instant::now())
        .unwrap()
    {
        Join::Leader(flight) => flight,
        Join::Follower(_) | Join::Cached(_) => panic!("new store key must start a flight"),
    };
    flight.finish(Ok(EdgeHit::Local));

    assert_eq!(
        source.coalesce(key, Deadline::new(TEST_TIMEOUT).unwrap(), || {
            panic!("a follower must not run the leader closure")
        }),
        Ok(EdgeHit::Local)
    );
}

#[test]
fn a_cached_representation_failure_retries_for_a_coalesced_logical_nar() {
    let fixture = Fixture::new();
    let retries = AtomicUsize::new(0);

    let result = finish_shared_fill_or_retry_representation(
        Key::Nar(fixture.identity),
        Err(EdgeMiss::Cached(EdgeFailure::Transient)),
        || {
            retries.fetch_add(1, Ordering::Relaxed);
            Ok(EdgeHit::Filled)
        },
    );

    assert_eq!(result, Ok(EdgeHit::Filled));
    assert_eq!(retries.load(Ordering::Relaxed), 1);
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
        Ok(EdgeHit::Filled)
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
        Err(EdgeMiss::Failed(EdgeFailure::Transient))
    );
    healthy.store(true, Ordering::Release);
    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Cached(EdgeFailure::Transient))
    );
    assert_eq!(
        upstream.count(".narinfo"),
        1,
        "requests: {:?}",
        upstream.requests.lock().unwrap()
    );
    // Advance the cleanup clock instead of sleeping until the cached failure expires.
    source
        .state
        .lock()
        .unwrap()
        .prune(Instant::now() + Duration::from_secs(2));
    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
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
        Err(EdgeMiss::Failed(case.expected())),
        "{case:?}"
    );
    assert!(storage.open_narinfo(&store).unwrap().is_none(), "{case:?}");
    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Cached(case.expected())),
        "cached failures must retain the original class: {case:?}"
    );
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
        Err(EdgeMiss::Failed(EdgeFailure::Transient))
    );
    assert_eq!(
        source.ensure_local(&storage, &store),
        Err(EdgeMiss::Cached(EdgeFailure::Transient))
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
    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
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
    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Local));
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
    assert_eq!(source.ensure_local(&storage, &store), Ok(EdgeHit::Filled));
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
        Err(EdgeMiss::Failed(EdgeFailure::Invalid))
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
