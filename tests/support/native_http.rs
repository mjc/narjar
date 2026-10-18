use super::*;
use narjar::object::{NarHash, NarIdentity};

fn body(response: &[u8]) -> Vec<u8> {
    response_parts(response).1
}

#[track_caller]
fn assert_status(response: &[u8], expected: u16) {
    let (headers, _) = response_parts(response);
    assert_eq!(
        headers.split_ascii_whitespace().nth(1),
        Some(expected.to_string().as_str()),
        "{headers}"
    );
}

struct NativeHttpFixture {
    owner: TestDir,
    cache: PathBuf,
    state: PathBuf,
    roots: PathBuf,
    file: PathBuf,
    nar: Vec<u8>,
    hash: NarHash,
    store_hash: String,
    key: PathBuf,
}

impl NativeHttpFixture {
    fn new() -> Self {
        let file = PathBuf::from(
            std::env::var_os("NARJAR_NATIVE_TEST_FILE")
                .expect("the Nix test gate must provide its immutable store fixture"),
        );
        assert_eq!(file.parent(), Some(Path::new("/nix/store")));
        let owner = data_dir("native-http");
        let cache = owner.join("cache");
        let state = owner.join("state");
        let roots = state.join("gcroots/auto/narjar");
        fs::create_dir_all(state.join("db")).unwrap();
        fs::create_dir_all(&roots).unwrap();
        fs::set_permissions(&roots, fs::Permissions::from_mode(0o700)).unwrap();
        fs::File::create(state.join("gc.lock")).unwrap();
        fs::write(state.join("db/schema"), "10\n").unwrap();
        assert!(
            run(&["init", "--data-dir", cache.to_str().unwrap()])
                .status
                .success()
        );
        write_test_trusted_public_keys(cache.join("trusted-public-keys"));
        let nar = native_nar_bytes_with_contents(&fs::read(&file).unwrap());
        let hash = NarHash::from_digest(Sha256::digest(&nar).into());
        let store_hash = file.file_name().unwrap().to_str().unwrap()[..32].to_owned();
        let key = owner.join("secret-key");
        let signing = SigningKey::from_bytes(&[7; 32]);
        fs::write(
            &key,
            format!(
                "narjar-test:{}\n",
                BASE64.encode(&signing.to_keypair_bytes())
            ),
        )
        .unwrap();
        let metadata = crate::cache::narinfo::NarInfoMetadata::from_store_metadata(
            file.to_str().unwrap().to_owned(),
            None,
            None,
            NarIdentity::new(hash, (nar.len() as u64).into()),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let signature = format!(
            "narjar-test:{}",
            BASE64.encode(
                &signing
                    .sign(metadata.claims().fingerprint().as_bytes())
                    .to_bytes()
            )
        );
        let db = sqlite::Connection::open(state.join("db/db.sqlite")).unwrap();
        db.execute("CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY, path TEXT, hash TEXT, registrationTime INTEGER, deriver TEXT, narSize INTEGER, sigs TEXT, ca TEXT);
            CREATE TABLE Refs(referrer INTEGER, reference INTEGER);
            CREATE TABLE SchemaMigrations(migration TEXT);
            INSERT INTO SchemaMigrations VALUES ('20260309-drop-redundant-indexreferrer');").unwrap();
        let mut row = db
            .prepare("INSERT INTO ValidPaths VALUES(1, ?, ?, 1, NULL, ?, ?, NULL)")
            .unwrap();
        row.bind((1, file.to_str().unwrap())).unwrap();
        row.bind((
            2,
            format!("sha256:{}", data_encoding::HEXLOWER.encode(hash.as_bytes())).as_str(),
        ))
        .unwrap();
        row.bind((3, nar.len() as i64)).unwrap();
        row.bind((4, signature.as_str())).unwrap();
        row.next().unwrap();
        Self {
            owner,
            cache,
            state,
            roots,
            file,
            nar,
            hash,
            store_hash,
            key,
        }
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--serve-source".into(),
            "native-store".into(),
            "--native-store-dir".into(),
            "/nix/store".into(),
            "--native-state-dir".into(),
            self.state.to_str().unwrap().into(),
            "--native-roots-dir".into(),
            self.roots.to_str().unwrap().into(),
            "--native-min-lease-seconds".into(),
            "3600".into(),
            "--min-free-bytes".into(),
            "0".into(),
        ]
    }

    fn start(self, extra: &[&str]) -> RunningServer {
        let args = self.args();
        let args = args
            .iter()
            .map(String::as_str)
            .chain(extra.iter().copied())
            .collect::<Vec<_>>();
        RunningServer::start_with_existing_path(self.cache, self.owner, &args)
    }
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_serves_signed_raw_get_head_ranges_and_rejects_writes_after_restart() {
    let fixture = NativeHttpFixture::new();
    let nar = fixture.nar.clone();
    let hash = fixture.hash;
    let metadata_path = format!("/{}.narinfo", fixture.store_hash);
    let payload_path = format!("/nar/{hash}.nar");
    let roots = fixture.roots.clone();
    let cache = fixture.cache.clone();
    let args = fixture.args();
    let file = fixture.file.clone();
    let server = fixture.start(&[]);
    let response = server.request("GET", &metadata_path);
    assert_status(&response, 200);
    let metadata = String::from_utf8(body(&response).to_vec()).unwrap();
    assert!(metadata.contains("Compression: none\n"));
    assert!(metadata.contains(&format!("URL: nar/{hash}.nar\n")));
    assert!(
        fs::read_dir(&roots).unwrap().any(|entry| fs::read_link(
            entry.unwrap().path().join("root")
        )
        .ok()
        .as_deref()
            == Some(&file)),
        "advertisement must already have a discoverable durable root"
    );
    assert_eq!(body(&server.request("GET", &payload_path)), nar);
    assert_status(&server.request("HEAD", &payload_path), 200);
    let range = server.request_with_headers("GET", &payload_path, &[("Range", "bytes=5-14")]);
    assert_status(&range, 206);
    assert_eq!(body(&range), &nar[5..15]);
    assert_status(
        &server.request_with_headers("GET", &payload_path, &[("Range", "bytes=999999-")]),
        416,
    );
    assert_status(&server.request("GET", &format!("{payload_path}.xz")), 404);
    assert_status(
        &server.request("GET", "/11111111111111111111111111111111.narinfo"),
        404,
    );
    assert_status(
        &server.request_with_body(
            "PUT",
            &payload_path,
            &[("Authorization", TEST_AUTHORIZATION)],
            b"ignored",
        ),
        405,
    );
    assert_status(&server.request("GET", "/readyz"), 200);
    let metrics = server.request("GET", "/metrics");
    let exposition = String::from_utf8(body(&metrics)).unwrap();
    assert_eq!(metric_value(&exposition, "narjar_request_workers_limit"), 1);
    assert_eq!(
        metric_value(&exposition, "narjar_publication_workers_limit"),
        0
    );
    assert!(
        String::from_utf8_lossy(&body(&metrics))
            .contains("narjar_source_info{source=\"native-store\"} 1")
    );
    assert!(
        fs::read_dir(cache.join("nar"))
            .unwrap()
            .all(|entry| entry.unwrap().file_name() == ".tmp"),
        "serving must not materialize another NAR"
    );
    let (owner, signal, status) = server.stop_preserving();
    assert_clean_shutdown(signal, status);
    let server = RunningServer::start_with_existing_path(
        cache,
        owner,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(body(&server.request("GET", &payload_path)), nar);
    assert_status(&server.request("GET", &metadata_path), 200);
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_requires_trust_and_can_sign_unsigned_paths_with_a_configured_key() {
    for sign in [false, true] {
        let fixture = NativeHttpFixture::new();
        sqlite::Connection::open(fixture.state.join("db/db.sqlite"))
            .unwrap()
            .execute("UPDATE ValidPaths SET sigs = ''")
            .unwrap();
        let path = format!("/{}.narinfo", fixture.store_hash);
        let payload = format!("/nar/{}.nar", fixture.hash);
        let key = fixture.key.clone();
        let extra = if sign {
            vec!["--native-signing-key-file", key.to_str().unwrap()]
        } else {
            vec![]
        };
        let server = fixture.start(&extra);
        assert_status(&server.request("GET", &payload), 404);
        assert_status(&server.request("GET", &path), if sign { 200 } else { 404 });
        assert_status(
            &server.request("GET", &payload),
            if sign { 200 } else { 404 },
        );
        if !sign {
            assert!(
                fs::read_dir(
                    server
                        .temp_dir
                        .as_ref()
                        .unwrap()
                        .join("state/gcroots/auto/narjar")
                )
                .unwrap()
                .all(|entry| !entry.unwrap().file_type().unwrap().is_dir()),
                "untrusted claims must not consume a lease"
            );
        }
    }
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_checks_auth_before_rooting_and_rechecks_live_database_and_lease_failures() {
    let fixture = NativeHttpFixture::new();
    let read_tokens = fixture.cache.join("auth/read.tokens");
    fs::write(&read_tokens, TEST_WRITE_TOKEN).unwrap();
    fs::set_permissions(&read_tokens, fs::Permissions::from_mode(0o600)).unwrap();
    let roots = fixture.roots.clone();
    let state = fixture.state.clone();
    let path = format!("/{}.narinfo", fixture.store_hash);
    let payload = format!("/nar/{}.nar", fixture.hash);
    let server = fixture.start(&[]);
    assert_status(&server.request("GET", &path), 401);
    assert_status(&server.request("GET", "/readyz"), 401);
    assert_status(&server.request("GET", "/metrics"), 401);
    assert!(
        fs::read_dir(&roots)
            .unwrap()
            .all(|entry| !entry.unwrap().file_type().unwrap().is_dir())
    );
    let auth = [("Authorization", TEST_AUTHORIZATION)];
    let response = server.request_with_headers("GET", &path, &auth);
    assert_status(&response, 200);
    assert!(
        response_parts(&response)
            .0
            .contains("Cache-Control: private, no-store\r\n")
    );
    assert!(
        response_parts(&response)
            .0
            .contains("Vary: Authorization\r\n")
    );
    assert_status(&server.request_with_headers("GET", &payload, &auth), 200);
    let db = sqlite::Connection::open(state.join("db/db.sqlite")).unwrap();
    db.execute("UPDATE ValidPaths SET sigs = ''").unwrap();
    assert_status(&server.request_with_headers("GET", &path, &auth), 404);
    drop(db);
    fs::rename(&roots, roots.with_file_name("held-roots")).unwrap();
    fs::write(&roots, b"not a directory").unwrap();
    assert_status(&server.request_with_headers("GET", &payload, &auth), 503);
    assert_status(&server.request_with_headers("GET", "/readyz", &auth), 503);
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_readiness_requires_the_gc_lock_to_remain_readable() {
    let fixture = NativeHttpFixture::new();
    let lock = fixture.state.join("gc.lock");
    let path = format!("/{}.narinfo", fixture.store_hash);
    let server = fixture.start(&[]);
    assert_status(&server.request("GET", "/readyz"), 200);
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o000)).unwrap();
    assert_status(&server.request("GET", "/readyz"), 503);
    assert_status(&server.request("GET", &path), 503);
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert_status(&server.request("GET", "/readyz"), 200);
    assert_status(&server.request("GET", &path), 200);
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_unadvertised_payload_misses_do_not_query_the_database() {
    let fixture = NativeHttpFixture::new();
    let database = fixture.state.join("db/db.sqlite");
    let path = format!("/nar/{}.nar", fixture.hash);
    let server = fixture.start(&[]);
    sqlite::Connection::open(database)
        .unwrap()
        .execute("DROP TABLE ValidPaths")
        .unwrap();
    assert_status(&server.request("GET", &path), 404);
    assert_status(&server.request("HEAD", &path), 404);
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_readiness_does_not_depend_on_upload_staging() {
    let fixture = NativeHttpFixture::new();
    let cache = fixture.cache.clone();
    let path = format!("/{}.narinfo", fixture.store_hash);
    let server = fixture.start(&[]);
    fs::rename(cache.join("nar/.tmp"), cache.join("unused-upload-staging")).unwrap();
    assert_status(&server.request("GET", "/readyz"), 200);
    assert_status(&server.request("GET", &path), 200);
}

#[test]
#[ignore = "requires the pinned Nix store fixture; run by the Nix test gate"]
fn native_store_http_counts_full_and_range_streaming_hash_failures_once_per_response() {
    let fixture = NativeHttpFixture::new();
    let hash = NarHash::from_digest([42; 32]);
    let db = sqlite::Connection::open(fixture.state.join("db/db.sqlite")).unwrap();
    db.execute(format!(
        "UPDATE ValidPaths SET hash = 'sha256:{}'",
        data_encoding::HEXLOWER.encode(hash.as_bytes())
    ))
    .unwrap();
    drop(db);
    let full_length = fixture.nar.len();
    let metadata = format!("/{}.narinfo", fixture.store_hash);
    let key = fixture.key.clone();
    let server = fixture.start(&["--native-signing-key-file", key.to_str().unwrap()]);
    assert_status(&server.request("GET", &metadata), 200);
    let path = format!("/nar/{hash}.nar");
    for (index, (headers, expected_status, expected_length)) in [
        (vec![], 200, full_length),
        (vec![("Range", "bytes=5-14")], 206, 10),
    ]
    .into_iter()
    .enumerate()
    {
        let response = server.request_with_headers("GET", &path, &headers);
        assert_status(&response, expected_status);
        assert!(
            body(&response).len() < expected_length,
            "a hash mismatch must not complete a response"
        );
        let metrics = String::from_utf8(body(&server.request("GET", "/metrics"))).unwrap();
        assert_eq!(
            metric_value(&metrics, "narjar_native_failures_total{phase=\"delivery\"}"),
            index as u64 + 1
        );
    }
}
