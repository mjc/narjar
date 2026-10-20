use super::*;
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
#[test]
fn native_push_and_raw_read_share_one_chunked_cache_url() {
    for compression in ["none", "zstd", "xz"] {
        let server = RunningServer::start_with_workers(
            &format!("chunked-native-push-{compression}"),
            2,
            &["--storage-backend", "chunked"],
        );
        let fixture = native_push_fixture();
        let output = run_native_push_fixture_with_options(
            &fixture,
            &format!("http://{}", server.address),
            compression,
            NativePushRunOptions {
                signing: true,
                insecure_http: true,
                ..NativePushRunOptions::default()
            },
        );
        assert!(
            output.status.success(),
            "{compression} native push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let nar_hash = nix32_sha256(&native_nar_bytes());
        let response = server.request("GET", &format!("/nar/{nar_hash}.nar"));
        let (headers, body) = response_parts(&response);
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
        assert_eq!(body, native_nar_bytes());
        assert!(
            fs::read_dir(server.data_dir.join(".narjar-manifests"))
                .expect("chunk manifest directory should be readable")
                .any(|entry| entry.is_ok()),
            "native push should publish a chunk manifest"
        );

        let (signal, status) = server.stop();
        assert_clean_shutdown(signal, status);
    }
}

#[test]
fn push_uses_native_transfer_without_nix_copy() {
    for (compression, suffix) in [("none", ".nar"), ("zstd", ".nar.zst"), ("xz", ".nar.xz")] {
        assert_native_push_process_boundary(compression, suffix);
    }
}

#[test]
fn native_push_signs_metadata_without_invoking_nix() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native signing listener");
    let address = listener
        .local_addr()
        .expect("inspect native signing listener");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept native narinfo lookup");
        let request = read_http_request(&mut stream);
        assert!(String::from_utf8_lossy(&request).starts_with("GET /"));
        write!(
            stream,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write missing narinfo response");

        let (mut stream, _) = listener.accept().expect("accept native NAR upload");
        let request = read_http_request(&mut stream);
        assert!(String::from_utf8_lossy(&request).starts_with("PUT /nar/"));
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write native NAR response");

        let (mut stream, _) = listener.accept().expect("accept signed narinfo upload");
        let request = read_http_request(&mut stream);
        let body = String::from_utf8_lossy(&request[http_request_body_start(&request)..]);
        assert_eq!(body.matches("Sig: ").count(), 1);
        assert!(body.contains("Sig: narjar-test:"));
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write signed narinfo response");
    });

    let fixture = native_push_fixture();
    let output =
        run_native_push_fixture_with_signing(&fixture, &format!("http://{address}"), "none", false);
    server.join().expect("native signing server should exit");
    assert!(
        output.status.success(),
        "native signing push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !fixture.invocation_log.exists(),
        "native signing push must not invoke Nix"
    );
}

#[test]
fn native_push_skips_payload_generation_for_a_matching_trusted_upstream() {
    let destination = TcpListener::bind("127.0.0.1:0").expect("bind destination listener");
    let destination_address = destination
        .local_addr()
        .expect("inspect destination listener");
    let destination_server = thread::spawn(move || {
        let (mut stream, _) = destination.accept().expect("accept destination lookup");
        let request = read_http_request(&mut stream);
        assert!(
            String::from_utf8_lossy(&request)
                .starts_with("GET /00000000000000000000000000000000.narinfo")
        );
        write!(
            stream,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write destination miss");
    });

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream listener");
    let upstream_address = upstream.local_addr().expect("inspect upstream listener");
    let nar_bytes = native_nar_bytes();
    let narinfo = signed_narinfo_for(
        STORE_HASH,
        &nix32_sha256(&nar_bytes),
        nar_bytes.len() as u64,
    );
    let upstream_server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream lookup");
        let request = read_http_request(&mut stream);
        assert!(
            String::from_utf8_lossy(&request)
                .starts_with("GET /00000000000000000000000000000000.narinfo")
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            narinfo.len(),
            narinfo,
        )
        .expect("write trusted upstream narinfo");
    });

    let fixture = native_push_fixture();
    fs::write(
        fixture.store_dir.join(format!("{STORE_HASH}-narjar")),
        b"payload contradicts registered NAR identity",
    )
    .expect("make serialization fail identity validation if preflight does not skip it");
    let upstream_url = format!("http://{upstream_address}");
    let upstream_key = trusted_upstream_key_for(&upstream_url, 7);
    let output = run_native_push_fixture_with_options(
        &fixture,
        &format!("http://{destination_address}"),
        "none",
        NativePushRunOptions {
            extra_args: &[
                "--trusted-upstream",
                &upstream_url,
                "--trusted-upstream-key",
                &upstream_key,
            ],
            ..NativePushRunOptions::default()
        },
    );

    assert!(
        output.status.success(),
        "trusted upstream push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    destination_server
        .join()
        .expect("destination server should exit");
    upstream_server.join().expect("upstream server should exit");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("trusted-upstream-present 1"),
        "push summary should distinguish the trusted upstream skip: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !fixture.invocation_log.exists(),
        "trusted upstream lookup must not invoke Nix"
    );
}

fn one_response_cache(
    status: u16,
    reason: &'static str,
    body: String,
) -> (String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind one-response cache");
    let address = listener.local_addr().expect("inspect one-response cache");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept cache lookup");
        let request = read_http_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write cache lookup response");
        request
    });
    (format!("http://{address}"), server)
}

fn trusted_upstream_key(seed: u8) -> String {
    format!(
        "narjar-test:{}",
        BASE64.encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes()
        )
    )
}

fn trusted_upstream_key_for(upstream: &str, seed: u8) -> String {
    format!("{upstream}#{}", trusted_upstream_key(seed))
}

fn signed_narinfo_with_store_path(
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[&str],
) -> String {
    let reference_basenames = references
        .iter()
        .map(|reference| {
            reference
                .strip_prefix("/nix/store/")
                .expect("test reference should be a store path")
        })
        .collect::<Vec<_>>();
    let fingerprint = format!(
        "1;{store_path};sha256:{nar_hash};{nar_size};{}",
        references.join(",")
    );
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());
    format!(
        "StorePath: {store_path}\nURL: nar/{nar_hash}.nar\nCompression: none\nFileHash: sha256:{nar_hash}\nFileSize: {nar_size}\nNarHash: sha256:{nar_hash}\nNarSize: {nar_size}\nReferences: {}\nSig: narjar-test:{}\n",
        reference_basenames.join(" "),
        BASE64.encode(&signature.to_bytes())
    )
}

#[test]
fn native_push_skips_payload_generation_when_the_destination_is_present() {
    let native_nar = native_nar_bytes();
    let narinfo = signed_narinfo_for(
        STORE_HASH,
        &nix32_sha256(&native_nar),
        native_nar.len() as u64,
    );
    let (destination, server) = one_response_cache(200, "OK", narinfo);
    let fixture = native_push_fixture();
    fs::write(
        fixture.store_dir.join(format!("{STORE_HASH}-narjar")),
        b"payload contradicts registered NAR identity",
    )
    .expect("make serialization fail identity validation if preflight does not skip it");

    let output = run_native_push_fixture(&fixture, &destination, "none", false);

    assert!(
        output.status.success(),
        "destination-present push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = server.join().expect("destination server should exit");
    assert!(String::from_utf8_lossy(&request).starts_with("GET /"));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "push complete: uploaded 0, destination-present 1, trusted-upstream-present 0; 1 workers\n"
    );
}

#[test]
fn native_push_keeps_the_first_valid_publication_of_a_store_path() {
    let server = RunningServer::start("first-store-path-publication-wins");
    let published_nar = native_nar_bytes_with_contents(b"the previously published build");
    let published_hash = nix32_sha256(&published_nar);
    let published_narinfo = signed_narinfo(&published_hash, published_nar.len() as u64);
    let narinfo_path = format!("/{STORE_HASH}.narinfo");
    let published_nar_path = format!("/nar/{published_hash}.nar");
    for (path, body) in [
        (published_nar_path.as_str(), published_nar.as_slice()),
        (narinfo_path.as_str(), published_narinfo.as_bytes()),
    ] {
        let response = server.request_with_body("PUT", path, &[], body);
        assert!(
            response_parts(&response)
                .0
                .starts_with("HTTP/1.1 201 Created\r\n")
        );
    }

    let local_nar = native_nar_bytes();
    let local_hash = nix32_sha256(&local_nar);
    assert_ne!(local_hash, published_hash);
    assert_ne!(local_nar.len(), published_nar.len());

    for compression in ["none", "xz", "zstd"] {
        let fixture = native_push_fixture();
        let local_file = fixture.store_dir.join(format!("{STORE_HASH}-narjar"));
        fs::write(&local_file, b"payload contradicts registered NAR identity")
            .expect("make payload generation fail if preflight tries it");
        let payloads_before = fs::read_dir(server.data_dir.join("nar")).unwrap().count();

        let skipped = run_native_push_fixture(
            &fixture,
            &format!("http://{}", server.address),
            compression,
            false,
        );
        assert!(
            skipped.status.success(),
            "{}",
            String::from_utf8_lossy(&skipped.stderr)
        );
        assert!(
            String::from_utf8_lossy(&skipped.stdout).contains("uploaded 0, destination-present 1")
        );
        assert_eq!(
            fs::read_dir(server.data_dir.join("nar")).unwrap().count(),
            payloads_before,
            "preflight must not create another payload"
        );

        fs::write(&local_file, NAR_BYTES).expect("restore the different local build for refresh");
        let refreshed = run_native_push_fixture_with_options(
            &fixture,
            &format!("http://{}", server.address),
            compression,
            NativePushRunOptions {
                refresh: true,
                signing: true,
                insecure_http: true,
                ..NativePushRunOptions::default()
            },
        );
        assert!(
            refreshed.status.success(),
            "{}",
            String::from_utf8_lossy(&refreshed.stderr)
        );
        assert!(
            String::from_utf8_lossy(&refreshed.stdout)
                .contains("uploaded 0, destination-present 1")
        );
        assert_eq!(
            fs::read(server.data_dir.join(format!("nar/{local_hash}.nar"))).unwrap(),
            local_nar,
            "the alternative payload keeps its own content identity"
        );
        assert_eq!(
            response_parts(&server.request("GET", &narinfo_path)).1,
            published_narinfo.as_bytes()
        );
        assert_eq!(
            response_parts(&server.request("GET", &published_nar_path)).1,
            published_nar
        );
        assert!(!fixture.invocation_log.exists(), "push must not invoke Nix");
    }

    let wrong_payload_claim = signed_narinfo(&local_hash, local_nar.len() as u64)
        .replace(
            &format!("URL: nar/{local_hash}.nar"),
            &format!("URL: nar/{published_hash}.nar"),
        )
        .replace(
            &format!("FileHash: sha256:{local_hash}"),
            &format!("FileHash: sha256:{published_hash}"),
        )
        .replace(
            &format!("FileSize: {}", local_nar.len()),
            &format!("FileSize: {}", published_nar.len()),
        );
    let rejected =
        server.request_with_body("PUT", &narinfo_path, &[], wrong_payload_claim.as_bytes());
    assert!(
        response_parts(&rejected)
            .0
            .starts_with("HTTP/1.1 422 Unprocessable Entity\r\n")
    );
    assert_eq!(
        response_parts(&server.request("GET", &narinfo_path)).1,
        published_narinfo.as_bytes()
    );
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn native_push_uploads_when_upstream_metadata_is_not_an_exact_trusted_match() {
    let nar_bytes = native_nar_bytes();
    let nar_hash = nix32_sha256(&nar_bytes);
    let nar_size = nar_bytes.len() as u64;
    let store_path = format!("/nix/store/{STORE_HASH}-narjar");
    let different_hash = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    let reference = "/nix/store/11111111111111111111111111111111-dependency";
    let cases = [
        (
            "untrusted-signature",
            signed_narinfo_with_store_path(&store_path, &nar_hash, nar_size, &[]),
            8,
            "invalid or untrusted narinfo",
        ),
        (
            "nar-hash",
            signed_narinfo_with_store_path(&store_path, different_hash, nar_size, &[]),
            7,
            "NAR hash or size differs",
        ),
        (
            "nar-size",
            signed_narinfo_with_store_path(&store_path, &nar_hash, nar_size + 1, &[]),
            7,
            "NAR hash or size differs",
        ),
        (
            "store-path",
            signed_narinfo_with_store_path(
                &format!("/nix/store/{STORE_HASH}-different-name"),
                &nar_hash,
                nar_size,
                &[],
            ),
            7,
            "store path differs",
        ),
        (
            "references",
            signed_narinfo_with_store_path(&store_path, &nar_hash, nar_size, &[reference]),
            7,
            "references differ",
        ),
    ];

    for (name, narinfo, key_seed, expected_diagnostic) in cases {
        let destination = RunningServer::start(&format!("upstream-mismatch-{name}"));
        let (upstream, upstream_server) = one_response_cache(200, "OK", narinfo);
        let key = trusted_upstream_key_for(&upstream, key_seed);
        let fixture = native_push_fixture();
        let output = run_native_push_fixture_with_options(
            &fixture,
            &format!("http://{}", destination.address),
            "none",
            NativePushRunOptions {
                signing: true,
                insecure_http: true,
                extra_args: &[
                    "--trusted-upstream",
                    &upstream,
                    "--trusted-upstream-key",
                    &key,
                ],
                ..NativePushRunOptions::default()
            },
        );

        assert!(
            output.status.success(),
            "{name} should fall back to upload: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_diagnostic),
            "{name} should explain why it uploaded: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("uploaded 1"),
            "{name} should be reported as uploaded"
        );
        upstream_server.join().expect("upstream server should exit");
        let (signal, status) = destination.stop();
        assert_clean_shutdown(signal, status);
    }
}

#[test]
fn native_push_uses_the_first_matching_trusted_upstream_in_configured_order() {
    let nar_bytes = native_nar_bytes();
    let nar_hash = nix32_sha256(&nar_bytes);
    let nar_size = nar_bytes.len() as u64;
    let mismatched = signed_narinfo_for(STORE_HASH, &nar_hash, nar_size + 1);
    let matching = signed_narinfo_for(STORE_HASH, &nar_hash, nar_size);
    let (first, first_server) = one_response_cache(200, "OK", mismatched);
    let (second, second_server) = one_response_cache(200, "OK", matching);
    let (destination, destination_server) = one_response_cache(404, "Not Found", String::new());
    let fixture = native_push_fixture();
    fs::write(
        fixture.store_dir.join(format!("{STORE_HASH}-narjar")),
        b"payload contradicts registered NAR identity",
    )
    .expect("make serialization fail identity validation if preflight does not skip it");
    let first_key = trusted_upstream_key_for(&first, 7);
    let second_key = trusted_upstream_key_for(&second, 7);

    let output = run_native_push_fixture_with_options(
        &fixture,
        &destination,
        "none",
        NativePushRunOptions {
            extra_args: &[
                "--trusted-upstream",
                &first,
                "--trusted-upstream",
                &second,
                "--trusted-upstream-key",
                &first_key,
                "--trusted-upstream-key",
                &second_key,
            ],
            ..NativePushRunOptions::default()
        },
    );

    assert!(
        output.status.success(),
        "ordered upstream lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    destination_server.join().expect("destination should exit");
    first_server.join().expect("first upstream should exit");
    second_server.join().expect("second upstream should exit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains(&format!("trusted upstream {second}")));
    assert!(stdout.contains("trusted-upstream-present 1"));
    assert!(stderr.contains("checking next source"));
    assert!(!stderr.contains("uploading instead"));
}

#[test]
fn native_push_accepts_external_trusted_narinfo_transport_fields() {
    let nar_bytes = native_nar_bytes();
    let nar_hash = nix32_sha256(&nar_bytes);
    let nar_size = nar_bytes.len() as u64;
    let standard_url = format!("nar/{nar_hash}.nar");
    let cases = [
        (
            "store-path-url",
            format!("nar/{STORE_HASH}-narjar.nar"),
            false,
        ),
        (
            "absolute-url",
            format!("https://upstream.example/nar/{STORE_HASH}-narjar.nar"),
            false,
        ),
        (
            "query-url-with-optional-fields-omitted",
            format!("https://upstream.example/nar/{STORE_HASH}-narjar.nar?channel=stable"),
            true,
        ),
    ];

    for (name, url, omit_transport_fields) in cases {
        let narinfo =
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size).replace(&standard_url, &url);
        let narinfo = if omit_transport_fields {
            narinfo
                .lines()
                .filter(|line| !line.starts_with("FileHash: ") && !line.starts_with("FileSize: "))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        } else {
            narinfo
        };
        let (destination, destination_server) = one_response_cache(404, "Not Found", String::new());
        let (upstream, upstream_server) = one_response_cache(200, "OK", narinfo);
        let key = trusted_upstream_key_for(&upstream, 7);
        let fixture = native_push_fixture();
        fs::write(
            fixture.store_dir.join(format!("{STORE_HASH}-narjar")),
            b"payload contradicts registered NAR identity",
        )
        .expect("make serialization fail identity validation if preflight does not skip it");
        let output = run_native_push_fixture_with_options(
            &fixture,
            &destination,
            "none",
            NativePushRunOptions {
                extra_args: &[
                    "--trusted-upstream",
                    &upstream,
                    "--trusted-upstream-key",
                    &key,
                ],
                ..NativePushRunOptions::default()
            },
        );

        assert!(
            output.status.success(),
            "{name} should skip from the trusted upstream: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        destination_server.join().expect("destination should exit");
        upstream_server.join().expect("upstream should exit");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("trusted-upstream-present 1"),
            "{name} should be recognized as a trusted upstream hit: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !fixture.invocation_log.exists(),
            "{name} should not invoke Nix"
        );
    }
}

#[test]
fn native_push_uploads_when_upstream_transport_fields_are_unusable() {
    let nar_bytes = native_nar_bytes();
    let nar_hash = nix32_sha256(&nar_bytes);
    let nar_size = nar_bytes.len() as u64;
    let standard_url = format!("nar/{nar_hash}.nar");
    let cases = [
        (
            "invalid-file-hash",
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size).replace(
                &format!("FileHash: sha256:{nar_hash}"),
                "FileHash: sha256:not-a-nix-hash",
            ),
        ),
        (
            "invalid-file-size",
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size)
                .replace(&format!("FileSize: {nar_size}"), "FileSize: not-a-size"),
        ),
        (
            "partial-transport-fields",
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size)
                .lines()
                .filter(|line| !line.starts_with("FileSize: "))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        ),
        (
            "file-url",
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size)
                .replace(&standard_url, "file:///tmp/narjar.nar"),
        ),
        (
            "ftp-url",
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size)
                .replace(&standard_url, "ftp://cache.example/nar/object.nar"),
        ),
        (
            "fragment-url",
            signed_narinfo_for(STORE_HASH, &nar_hash, nar_size)
                .replace(&standard_url, "nar/object.nar#fragment"),
        ),
    ];

    for (name, narinfo) in cases {
        let destination = RunningServer::start(&format!("invalid-upstream-transport-{name}"));
        let (upstream, upstream_server) = one_response_cache(200, "OK", narinfo);
        let key = trusted_upstream_key_for(&upstream, 7);
        let fixture = native_push_fixture();
        let output = run_native_push_fixture_with_options(
            &fixture,
            &format!("http://{}", destination.address),
            "none",
            NativePushRunOptions {
                signing: true,
                insecure_http: true,
                extra_args: &[
                    "--trusted-upstream",
                    &upstream,
                    "--trusted-upstream-key",
                    &key,
                ],
                ..NativePushRunOptions::default()
            },
        );

        assert!(
            output.status.success(),
            "{name} should fall back to upload: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("uploaded 1"),
            "{name} should not be treated as a trusted upstream hit"
        );
        upstream_server.join().expect("upstream should exit");
        let (signal, status) = destination.stop();
        assert_clean_shutdown(signal, status);
    }
}

#[test]
fn native_push_treats_upstream_misses_and_outages_as_upload_required() {
    #[derive(Clone, Copy)]
    enum UpstreamFailure {
        Missing,
        ServerError,
        Unavailable,
    }

    for failure in [
        UpstreamFailure::Missing,
        UpstreamFailure::ServerError,
        UpstreamFailure::Unavailable,
    ] {
        let (name, upstream, upstream_server) = match failure {
            UpstreamFailure::Missing => {
                let (upstream, server) = one_response_cache(404, "Not Found", String::new());
                ("upstream-miss", upstream, Some(server))
            }
            UpstreamFailure::ServerError => {
                let (upstream, server) =
                    one_response_cache(503, "Service Unavailable", String::new());
                ("upstream-server-error", upstream, Some(server))
            }
            UpstreamFailure::Unavailable => {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind unavailable upstream");
                let address = listener.local_addr().expect("inspect unavailable upstream");
                drop(listener);
                ("upstream-outage", format!("http://{address}"), None)
            }
        };
        let destination = RunningServer::start(name);
        let fixture = native_push_fixture();
        let key = trusted_upstream_key_for(&upstream, 7);
        let output = run_native_push_fixture_with_options(
            &fixture,
            &format!("http://{}", destination.address),
            "none",
            NativePushRunOptions {
                signing: true,
                insecure_http: true,
                extra_args: &[
                    "--trusted-upstream",
                    &upstream,
                    "--trusted-upstream-key",
                    &key,
                ],
                ..NativePushRunOptions::default()
            },
        );

        assert!(
            output.status.success(),
            "upstream miss/outage should fall back to upload: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("uploaded 1"));
        if !matches!(failure, UpstreamFailure::Missing) {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("uploading instead"),
                "upstream failure fallback should be diagnosed"
            );
        }
        if let Some(server) = upstream_server {
            server.join().expect("upstream server should exit");
        }
        let (signal, status) = destination.stop();
        assert_clean_shutdown(signal, status);
    }
}

fn add_dependency_to_native_push_fixture(fixture: &NativePushFixture) -> String {
    const DEPENDENCY_HASH: &str = "11111111111111111111111111111111";
    let dependency = format!("/nix/store/{DEPENDENCY_HASH}-dependency");
    fs::write(
        fixture
            .store_dir
            .join(format!("{DEPENDENCY_HASH}-dependency")),
        NAR_BYTES,
    )
    .expect("write dependency store object");
    let native_nar = native_nar_bytes();
    let database = sqlite::open(fixture.state_dir.join("db/db.sqlite"))
        .expect("open native metadata database");
    let hash = format!("sha256:{}", hex_sha256(&Sha256::digest(&native_nar)));
    let mut insert = database
        .prepare(
            "INSERT INTO ValidPaths
             (id, path, hash, registrationTime, narSize, sigs)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .expect("prepare dependency metadata insert");
    insert.bind((1, 2_i64)).expect("bind dependency id");
    insert
        .bind((2, dependency.as_str()))
        .expect("bind dependency path");
    insert
        .bind((3, hash.as_str()))
        .expect("bind dependency NAR hash");
    insert
        .bind((4, 1_i64))
        .expect("bind dependency registration time");
    insert
        .bind((5, native_nar.len() as i64))
        .expect("bind dependency NAR size");
    insert.bind((6, "")).expect("bind dependency signatures");
    insert.next().expect("insert dependency metadata");
    database
        .execute("INSERT INTO Refs (referrer, reference) VALUES (1, 2)")
        .expect("link root to dependency");
    dependency
}

#[test]
fn native_push_classifies_each_closure_member_independently() {
    const DEPENDENCY_HASH: &str = "11111111111111111111111111111111";
    let destination = RunningServer::start("upstream-closure");
    let fixture = native_push_fixture();
    let dependency = add_dependency_to_native_push_fixture(&fixture);
    fs::remove_file(
        fixture
            .store_dir
            .join(format!("{DEPENDENCY_HASH}-dependency")),
    )
    .expect("remove dependency payload so uploading it would fail");
    let nar_bytes = native_nar_bytes();
    let dependency_narinfo = signed_narinfo_with_store_path(
        &dependency,
        &nix32_sha256(&nar_bytes),
        nar_bytes.len() as u64,
        &[],
    );
    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind closure upstream");
    let upstream_address = upstream.local_addr().expect("inspect closure upstream");
    let upstream_server = thread::spawn(move || {
        let (mut dependency_stream, _) = upstream.accept().expect("accept dependency lookup");
        let dependency_request = read_http_request(&mut dependency_stream);
        assert!(
            String::from_utf8_lossy(&dependency_request)
                .starts_with(&format!("GET /{DEPENDENCY_HASH}.narinfo"))
        );
        write!(
            dependency_stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            dependency_narinfo.len(),
            dependency_narinfo,
        )
        .expect("write dependency hit");

        let (mut root_stream, _) = upstream.accept().expect("accept root lookup");
        let root_request = read_http_request(&mut root_stream);
        assert!(
            String::from_utf8_lossy(&root_request)
                .starts_with(&format!("GET /{STORE_HASH}.narinfo"))
        );
        write!(
            root_stream,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write root miss");
    });
    let upstream_url = format!("http://{upstream_address}");
    let key = trusted_upstream_key_for(&upstream_url, 7);

    let output = run_native_push_fixture_with_options(
        &fixture,
        &format!("http://{}", destination.address),
        "none",
        NativePushRunOptions {
            signing: true,
            insecure_http: true,
            extra_args: &[
                "--trusted-upstream",
                &upstream_url,
                "--trusted-upstream-key",
                &key,
            ],
            ..NativePushRunOptions::default()
        },
    );

    assert!(
        output.status.success(),
        "closure push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    upstream_server.join().expect("upstream server should exit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("skipped {dependency}: trusted upstream")));
    assert!(stdout.contains("uploaded 1, destination-present 0, trusted-upstream-present 1"));
    assert!(
        destination
            .data_dir
            .join(format!("{STORE_HASH}.narinfo"))
            .is_file(),
        "the dependent root should be uploaded"
    );
    assert!(
        !destination
            .data_dir
            .join(format!("{DEPENDENCY_HASH}.narinfo"))
            .exists(),
        "the upstream dependency should not be copied to the destination"
    );
    let (signal, status) = destination.stop();
    assert_clean_shutdown(signal, status);
}

struct NativePushFixture {
    tools: TempDir,
    invocation_log: PathBuf,
    netrc: PathBuf,
    signing_key: PathBuf,
    store_path: String,
    store_dir: PathBuf,
    state_dir: PathBuf,
}

fn native_push_fixture() -> NativePushFixture {
    let tools = tempfile::tempdir().expect("fake Nix directory should be created");
    let fake_nix = tools.path().join("nix");
    let invocation_log = tools.path().join("nix-invocations");
    let store_path = format!("/nix/store/{STORE_HASH}-narjar");
    let store_dir = tools.path().join("store");
    fs::create_dir(&store_dir).expect("native store directory should be created");
    fs::write(store_dir.join(format!("{STORE_HASH}-narjar")), NAR_BYTES)
        .expect("native store object should be written");
    let state_dir = tools.path().join("state");
    fs::create_dir(&state_dir).expect("native state directory should be created");
    fs::File::create(state_dir.join("gc.lock")).expect("native GC lock should be created");
    fs::create_dir_all(state_dir.join("gcroots/auto"))
        .expect("native automatic roots directory should be created");
    fs::create_dir(state_dir.join("db")).expect("native database directory should be created");
    fs::write(state_dir.join("db/schema"), "10\n")
        .expect("supported Nix schema version should be created");
    let native_nar = native_nar_bytes();
    let nar_hash = nix32_sha256(&native_nar);
    let nar_hash_sri = format!("sha256-{}", BASE64.encode(&Sha256::digest(&native_nar)));
    let fingerprint = format!("1;{store_path};sha256:{nar_hash};{};", native_nar.len());
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());
    let signature = format!("narjar-test:{}", BASE64.encode(&signature.to_bytes()));
    let database = sqlite::open(state_dir.join("db/db.sqlite"))
        .expect("native metadata database should be created");
    database
        .execute(
            "CREATE TABLE ValidPaths (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE NOT NULL,
                hash TEXT NOT NULL,
                registrationTime INTEGER NOT NULL,
                deriver TEXT,
                narSize INTEGER,
                ultimate INTEGER,
                sigs TEXT,
                ca TEXT
            );
            CREATE TABLE Refs (
                referrer INTEGER NOT NULL,
                reference INTEGER NOT NULL,
                PRIMARY KEY (referrer, reference)
            );
            CREATE TABLE SchemaMigrations (migration TEXT PRIMARY KEY NOT NULL);",
        )
        .expect("native metadata schema should be created");
    let mut insert = database
        .prepare(
            "INSERT INTO ValidPaths
             (id, path, hash, registrationTime, narSize, sigs)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .expect("native metadata insert should prepare");
    insert.bind((1, 1_i64)).expect("bind native path id");
    insert
        .bind((2, store_path.as_str()))
        .expect("bind native path");
    let native_nar_hash = format!("sha256:{}", hex_sha256(&Sha256::digest(&native_nar)));
    insert
        .bind((3, native_nar_hash.as_str()))
        .expect("bind native NAR hash");
    insert
        .bind((4, 1_i64))
        .expect("bind native registration time");
    insert
        .bind((5, native_nar.len() as i64))
        .expect("bind native NAR size");
    insert.bind((6, "")).expect("bind native signature");
    insert.next().expect("native metadata row should insert");
    let fake_nix_contents = format!(
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> \"$NIX_TEST_INVOCATIONS\"\n",
            "if [ \"$1\" = path-info ]; then\n",
            "  printf '%s\\n' '{{\"{store_path}\":{{\"ca\":null,\"deriver\":null,\"narHash\":\"{nar_hash_sri}\",\"narSize\":{nar_size},\"references\":[],\"signatures\":[\"{signature}\"]}}}}'\n",
            "else\n",
            "  printf '%s\\n' \"unexpected nix invocation: $*\" >&2\n",
            "  exit 1\n",
            "fi\n"
        ),
        store_path = store_path,
        nar_hash_sri = nar_hash_sri,
        signature = signature,
        nar_size = native_nar.len()
    );
    fs::write(&fake_nix, fake_nix_contents).expect("fake Nix should be written");
    fs::set_permissions(&fake_nix, fs::Permissions::from_mode(0o755))
        .expect("fake Nix should be executable");
    let netrc = tools.path().join("netrc");
    fs::write(
        &netrc,
        "machine 127.0.0.1 login narjar password test-write-token\n",
    )
    .expect("netrc should be written");
    crate::cache::test_support::make_private_file(&netrc).expect("netrc should be private");
    let signing_key = tools.path().join("secret-key");
    let mut secret = [0; 64];
    secret[..32].copy_from_slice(&[7; 32]);
    secret[32..].copy_from_slice(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    fs::write(
        &signing_key,
        format!("narjar-test:{}\n", BASE64.encode(&secret)),
    )
    .expect("native signing key should be written");
    crate::cache::test_support::make_private_file(&signing_key)
        .expect("native signing key should be private");

    NativePushFixture {
        tools,
        invocation_log,
        netrc,
        signing_key,
        store_path,
        store_dir,
        state_dir,
    }
}

fn hex_sha256(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Default)]
struct NativePushRunOptions<'a> {
    refresh: bool,
    timeout_seconds: Option<u64>,
    signing: bool,
    insecure_http: bool,
    extra_args: &'a [&'a str],
}

fn run_native_push_fixture(
    fixture: &NativePushFixture,
    target: &str,
    compression: &str,
    refresh: bool,
) -> Output {
    run_native_push_fixture_with_options(
        fixture,
        target,
        compression,
        NativePushRunOptions {
            refresh,
            ..NativePushRunOptions::default()
        },
    )
}

fn run_native_push_fixture_with_signing(
    fixture: &NativePushFixture,
    target: &str,
    compression: &str,
    refresh: bool,
) -> Output {
    run_native_push_fixture_with_options(
        fixture,
        target,
        compression,
        NativePushRunOptions {
            refresh,
            signing: true,
            ..NativePushRunOptions::default()
        },
    )
}

fn run_native_push_fixture_with_timeout(
    fixture: &NativePushFixture,
    target: &str,
    compression: &str,
    refresh: bool,
    timeout_seconds: Option<u64>,
) -> Output {
    run_native_push_fixture_with_options(
        fixture,
        target,
        compression,
        NativePushRunOptions {
            refresh,
            timeout_seconds,
            ..NativePushRunOptions::default()
        },
    )
}

fn run_native_push_fixture_with_options(
    fixture: &NativePushFixture,
    target: &str,
    compression: &str,
    options: NativePushRunOptions<'_>,
) -> Output {
    let original_path = std::env::var_os("PATH").expect("test PATH should be set");
    let path = format!(
        "{}:{}",
        fixture.tools.path().display(),
        original_path.to_string_lossy()
    );
    let mut args = vec![
        "push".to_owned(),
        "--to".to_owned(),
        target.to_owned(),
        "--compression".to_owned(),
        compression.to_owned(),
        "--netrc-file".to_owned(),
        fixture
            .netrc
            .to_str()
            .expect("netrc path should be UTF-8")
            .to_owned(),
    ];
    if let Some(timeout_seconds) = options.timeout_seconds {
        args.push("--timeout-seconds".to_owned());
        args.push(timeout_seconds.to_string());
    }
    if options.refresh {
        args.push("--refresh".to_owned());
    }
    if options.insecure_http {
        args.push("--insecure-http".to_owned());
    }
    if options.signing {
        args.push("--signing-key-file".to_owned());
        args.push(
            fixture
                .signing_key
                .to_str()
                .expect("signing key path should be UTF-8")
                .to_owned(),
        );
    }
    args.extend(
        options
            .extra_args
            .iter()
            .map(|argument| (*argument).to_owned()),
    );
    args.push(fixture.store_path.clone());
    command()
        .args(&args)
        .env("PATH", path)
        .env("NIX_TEST_INVOCATIONS", &fixture.invocation_log)
        .env("NIX_STORE_DIR", &fixture.store_dir)
        .env("NIX_STATE_DIR", &fixture.state_dir)
        .output()
        .expect("narjar push should run")
}

#[test]
fn native_push_honors_configured_http_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native timeout listener");
    let address = listener
        .local_addr()
        .expect("inspect native timeout listener");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept stalled native request");
        let request = read_http_request(&mut stream);
        let request = String::from_utf8_lossy(&request);
        assert!(
            request.starts_with("GET /") && request.contains(".narinfo"),
            "first request should be a narinfo lookup"
        );
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            drop(stream);
        });

        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept retried native request");
            let request = read_http_request(&mut stream);
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.starts_with("GET /") && request.contains(".narinfo"),
                "retries should repeat the narinfo lookup"
            );
            write!(
                stream,
                "HTTP/1.1 500 Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write timeout retry response");
        }
    });
    let fixture = native_push_fixture();
    let started = Instant::now();
    let output = run_native_push_fixture_with_timeout(
        &fixture,
        &format!("http://{address}"),
        "none",
        false,
        Some(1),
    );
    let elapsed = started.elapsed();
    server.join().expect("native timeout server should exit");

    assert!(
        !output.status.success(),
        "a timed-out push should fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        elapsed >= Duration::from_millis(800),
        "configured timeout should wait for the stalled request: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "configured timeout should avoid the server's full delay: {elapsed:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("narinfo lookup"),
        "failure should identify the failed lookup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_push_does_not_treat_a_malformed_200_narinfo_as_present() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind malformed narinfo listener");
    let address = listener
        .local_addr()
        .expect("inspect malformed narinfo listener");
    let expected_nar = native_nar_bytes();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept narinfo lookup");
        let request = read_http_request(&mut stream);
        assert!(
            String::from_utf8_lossy(&request).starts_with("GET /")
                && String::from_utf8_lossy(&request).contains(".narinfo"),
            "first request should look up the narinfo"
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write malformed narinfo response");

        let (mut stream, _) = listener.accept().expect("accept NAR upload");
        let request = read_http_request(&mut stream);
        assert!(
            String::from_utf8_lossy(&request).starts_with("PUT /nar/"),
            "malformed destination metadata must not suppress the NAR upload"
        );
        assert_eq!(&request[http_request_body_start(&request)..], expected_nar);
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write NAR upload response");

        let (mut stream, _) = listener.accept().expect("accept narinfo upload");
        let request = read_http_request(&mut stream);
        assert!(
            String::from_utf8_lossy(&request).starts_with("PUT /")
                && String::from_utf8_lossy(&request).contains(".narinfo"),
            "malformed destination metadata must still publish narinfo"
        );
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write narinfo upload response");
    });

    let fixture = native_push_fixture();
    let output = run_native_push_fixture(&fixture, &format!("http://{address}"), "none", false);
    server.join().expect("malformed narinfo server should exit");

    assert!(
        output.status.success(),
        "push should recover from malformed destination metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("uploaded 1, destination-present 0"),
        "malformed destination metadata must not be reported as present: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn native_push_retries_a_429_at_the_process_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native retry listener");
    let address = listener
        .local_addr()
        .expect("inspect native retry listener");
    let expected_nar = native_nar_bytes();
    let server = thread::spawn(move || {
        for (request_number, status) in [(0, 429), (1, 201), (2, 201)] {
            let (mut stream, _) = listener.accept().expect("accept native retry request");
            let request = read_http_request(&mut stream);
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("request should contain headers")
                + 4;
            let body = &request[header_end..];
            if request_number < 2 {
                assert_eq!(body, expected_nar, "every NAR retry must resend the body");
                assert!(
                    String::from_utf8_lossy(&request).starts_with("PUT /nar/"),
                    "request {request_number} should upload the NAR"
                );
            } else {
                assert!(
                    String::from_utf8_lossy(&request).starts_with("PUT /"),
                    "final request should publish narinfo"
                );
                assert!(body.starts_with(b"StorePath: "));
            }
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write native retry response");
        }
    });
    let fixture = native_push_fixture();
    let output = run_native_push_fixture(&fixture, &format!("http://{address}"), "none", true);
    server.join().expect("native retry server should exit");

    assert!(
        output.status.success(),
        "native push retry failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !fixture.invocation_log.exists(),
        "native push must not invoke Nix"
    );
}

#[test]
fn native_push_follows_a_307_for_the_nar_upload_at_the_process_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native redirect listener");
    let address = listener
        .local_addr()
        .expect("inspect native redirect listener");
    let expected_nar = native_nar_bytes();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept initial native upload");
        let request = read_http_request(&mut stream);
        let request_text = String::from_utf8_lossy(&request);
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("initial upload should contain headers")
            + 4;
        assert!(
            request_text.starts_with("PUT /nar/"),
            "initial request should upload the NAR"
        );
        assert_eq!(&request[header_end..], expected_nar);
        write!(
            stream,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /redirect-target/nar/upload.nar\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write native redirect response");

        let (mut stream, _) = listener.accept().expect("accept redirected native upload");
        let request = read_http_request(&mut stream);
        let request_text = String::from_utf8_lossy(&request);
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("redirected upload should contain headers")
            + 4;
        assert!(
            request_text.starts_with("PUT /redirect-target/nar/upload.nar"),
            "redirected request should use the Location path"
        );
        assert_eq!(&request[header_end..], expected_nar);
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write redirected native upload response");

        let (mut stream, _) = listener.accept().expect("accept native narinfo");
        let request = read_http_request(&mut stream);
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("narinfo request should contain headers")
            + 4;
        assert!(request[header_end..].starts_with(b"StorePath: "));
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write native narinfo response");
    });
    let fixture = native_push_fixture();
    let output = run_native_push_fixture(&fixture, &format!("http://{address}"), "none", true);
    server.join().expect("native redirect server should exit");

    assert!(
        output.status.success(),
        "native redirect push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !fixture.invocation_log.exists(),
        "native push must not invoke Nix"
    );
}

#[test]
fn native_push_retries_after_an_interrupted_upload_at_the_process_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native interruption listener");
    let address = listener
        .local_addr()
        .expect("inspect native interruption listener");
    let expected_nar = native_nar_bytes();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept interrupted native upload");
        let mut request = Vec::new();
        loop {
            let mut byte = [0; 1];
            stream
                .read_exact(&mut byte)
                .expect("read interrupted upload headers");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&request).starts_with("PUT /nar/"),
            "first request should upload the NAR"
        );
        let mut partial_body = [0; 1];
        stream
            .read_exact(&mut partial_body)
            .expect("read part of interrupted NAR");
        stream
            .shutdown(Shutdown::Both)
            .expect("close interrupted upload connection");

        let (mut stream, _) = listener.accept().expect("accept retried native upload");
        let request = read_http_request(&mut stream);
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("retried request should contain headers")
            + 4;
        assert_eq!(&request[header_end..], expected_nar);
        assert!(String::from_utf8_lossy(&request).starts_with("PUT /nar/"));
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write retried upload response");

        let (mut stream, _) = listener.accept().expect("accept native narinfo");
        let request = read_http_request(&mut stream);
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("narinfo request should contain headers")
            + 4;
        assert!(request[header_end..].starts_with(b"StorePath: "));
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write narinfo response");
    });
    let fixture = native_push_fixture();
    let output = run_native_push_fixture(&fixture, &format!("http://{address}"), "none", true);
    server
        .join()
        .expect("native interruption server should exit");

    assert!(
        output.status.success(),
        "native push interruption retry failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !fixture.invocation_log.exists(),
        "native push must not invoke Nix"
    );
}

fn assert_native_push_process_boundary(compression: &str, suffix: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native push listener");
    let address = listener.local_addr().expect("inspect native push listener");
    let expected_compression = compression.to_owned();
    let expected_suffix = suffix.to_owned();
    let expected_nar = native_nar_bytes();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept narinfo lookup");
        let request = read_http_request(&mut stream);
        assert!(
            String::from_utf8_lossy(&request)
                .starts_with("GET /00000000000000000000000000000000.narinfo"),
            "first request should look up the narinfo"
        );
        assert_http_request_has_no_authorization(&request);
        write!(
            stream,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write missing narinfo response");

        let (mut stream, _) = listener.accept().expect("accept NAR upload");
        let request = read_http_request(&mut stream);
        let header_end = http_request_body_start(&request);
        assert!(
            String::from_utf8_lossy(&request).starts_with("PUT /nar/"),
            "second request should upload the NAR"
        );
        assert_http_request_has_no_authorization(&request);
        assert!(
            !request[header_end..].is_empty(),
            "NAR upload should have a body"
        );
        if expected_compression == "none" {
            assert_eq!(&request[header_end..], expected_nar);
        } else {
            assert_ne!(&request[header_end..], expected_nar);
        }
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write NAR upload response");

        let (mut stream, _) = listener.accept().expect("accept narinfo upload");
        let request = read_http_request(&mut stream);
        let header_end = http_request_body_start(&request);
        assert!(
            String::from_utf8_lossy(&request)
                .starts_with("PUT /00000000000000000000000000000000.narinfo"),
            "third request should publish the narinfo"
        );
        assert_http_request_has_no_authorization(&request);
        let narinfo = String::from_utf8_lossy(&request[header_end..]);
        let url = narinfo
            .lines()
            .find_map(|line| line.strip_prefix("URL: nar/"))
            .expect("narinfo should contain a NAR URL");
        assert!(
            url.ends_with(&expected_suffix),
            "NAR URL should use {expected_suffix:?}"
        );
        assert!(narinfo.contains(&format!("Compression: {expected_compression}\n")));
        assert!(narinfo.contains(&format!("NarSize: {}\n", expected_nar.len())));
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write narinfo response");
    });
    let fixture = native_push_fixture();
    let output = run_native_push_fixture(
        &fixture,
        &format!("http://{address}?compression={compression}"),
        compression,
        false,
    );
    server.join().expect("native push server should exit");

    assert!(
        output.status.success(),
        "native push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "push complete: uploaded 1, destination-present 0, trusted-upstream-present 0; 1 workers\n"
    );

    assert!(
        !fixture.invocation_log.exists(),
        "native push must not invoke Nix"
    );
}
