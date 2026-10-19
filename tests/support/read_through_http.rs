use super::*;
use std::sync::mpsc;

enum PayloadEnd {
    Complete,
    Disconnect,
}

fn assert_edge_waits_for_the_exact_payload(end: PayloadEnd) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_url = format!("http://{}", upstream.local_addr().unwrap());
    let (paused, received_pause) = mpsc::channel();
    let (release, receive_release) = mpsc::channel();
    let successful = matches!(end, PayloadEnd::Complete);
    let upstream_thread = thread::spawn(move || {
        let (mut metadata, _) = upstream.accept().unwrap();
        let request = read_http_request(&mut metadata);
        assert!(
            String::from_utf8_lossy(&request).starts_with(&format!("GET /{STORE_HASH}.narinfo "))
        );
        let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
        write!(
            metadata,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{narinfo}",
            narinfo.len()
        )
        .unwrap();
        drop(metadata);

        let (mut payload, _) = upstream.accept().unwrap();
        let request = read_http_request(&mut payload);
        assert!(
            String::from_utf8_lossy(&request).starts_with(&format!("GET /nar/{NARJAR_HASH}.nar "))
        );
        write!(
            payload,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            NAR_BYTES.len()
        )
        .unwrap();
        payload.write_all(&NAR_BYTES[..3]).unwrap();
        paused.send(()).unwrap();
        receive_release
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        match end {
            PayloadEnd::Complete => payload.write_all(&NAR_BYTES[3..]).unwrap(),
            PayloadEnd::Disconnect => {}
        }
    });
    let edge = RunningServer::start_with_workers(
        "edge-publication-barrier",
        8,
        &[
            "--serve-source",
            "read-through",
            "--edge-upstream",
            &upstream_url,
            "--edge-max-fills",
            "1",
            "--max-in-flight",
            "2",
            "--min-free-bytes",
            "0",
        ],
    );
    let route = format!("/{STORE_HASH}.narinfo");
    let mut request = edge.open_request("GET", &route, &[]);
    received_pause
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    request
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut first = [0; 1];
    let error = request
        .read(&mut first)
        .expect_err("no positive or partial response before payload completion");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    assert!(!edge.data_dir.join(format!("{STORE_HASH}.narinfo")).exists());

    // Connection capacity is smaller than the worker pool. The downloading
    // request must keep the only download/wait slot; cached reads and health
    // checks stay available.
    let rejected_follower = edge.request("GET", &route);
    assert!(
        response_parts(&rejected_follower)
            .0
            .starts_with("HTTP/1.1 404")
    );
    assert!(
        response_parts(&edge.request("GET", "/healthz"))
            .0
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        response_parts(&edge.request("GET", "/metrics"))
            .0
            .starts_with("HTTP/1.1 200")
    );

    release.send(()).unwrap();
    request
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut response = Vec::new();
    request.read_to_end(&mut response).unwrap();
    upstream_thread.join().unwrap();
    let (headers, body) = response_parts(&response);
    if successful {
        assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
        assert!(headers.contains("Cache-Control: no-store"), "{headers}");
        assert!(String::from_utf8_lossy(&body).contains("Compression: none\n"));
        let payload = edge.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
        assert_eq!(response_parts(&payload).1, NAR_BYTES);
    } else {
        assert!(headers.starts_with("HTTP/1.1 404"), "{headers}");
        assert!(!edge.data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
        assert_eq!(
            fs::read_dir(edge.data_dir.join("nar/.tmp"))
                .unwrap()
                .count(),
            0
        );
    }
    for path in [&route, &format!("/nar/{NARJAR_HASH}.nar")] {
        let rejected = edge.request_with_body("PUT", path, &[], NAR_BYTES);
        assert!(response_parts(&rejected).0.starts_with("HTTP/1.1 405"));
    }
    let (signal, status) = edge.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn read_through_http_advertises_only_after_complete_durable_payload() {
    assert_edge_waits_for_the_exact_payload(PayloadEnd::Complete);
}

#[test]
fn read_through_http_turns_mid_payload_disconnect_into_a_clean_miss() {
    assert_edge_waits_for_the_exact_payload(PayloadEnd::Disconnect);
}

#[test]
fn doctor_accepts_the_edge_source_environment_for_local_checks() {
    let data_dir = init_data_dir("edge-doctor-environment");
    let output = run_with_env(
        &["doctor", "--data-dir", data_dir.to_str().unwrap(), "--json"],
        &[("NARJAR_SERVE_SOURCE", "read-through")],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("flat-cache"));
}

#[test]
fn read_through_http_failed_renewal_is_a_miss_without_revoking_the_payload() {
    use crate::cache::storage::{Directory, Storage, StoreHash, SupportedStorageBackend};
    let central = RunningServer::start("edge-renewal-central");
    assert!(
        response_parts(&central.request_with_body(
            "PUT",
            &format!("/nar/{NARJAR_HASH}.nar"),
            &[],
            NAR_BYTES
        ))
        .0
        .starts_with("HTTP/1.1 201")
    );
    assert!(
        response_parts(&central.request_with_body(
            "PUT",
            &format!("/{STORE_HASH}.narinfo"),
            &[],
            signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64).as_bytes()
        ))
        .0
        .starts_with("HTTP/1.1 201")
    );
    let upstream = format!("http://{}", central.address);
    let args = [
        "--serve-source",
        "read-through",
        "--edge-upstream",
        &upstream,
        "--edge-lease-seconds",
        "60",
        "--min-free-bytes",
        "0",
    ];
    let edge = RunningServer::start_with_workers("edge-renewal-capacity", 2, &args);
    let route = format!("/{STORE_HASH}.narinfo");
    assert!(
        response_parts(&edge.request("GET", &route))
            .0
            .starts_with("HTTP/1.1 200")
    );
    let (directory, signal, status) = edge.stop_preserving();
    assert_clean_shutdown(signal, status);
    let (signal, status) = central.stop();
    assert_clean_shutdown(signal, status);
    let mut storage = Storage::open(
        &Directory::open(directory.path()).unwrap(),
        SupportedStorageBackend::FLAT,
    )
    .unwrap();
    storage
        .force_advertisement_renewal_with_unavailable_reserve_for_test(
            StoreHash::parse(STORE_HASH).unwrap(),
        )
        .unwrap();
    drop(storage);
    let reserve = u64::MAX.to_string();
    let args = [
        "--serve-source",
        "read-through",
        "--edge-upstream",
        &upstream,
        "--edge-lease-seconds",
        "60",
        "--min-free-bytes",
        &reserve,
    ];
    let edge = RunningServer::start_in_with_workers(directory, 2, &args);
    for method in ["GET", "HEAD"] {
        let response = edge.request(method, &route);
        assert!(
            response_parts(&response).0.starts_with("HTTP/1.1 404"),
            "{method} must fail open when a new durable promise cannot be made: {}",
            response_parts(&response).0
        );
    }
    let response = edge.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
    assert!(response_parts(&response).0.starts_with("HTTP/1.1 200"));
    assert_eq!(response_parts(&response).1, NAR_BYTES);
    let (signal, status) = edge.stop();
    assert_clean_shutdown(signal, status);
}
