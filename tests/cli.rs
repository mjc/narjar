use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpStream},
    os::unix::fs::symlink,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, SystemTime},
};

const CONFIG_ENV: &[&str] = &[
    "NARJAR_DATA_DIR",
    "NARJAR_LISTEN",
    "NARJAR_WORKERS",
    "NARJAR_MAX_IN_FLIGHT",
    "NARJAR_MAX_NAR_BYTES",
    "NARJAR_MIN_FREE_BYTES",
];

const NAR_ID: &str = "0000000000000000000000000000000000000000000000000000";
const STORE_HASH: &str = "00000000000000000000000000000000";
const TEST_AUTHORIZATION: &str = "Basic bmFyamFyOnRlc3Qtd3JpdGUtdG9rZW4=";
const TEST_WRITE_TOKEN: &str =
    "test 4c6fe1d79dd5595d75e9b7c82dbdc4481996f7aea7143e7153c8eb5e9f94ea45\n";

fn signed_narinfo(nar_hash: &str, nar_size: u64) -> String {
    let store_path = format!("/nix/store/{STORE_HASH}-narjar");
    let fingerprint = format!("1;{store_path};sha256:{nar_hash};{nar_size};");
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());

    format!(
        "StorePath: {store_path}\n\
         URL: nar/{nar_hash}.nar\n\
         Compression: none\n\
         FileHash: sha256:{nar_hash}\n\
         FileSize: {nar_size}\n\
         NarHash: sha256:{nar_hash}\n\
         NarSize: {nar_size}\n\
         References: \n\
         Sig: narjar-test:{}\n",
        BASE64.encode(&signature.to_bytes())
    )
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_narjar"));
    for variable in CONFIG_ENV {
        command.env_remove(*variable);
    }
    command
}

fn run(args: &[&str]) -> Output {
    command().args(args).output().expect("narjar should run")
}

fn run_with_env(args: &[&str], environment: &[(&str, &str)]) -> Output {
    command()
        .args(args)
        .envs(environment.iter().copied())
        .output()
        .expect("narjar should run")
}

fn data_dir(test: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock should be after the Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("narjar-{test}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).expect("test data directory should be created");
    path
}

#[test]
fn serve_requires_data_dir() {
    let output = run(&["serve"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --data-dir is required\n"
    );
}

#[test]
fn serve_accepts_data_dir_from_environment() {
    let data_dir = data_dir("environment-data-dir");
    let output = run_with_env(
        &["serve", "--listen", "not-an-address"],
        &[(
            "NARJAR_DATA_DIR",
            data_dir.to_str().expect("temporary path should be UTF-8"),
        )],
    );
    fs::remove_dir_all(data_dir).expect("test data directory should be removed");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --listen must be an IP socket address\n"
    );
}

#[test]
fn serve_rejects_zero_workers() {
    let data_dir = data_dir("zero-workers");
    let output = run(&[
        "serve",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--workers",
        "0",
    ]);
    fs::remove_dir_all(data_dir).expect("test data directory should be removed");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --workers must be greater than zero\n"
    );
}

#[test]
fn serve_rejects_zero_workers_from_environment() {
    let missing = data_dir("environment-zero-workers");
    fs::remove_dir_all(&missing).expect("test data directory should be removed");
    let output = run_with_env(
        &[
            "serve",
            "--data-dir",
            missing.to_str().expect("temporary path should be UTF-8"),
        ],
        &[("NARJAR_WORKERS", "0")],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: NARJAR_WORKERS must be greater than zero\n"
    );
}

#[test]
fn serve_flag_overrides_environment() {
    let missing = data_dir("flag-precedence");
    fs::remove_dir_all(&missing).expect("test data directory should be removed");
    let output = run_with_env(
        &[
            "serve",
            "--data-dir",
            missing.to_str().expect("temporary path should be UTF-8"),
            "--workers",
            "1",
        ],
        &[("NARJAR_WORKERS", "0")],
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        format!(
            "narjar: data directory is not a directory: {}\n",
            missing.display()
        )
    );
}

#[test]
fn serve_rejects_duplicate_options() {
    let missing = data_dir("duplicate-workers");
    fs::remove_dir_all(&missing).expect("test data directory should be removed");
    let output = run(&[
        "serve",
        "--data-dir",
        missing.to_str().expect("temporary path should be UTF-8"),
        "--workers",
        "1",
        "--workers",
        "2",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --workers may only be specified once\n"
    );
}

#[test]
fn serve_rejects_zero_request_limit() {
    let missing = data_dir("zero-request-limit");
    fs::remove_dir_all(&missing).expect("test data directory should be removed");
    let output = run(&[
        "serve",
        "--data-dir",
        missing.to_str().expect("temporary path should be UTF-8"),
        "--max-in-flight",
        "0",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --max-in-flight must be greater than zero\n"
    );
}

#[test]
fn serve_rejects_zero_nar_limit() {
    let missing = data_dir("zero-nar-limit");
    fs::remove_dir_all(&missing).expect("test data directory should be removed");
    let output = run(&[
        "serve",
        "--data-dir",
        missing.to_str().expect("temporary path should be UTF-8"),
        "--max-nar-bytes",
        "0",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --max-nar-bytes must be greater than zero\n"
    );
}

struct RunningServer {
    child: Child,
    data_dir: PathBuf,
    startup_line: String,
    address: String,
}

impl RunningServer {
    fn start(test: &str) -> Self {
        Self::start_with_args(test, &[])
    }

    fn start_with_args(test: &str, extra_args: &[&str]) -> Self {
        Self::start_with_auth(test, extra_args, None)
    }

    fn start_with_read_tokens(test: &str, read_tokens: &str) -> Self {
        Self::start_with_auth(test, &[], Some(read_tokens))
    }

    fn start_with_auth(test: &str, extra_args: &[&str], read_tokens: Option<&str>) -> Self {
        let data_dir = data_dir(test);
        let auth_dir = data_dir.join("auth");
        fs::create_dir(&auth_dir).expect("test auth directory should be created");
        let write_tokens = auth_dir.join("write.tokens");
        fs::write(&write_tokens, TEST_WRITE_TOKEN).expect("test write token should be written");
        fs::set_permissions(
            &write_tokens,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .expect("test write token should be private");
        if let Some(contents) = read_tokens {
            let read_tokens = auth_dir.join("read.tokens");
            fs::write(&read_tokens, contents).expect("test read tokens should be written");
            fs::set_permissions(
                &read_tokens,
                <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .expect("test read tokens should be private");
        }
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let trusted_key = format!(
            "narjar-test:{}\n",
            BASE64.encode(signing_key.verifying_key().as_bytes())
        );
        fs::write(data_dir.join("trusted-public-keys"), trusted_key)
            .expect("test trusted key should be written");
        let mut process = command();
        process
            .args([
                "serve",
                "--data-dir",
                data_dir.to_str().expect("temporary path should be UTF-8"),
                "--listen",
                "127.0.0.1:0",
                "--workers",
                "1",
            ])
            .args(extra_args);
        let mut child = process
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("narjar should start");

        let mut startup_line = String::new();
        BufReader::new(child.stdout.take().expect("stdout should be piped"))
            .read_line(&mut startup_line)
            .expect("startup line should be readable");
        let address = startup_line
            .split_whitespace()
            .nth(1)
            .and_then(|url| url.strip_prefix("http://"))
            .expect("startup line should contain listener address")
            .to_owned();

        Self {
            child,
            data_dir,
            startup_line,
            address,
        }
    }

    fn request(&self, method: &str, path: &str) -> Vec<u8> {
        self.request_with_headers(method, path, &[])
    }

    fn request_with_headers(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut stream = self.open_request(method, path, headers);
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        response
    }

    fn request_with_body(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut headers = headers.to_vec();
        if method == "PUT" {
            headers.push(("Authorization", TEST_AUTHORIZATION));
        }
        self.raw_request_with_body(method, path, &headers, body)
    }

    fn raw_request_with_body(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let content_length = body.len().to_string();
        let mut headers = headers.to_vec();
        headers.push(("Content-Length", content_length.as_str()));
        let mut stream = self.open_raw_request(method, path, &headers);
        stream.write_all(body).expect("write request body");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        response
    }

    fn open_request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> TcpStream {
        let mut headers = headers.to_vec();
        if method == "PUT" {
            headers.push(("Authorization", TEST_AUTHORIZATION));
        }
        self.open_raw_request(method, path, &headers)
    }

    fn open_raw_request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> TcpStream {
        let mut stream = TcpStream::connect(&self.address).expect("connect to narjar");
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.address
        )
        .expect("write request");
        for &(name, value) in headers {
            write!(stream, "{name}: {value}\r\n").expect("write request header");
        }
        write!(stream, "\r\n").expect("finish request");
        stream
    }

    fn stop(mut self) -> (ExitStatus, ExitStatus) {
        let signal = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill should run");

        let mut status = None;
        for _ in 0..100 {
            status = self
                .child
                .try_wait()
                .expect("child status should be readable");
            if status.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        if status.is_none() {
            self.child.kill().expect("hung child should be killed");
            let _ = self.child.wait();
        }
        fs::remove_dir_all(&self.data_dir).expect("test data directory should be removed");

        (signal, status.expect("narjar should stop after SIGTERM"))
    }
}

#[test]
fn serve_reports_listener_and_stops_on_sigterm() {
    let server = RunningServer::start("lifecycle");

    for directory in ["nar", ".tmp", "realisations"] {
        assert!(
            server.data_dir.join(directory).is_dir(),
            "daemon did not initialize {directory}"
        );
    }
    assert!(
        server
            .startup_line
            .starts_with("listening http://127.0.0.1:"),
        "unexpected startup line: {:?}",
        server.startup_line
    );
    assert!(
        server.startup_line.ends_with(
            " workers=1 max_in_flight=64 max_nar_bytes=17179869184 min_free_bytes=1073741824\n"
        ),
        "startup line omits effective limits: {:?}",
        server.startup_line
    );

    let (signal, status) = server.stop();
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn nix_cache_info_get_and_head_match_contract() {
    let server = RunningServer::start("nix-cache-info");
    let get = String::from_utf8(server.request("GET", "/nix-cache-info"))
        .expect("GET response should be UTF-8");
    let head = String::from_utf8(server.request("HEAD", "/nix-cache-info"))
        .expect("HEAD response should be UTF-8");
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");

    let body = "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
    for response in [&get, &head] {
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response:?}");
        assert!(
            response.contains("Content-Type: text/x-nix-cache-info\r\n"),
            "{response:?}"
        );
        assert!(response.contains("Content-Length: 51\r\n"), "{response:?}");
        assert!(
            response.contains("Cache-Control: public, max-age=3600\r\n"),
            "{response:?}"
        );
    }
    assert!(get.ends_with(&format!("\r\n\r\n{body}")), "{get:?}");
    assert!(head.ends_with("\r\n\r\n"), "{head:?}");
}

#[test]
fn published_narinfo_and_nar_get_head_are_pair_gated() {
    let server = RunningServer::start("published-pair");
    let narinfo = format!("URL: nar/{NAR_ID}.nar\n");
    fs::write(
        server.data_dir.join(format!("{STORE_HASH}.narinfo")),
        &narinfo,
    )
    .expect("write narinfo fixture");

    let missing = String::from_utf8(server.request("GET", &format!("/{STORE_HASH}.narinfo")))
        .expect("missing response should be UTF-8");
    assert!(
        missing.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{missing:?}"
    );

    let nar_bytes = b"known NAR bytes";
    fs::write(server.data_dir.join(format!("nar/{NAR_ID}.nar")), nar_bytes)
        .expect("write NAR fixture");

    let narinfo_get = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let narinfo_head = server.request("HEAD", &format!("/{STORE_HASH}.narinfo"));
    let nar_get = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    let nar_head = server.request("HEAD", &format!("/nar/{NAR_ID}.nar"));
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");

    let split = |response: &[u8]| {
        response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .expect("response must contain a header terminator")
    };

    let narinfo_get_body = split(&narinfo_get);
    let narinfo_head_body = split(&narinfo_head);
    let nar_get_body = split(&nar_get);
    let nar_head_body = split(&nar_head);
    let narinfo_get_headers =
        String::from_utf8_lossy(&narinfo_get[..narinfo_get_body]).into_owned();
    let narinfo_head_headers =
        String::from_utf8_lossy(&narinfo_head[..narinfo_head_body]).into_owned();
    let nar_get_headers = String::from_utf8_lossy(&nar_get[..nar_get_body]).into_owned();
    let nar_head_headers = String::from_utf8_lossy(&nar_head[..nar_head_body]).into_owned();

    for headers in [&narinfo_get_headers, &narinfo_head_headers] {
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers:?}");
        assert!(
            headers.contains("Content-Type: text/x-nix-narinfo\r\n"),
            "{headers:?}"
        );
        assert!(
            headers.contains(&format!("Content-Length: {}\r\n", narinfo.len())),
            "{headers:?}"
        );
        assert!(
            headers.contains("Cache-Control: public, max-age=31536000, immutable\r\n"),
            "{headers:?}"
        );
    }
    for headers in [&nar_get_headers, &nar_head_headers] {
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers:?}");
        assert!(
            headers.contains("Content-Type: application/x-nix-nar\r\n"),
            "{headers:?}"
        );
        assert!(
            headers.contains(&format!("Content-Length: {}\r\n", nar_bytes.len())),
            "{headers:?}"
        );
        assert!(headers.contains("Accept-Ranges: bytes\r\n"), "{headers:?}");
        assert!(
            headers.contains("Cache-Control: public, max-age=31536000, immutable\r\n"),
            "{headers:?}"
        );
    }

    assert_eq!(&narinfo_get[narinfo_get_body..], narinfo.as_bytes());
    assert!(narinfo_head[narinfo_head_body..].is_empty());
    assert_eq!(&nar_get[nar_get_body..], nar_bytes);
    assert!(nar_head[nar_head_body..].is_empty());
}
fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        if body.is_empty() {
            break;
        }
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk must start with a size");
        let size = std::str::from_utf8(&body[..line_end])
            .ok()
            .and_then(|size| size.split(';').next())
            .and_then(|size| usize::from_str_radix(size, 16).ok())
            .expect("chunk size must be hexadecimal");
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        assert!(body.len() >= size + 2, "chunk body must be complete");
        decoded.extend_from_slice(&body[..size]);
        assert_eq!(&body[size..size + 2], b"\r\n");
        body = &body[size + 2..];
    }
    decoded
}

fn response_parts(response: &[u8]) -> (String, Vec<u8>) {
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("response must contain a header terminator");
    let headers = String::from_utf8_lossy(&response[..body]).into_owned();
    let body = if headers.contains("Transfer-Encoding: chunked\r\n") {
        decode_chunked(&response[body..])
    } else {
        response[body..].to_vec()
    };
    (headers, body)
}

#[test]
fn nar_get_and_head_support_one_byte_range() {
    let server = RunningServer::start("nar-ranges");
    let nar_bytes = b"0123456789";
    fs::write(server.data_dir.join(format!("nar/{NAR_ID}.nar")), nar_bytes)
        .expect("write NAR fixture");
    let path = format!("/nar/{NAR_ID}.nar");
    let request = |method, range| server.request_with_headers(method, &path, &[("Range", range)]);

    let closed = request("GET", "bytes=2-5");
    let open = request("GET", "bytes=5-");
    let suffix = request("GET", "bytes=-4");
    let head = request("HEAD", "bytes=2-5");
    let unsatisfiable = request("GET", "bytes=20-");
    let multiple = request("GET", "bytes=0-1,4-5");
    let malformed = request("GET", "bytes=wat");
    let empty = request("GET", "bytes=-");
    let overflow = request("GET", "bytes=18446744073709551616-");
    let reversed = request("GET", "bytes=8-2");
    let duplicate = server.request_with_headers(
        "GET",
        &path,
        &[("Range", "bytes=0-1"), ("Range", "bytes=4-5")],
    );
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");

    for (response, content_range, body) in [
        (&closed, "bytes 2-5/10", &b"2345"[..]),
        (&open, "bytes 5-9/10", &b"56789"[..]),
        (&suffix, "bytes 6-9/10", &b"6789"[..]),
    ] {
        let (headers, actual_body) = response_parts(response);
        assert!(
            headers.starts_with("HTTP/1.1 206 Partial Content\r\n"),
            "{headers:?}"
        );
        assert!(
            headers.contains(&format!("Content-Range: {content_range}\r\n")),
            "{headers:?}"
        );
        assert!(
            headers.contains(&format!("Content-Length: {}\r\n", body.len())),
            "{headers:?}"
        );
        assert_eq!(actual_body, body);
    }

    let (head_headers, head_body) = response_parts(&head);
    assert!(
        head_headers.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{head_headers:?}"
    );
    assert!(
        head_headers.contains("Content-Range: bytes 2-5/10\r\n"),
        "{head_headers:?}"
    );
    assert!(
        head_headers.contains("Content-Length: 4\r\n"),
        "{head_headers:?}"
    );
    assert!(head_body.is_empty());

    for response in [&unsatisfiable, &reversed] {
        let (headers, body) = response_parts(response);
        assert!(
            headers.starts_with("HTTP/1.1 416 Range Not Satisfiable\r\n"),
            "{headers:?}"
        );
        assert!(
            headers.contains("Content-Range: bytes */10\r\n"),
            "{headers:?}"
        );
        assert!(body.is_empty());
    }

    for response in [&multiple, &malformed, &empty, &overflow, &duplicate] {
        let (headers, body) = response_parts(response);
        assert!(
            headers.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{headers:?}"
        );
        assert!(body.is_empty());
    }
}

#[test]
fn read_routes_distinguish_bad_methods_names_and_unsupported_surfaces() {
    let server = RunningServer::start("read-negatives");

    let wrong_method = server.request("POST", "/nix-cache-info");
    let invalid_routes = [
        format!("/{}.narinfo", &STORE_HASH[..STORE_HASH.len() - 1]),
        format!("/nar/{}.nar", &NAR_ID[..NAR_ID.len() - 1]),
        format!("/nar/{NAR_ID}.nar/extra"),
        "//nix-cache-info".to_owned(),
    ]
    .map(|path| server.request("GET", &path));
    let unsupported_routes = [
        format!("/{STORE_HASH}.ls"),
        format!("/log/{STORE_HASH}"),
        "/realisations/example.doi".to_owned(),
        "/query-paths".to_owned(),
    ]
    .map(|path| server.request("GET", &path));
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");

    let (headers, body) = response_parts(&wrong_method);
    assert!(
        headers.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{headers:?}"
    );
    assert!(headers.contains("Allow: GET, HEAD\r\n"), "{headers:?}");
    assert!(body.is_empty());

    for response in invalid_routes {
        let (headers, body) = response_parts(&response);
        assert!(
            headers.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{headers:?}"
        );
        assert!(body.is_empty());
    }

    for response in unsupported_routes {
        let (headers, body) = response_parts(&response);
        assert!(
            headers.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{headers:?}"
        );
        assert!(body.is_empty());
    }
}

#[test]
fn nar_reads_survive_unlink_and_aborted_slow_clients_without_exposing_temps() {
    let server = RunningServer::start("nar-read-races");
    let nar_path = server.data_dir.join(format!("nar/{NAR_ID}.nar"));
    let nar_bytes = vec![0x5a; 8 * 1024 * 1024];
    fs::write(&nar_path, &nar_bytes).expect("write large NAR fixture");
    let path = format!("/nar/{NAR_ID}.nar");

    let range = format!("bytes=0-{}", nar_bytes.len() - 1);
    let mut deleting_stream = server.open_request("GET", &path, &[("Range", &range)]);
    deleting_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut deleting_response = Vec::new();
    let mut chunk = [0; 8192];
    while !deleting_response
        .windows(4)
        .any(|window| window == b"\r\n\r\n")
    {
        let read = deleting_stream
            .read(&mut chunk)
            .expect("read response headers");
        assert_ne!(read, 0, "response ended before headers");
        deleting_response.extend_from_slice(&chunk[..read]);
    }

    fs::remove_file(&nar_path).expect("unlink open NAR");
    deleting_stream
        .read_to_end(&mut deleting_response)
        .expect("finish unlinked NAR response");
    let (headers, body) = response_parts(&deleting_response);
    assert!(
        headers.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{headers:?}"
    );
    assert_eq!(body.len(), nar_bytes.len());
    assert!(body.iter().all(|&byte| byte == 0x5a));

    let missing = server.request("GET", &path);
    let (missing_headers, missing_body) = response_parts(&missing);
    assert!(
        missing_headers.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{missing_headers:?}"
    );
    assert!(missing_body.is_empty());

    fs::write(
        server.data_dir.join(".tmp/read-race-unvalidated"),
        b"temporary bytes",
    )
    .expect("write temporary fixture");
    for temp_path in [
        "/.tmp/read-race-unvalidated",
        &format!("/nar/{NAR_ID}.nar.tmp"),
    ] {
        let response = server.request("GET", temp_path);
        let (headers, _) = response_parts(&response);
        assert!(!headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers:?}");
    }

    let sparse = fs::File::create(&nar_path).expect("create sparse NAR");
    let sparse_length = 64_u64 * 1024 * 1024;
    sparse.set_len(sparse_length).expect("size sparse NAR");
    drop(sparse);

    let head = server.request("HEAD", &path);
    let (head_headers, head_body) = response_parts(&head);
    assert!(
        head_headers.starts_with("HTTP/1.1 200 OK\r\n"),
        "{head_headers:?}"
    );
    assert!(
        head_headers.contains(&format!("Content-Length: {sparse_length}\r\n")),
        "{head_headers:?}"
    );
    assert!(head_body.is_empty());

    let mut aborted = server.open_request("GET", &path, &[]);
    aborted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let read = aborted
        .read(&mut chunk)
        .expect("read initial response bytes");
    assert_ne!(read, 0, "response should start before abort");
    drop(aborted);

    let after_abort = server.request("GET", "/nix-cache-info");
    let (after_abort_headers, _) = response_parts(&after_abort);
    let (signal, status) = server.stop();

    assert!(
        after_abort_headers.starts_with("HTTP/1.1 200 OK\r\n"),
        "{after_abort_headers:?}"
    );
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn read_misses_do_not_hide_corrupt_or_unreadable_finals() {
    let server = RunningServer::start("read-errors");
    let narinfo_path = server.data_dir.join(format!("{STORE_HASH}.narinfo"));
    fs::write(&narinfo_path, [0xff]).expect("write corrupt narinfo");

    let corrupt_narinfo = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let (corrupt_headers, corrupt_body) = response_parts(&corrupt_narinfo);
    assert!(
        corrupt_headers.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "{corrupt_headers:?}"
    );
    assert!(corrupt_body.is_empty());
    fs::remove_file(narinfo_path).expect("remove corrupt narinfo");

    let nar_path = server.data_dir.join(format!("nar/{NAR_ID}.nar"));
    symlink(nar_path.file_name().expect("NAR file name"), &nar_path)
        .expect("create unreadable final");
    let unreadable_nar = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    let (unreadable_headers, unreadable_body) = response_parts(&unreadable_nar);
    assert!(
        unreadable_headers.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "{unreadable_headers:?}"
    );
    assert!(unreadable_body.is_empty());
    fs::remove_file(&nar_path).expect("remove unreadable final");

    let missing_nar = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    let (missing_headers, missing_body) = response_parts(&missing_nar);
    let (signal, status) = server.stop();

    assert!(
        missing_headers.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{missing_headers:?}"
    );
    assert!(missing_body.is_empty());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn nar_put_streams_hash_checks_and_retries_immutably() {
    const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";

    let server = RunningServer::start("nar-put");
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let created = server.request_with_body("PUT", &path, &[], b"narjar");
    let identical = server.request_with_body("PUT", &path, &[], b"narjar");
    let mismatch = server.request_with_body("PUT", &format!("/nar/{NAR_ID}.nar"), &[], b"narjar");
    let missing_length = server.request("PUT", &path);
    let published = fs::read(server.data_dir.join(format!("nar/{NARJAR_HASH}.nar")));
    let mismatched_path = server.data_dir.join(format!("nar/{NAR_ID}.nar"));
    let (signal, status) = server.stop();

    for (response, expected_status) in [
        (&created, "HTTP/1.1 201 Created\r\n"),
        (&identical, "HTTP/1.1 200 OK\r\n"),
        (&mismatch, "HTTP/1.1 422 Unprocessable Entity\r\n"),
        (&missing_length, "HTTP/1.1 411 Length Required\r\n"),
    ] {
        let (headers, body) = response_parts(response);
        assert!(headers.starts_with(expected_status), "{headers:?}");
        assert!(body.is_empty());
    }
    assert_eq!(published.expect("published NAR"), b"narjar");
    assert!(!mismatched_path.exists());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn narinfo_put_rejects_unsigned_metadata_without_publication() {
    const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    let server = RunningServer::start("narinfo-put-unsigned");
    let nar_path = format!("/nar/{NARJAR_HASH}.nar");
    let nar_created = server.request_with_body("PUT", &nar_path, &[], b"narjar");
    let narinfo = format!(
        "StorePath: /nix/store/{STORE_HASH}-narjar\n\
         URL: nar/{NARJAR_HASH}.nar\n\
         Compression: none\n\
         FileHash: sha256:{NARJAR_HASH}\n\
         FileSize: 6\n\
         NarHash: sha256:{NARJAR_HASH}\n\
         NarSize: 6\n\
         References: \n"
    );
    let rejected = server.request_with_body(
        "PUT",
        &format!("/{STORE_HASH}.narinfo"),
        &[],
        narinfo.as_bytes(),
    );
    let published = server.data_dir.join(format!("{STORE_HASH}.narinfo"));
    let (signal, status) = server.stop();

    assert!(
        response_parts(&nar_created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    let (headers, body) = response_parts(&rejected);
    assert!(
        headers.starts_with("HTTP/1.1 422 Unprocessable Entity\r\n"),
        "{headers:?}"
    );
    assert!(body.is_empty());
    assert!(!published.exists());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn narinfo_put_accepts_a_trusted_nix_signature() {
    const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    let server = RunningServer::start("narinfo-put-trusted");
    let nar_created =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], b"narjar");
    let narinfo = signed_narinfo(NARJAR_HASH, 6);
    let path = format!("/{STORE_HASH}.narinfo");
    let created = server.request_with_body("PUT", &path, &[], narinfo.as_bytes());
    let identical = server.request_with_body("PUT", &path, &[], narinfo.as_bytes());
    let visible = server.request("GET", &path);
    let (signal, status) = server.stop();

    assert!(
        response_parts(&nar_created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    for (response, expected) in [
        (&created, "HTTP/1.1 201 Created\r\n"),
        (&identical, "HTTP/1.1 200 OK\r\n"),
    ] {
        let (headers, body) = response_parts(response);
        assert!(headers.starts_with(expected), "{headers:?}");
        assert!(body.is_empty());
    }
    let (headers, body) = response_parts(&visible);
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers:?}");
    assert_eq!(body, narinfo.as_bytes());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn nar_put_rejects_encoded_oversized_and_truncated_bodies() {
    const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    let path = format!("/nar/{NARJAR_HASH}.nar");

    let server = RunningServer::start("nar-put-invalid");
    let encoded =
        server.request_with_body("PUT", &path, &[("Content-Encoding", "gzip")], b"narjar");
    let compressed = server.request_with_body("PUT", &format!("{path}.xz"), &[], b"narjar");

    let mut truncated_stream = server.open_request("PUT", &path, &[("Content-Length", "7")]);
    truncated_stream
        .write_all(b"narjar")
        .expect("write truncated request body");
    truncated_stream
        .shutdown(Shutdown::Write)
        .expect("finish truncated request");
    let mut truncated = Vec::new();
    truncated_stream
        .read_to_end(&mut truncated)
        .expect("read truncated response");

    let final_path = server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
    let temp_is_empty = fs::read_dir(server.data_dir.join(".tmp"))
        .expect("read temp directory")
        .next()
        .is_none();
    let (signal, status) = server.stop();

    let limited = RunningServer::start_with_args("nar-put-oversized", &["--max-nar-bytes", "5"]);
    let oversized = limited.request_with_body("PUT", &path, &[], b"narjar");
    let oversized_path = limited.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
    let (limited_signal, limited_status) = limited.stop();

    for (case, response, expected_status) in [
        (
            "encoded",
            &encoded,
            "HTTP/1.1 415 Unsupported Media Type\r\n",
        ),
        (
            "compressed",
            &compressed,
            "HTTP/1.1 415 Unsupported Media Type\r\n",
        ),
        (
            "oversized",
            &oversized,
            "HTTP/1.1 413 Payload Too Large\r\n",
        ),
    ] {
        assert!(!response.is_empty(), "{case} response is empty");
        let (headers, body) = response_parts(response);
        assert!(headers.starts_with(expected_status), "{case}: {headers:?}");
        assert!(body.is_empty(), "{case}");
    }
    assert!(!final_path.exists());
    assert!(
        truncated.is_empty(),
        "truncated request closes without a response"
    );
    assert!(temp_is_empty);
    assert!(!oversized_path.exists());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
    assert!(limited_signal.success(), "SIGTERM should be sent");
    assert!(limited_status.success(), "narjar should shut down cleanly");
}

#[test]
fn nar_put_preserves_the_configured_free_space_reserve() {
    const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    let server = RunningServer::start_with_args(
        "nar-put-reserve",
        &["--min-free-bytes", "18446744073709551615"],
    );
    let response =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], b"narjar");
    let final_path = server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
    let (signal, status) = server.stop();
    let (headers, body) = response_parts(&response);

    assert!(
        headers.starts_with("HTTP/1.1 507 Insufficient Storage\r\n"),
        "{headers:?}"
    );
    assert!(body.is_empty());
    assert!(!final_path.exists());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn saturated_request_limit_rejects_excess_work() {
    let server = RunningServer::start_with_args("request-saturation", &["--max-in-flight", "1"]);
    let nar_path = server.data_dir.join(format!("nar/{NAR_ID}.nar"));
    fs::write(&nar_path, vec![0x5a; 8 * 1024 * 1024]).expect("write large NAR fixture");
    let path = format!("/nar/{NAR_ID}.nar");
    let mut blocked = server.open_request("GET", &path, &[]);
    blocked
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set slow response timeout");
    let mut started_response = Vec::new();
    let mut chunk = [0; 8192];
    while !started_response
        .windows(4)
        .any(|window| window == b"\r\n\r\n")
    {
        let read = blocked
            .read(&mut chunk)
            .expect("read slow response headers");
        assert_ne!(read, 0, "slow response ended before headers");
        started_response.extend_from_slice(&chunk[..read]);
    }

    let mut rejected = server.open_request("GET", "/nix-cache-info", &[]);
    rejected
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set response timeout");
    let mut response = Vec::new();
    let _ = rejected.read_to_end(&mut response);

    assert!(
        response.starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"),
        "{response:?}"
    );

    drop(blocked);
    let (signal, status) = server.stop();
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn writes_require_valid_basic_auth_before_route_or_storage() {
    const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    let server = RunningServer::start("write-auth");
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let missing = server.raw_request_with_body("PUT", &path, &[], b"narjar");
    let malformed =
        server.raw_request_with_body("PUT", &path, &[("Authorization", "Basic !!!")], b"narjar");
    let public_read = server.request("GET", "/nix-cache-info");
    let final_path = server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
    let (signal, status) = server.stop();

    for response in [missing, malformed] {
        let (headers, body) = response_parts(&response);
        assert!(
            headers.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{headers:?}"
        );
        assert!(
            headers.contains("WWW-Authenticate: Basic realm=\"narjar\"\r\n"),
            "{headers:?}"
        );
        assert!(body.is_empty());
    }
    assert!(
        public_read.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "{public_read:?}"
    );
    assert!(!final_path.exists());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn configured_empty_read_token_set_stays_private() {
    let server = RunningServer::start_with_read_tokens("empty-private-read", "");
    let response = server.request("GET", "/nix-cache-info");
    let (signal, status) = server.stop();
    let (headers, body) = response_parts(&response);

    assert!(
        headers.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{headers:?}"
    );
    assert!(
        headers.contains("WWW-Authenticate: Basic realm=\"narjar\"\r\n"),
        "{headers:?}"
    );
    assert!(body.is_empty());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}
