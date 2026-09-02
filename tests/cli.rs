use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpStream},
    ops::Deref,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const CONFIG_ENV: &[&str] = &[
    "NARJAR_DATA_DIR",
    "NARJAR_LISTEN",
    "NARJAR_WORKERS",
    "NARJAR_MAX_IN_FLIGHT",
    "NARJAR_MAX_NAR_BYTES",
    "NARJAR_MIN_FREE_BYTES",
];

const NAR_ID: &str = "0000000000000000000000000000000000000000000000000000";
const NAR_BYTES: &[u8] = b"narjar";
const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
const CACHE_INFO: &[u8] = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
const STORE_HASH: &str = "00000000000000000000000000000000";
const TEST_AUTHORIZATION: &str = "Basic bmFyamFyOnRlc3Qtd3JpdGUtdG9rZW4=";
const TEST_WRITE_TOKEN: &str =
    "test 4c6fe1d79dd5595d75e9b7c82dbdc4481996f7aea7143e7153c8eb5e9f94ea45\n";

fn signed_narinfo(nar_hash: &str, nar_size: u64) -> String {
    signed_narinfo_for(STORE_HASH, nar_hash, nar_size)
}

fn signed_narinfo_for(store_hash: &str, nar_hash: &str, nar_size: u64) -> String {
    signed_narinfo_for_with_references(store_hash, nar_hash, nar_size, &[])
}

fn signed_narinfo_for_with_references(
    store_hash: &str,
    nar_hash: &str,
    nar_size: u64,
    reference_hashes: &[&str],
) -> String {
    let store_path = format!("/nix/store/{store_hash}-narjar");
    let references = reference_hashes
        .iter()
        .map(|hash| format!("/nix/store/{hash}-narjar"))
        .collect::<Vec<_>>();
    let fingerprint = format!(
        "1;{store_path};sha256:{nar_hash};{nar_size};{}",
        references.join(",")
    );
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());

    format!(
        "StorePath: {store_path}\nURL: nar/{nar_hash}.nar\nCompression: none\nFileHash: sha256:{nar_hash}\nFileSize: {nar_size}\nNarHash: sha256:{nar_hash}\nNarSize: {nar_size}\nReferences: {}\nSig: narjar-test:{}\n",
        references.join(" "),
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

struct TestDir(TempDir);

impl TestDir {
    fn path(&self) -> &Path {
        self.0.path()
    }

    fn close(self) -> std::io::Result<()> {
        self.0.close()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

fn data_dir(test: &str) -> TestDir {
    TestDir(
        tempfile::Builder::new()
            .prefix(&format!("narjar-{test}-"))
            .tempdir()
            .expect("test data directory should be created"),
    )
}

fn missing_data_dir(test: &str) -> PathBuf {
    let directory = data_dir(test);
    let path = directory.path().to_owned();
    directory
        .close()
        .expect("test data directory should be removed");
    path
}

#[test]
fn serve_requires_data_dir() {
    let output = run(&["serve"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "error: one or more required arguments were not provided\n"
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

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "error: invalid value for one of the arguments\n"
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

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "error: invalid value for one of the arguments\n"
    );
}

#[test]
fn serve_rejects_zero_workers_from_environment() {
    let missing = missing_data_dir("environment-zero-workers");
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
        "error: invalid value for one of the arguments\n"
    );
}

#[test]
fn serve_flag_overrides_environment() {
    let missing = missing_data_dir("flag-precedence");
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
    let missing = missing_data_dir("duplicate-workers");
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
        "error: an argument cannot be used with one or more of the other specified arguments\n"
    );
}

#[test]
fn serve_rejects_zero_request_limit() {
    let missing = missing_data_dir("zero-request-limit");
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
        "error: invalid value for one of the arguments\n"
    );
}

#[test]
fn serve_rejects_zero_nar_limit() {
    let missing = missing_data_dir("zero-nar-limit");
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
        "error: invalid value for one of the arguments\n"
    );
}

struct RunningServer {
    child: Option<Child>,
    data_dir: PathBuf,
    temp_dir: Option<TestDir>,
    startup_line: String,
    address: String,
}

struct HttpExchange {
    request: Vec<u8>,
    response: Vec<u8>,
}

impl HttpExchange {
    fn sanitized_transcript(&self) -> String {
        let header_end = self
            .request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("request must contain a header terminator");
        let request_head = String::from_utf8_lossy(&self.request[..header_end]);
        let mut lines = request_head.lines();
        let mut transcript = String::new();
        transcript.push_str(lines.next().expect("request must contain a request line"));
        transcript.push('\n');
        for line in lines {
            let name = line.split_once(':').map_or(line, |(name, _)| name);
            if name.eq_ignore_ascii_case("authorization") {
                transcript.push_str("> Authorization: <redacted>\n");
            } else {
                transcript.push_str(&format!("> {line}\n"));
            }
        }
        let body_len = self.request.len() - header_end - 4;
        if body_len != 0 {
            transcript.push_str(&format!("> [body: {body_len} bytes]\n"));
        }
        transcript.push_str("< ");
        transcript.push_str(&String::from_utf8_lossy(&self.response).replace("\r\n", "\n< "));
        transcript.push('\n');
        transcript
    }
}

impl RunningServer {
    fn start(test: &str) -> Self {
        Self::start_with_args(test, &[])
    }

    fn start_with_args(test: &str, extra_args: &[&str]) -> Self {
        Self::start_with_auth(test, extra_args, None, None)
    }

    fn start_with_read_tokens(test: &str, read_tokens: &str) -> Self {
        Self::start_with_auth(test, &[], Some(read_tokens), None)
    }

    fn start_with_trusted_keys(test: &str, trusted_keys: &str) -> Self {
        Self::start_with_auth(test, &[], None, Some(trusted_keys))
    }

    fn start_with_auth(
        test: &str,
        extra_args: &[&str],
        read_tokens: Option<&str>,
        trusted_keys: Option<&str>,
    ) -> Self {
        let data_dir = data_dir(test);
        let auth_dir = data_dir.path().join("auth");
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
        let trusted_key = trusted_keys.map(str::to_owned).unwrap_or_else(|| {
            let signing_key = SigningKey::from_bytes(&[7; 32]);
            format!(
                "narjar-test:{}\n",
                BASE64.encode(signing_key.verifying_key().as_bytes())
            )
        });
        fs::write(data_dir.path().join("trusted-public-keys"), trusted_key)
            .expect("test trusted key should be written");

        Self::start_in(data_dir, extra_args)
    }

    fn start_in(temp_dir: TestDir, extra_args: &[&str]) -> Self {
        let data_dir = temp_dir.path().to_owned();
        let mut child = Self::spawn(&data_dir, extra_args);
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
            child: Some(child),
            data_dir,
            temp_dir: Some(temp_dir),
            startup_line,
            address,
        }
    }

    fn spawn(data_dir: &Path, extra_args: &[&str]) -> Child {
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
            .args(extra_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process.spawn().expect("narjar should start")
    }

    fn request(&self, method: &str, path: &str) -> Vec<u8> {
        self.request_with_headers(method, path, &[])
    }

    fn request_with_headers(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        self.exchange(method, path, headers, None).response
    }

    fn request_with_body(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        self.exchange(method, path, headers, Some(body)).response
    }

    fn raw_request_with_body(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        self.raw_exchange(method, path, headers, Some(body))
            .response
    }

    fn exchange(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> HttpExchange {
        let headers = Self::authenticated_headers(method, headers);
        self.raw_exchange(method, path, &headers, body)
    }

    fn raw_exchange(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> HttpExchange {
        let content_length = body.map(|body| body.len().to_string());
        let mut headers = headers.to_vec();
        if let Some(content_length) = content_length.as_deref() {
            headers.push(("Content-Length", content_length));
        }
        let mut request = self.raw_request_head(method, path, &headers);
        if let Some(body) = body {
            request.extend_from_slice(body);
        }

        let mut stream = TcpStream::connect(&self.address).expect("connect to narjar");
        stream.write_all(&request).expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        HttpExchange { request, response }
    }

    fn open_request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> TcpStream {
        let headers = Self::authenticated_headers(method, headers);
        self.open_raw_request(method, path, &headers)
    }

    fn authenticated_headers<'a>(
        method: &str,
        headers: &[(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut headers = headers.to_vec();
        if method == "PUT" {
            headers.push(("Authorization", TEST_AUTHORIZATION));
        }
        headers
    }

    fn open_raw_request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> TcpStream {
        let request = self.raw_request_head(method, path, headers);
        let mut stream = TcpStream::connect(&self.address).expect("connect to narjar");
        stream.write_all(&request).expect("write request");
        stream
    }

    fn raw_request_head(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut request = Vec::new();
        write!(
            request,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.address
        )
        .expect("write request line");
        for &(name, value) in headers {
            write!(request, "{name}: {value}\r\n").expect("write request header");
        }
        write!(request, "\r\n").expect("finish request");
        request
    }

    fn stop(mut self) -> (ExitStatus, ExitStatus) {
        self.stop_process()
    }

    fn stop_preserving(mut self) -> (TestDir, ExitStatus, ExitStatus) {
        let (signal, status) = self.stop_process();
        let temp_dir = self
            .temp_dir
            .take()
            .expect("running server should own its data directory");
        (temp_dir, signal, status)
    }

    fn stop_process(&mut self) -> (ExitStatus, ExitStatus) {
        let child = self
            .child
            .as_mut()
            .expect("running server should own its child");
        let signal = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("kill should run");

        let mut status = None;
        for _ in 0..100 {
            status = child.try_wait().expect("child status should be readable");
            if status.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        let status = status.unwrap_or_else(|| {
            child.kill().expect("hung child should be killed");
            child.wait().expect("killed child should be reaped")
        });
        self.child.take();

        (signal, status)
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
            let _ = child.wait();
        }
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
    let nar_bytes = b"known NAR bytes";
    let narinfo = signed_narinfo(NAR_ID, nar_bytes.len() as u64);
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

fn run_conformance_trace(server: &RunningServer, fixture: &str) -> String {
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
    let mut transcript = String::new();
    for (line_number, line) in fixture.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let [
            method,
            path,
            expected_status,
            body_fixture,
            header_fixture @ ..,
        ] = fields.as_slice()
        else {
            panic!("invalid conformance fixture line {}", line_number + 1);
        };
        let headers: &[(&str, &str)] = match header_fixture {
            [] => &[],
            ["if-none-match"] => &[("If-None-Match", "\"narjar-ignored\"")],
            ["if-modified-since"] => &[("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")],
            _ => panic!("invalid request header fixture on line {}", line_number + 1),
        };
        let body: Option<&[u8]> = match *body_fixture {
            "-" => None,
            "cache-info" => Some(CACHE_INFO),
            "nar" => Some(NAR_BYTES),
            "narinfo" => Some(narinfo.as_bytes()),
            fixture => panic!(
                "unknown body fixture {fixture:?} on line {}",
                line_number + 1
            ),
        };

        let exchange = server.exchange(method, path, headers, body);
        transcript.push_str(&exchange.sanitized_transcript());

        let expected = format!("HTTP/1.1 {expected_status} ");
        assert!(
            exchange.response.starts_with(expected.as_bytes()),
            "conformance fixture line {} expected status {expected_status}\n{transcript}",
            line_number + 1
        );
    }
    transcript
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
    assert!(headers.contains("Allow: GET, HEAD, PUT\r\n"), "{headers:?}");
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
    let server = RunningServer::start("nar-put");
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let created = server.request_with_body("PUT", &path, &[], NAR_BYTES);
    let identical = server.request_with_body("PUT", &path, &[], NAR_BYTES);
    let mismatch = server.request_with_body("PUT", &format!("/nar/{NAR_ID}.nar"), &[], NAR_BYTES);
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
    assert_eq!(published.expect("published NAR"), NAR_BYTES);
    assert!(!mismatched_path.exists());
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn narinfo_put_rejects_unsigned_metadata_without_publication() {
    let server = RunningServer::start("narinfo-put-unsigned");
    let nar_path = format!("/nar/{NARJAR_HASH}.nar");
    let nar_created = server.request_with_body("PUT", &nar_path, &[], NAR_BYTES);
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
    let server = RunningServer::start("narinfo-put-trusted");
    let nar_created =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
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
fn narinfo_put_rejects_a_signed_malformed_deriver() {
    let server = RunningServer::start("narinfo-put-bad-deriver");
    let nar_created =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64).replacen(
        "Sig:",
        "Deriver: not-a-store-path\nSig:",
        1,
    );
    let path = format!("/{STORE_HASH}.narinfo");
    let rejected = server.request_with_body("PUT", &path, &[], narinfo.as_bytes());
    let missing = server.request("GET", &path);
    let (signal, status) = server.stop();

    assert!(
        response_parts(&nar_created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    assert!(
        response_parts(&rejected)
            .0
            .starts_with("HTTP/1.1 422 Unprocessable Entity\r\n")
    );
    assert!(
        response_parts(&missing)
            .0
            .starts_with("HTTP/1.1 404 Not Found\r\n")
    );
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}
#[test]
fn narinfo_put_rejects_a_signed_malformed_content_address() {
    let server = RunningServer::start("narinfo-put-bad-ca");
    let nar_created =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64).replacen(
        "Sig:",
        "CA: fixed:sha256:not-a-hash\nSig:",
        1,
    );
    let path = format!("/{STORE_HASH}.narinfo");
    let rejected = server.request_with_body("PUT", &path, &[], narinfo.as_bytes());
    let missing = server.request("GET", &path);
    let (signal, status) = server.stop();

    assert!(
        response_parts(&nar_created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    assert!(
        response_parts(&rejected)
            .0
            .starts_with("HTTP/1.1 422 Unprocessable Entity\r\n")
    );
    assert!(
        response_parts(&missing)
            .0
            .starts_with("HTTP/1.1 404 Not Found\r\n")
    );
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}
#[test]
fn trusted_key_rotation_blocks_deleting_a_still_used_key() {
    let old = SigningKey::from_bytes(&[7; 32]);
    let new = SigningKey::from_bytes(&[8; 32]);
    let overlap = format!(
        "narjar-test:{}\nnarjar-next:{}\n",
        BASE64.encode(old.verifying_key().as_bytes()),
        BASE64.encode(new.verifying_key().as_bytes())
    );
    let server = RunningServer::start_with_trusted_keys("trusted-key-rotation", &overlap);
    let path = format!("/{STORE_HASH}.narinfo");
    let nar_created =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
    let metadata_created = server.request_with_body("PUT", &path, &[], narinfo.as_bytes());
    let (data_dir, signal, status) = server.stop_preserving();

    assert!(
        response_parts(&nar_created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    assert!(
        response_parts(&metadata_created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    assert!(signal.success());
    assert!(status.success());

    let restarted = RunningServer::start_in(data_dir, &[]);
    assert!(
        response_parts(&restarted.request("GET", &path))
            .0
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let (data_dir, signal, status) = restarted.stop_preserving();
    assert!(signal.success());
    assert!(status.success());

    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-next:{}\n",
            BASE64.encode(new.verifying_key().as_bytes())
        ),
    )
    .expect("new-only trust file should be written");
    let mut child = RunningServer::spawn(&data_dir, &[]);
    let mut startup_line = String::new();
    BufReader::new(child.stdout.take().expect("stdout should be piped"))
        .read_line(&mut startup_line)
        .expect("startup result should be readable");
    if !startup_line.is_empty() {
        child.kill().expect("unexpected server should be stopped");
    }
    let status = child.wait().expect("startup status should be readable");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr should be piped")
        .read_to_string(&mut stderr)
        .expect("startup error should be readable");

    assert!(startup_line.is_empty(), "{startup_line:?}");
    assert!(!status.success());
    assert!(
        stderr.contains("published narinfo is not trusted"),
        "{stderr:?}"
    );
}

#[test]
fn nar_put_rejects_encoded_oversized_and_truncated_bodies() {
    let path = format!("/nar/{NARJAR_HASH}.nar");

    let server = RunningServer::start("nar-put-invalid");
    let encoded =
        server.request_with_body("PUT", &path, &[("Content-Encoding", "gzip")], NAR_BYTES);
    let compressed = server.request_with_body("PUT", &format!("{path}.xz"), &[], NAR_BYTES);

    let mut truncated_stream = server.open_request("PUT", &path, &[("Content-Length", "7")]);
    truncated_stream
        .write_all(NAR_BYTES)
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
    let oversized = limited.request_with_body("PUT", &path, &[], NAR_BYTES);
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
    let server = RunningServer::start_with_args(
        "nar-put-reserve",
        &["--min-free-bytes", "18446744073709551615"],
    );
    let response =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
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
    let server = RunningServer::start("write-auth");
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let missing = server.raw_request_with_body("PUT", &path, &[], NAR_BYTES);
    let malformed =
        server.raw_request_with_body("PUT", &path, &[("Authorization", "Basic !!!")], NAR_BYTES);
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

#[test]
fn token_create_and_revoke_rotate_hashed_write_credentials() {
    let data_dir = data_dir("token-lifecycle");
    let root_path = data_dir.path().to_owned();
    let root = root_path.to_str().expect("temporary path should be UTF-8");
    let old = run(&[
        "token",
        "create",
        "--data-dir",
        root,
        "--scope",
        "write",
        "--name",
        "old",
    ]);
    assert!(old.status.success(), "{:?}", old.stderr);
    assert!(old.stderr.is_empty());
    let old_token = String::from_utf8(old.stdout)
        .expect("token should be UTF-8")
        .trim()
        .to_owned();
    assert_eq!(old_token.len(), 64);
    assert!(old_token.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let token_path = data_dir.join("auth/write.tokens");
    let stored = fs::read_to_string(&token_path).expect("hashed token file should be readable");
    assert!(stored.starts_with("old "));
    assert!(!stored.contains(&old_token));
    assert_eq!(
        std::os::unix::fs::MetadataExt::mode(
            &fs::metadata(&token_path).expect("hashed token metadata should be readable")
        ) & 0o777,
        0o600
    );

    let new = run(&[
        "token",
        "create",
        "--data-dir",
        root,
        "--scope",
        "write",
        "--name",
        "new",
    ]);
    assert!(new.status.success(), "{:?}", new.stderr);
    let new_token = String::from_utf8(new.stdout)
        .expect("token should be UTF-8")
        .trim()
        .to_owned();
    assert_ne!(old_token, new_token);

    let authorization = |token: &str| {
        format!(
            "Basic {}",
            BASE64.encode(format!("narjar:{token}").as_bytes())
        )
    };
    let reaches_router = |server: &RunningServer, token: &str| {
        let authorization = authorization(token);
        server.raw_request_with_body(
            "PUT",
            "/not-a-route",
            &[("Authorization", &authorization)],
            &[],
        )
    };

    let server = RunningServer::start_in(data_dir, &[]);
    for token in [&old_token, &new_token] {
        let response = reaches_router(&server, token);
        assert!(
            !response.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"),
            "{response:?}"
        );
    }
    let (data_dir, signal, status) = server.stop_preserving();
    assert!(signal.success());
    assert!(status.success());

    let revoked = run(&[
        "token",
        "revoke",
        "--data-dir",
        root,
        "--scope",
        "write",
        "--name",
        "old",
    ]);
    assert!(revoked.status.success(), "{:?}", revoked.stderr);
    assert!(revoked.stdout.is_empty());
    let stored = fs::read_to_string(&token_path).expect("rotated token file should be readable");
    assert!(!stored.contains("old "));
    assert!(stored.contains("new "));

    let server = RunningServer::start_in(data_dir, &[]);
    let rejected = reaches_router(&server, &old_token);
    let accepted = reaches_router(&server, &new_token);
    let (signal, status) = server.stop();

    assert!(rejected.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
    assert!(!accepted.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
    assert!(signal.success());
    assert!(status.success());
}

#[test]
fn nix_cache_info_put_is_durable_idempotent_and_immutable() {
    let server = RunningServer::start("nix-cache-info-put");
    let created = server.request_with_body("PUT", "/nix-cache-info", &[], CACHE_INFO);
    let identical = server.request_with_body("PUT", "/nix-cache-info", &[], CACHE_INFO);
    let conflict = server.request_with_body(
        "PUT",
        "/nix-cache-info",
        &[],
        b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 31\n",
    );
    let stored = fs::read(server.data_dir.join("nix-cache-info"))
        .expect("cache info should be durably stored");
    let (signal, status) = server.stop();

    assert!(
        response_parts(&created)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n"),
        "{:?}",
        String::from_utf8_lossy(&created)
    );
    assert!(
        response_parts(&identical)
            .0
            .starts_with("HTTP/1.1 200 OK\r\n"),
        "{:?}",
        String::from_utf8_lossy(&identical)
    );
    assert!(
        response_parts(&conflict)
            .0
            .starts_with("HTTP/1.1 409 Conflict\r\n"),
        "{:?}",
        String::from_utf8_lossy(&conflict)
    );
    assert_eq!(stored, CACHE_INFO);
    assert!(signal.success());
    assert!(status.success());
}

#[test]
fn nix_2_31_5_trace_drives_redacted_socket_conformance() {
    let server = RunningServer::start("nix-trace-conformance");
    let transcript =
        run_conformance_trace(&server, include_str!("fixtures/nix-2.31.5-http-v0.1.tsv"));
    let (signal, status) = server.stop();

    assert!(transcript.contains("GET /nix-cache-info"), "{transcript}");
    assert!(transcript.contains("< HTTP/1.1 200 OK"), "{transcript}");
    assert!(
        transcript.contains("Authorization: <redacted>"),
        "{transcript}"
    );
    assert!(!transcript.contains(TEST_AUTHORIZATION), "{transcript}");
    assert!(signal.success());
    assert!(status.success());
}

fn init_data_dir(test: &str) -> TestDir {
    let data_dir = data_dir(test);
    let output = run(&[
        "init",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
    ]);
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    data_dir
}

#[test]
fn init_and_key_generate_create_secure_operator_material() {
    use std::os::unix::fs::PermissionsExt as _;

    let data_dir = init_data_dir("operator-init");
    for directory in ["nar", ".tmp", "realisations", "auth"] {
        assert!(data_dir.join(directory).is_dir(), "{directory}");
    }
    for file in ["nix-cache-info", "trusted-public-keys", "auth/write.tokens"] {
        assert!(data_dir.join(file).is_file(), "{file}");
    }
    assert_eq!(
        fs::metadata(&data_dir)
            .expect("data directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let secret = data_dir.join("cache-secret-key");
    let public = data_dir.join("cache-public-key");
    let output = run(&[
        "key",
        "generate",
        "--name",
        "narjar-test",
        "--secret-key-file",
        secret.to_str().expect("secret path should be UTF-8"),
        "--public-key-file",
        public.to_str().expect("public path should be UTF-8"),
    ]);
    assert!(
        output.status.success(),
        "key generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let secret_line = fs::read_to_string(&secret).expect("secret key should be readable");
    let public_line = fs::read_to_string(&public).expect("public key should be readable");
    let (_, secret_bytes) = secret_line
        .trim()
        .split_once(':')
        .expect("secret key should be named");
    let (_, public_bytes) = public_line
        .trim()
        .split_once(':')
        .expect("public key should be named");
    assert_eq!(
        BASE64
            .decode(secret_bytes.as_bytes())
            .expect("secret key should be base64")
            .len(),
        64
    );
    assert_eq!(
        BASE64
            .decode(public_bytes.as_bytes())
            .expect("public key should be base64")
            .len(),
        32
    );
    assert_eq!(
        fs::metadata(secret)
            .expect("secret key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn reconcile_and_verify_classify_operator_findings() {
    let data_dir = init_data_dir("operator-verify");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");

    let missing_store = "11111111111111111111111111111111";
    let malformed_store = "22222222222222222222222222222222";
    let mismatch_store = "33333333333333333333333333333333";
    let untrusted_store = "44444444444444444444444444444444";
    let missing_nar = "1111111111111111111111111111111111111111111111111111";

    fs::write(data_dir.join(format!("nar/{NAR_ID}.nar")), b"orphan")
        .expect("orphan should be written");
    fs::write(
        data_dir.join(format!("{missing_store}.narinfo")),
        signed_narinfo_for(missing_store, missing_nar, 6),
    )
    .expect("missing-NAR metadata should be written");
    fs::write(
        data_dir.join(format!("{malformed_store}.narinfo")),
        b"not a narinfo\n",
    )
    .expect("malformed metadata should be written");
    fs::write(
        data_dir.join(format!("{untrusted_store}.narinfo")),
        signed_narinfo_for(untrusted_store, missing_nar, 6)
            .replace("Sig: narjar-test:", "Sig: unknown:"),
    )
    .expect("untrusted metadata should be written");
    fs::write(
        data_dir.join(format!("{mismatch_store}.narinfo")),
        signed_narinfo_for(mismatch_store, NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("mismatched metadata should be written");
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), b"narjax")
        .expect("same-size corrupt NAR should be written");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let reconcile = run(&["reconcile", "--data-dir", path, "--verify-hashes", "--json"]);
    assert!(
        reconcile.status.success(),
        "reconcile failed: {}",
        String::from_utf8_lossy(&reconcile.stderr)
    );
    let report = String::from_utf8(reconcile.stdout).expect("report should be UTF-8");
    for class in [
        "orphan_nar",
        "missing_nar",
        "malformed_narinfo",
        "untrusted_signature",
        "hash_or_size_mismatch",
    ] {
        assert!(
            report.contains(&format!("\"class\":\"{class}\"")),
            "{report}"
        );
    }

    let verify = run(&["verify", "--data-dir", path, "--json"]);
    assert_eq!(verify.status.code(), Some(1));
    let report = String::from_utf8(verify.stdout).expect("report should be UTF-8");
    assert!(report.contains("\"class\":\"hash_or_size_mismatch\""));
}

#[test]
fn delete_is_offline_and_leaves_shared_nar_objects() {
    let server = RunningServer::start("operator-delete");
    let nar_path = format!("/nar/{NARJAR_HASH}.nar");
    let narinfo_path = format!("/{STORE_HASH}.narinfo");
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
    let headers: [(&str, &str); 0] = [];
    let nar_created = server.request_with_body("PUT", &nar_path, &headers, NAR_BYTES);
    let narinfo_created =
        server.request_with_body("PUT", &narinfo_path, &headers, narinfo.as_bytes());
    assert!(
        response_parts(&nar_created).0.starts_with("HTTP/1.1 201"),
        "{}",
        String::from_utf8_lossy(&nar_created)
    );
    assert!(
        response_parts(&narinfo_created)
            .0
            .starts_with("HTTP/1.1 201")
    );

    let data_path = server.data_dir.clone();
    let path = data_path.to_str().expect("temporary path should be UTF-8");
    let locked = run(&[
        "delete",
        "--data-dir",
        path,
        "--store-hash",
        STORE_HASH,
        "--json",
    ]);
    assert_eq!(locked.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&locked.stderr).contains("locked"));

    let (data_dir, signal, status) = server.stop_preserving();
    assert!(signal.success());
    assert!(status.success());
    let deleted = run(&[
        "delete",
        "--data-dir",
        path,
        "--store-hash",
        STORE_HASH,
        "--json",
    ]);
    assert!(
        deleted.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(
        !data_dir
            .path()
            .join(format!("{STORE_HASH}.narinfo"))
            .exists()
    );
    assert!(
        data_dir
            .path()
            .join(format!("nar/{NARJAR_HASH}.nar"))
            .exists()
    );
}

#[test]
fn health_readiness_metrics_and_stats_follow_the_operator_contract() {
    let server = RunningServer::start("operator-observability");

    let (health_headers, health_body) = response_parts(&server.request("GET", "/healthz"));
    assert!(
        health_headers.starts_with("HTTP/1.1 200"),
        "{health_headers}"
    );
    assert_eq!(health_body, b"ok\n");

    let (ready_headers, ready_body) = response_parts(&server.request("GET", "/readyz"));
    assert!(ready_headers.starts_with("HTTP/1.1 200"), "{ready_headers}");
    assert_eq!(ready_body, b"ready\n");

    let _ = server.request("GET", "/missing");
    let (metric_headers, metric_body) = response_parts(&server.request("GET", "/metrics"));
    assert!(
        metric_headers.starts_with("HTTP/1.1 200"),
        "{metric_headers}"
    );
    let metrics = String::from_utf8(metric_body).expect("metrics should be UTF-8");
    for series in [
        "narjar_http_requests_total",
        "narjar_http_bytes_in_total",
        "narjar_http_bytes_out_total",
        "narjar_auth_failures_total",
        "narjar_validation_failures_total",
        "narjar_uploads_in_flight",
        "narjar_requests_in_flight",
        "narjar_temp_objects",
        "narjar_disk_full_total",
        "narjar_publications_total",
        "narjar_publication_duration_seconds",
        "narjar_ready",
    ] {
        assert!(metrics.contains(series), "missing {series}: {metrics}");
    }

    let url = format!("http://{}", server.address);
    let stats = run(&["stats", "--url", &url]);
    assert!(
        stats.status.success(),
        "stats failed: {}",
        String::from_utf8_lossy(&stats.stderr)
    );
    assert!(String::from_utf8_lossy(&stats.stdout).contains("narjar_ready 1"));

    let (signal, status) = server.stop();
    assert!(signal.success());
    assert!(status.success());
}

#[test]
fn health_is_public_but_private_read_protects_readiness_and_metrics() {
    let server =
        RunningServer::start_with_read_tokens("private-operator-observability", TEST_WRITE_TOKEN);

    let health = response_parts(&server.request("GET", "/healthz")).0;
    let ready = response_parts(&server.request("GET", "/readyz")).0;
    let metrics = response_parts(&server.request("GET", "/metrics")).0;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(ready.starts_with("HTTP/1.1 401"), "{ready}");
    assert!(metrics.starts_with("HTTP/1.1 401"), "{metrics}");

    let (signal, status) = server.stop();
    assert!(signal.success());
    assert!(status.success());
}

#[test]
fn readiness_fails_without_affecting_liveness_when_space_is_reserved() {
    let server = RunningServer::start_with_args(
        "operator-not-ready",
        &["--min-free-bytes", "18446744073709551615"],
    );

    let health = response_parts(&server.request("GET", "/healthz")).0;
    let (ready, reason) = response_parts(&server.request("GET", "/readyz"));
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(ready.starts_with("HTTP/1.1 503"), "{ready}");
    assert_eq!(reason, b"insufficient_space\n");

    let (signal, status) = server.stop();
    assert!(signal.success());
    assert!(status.success());
}

#[test]
fn restored_cache_verifies_before_serving() {
    let source = init_data_dir("backup-source");
    fs::write(
        source.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    fs::write(source.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        source.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("narinfo should be written");

    let restored = init_data_dir("backup-restored");
    for relative in [
        "nix-cache-info",
        "trusted-public-keys",
        "auth/write.tokens",
        "nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar",
        "00000000000000000000000000000000.narinfo",
    ] {
        fs::copy(source.join(relative), restored.join(relative))
            .expect("backup file should be restored");
    }
    let output = run(&[
        "verify",
        "--data-dir",
        restored.to_str().expect("restored path should be UTF-8"),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "restored cache failed verification: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gc_dry_run_preserves_and_apply_removes_old_pair() {
    let data_dir = init_data_dir("operator-gc");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("narinfo should be written");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let dry_run = run(&[
        "gc",
        "--data-dir",
        path,
        "--target-bytes",
        "0",
        "--min-age-seconds",
        "0",
        "--dry-run",
        "--json",
    ]);
    assert!(
        dry_run.status.success(),
        "gc dry-run failed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert!(data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
    assert!(data_dir.join(format!("nar/{NARJAR_HASH}.nar")).exists());
    assert!(String::from_utf8_lossy(&dry_run.stdout).contains("\"dry_run\":true"));

    let apply = run(&[
        "gc",
        "--data-dir",
        path,
        "--target-bytes",
        "0",
        "--min-age-seconds",
        "0",
        "--apply",
        "--json",
    ]);
    assert!(
        apply.status.success(),
        "gc apply failed: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert!(!data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
    assert!(!data_dir.join(format!("nar/{NARJAR_HASH}.nar")).exists());
    assert!(String::from_utf8_lossy(&apply.stdout).contains("\"deleted_narinfos\":1"));
}

#[test]
fn gc_deletes_a_shared_nar_only_after_the_last_narinfo() {
    let data_dir = init_data_dir("operator-gc-shared");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    let second_store = "11111111111111111111111111111111";
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo_for(STORE_HASH, NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("first narinfo should be written");
    fs::write(
        data_dir.join(format!("{second_store}.narinfo")),
        signed_narinfo_for(second_store, NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("second narinfo should be written");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let output = run(&[
        "gc",
        "--data-dir",
        path,
        "--target-bytes",
        "0",
        "--min-age-seconds",
        "0",
        "--apply",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "gc apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
    assert!(!data_dir.join(format!("{second_store}.narinfo")).exists());
    assert!(!data_dir.join(format!("nar/{NARJAR_HASH}.nar")).exists());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"deleted_narinfos\":2"));
    assert!(stdout.contains("\"deleted_nars\":1"));
}

#[test]
fn gc_protected_roots_are_not_candidates() {
    let data_dir = init_data_dir("operator-gc-protected");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("narinfo should be written");
    let roots = data_dir.join("protected-roots");
    fs::write(&roots, format!("/nix/store/{STORE_HASH}-narjar\n"))
        .expect("protected roots should be written");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let roots_path = roots
        .to_str()
        .expect("protected roots path should be UTF-8");
    let output = run(&[
        "gc",
        "--data-dir",
        path,
        "--target-bytes",
        "0",
        "--protected-roots",
        roots_path,
        "--apply",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "gc apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
    assert!(data_dir.join(format!("nar/{NARJAR_HASH}.nar")).exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"candidates\":0"));
}

#[test]
fn gc_refuses_to_apply_while_the_cache_is_serving() {
    let server = RunningServer::start("operator-gc-lock");
    let path = server
        .data_dir
        .to_str()
        .expect("temporary path should be UTF-8");
    let output = run(&["gc", "--data-dir", path, "--target-bytes", "0", "--apply"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("locked"));
}
