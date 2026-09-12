use data_encoding::{BASE64, BitOrder, Specification};
use ed25519_dalek::{Signer, SigningKey};
use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    ops::Deref,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use structured_zstd::encoding::{CompressionLevel, compress};
use tempfile::TempDir;

const CONFIG_ENV: &[&str] = &[
    "NARJAR_DATA_DIR",
    "NARJAR_LISTEN",
    "NARJAR_WORKERS",
    "NARJAR_MAX_IN_FLIGHT",
    "NARJAR_MAX_NAR_BYTES",
    "NARJAR_MIN_FREE_BYTES",
    "NARJAR_SHUTDOWN_GRACE_SECONDS",
    "NARJAR_IO_TIMEOUT_SECONDS",
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

fn read_http_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut header_end = None;
    let mut content_length = None;
    loop {
        let mut buffer = [0; 4096];
        let count = stream
            .read(&mut buffer)
            .expect("response should be readable");
        assert_ne!(count, 0, "response ended before its declared body");
        response.extend_from_slice(&buffer[..count]);
        if header_end.is_none() {
            header_end = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|offset| offset + 4);
            if let Some(header_end) = header_end {
                let headers = std::str::from_utf8(&response[..header_end])
                    .expect("response headers should be UTF-8");
                content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .map(|value| value.trim().parse::<usize>().expect("valid Content-Length"));
            }
        }
        if let (Some(header_end), Some(content_length)) = (header_end, content_length)
            && response.len() >= header_end + content_length
        {
            return response;
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let count = stream
            .read(&mut buffer)
            .expect("request should be readable");
        assert_ne!(count, 0, "request ended before its declared body");
        request.extend_from_slice(&buffer[..count]);
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
        else {
            continue;
        };
        let headers = std::str::from_utf8(&request[..header_end]).expect("request headers UTF-8");
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("Content-Length")
                    .then(|| value.trim().parse::<usize>().expect("valid Content-Length"))
            })
            .unwrap_or(0);
        if request.len() >= header_end + content_length {
            return request;
        }
    }
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
    let reference_basenames = reference_hashes
        .iter()
        .map(|hash| format!("{hash}-narjar"))
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

fn nix32_sha256(bytes: &[u8]) -> String {
    let mut specification = Specification::new();
    specification
        .symbols
        .push_str("0123456789abcdfghijklmnpqrsvwxyz");
    specification.bit_order = BitOrder::LeastSignificantFirst;
    let encoding = specification
        .encoding()
        .expect("Nix base-32 specification is valid");
    encoding
        .encode(&Sha256::digest(bytes))
        .chars()
        .rev()
        .collect()
}

fn signed_xz_narinfo(file_hash: &str, nar_hash: &str, nar_size: u64, file_size: u64) -> String {
    let store_path = format!("/nix/store/{STORE_HASH}-narjar");
    let fingerprint = format!("1;{store_path};sha256:{nar_hash};{nar_size};");
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());

    format!(
        "StorePath: {store_path}\nURL: nar/{file_hash}.nar.xz\nCompression: xz\nFileHash: sha256:{file_hash}\nFileSize: {file_size}\nNarHash: sha256:{nar_hash}\nNarSize: {nar_size}\nReferences: \nSig: narjar-test:{}\n",
        BASE64.encode(&signature.to_bytes())
    )
}

fn signed_zstd_narinfo(file_hash: &str, nar_hash: &str, nar_size: u64, file_size: u64) -> String {
    let store_path = format!("/nix/store/{STORE_HASH}-narjar");
    let fingerprint = format!("1;{store_path};sha256:{nar_hash};{nar_size};");
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());

    format!(
        "StorePath: {store_path}\nURL: nar/{file_hash}.nar.zst\nCompression: zstd\nFileHash: sha256:{file_hash}\nFileSize: {file_size}\nNarHash: sha256:{nar_hash}\nNarSize: {nar_size}\nReferences: \nSig: narjar-test:{}\n",
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

#[test]
fn push_uses_native_transfer_without_nix_copy() {
    for (compression, suffix) in [("none", ".nar"), ("zstd", ".nar.zst"), ("xz", ".nar.xz")] {
        assert_native_push_process_boundary(compression, suffix);
    }
}

struct NativePushFixture {
    tools: TempDir,
    invocation_log: PathBuf,
    netrc: PathBuf,
    store_path: String,
}

fn native_push_fixture() -> NativePushFixture {
    let tools = tempfile::tempdir().expect("fake Nix directory should be created");
    let fake_nix = tools.path().join("nix");
    let invocation_log = tools.path().join("nix-invocations");
    let store_path = format!("/nix/store/{STORE_HASH}-narjar");
    let nar_hash = nix32_sha256(NAR_BYTES);
    let nar_hash_sri = format!("sha256-{}", BASE64.encode(&Sha256::digest(NAR_BYTES)));
    let fingerprint = format!("1;{store_path};sha256:{nar_hash};{};", NAR_BYTES.len());
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());
    let signature = format!("narjar-test:{}", BASE64.encode(&signature.to_bytes()));
    let fake_nix_contents = format!(
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> \"$NIX_TEST_INVOCATIONS\"\n",
            "if [ \"$1\" = path-info ]; then\n",
            "  printf '%s\\n' '{{\"{store_path}\":{{\"ca\":null,\"deriver\":null,\"narHash\":\"{nar_hash_sri}\",\"narSize\":{nar_size},\"references\":[],\"signatures\":[\"{signature}\"]}}}}'\n",
            "elif [ \"$1\" = store ] && [ \"$2\" = dump-path ]; then\n",
            "  printf '%s' narjar\n",
            "else\n",
            "  printf '%s\\n' \"unexpected nix invocation: $*\" >&2\n",
            "  exit 1\n",
            "fi\n"
        ),
        store_path = store_path,
        nar_hash_sri = nar_hash_sri,
        signature = signature,
        nar_size = NAR_BYTES.len()
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
    fs::set_permissions(&netrc, fs::Permissions::from_mode(0o600))
        .expect("netrc should be private");

    NativePushFixture {
        tools,
        invocation_log,
        netrc,
        store_path,
    }
}

fn run_native_push_fixture(
    fixture: &NativePushFixture,
    target: &str,
    compression: &str,
    refresh: bool,
) -> Output {
    run_native_push_fixture_with_timeout(fixture, target, compression, refresh, None)
}

fn run_native_push_fixture_with_timeout(
    fixture: &NativePushFixture,
    target: &str,
    compression: &str,
    refresh: bool,
    timeout_seconds: Option<u64>,
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
    if let Some(timeout_seconds) = timeout_seconds {
        args.push("--timeout-seconds".to_owned());
        args.push(timeout_seconds.to_string());
    }
    if refresh {
        args.push("--refresh".to_owned());
    }
    args.push(fixture.store_path.clone());
    command()
        .args(&args)
        .env("PATH", path)
        .env("NIX_TEST_INVOCATIONS", &fixture.invocation_log)
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

        for _ in 0..2 {
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
fn native_push_retries_a_429_at_the_process_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native retry listener");
    let address = listener
        .local_addr()
        .expect("inspect native retry listener");
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
                assert_eq!(body, NAR_BYTES, "every NAR retry must resend the body");
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
    assert_eq!(
        fs::read_to_string(fixture.invocation_log).expect("Nix invocations should be logged"),
        format!(
            "path-info --recursive --json -- {}\nstore dump-path -- {}\n",
            fixture.store_path, fixture.store_path
        )
    );
}

#[test]
fn native_push_retries_after_an_interrupted_upload_at_the_process_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native interruption listener");
    let address = listener
        .local_addr()
        .expect("inspect native interruption listener");
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
        assert_eq!(&request[header_end..], NAR_BYTES);
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
    assert_eq!(
        fs::read_to_string(fixture.invocation_log).expect("Nix invocations should be logged"),
        format!(
            "path-info --recursive --json -- {}\nstore dump-path -- {}\n",
            fixture.store_path, fixture.store_path
        )
    );
}

fn assert_native_push_process_boundary(compression: &str, suffix: &str) {
    let server = RunningServer::start("native-push-process-boundary");
    let fixture = native_push_fixture();
    let output = run_native_push_fixture(
        &fixture,
        &format!("http://{}?compression={compression}", server.address),
        compression,
        false,
    );

    assert!(
        output.status.success(),
        "native push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "pushed 1 paths with 1 workers\n"
    );
    let narinfo = fs::read_to_string(server.data_dir.join(format!("{STORE_HASH}.narinfo")))
        .expect("native narinfo should be published");
    let url = narinfo
        .lines()
        .find_map(|line| line.strip_prefix("URL: nar/"))
        .expect("native narinfo should contain a NAR URL");
    assert!(
        url.ends_with(suffix),
        "NAR URL {url:?} should use requested suffix {suffix:?} for {compression}"
    );
    let published_nar = fs::read(server.data_dir.join(format!("nar/{url}")))
        .expect("native NAR should be published");
    if compression == "none" {
        assert_eq!(published_nar, NAR_BYTES);
    } else {
        assert_ne!(published_nar, NAR_BYTES);
    }
    assert!(narinfo.contains(&format!("Compression: {compression}\n")));
    assert!(narinfo.contains(&format!("NarSize: {}\n", NAR_BYTES.len())));

    let invocations =
        fs::read_to_string(fixture.invocation_log).expect("Nix invocations should be logged");
    assert_eq!(
        invocations,
        format!(
            "path-info --recursive --json -- {}\nstore dump-path -- {}\n",
            fixture.store_path, fixture.store_path
        )
    );
    assert!(!invocations.contains(" copy "));
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
fn serve_rejects_uninitialized_data_dir() {
    let data_dir = data_dir("uninitialized-data-dir");
    let output = run(&[
        "serve",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--listen",
        "127.0.0.1:0",
        "--workers",
        "1",
    ]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr should be UTF-8")
            .contains("nar is unavailable")
    );
}

#[test]
fn serve_rejects_partial_data_dir() {
    let data_dir = data_dir("partial-data-dir");
    fs::create_dir(data_dir.path().join("nar")).expect("partial NAR directory should exist");
    fs::create_dir(data_dir.path().join("nar/.tmp"))
        .expect("partial NAR temporary directory should exist");
    fs::create_dir(data_dir.path().join(".tmp")).expect("partial temporary directory should exist");
    fs::create_dir(data_dir.path().join("realisations"))
        .expect("partial realisations directory should exist");
    fs::create_dir(data_dir.path().join("realisations/.tmp"))
        .expect("partial realisation temporary directory should exist");
    fs::create_dir(data_dir.path().join("auth")).expect("partial auth directory should exist");
    let output = run(&[
        "serve",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--listen",
        "127.0.0.1:0",
        "--workers",
        "1",
    ]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr should be UTF-8")
            .contains("nix-cache-info is unavailable")
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
fn serve_rejects_a_symlinked_data_directory() {
    let directory = data_dir("symlinked-data-directory");
    let target = directory.path().join("target");
    let link = directory.path().join("data");
    fs::create_dir(&target).expect("create data directory target");
    symlink(&target, &link).expect("create data directory symlink");

    let output = run(&[
        "serve",
        "--data-dir",
        link.to_str().expect("temporary path should be UTF-8"),
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        format!(
            "narjar: data directory is not a directory: {}\n",
            link.display()
        )
    );
    assert!(!target.join("nar").exists());
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

    fn start_with_workers(test: &str, workers: usize, extra_args: &[&str]) -> Self {
        Self::start_with_auth_and_workers(test, workers, extra_args, None, None)
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
        Self::start_with_auth_and_workers(test, 1, extra_args, read_tokens, trusted_keys)
    }

    fn start_with_auth_and_workers(
        test: &str,
        workers: usize,
        extra_args: &[&str],
        read_tokens: Option<&str>,
        trusted_keys: Option<&str>,
    ) -> Self {
        let data_dir = data_dir(test);
        let output = run(&[
            "init",
            "--data-dir",
            data_dir.to_str().expect("temporary path should be UTF-8"),
        ]);
        assert!(
            output.status.success(),
            "test data initialization failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let auth_dir = data_dir.path().join("auth");
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

        Self::start_in_with_workers(data_dir, workers, extra_args)
    }

    fn start_in(temp_dir: TestDir, extra_args: &[&str]) -> Self {
        Self::start_in_with_workers(temp_dir, 1, extra_args)
    }

    fn start_in_with_workers(temp_dir: TestDir, workers: usize, extra_args: &[&str]) -> Self {
        let data_dir = temp_dir.path().to_owned();
        let mut child = Self::spawn(&data_dir, workers, extra_args);
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

    fn spawn(data_dir: &Path, workers: usize, extra_args: &[&str]) -> Child {
        let mut process = command();
        process
            .args([
                "serve",
                "--data-dir",
                data_dir.to_str().expect("temporary path should be UTF-8"),
                "--listen",
                "127.0.0.1:0",
                "--workers",
                &workers.to_string(),
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
            " workers=1 max_in_flight=64 max_nar_bytes=17179869184 min_free_bytes=1073741824 shutdown_grace_seconds=30 io_timeout_seconds=30\n"
        ),
        "startup line omits effective limits: {:?}",
        server.startup_line
    );

    let (signal, status) = server.stop();
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn stalled_request_headers_are_closed_by_the_socket_timeout() {
    let server =
        RunningServer::start_with_args("stalled-request-headers", &["--io-timeout-seconds", "1"]);
    let started = Instant::now();
    let mut stream = TcpStream::connect(&server.address).expect("connect to narjar");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: test\r\n")
        .expect("write partial request");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("configure client timeout");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("timed-out request should close");

    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    let (_, status) = server.stop();
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn stalled_upload_body_is_rejected_without_publication() {
    let server =
        RunningServer::start_with_args("stalled-upload-body", &["--io-timeout-seconds", "1"]);
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let mut stream = server.open_request("PUT", &path, &[("Content-Length", "1")]);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("configure client timeout");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("timed-out upload should receive a response");

    assert!(response.is_empty(), "unexpected response: {:?}", response);
    assert!(
        !server
            .data_dir
            .join(format!("nar/{NARJAR_HASH}.nar"))
            .exists()
    );
    assert!(
        !server
            .data_dir
            .join(format!("narinfo/{STORE_HASH}.narinfo"))
            .exists()
    );
    let (_, status) = server.stop();
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn second_sigterm_exits_a_stalled_request_immediately() {
    let mut server =
        RunningServer::start_with_args("second-sigterm", &["--shutdown-grace-seconds", "30"]);
    let _stalled = server.open_request(
        "PUT",
        &format!("/nar/{NAR_ID}.nar"),
        &[("Content-Length", "1")],
    );
    thread::sleep(Duration::from_millis(100));

    let pid = server
        .child
        .as_ref()
        .expect("server child should exist")
        .id();
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("first SIGTERM should be sent");
    thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("second SIGTERM should be sent");
    let status = server
        .child
        .take()
        .expect("server child should be available")
        .wait()
        .expect("server should exit after the second signal");

    assert!(!status.success());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "second signal should bypass the grace period: {started:?}"
    );
}

#[test]
fn shutdown_grace_deadline_terminates_a_stalled_request() {
    let mut server =
        RunningServer::start_with_args("shutdown-deadline", &["--shutdown-grace-seconds", "1"]);
    let _stalled = server.open_request(
        "PUT",
        &format!("/nar/{NAR_ID}.nar"),
        &[("Content-Length", "1")],
    );
    thread::sleep(Duration::from_millis(100));

    let pid = server
        .child
        .as_ref()
        .expect("server child should exist")
        .id();
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("SIGTERM should be sent");
    let started = Instant::now();
    let status = server
        .child
        .take()
        .expect("server child should be available")
        .wait()
        .expect("server should exit at the grace deadline");

    assert!(!status.success());
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "shutdown should honor the configured grace period: {started:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "shutdown should remain bounded: {started:?}"
    );
}

#[test]
fn shutdown_grace_deadline_covers_a_queued_publication() {
    let mut server = RunningServer::start_with_args(
        "shutdown-queued-publication",
        &["--max-in-flight", "3", "--shutdown-grace-seconds", "1"],
    );
    let path = format!("/nar/{NAR_ID}.nar");
    let _active = server.open_request("PUT", &path, &[("Content-Length", "1")]);
    thread::sleep(Duration::from_millis(50));
    let _queued = server.open_request("PUT", &path, &[("Content-Length", "1")]);
    thread::sleep(Duration::from_millis(50));

    let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
        .expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_publication_queue_depth 1"),
        "{metrics}"
    );

    let pid = server
        .child
        .as_ref()
        .expect("server child should exist")
        .id();
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("SIGTERM should be sent");
    let started = Instant::now();
    let status = server
        .child
        .take()
        .expect("server child should be available")
        .wait()
        .expect("server should exit at the grace deadline");

    assert!(!status.success());
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "shutdown should honor the configured grace period: {started:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "shutdown should remain bounded: {started:?}"
    );
}

#[test]
fn nix_cache_info_get_and_head_match_contract() {
    let server = RunningServer::start("nix-cache-info");
    let get = String::from_utf8(server.request("GET", "/nix-cache-info"))
        .expect("GET response should be UTF-8");
    let head = String::from_utf8(server.request("HEAD", "/nix-cache-info"))
        .expect("HEAD response should be UTF-8");
    let legacy_get = String::from_utf8(server.request("GET", "/main/nix-cache-info"))
        .expect("legacy GET response should be UTF-8");
    let legacy_head = String::from_utf8(server.request("HEAD", "/main/nix-cache-info"))
        .expect("legacy HEAD response should be UTF-8");
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");

    let body = "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
    for response in [&get, &head, &legacy_get, &legacy_head] {
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
    assert!(
        legacy_get.ends_with(&format!("\r\n\r\n{body}")),
        "{legacy_get:?}"
    );
    assert!(legacy_head.ends_with("\r\n\r\n"), "{legacy_head:?}");
}

#[test]
fn private_cache_info_is_not_shared() {
    let server = RunningServer::start_with_read_tokens("private-cache-info", TEST_WRITE_TOKEN);
    let response = String::from_utf8(server.request_with_headers(
        "GET",
        "/nix-cache-info",
        &[("Authorization", TEST_AUTHORIZATION)],
    ))
    .expect("response should be UTF-8");
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.contains("Cache-Control: private, no-store\r\n"),
        "{response}"
    );
    assert!(response.contains("Vary: Authorization\r\n"), "{response}");
    assert!(!response.contains("Cache-Control: public"), "{response}");
}

#[test]
fn cache_info_reads_the_initialized_priority() {
    let server = RunningServer::start("custom-cache-priority");
    fs::write(
        server.data_dir.join("nix-cache-info"),
        b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 17\n",
    )
    .expect("custom cache-info should be written");
    let response = String::from_utf8(server.request("GET", "/nix-cache-info"))
        .expect("response should be UTF-8");
    let (signal, status) = server.stop();

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
    assert!(response.ends_with("\r\n\r\nStoreDir: /nix/store\nWantMassQuery: 0\nPriority: 17\n"));
}

#[test]
fn http11_connection_serves_two_sequential_requests() {
    let server = RunningServer::start("http11-keep-alive");
    let mut stream = TcpStream::connect(&server.address).expect("connect to narjar");

    for _ in 0..2 {
        stream
            .write_all(
                format!(
                    "GET /nix-cache-info HTTP/1.1\r\nHost: {}\r\n\r\n",
                    server.address
                )
                .as_bytes(),
            )
            .expect("write HTTP/1.1 request");
        let response =
            String::from_utf8(read_http_response(&mut stream)).expect("response should be UTF-8");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response:?}");
        assert!(
            response.contains("Connection: keep-alive\r\n"),
            "{response:?}"
        );
        assert!(
            response.ends_with("\r\n\r\nStoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n")
        );
    }

    drop(stream);
    let (signal, status) = server.stop();
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
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
    let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
        .expect("metrics should be UTF-8");
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
    assert!(
        metrics.contains("narjar_http_bytes_out_total 13"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("narjar_http_requests_total{method=\"GET\",route=\"nar\",status=\"2xx\"} 3"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("narjar_http_requests_total{method=\"HEAD\",route=\"nar\",status=\"2xx\"} 1"),
        "{metrics}"
    );
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
    let nar_bytes = vec![0x5a; 128 * 1024];
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
fn nar_reads_external_symlinks_as_internal_errors() {
    let server = RunningServer::start("read-external-symlink");
    let nar_path = server.data_dir.join(format!("nar/{NAR_ID}.nar"));
    let external_path = server
        .data_dir
        .parent()
        .expect("data directory should have a parent")
        .join("external.nar");
    let external_bytes = b"must stay outside the cache";
    fs::write(&external_path, external_bytes).expect("write external target");
    symlink(&external_path, &nar_path).expect("create external NAR symlink");

    let response = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    let (headers, body) = response_parts(&response);
    let (signal, status) = server.stop();

    assert!(
        headers.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "{headers:?}"
    );
    assert!(body.is_empty());
    assert_eq!(
        fs::read(&external_path).expect("read external target"),
        external_bytes
    );
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn nar_reads_replaced_nar_directories_as_internal_errors() {
    let server = RunningServer::start("read-replaced-nar-directory");
    let nar_dir = server.data_dir.join("nar");
    let real_nar_dir = server.data_dir.join("nar-real");
    let external_dir = server
        .data_dir
        .parent()
        .expect("data directory should have a parent")
        .join("external-nar-dir");
    let external_nar = external_dir.join(format!("{NAR_ID}.nar"));
    fs::rename(&nar_dir, &real_nar_dir).expect("move real NAR directory");
    fs::create_dir(&external_dir).expect("create external directory");
    fs::write(&external_nar, NAR_BYTES).expect("write external NAR");
    symlink(&external_dir, &nar_dir).expect("create NAR directory symlink");

    let response = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    let (headers, body) = response_parts(&response);
    let (signal, status) = server.stop();

    assert!(
        headers.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "{headers:?}"
    );
    assert!(body.is_empty());
    assert_eq!(
        fs::read(&external_nar).expect("read external NAR"),
        NAR_BYTES
    );
    fs::remove_dir_all(&external_dir).expect("remove external directory");
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
fn nar_put_and_get_preserve_xz_bytes() {
    let server = RunningServer::start("nar-put-xz");
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ writer");
    writer.write_all(NAR_BYTES).expect("compress NAR");
    writer.finish().expect("finish XZ stream");

    let file_hash = nix32_sha256(&compressed);
    let wrong_path = format!("/nar/{NARJAR_HASH}.nar.xz");
    let wrong = server.request_with_body("PUT", &wrong_path, &[], &compressed);
    let path = format!("/nar/{file_hash}.nar.xz");
    let stored_path = server.data_dir.join(format!("nar/{file_hash}.nar.xz"));
    let uploaded = server.request_with_body("PUT", &path, &[], &compressed);
    let downloaded = server.request("GET", &path);
    let stored = fs::read(stored_path).expect("read stored XZ NAR");
    let (signal, status) = server.stop();

    let (upload_headers, upload_body) = response_parts(&uploaded);
    let (wrong_headers, wrong_body) = response_parts(&wrong);
    assert!(
        wrong_headers.starts_with("HTTP/1.1 422 Unprocessable Entity\r\n"),
        "{wrong_headers:?}"
    );
    assert!(wrong_body.is_empty());
    assert!(
        upload_headers.starts_with("HTTP/1.1 201 Created\r\n"),
        "{upload_headers:?}"
    );
    assert!(upload_body.is_empty());
    let (download_headers, download_body) = response_parts(&downloaded);
    assert!(
        download_headers.starts_with("HTTP/1.1 200 OK\r\n"),
        "{download_headers:?}"
    );
    assert_eq!(download_body, compressed);
    assert_eq!(stored, compressed);
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn nar_put_and_get_preserve_zstd_bytes() {
    let server = RunningServer::start("nar-put-zstd");
    let mut compressed = Vec::new();
    compress(
        std::io::Cursor::new(NAR_BYTES),
        &mut compressed,
        CompressionLevel::Fastest,
    );

    let file_hash = nix32_sha256(&compressed);
    let path = format!("/nar/{file_hash}.nar.zst");
    let stored_path = server.data_dir.join(format!("nar/{file_hash}.nar.zst"));
    let uploaded = server.request_with_body("PUT", &path, &[], &compressed);
    let downloaded = server.request("GET", &path);
    let stored = fs::read(stored_path).expect("read stored zstd NAR");
    let (signal, status) = server.stop();

    let (upload_headers, upload_body) = response_parts(&uploaded);
    assert!(
        upload_headers.starts_with("HTTP/1.1 201 Created\r\n"),
        "{upload_headers:?}"
    );
    assert!(upload_body.is_empty());
    let (download_headers, download_body) = response_parts(&downloaded);
    assert!(
        download_headers.starts_with("HTTP/1.1 200 OK\r\n"),
        "{download_headers:?}"
    );
    assert_eq!(download_body, compressed);
    assert_eq!(stored, compressed);
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn xz_publications_are_idempotent_at_1_8_and_32_way_concurrency() {
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(6)).expect("create XZ writer");
    writer.write_all(NAR_BYTES).expect("compress NAR");
    writer.finish().expect("finish XZ stream");
    let file_hash = nix32_sha256(&compressed);

    for concurrency in [1, 8, 32] {
        let server = RunningServer::start_with_workers("xz-publication-lane", 8, &[]);
        let path = format!("/nar/{file_hash}.nar.xz");
        let responses = thread::scope(|scope| {
            (0..concurrency)
                .map(|_| scope.spawn(|| server.request_with_body("PUT", &path, &[], &compressed)))
                .map(|handle| handle.join().expect("upload should not panic"))
                .collect::<Vec<_>>()
        });
        for response in responses {
            assert!(
                response.starts_with(b"HTTP/1.1 20"),
                "unexpected upload response: {response:?}"
            );
        }
        let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
            .expect("metrics should be UTF-8");
        assert!(
            metrics.contains("narjar_publication_queue_depth 0"),
            "{metrics}"
        );
        assert!(
            metrics.contains(&format!(
                "narjar_publication_queue_wait_seconds_count {concurrency}"
            )),
            "{metrics}"
        );

        let (signal, status) = server.stop();
        assert!(signal.success(), "SIGTERM should be sent");
        assert!(status.success(), "narjar should shut down cleanly");
    }
}

#[test]
fn stalled_publication_does_not_block_an_independent_put() {
    let server = RunningServer::start_with_workers(
        "publication-head-of-line",
        2,
        &["--io-timeout-seconds", "2"],
    );
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let mut stalled = server.open_request("PUT", &path, &[("Content-Length", "6")]);
    thread::sleep(Duration::from_millis(50));

    thread::scope(|scope| {
        let completed = Arc::new(AtomicBool::new(false));
        let second_completed = Arc::clone(&completed);
        let server_ref = &server;
        let path_ref = &path;
        let second = scope.spawn(move || {
            let response = server_ref.request_with_body("PUT", path_ref, &[], NAR_BYTES);
            second_completed.store(true, Ordering::Release);
            response
        });

        for _ in 0..100 {
            if completed.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            completed.load(Ordering::Acquire),
            "following publication remained blocked behind the stalled body"
        );

        stalled
            .write_all(NAR_BYTES)
            .expect("stalled upload body should be writable");
        let first_response = read_http_response(&mut stalled);
        assert!(first_response.starts_with(b"HTTP/1.1 200 OK\r\n"));

        let second_response = second.join().expect("following upload should not panic");
        assert!(second_response.starts_with(b"HTTP/1.1 201 Created\r\n"));
    });

    let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
        .expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_publication_queue_depth 0"),
        "{metrics}"
    );
    assert!(
        metrics.contains("narjar_publication_queue_wait_seconds_count 2"),
        "{metrics}"
    );

    let (signal, status) = server.stop();
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn xz_narinfo_gates_and_serves_the_compressed_pair() {
    let server = RunningServer::start("narinfo-xz");
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ writer");
    writer.write_all(NAR_BYTES).expect("compress NAR");
    writer.finish().expect("finish XZ stream");
    let file_hash = nix32_sha256(&compressed);
    let narinfo = signed_xz_narinfo(
        &file_hash,
        NARJAR_HASH,
        NAR_BYTES.len() as u64,
        compressed.len() as u64,
    );

    let nar_path = format!("/nar/{file_hash}.nar.xz");
    let uploaded = server.request_with_body("PUT", &nar_path, &[], &compressed);
    let published = server.request_with_body(
        "PUT",
        &format!("/{STORE_HASH}.narinfo"),
        &[],
        narinfo.as_bytes(),
    );
    let narinfo_get = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let nar_get = server.request("GET", &nar_path);
    let (signal, status) = server.stop();

    for response in [&uploaded, &published, &narinfo_get, &nar_get] {
        assert!(
            String::from_utf8_lossy(response).starts_with("HTTP/1.1 2"),
            "{response:?}"
        );
    }
    let (_, nar_body) = response_parts(&nar_get);
    assert_eq!(nar_body, compressed);
    assert!(signal.success(), "SIGTERM should be sent");
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn zstd_narinfo_gates_and_serves_the_compressed_pair() {
    let server = RunningServer::start("narinfo-zstd");
    let mut compressed = Vec::new();
    compress(
        std::io::Cursor::new(NAR_BYTES),
        &mut compressed,
        CompressionLevel::Fastest,
    );
    let file_hash = nix32_sha256(&compressed);
    let narinfo = signed_zstd_narinfo(
        &file_hash,
        NARJAR_HASH,
        NAR_BYTES.len() as u64,
        compressed.len() as u64,
    );

    let wrong_path = format!("/nar/{NARJAR_HASH}.nar.zst");
    let wrong = server.request_with_body("PUT", &wrong_path, &[], &compressed);
    let nar_path = format!("/nar/{file_hash}.nar.zst");
    let uploaded = server.request_with_body("PUT", &nar_path, &[], &compressed);
    let published = server.request_with_body(
        "PUT",
        &format!("/{STORE_HASH}.narinfo"),
        &[],
        narinfo.as_bytes(),
    );
    let narinfo_get = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let nar_get = server.request("GET", &nar_path);
    let (signal, status) = server.stop();

    let (wrong_headers, wrong_body) = response_parts(&wrong);
    assert!(
        wrong_headers.starts_with("HTTP/1.1 422 Unprocessable Entity\r\n"),
        "{wrong_headers:?}"
    );
    assert!(wrong_body.is_empty());
    for (name, response) in [
        ("uploaded", &uploaded),
        ("published", &published),
        ("narinfo_get", &narinfo_get),
        ("nar_get", &nar_get),
    ] {
        assert!(
            String::from_utf8_lossy(response).starts_with("HTTP/1.1 2"),
            "{name}: {response:?}"
        );
    }
    let (_, narinfo_body) = response_parts(&narinfo_get);
    assert_eq!(narinfo_body, narinfo.as_bytes());
    let (_, nar_body) = response_parts(&nar_get);
    assert_eq!(nar_body, compressed);
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
    let mut child = RunningServer::spawn(&data_dir, 1, &[]);
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
fn nar_put_rejects_encoded_malformed_oversized_and_truncated_bodies() {
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
            "HTTP/1.1 422 Unprocessable Entity\r\n",
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
    let path = format!("/nar/{NAR_ID}.nar");
    let blocked = server.open_request("PUT", &path, &[("Content-Length", "1")]);

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
fn reads_continue_while_a_publication_waits_for_its_body() {
    let server = RunningServer::start_with_args("publication-lane", &["--max-in-flight", "2"]);
    let path = format!("/nar/{NAR_ID}.nar");
    fs::write(
        server.data_dir.join(format!("nar/{NAR_ID}.nar")),
        b"0123456789",
    )
    .expect("write NAR fixture");
    let stalled = server.open_request("PUT", &path, &[("Content-Length", "1")]);
    thread::sleep(Duration::from_millis(50));

    let started = Instant::now();
    let response = server.request("GET", "/nix-cache-info");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "GET waited for the stalled publication: {:?}",
        started.elapsed()
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{response:?}");

    let started = Instant::now();
    let range = server.request_with_headers("GET", &path, &[("Range", "bytes=2-5")]);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "range GET waited for the stalled publication: {:?}",
        started.elapsed()
    );
    let (headers, body) = response_parts(&range);
    assert!(
        headers.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{headers:?}"
    );
    assert_eq!(body, b"2345");

    drop(stalled);
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
    let data_dir = init_data_dir("token-lifecycle");
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
            .starts_with("HTTP/1.1 200 OK\r\n"),
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
fn structural_reconcile_reports_temp_age_and_shape() {
    let data_dir = init_data_dir("operator-structural-reconcile");
    fs::write(data_dir.join(".tmp/nar-young.part"), b"temporary")
        .expect("temporary file should be written");
    fs::write(data_dir.join(".tmp/cache-info-young.part"), b"temporary")
        .expect("cache-info temporary file should be written");
    fs::write(data_dir.join("nar/.tmp/nar-young.part"), b"temporary")
        .expect("NAR temporary file should be written");
    fs::write(
        data_dir.join("realisations/.tmp/realisation-young.part"),
        b"temporary",
    )
    .expect("realisation temporary file should be written");
    fs::write(data_dir.join(".tmp/not-a-temp"), b"unexpected")
        .expect("invalid temporary file should be written");
    fs::create_dir(data_dir.join(".tmp/nar-directory.part"))
        .expect("unexpected temporary directory should be created");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let output = run(&[
        "reconcile",
        "--data-dir",
        path,
        "--structural",
        "--min-age-seconds",
        "3600",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "structural reconcile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).expect("report should be UTF-8");
    assert!(report.contains(
        "{\"class\":\"temp_young\",\"path\":\".tmp/nar-young.part\",\"action\":\"inspect\"}"
    ));
    for path in [
        ".tmp/cache-info-young.part",
        "nar/.tmp/nar-young.part",
        "realisations/.tmp/realisation-young.part",
    ] {
        assert!(
            report.contains(&format!(
                "{{\"class\":\"temp_young\",\"path\":\"{path}\",\"action\":\"inspect\"}}"
            )),
            "{report}"
        );
    }
    assert!(report.contains(
        "{\"class\":\"invalid_filename\",\"path\":\".tmp/not-a-temp\",\"action\":\"inspect\"}"
    ));
    assert!(report.contains(
        "{\"class\":\"unexpected_type\",\"path\":\".tmp/nar-directory.part\",\"action\":\"inspect\"}"
    ));
}

#[test]
fn cleanup_deletes_stale_temps_and_reports_the_action() {
    let data_dir = init_data_dir("operator-structural-cleanup");
    let temporary = data_dir.join(".tmp/nar-stale.part");
    fs::write(&temporary, b"temporary").expect("temporary file should be written");
    let unknown = data_dir.join("unknown-file");
    fs::write(&unknown, b"unknown").expect("unknown file should be written");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let output = run(&[
        "cleanup",
        "--data-dir",
        path,
        "--min-age-seconds",
        "0",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "cleanup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).expect("report should be UTF-8");
    assert!(report.contains(
        "{\"class\":\"temp_stale\",\"path\":\".tmp/nar-stale.part\",\"action\":\"deleted\"}"
    ));
    assert!(
        report
            .contains("{\"class\":\"unknown_file\",\"path\":\"unknown-file\",\"action\":\"kept\"}")
    );
    assert!(
        !temporary.exists(),
        "stale temporary file should be removed"
    );
    assert!(unknown.exists(), "unknown file should survive cleanup");
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

    let restored = data_dir("backup-restored");
    for directory in [
        "nar",
        "nar/.tmp",
        ".tmp",
        "realisations",
        "realisations/.tmp",
        "auth",
    ] {
        fs::create_dir_all(restored.join(directory)).expect("restore directory should be created");
    }
    for relative in [
        ".narjar-clean",
        "lock",
        "nix-cache-info",
        "trusted-public-keys",
        "auth/write.tokens",
        "nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar",
        "00000000000000000000000000000000.narinfo",
    ] {
        fs::copy(source.join(relative), restored.join(relative))
            .expect("backup file should be restored");
    }
    let path = restored.to_str().expect("restored path should be UTF-8");
    let reconcile = run(&["reconcile", "--data-dir", path, "--verify-hashes", "--json"]);
    assert!(
        reconcile.status.success(),
        "restored cache failed reconciliation: {}{}",
        String::from_utf8_lossy(&reconcile.stdout),
        String::from_utf8_lossy(&reconcile.stderr)
    );
    let verify = run(&["verify", "--data-dir", path, "--json"]);
    assert!(
        verify.status.success(),
        "restored cache failed verification: {}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let doctor = run(&["doctor", "--data-dir", path, "--json"]);
    assert!(
        doctor.status.success(),
        "restored cache failed doctor preflight: {}{}",
        String::from_utf8_lossy(&doctor.stdout),
        String::from_utf8_lossy(&doctor.stderr)
    );

    let server = RunningServer::start_in(restored, &[]);
    let (ready_headers, ready_body) = response_parts(&server.request("GET", "/readyz"));
    assert!(ready_headers.starts_with("HTTP/1.1 200"), "{ready_headers}");
    assert_eq!(ready_body, b"ready\n");
    let (nar_headers, nar_body) =
        response_parts(&server.request("GET", &format!("/nar/{NARJAR_HASH}.nar")));
    assert!(nar_headers.starts_with("HTTP/1.1 200"), "{nar_headers}");
    assert_eq!(nar_body, NAR_BYTES);
    let (signal, status) = server.stop();
    assert!(signal.success(), "restored server should receive SIGTERM");
    assert!(status.success(), "restored server should shut down cleanly");
}

#[test]
fn dirty_start_rejects_a_malformed_published_narinfo() {
    let data_dir = init_data_dir("dirty-start-malformed-narinfo");
    fs::remove_file(data_dir.join(".narjar-clean")).expect("clean marker should exist");
    let recovery = data_dir.join(".narjar-recovery");
    fs::write(&recovery, b"").expect("recovery marker should be created");
    fs::set_permissions(
        &recovery,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .expect("recovery marker should be private");
    fs::write(
        data_dir.join("00000000000000000000000000000000.narinfo"),
        b"not a narinfo\n",
    )
    .expect("malformed narinfo should be written");

    let output = run(&[
        "serve",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--listen",
        "127.0.0.1:0",
    ]);
    assert!(!output.status.success(), "dirty start must fail closed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("published narinfo is not trusted"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        data_dir.join(".narjar-recovery").exists(),
        "failed recovery must retain its marker"
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
    let apply_stdout = String::from_utf8_lossy(&apply.stdout);
    assert!(apply_stdout.contains("\"deleted_narinfos\":1"));
    assert!(apply_stdout.contains("\"after_bytes\":0"));
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"candidates\":0"));
    assert!(stdout.contains("\"protected\":1"));
    assert!(stdout.contains("\"eligible\":0"));
    assert!(stdout.contains("\"evicted\":0"));
    assert!(stdout.contains("\"target_met\":false"));
}

#[test]
fn gc_reports_missing_protected_references() {
    let data_dir = init_data_dir("operator-gc-missing-reference");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    let missing_store = "11111111111111111111111111111111";
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo_for_with_references(
            STORE_HASH,
            NARJAR_HASH,
            NAR_BYTES.len() as u64,
            &[missing_store],
        ),
    )
    .expect("narinfo should be written");
    let roots = data_dir.join("protected-roots");
    fs::write(
        &roots,
        format!(
            "/nix/store/{STORE_HASH}-narjar\n/nix/store/11111111111111111111111111111111-missing\n"
        ),
    )
    .expect("protected roots should be written");

    let output = run(&[
        "gc",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--target-bytes",
        "0",
        "--protected-roots",
        roots
            .to_str()
            .expect("protected roots path should be UTF-8"),
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"protected\":1"));
    assert!(stdout.contains("\"missing_roots\":1"));
    assert!(stdout.contains("\"missing_references\":1"));
    assert!(stdout.contains("\"target_met\":false"));
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

#[test]
fn gc_sigterm_leaves_a_cache_recoverable_before_restart() {
    let data_dir = init_data_dir("operator-gc-sigterm");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("shared NAR should be written");
    for index in 0..100 {
        let store = format!("{index:032o}");
        fs::write(
            data_dir.join(format!("{store}.narinfo")),
            signed_narinfo_for(&store, NARJAR_HASH, NAR_BYTES.len() as u64),
        )
        .expect("narinfo should be written");
    }

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let mut gc = command()
        .args(["gc", "--data-dir", path, "--target-bytes", "0", "--apply"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("gc should start");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !data_dir.join(".narjar-recovery").exists() {
        assert!(
            Instant::now() < deadline,
            "gc did not create the recovery marker"
        );
        assert!(
            gc.try_wait().expect("gc should be waitable").is_none(),
            "gc finished before the interruption fixture observed recovery"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let pid = gc.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("SIGTERM should be sent")
            .success()
    );
    assert!(
        !gc.wait().expect("gc should exit after SIGTERM").success(),
        "interrupted GC must not claim successful completion"
    );
    assert!(
        data_dir.join(".narjar-recovery").exists(),
        "interrupted GC must retain the recovery marker"
    );

    let mut server = command()
        .args(["serve", "--data-dir", path, "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server should start");
    let mut line = String::new();
    BufReader::new(server.stdout.take().expect("server stdout should be piped"))
        .read_line(&mut line)
        .expect("server startup line should be readable");
    assert!(line.starts_with("listening http://127.0.0.1:"), "{line}");
    assert!(
        !data_dir.join(".narjar-recovery").exists(),
        "server recovery should clear the marker after a valid inventory"
    );
    let server_pid = server.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &server_pid])
            .status()
            .expect("SIGTERM should be sent")
            .success()
    );
    assert!(
        server
            .wait()
            .expect("server should exit after SIGTERM")
            .success()
    );
}

#[test]
fn gc_reclaims_old_orphan_nars() {
    let data_dir = init_data_dir("operator-gc-orphan");
    fs::write(data_dir.join(".tmp/incomplete"), b"temp")
        .expect("temporary entry should be written");
    fs::write(data_dir.join(format!("nar/{NAR_ID}.nar")), b"orphan")
        .expect("orphan NAR should be written");

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
    assert!(!data_dir.join(format!("nar/{NAR_ID}.nar")).exists());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"deleted_orphans\":1"));
    assert!(stdout.contains("\"temporary\":1"));
    assert!(stdout.contains("\"orphaned_bytes\":6"));
    assert!(stdout.contains("\"temporary_bytes\":4"));
}

#[test]
fn gc_dry_run_and_apply_agree_on_partial_orphan_cleanup() {
    let data_dir = init_data_dir("operator-gc-retained-orphan");
    let retained_orphan_nar = "1".repeat(52);
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    fs::write(data_dir.join(format!("nar/{NAR_ID}.nar")), b"old-orphan")
        .expect("old orphan should be written");
    fs::write(
        data_dir.join(format!("nar/{retained_orphan_nar}.nar")),
        b"new-orphan",
    )
    .expect("new orphan should be written");

    thread::sleep(Duration::from_secs(2));
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
    let narinfo_bytes = narinfo.len() as u64;
    fs::write(data_dir.join(format!("{STORE_HASH}.narinfo")), narinfo)
        .expect("published narinfo should be written");
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("published NAR should be written");

    let published_bytes = narinfo_bytes + NAR_BYTES.len() as u64;
    let retained_orphan_bytes = b"new-orphan".len() as u64;
    let target_bytes = published_bytes + retained_orphan_bytes;
    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let dry_run = command()
        .args(["gc", "--data-dir", path, "--target-bytes"])
        .arg(target_bytes.to_string())
        .args(["--min-age-seconds", "1", "--json"])
        .output()
        .expect("gc should run");

    assert!(
        dry_run.status.success(),
        "gc dry-run failed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_run_stdout = String::from_utf8_lossy(&dry_run.stdout);
    assert!(dry_run_stdout.contains("\"accounting_basis\":\"logical\""));
    assert!(dry_run_stdout.contains(&format!(
        "\"before_bytes\":{}",
        published_bytes + b"old-orphan".len() as u64 + retained_orphan_bytes
    )));
    assert!(dry_run_stdout.contains(&format!("\"after_bytes\":{target_bytes}")));
    assert!(dry_run_stdout.contains("\"evicted_bytes\":10"));
    assert!(dry_run_stdout.contains("\"candidates\":1"));
    assert!(dry_run_stdout.contains("\"target_met\":true"));
    assert!(data_dir.join(format!("nar/{NAR_ID}.nar")).exists());
    assert!(
        data_dir
            .join(format!("nar/{retained_orphan_nar}.nar"))
            .exists()
    );

    let apply = command()
        .args(["gc", "--data-dir", path, "--target-bytes"])
        .arg(target_bytes.to_string())
        .args(["--min-age-seconds", "1", "--apply", "--json"])
        .output()
        .expect("gc should run");
    assert!(
        apply.status.success(),
        "gc apply failed: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let apply_stdout = String::from_utf8_lossy(&apply.stdout);
    assert!(apply_stdout.contains("\"dry_run\":false"));
    assert!(apply_stdout.contains(&format!("\"after_bytes\":{target_bytes}")));
    assert!(apply_stdout.contains("\"evicted_bytes\":10"));
    assert!(apply_stdout.contains("\"candidates\":1"));
    assert!(apply_stdout.contains("\"target_met\":true"));
    assert!(!data_dir.join(format!("nar/{NAR_ID}.nar")).exists());
    assert!(
        data_dir
            .join(format!("nar/{retained_orphan_nar}.nar"))
            .exists()
    );
    let direct_after_bytes = fs::metadata(data_dir.join(format!("{STORE_HASH}.narinfo")))
        .expect("published narinfo should remain")
        .len()
        + fs::metadata(data_dir.join(format!("nar/{NARJAR_HASH}.nar")))
            .expect("published NAR should remain")
            .len()
        + fs::metadata(data_dir.join(format!("nar/{retained_orphan_nar}.nar")))
            .expect("retained orphan should remain")
            .len();
    assert_eq!(direct_after_bytes, target_bytes);
}
#[test]
fn gc_rejects_symlinked_narinfo_without_removing_it() {
    let data_dir = init_data_dir("operator-gc-symlink");
    fs::write(
        data_dir.join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    fs::write(
        data_dir.join("narinfo-target"),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("narinfo target should be written");
    symlink(
        data_dir.join("narinfo-target"),
        data_dir.join(format!("{STORE_HASH}.narinfo")),
    )
    .expect("narinfo symlink should be created");

    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let output = run(&["gc", "--data-dir", path, "--target-bytes", "0", "--apply"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
    assert!(data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
}
