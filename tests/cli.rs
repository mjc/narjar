use crate::cache::storage::gc::{GcMode, GcOptions};
use crate::cache::test_support::symlink;

#[cfg(unix)]
#[path = "support/platform_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "support/platform_windows.rs"]
mod platform;
use platform::deny_fixture_data_reads;

const SUPPORTED_STORAGE_BACKENDS: &[&str] = &[
    "flat",
    #[cfg(target_os = "linux")]
    "chunked",
];

fn assert_private_path(path: impl AsRef<Path>) {
    let path = path.as_ref();
    match path.is_dir() {
        true => crate::cache::filesystem::validate_private_directory(
            &crate::cache::filesystem::open_directory(path).unwrap(),
        )
        .unwrap(),
        false => crate::cache::filesystem::validate_private_file(
            &crate::cache::filesystem::open_regular(path).unwrap(),
        )
        .unwrap(),
    }
}
use data_encoding::{BASE64, BitOrder, Specification};
use ed25519_dalek::{Signer, SigningKey};
use lzma_rust2::{XzOptions, XzWriter};
use narjar::nar_encode::{Encoder, Event as NarEvent};
use narjar::object::{CompressionCodec, WireEncoding};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    ops::Deref,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder, compress};
use tempfile::TempDir;

#[cfg(target_os = "linux")]
use std::sync::{Barrier, atomic::AtomicU64};

const CONFIG_ENV: &[&str] = &[
    "NARJAR_EDGE_UPSTREAM",
    "NARJAR_EDGE_LEASE_SECONDS",
    "NARJAR_EDGE_MAX_FILLS",
    "NARJAR_EDGE_TIMEOUT_SECONDS",
    "NARJAR_EDGE_FILL_TIMEOUT_SECONDS",
    "NARJAR_EDGE_NEGATIVE_TTL_SECONDS",
    "NARJAR_SERVE_SOURCE",
    "NARJAR_NATIVE_STORE_DIR",
    "NARJAR_NATIVE_STATE_DIR",
    "NARJAR_NATIVE_ROOTS_DIR",
    "NARJAR_NATIVE_MIN_LEASE_SECONDS",
    "NARJAR_NATIVE_SIGNING_KEY_FILE",
    "NOTIFY_SOCKET",
    "NARJAR_DATA_DIR",
    "NARJAR_LISTEN",
    "NARJAR_WORKERS",
    "NARJAR_MAX_IN_FLIGHT",
    "NARJAR_MAX_NAR_BYTES",
    "NARJAR_MIN_FREE_BYTES",
    "NARJAR_EGRESS_COMPRESSION",
    "NARJAR_TRACK_ACCESS",
    "NARJAR_SHUTDOWN_GRACE_SECONDS",
    "NARJAR_IO_TIMEOUT_SECONDS",
    "NARJAR_PUSH_TIMEOUT_SECONDS",
    "NARJAR_PUBLIC_URL",
    "NARJAR_ADVERTISE",
    "NARJAR_DISCOVERY_NAME",
    "NARJAR_ONBOARDING",
    "NARJAR_ONBOARDING_DIAGNOSTICS",
];

#[cfg(unix)]
#[path = "support/native_http.rs"]
mod native_http;
#[path = "support/read_through_http.rs"]
mod read_through_http;

const NAR_ID: &str = "0000000000000000000000000000000000000000000000000000";
const NAR_BYTES: &[u8] = b"narjar";
const NARJAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
const CACHE_INFO: &[u8] = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
const STORE_HASH: &str = "00000000000000000000000000000000";
const ABSENT_STORE_HASH: &str = "11111111111111111111111111111111";
const TEST_AUTHORIZATION: &str = "Basic bmFyamFyOnRlc3Qtd3JpdGUtdG9rZW4=";
const TEST_WRITE_TOKEN: &str =
    "test 4c6fe1d79dd5595d75e9b7c82dbdc4481996f7aea7143e7153c8eb5e9f94ea45\n";

fn test_trusted_public_key() -> String {
    format!(
        "narjar-test:{}\n",
        BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
    )
}

fn write_test_trusted_public_keys(path: impl AsRef<Path>) {
    fs::write(path, test_trusted_public_key()).expect("write trusted test public key");
}

#[track_caller]
fn assert_clean_shutdown(signal: std::io::Result<()>, status: ExitStatus) {
    assert!(signal.is_ok(), "shutdown request failed: {signal:?}");
    assert!(status.success(), "narjar should shut down cleanly");
}

fn wait_for_connection_refusal<T>(
    deadline: Instant,
    mut connect: impl FnMut() -> std::io::Result<T>,
) {
    for connection in std::iter::repeat_with(&mut connect) {
        match connection {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => return,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("checking shutdown listener: {error}"),
            Ok(stream) => drop(stream),
        }
        assert!(
            Instant::now() < deadline,
            "first SIGTERM must stop accepting connections"
        );
        thread::yield_now();
    }
}

#[test]
fn shutdown_probe_retries_resets_and_open_connections_until_refused() {
    let mut probes = [
        Err(std::io::ErrorKind::ConnectionReset.into()),
        Ok(()),
        Err(std::io::ErrorKind::ConnectionRefused.into()),
    ]
    .into_iter();
    wait_for_connection_refusal(Instant::now() + Duration::from_secs(1), || {
        probes
            .next()
            .expect("shutdown must be established by refusal, not a reset")
    });
    assert_eq!(probes.len(), 0);
}

#[test]
fn shutdown_probe_does_not_treat_resets_as_listener_closure() {
    let result = std::panic::catch_unwind(|| {
        wait_for_connection_refusal::<()>(Instant::now(), || {
            Err(std::io::ErrorKind::ConnectionReset.into())
        });
    });
    assert!(
        result.is_err(),
        "a reset without refusal must not satisfy the probe"
    );
}

#[test]
fn shutdown_probe_does_not_hide_other_connection_errors() {
    let result = std::panic::catch_unwind(|| {
        wait_for_connection_refusal::<()>(Instant::now() + Duration::from_secs(1), || {
            Err(std::io::ErrorKind::PermissionDenied.into())
        });
    });
    assert!(result.is_err());
}

fn signed_narinfo(nar_hash: &str, nar_size: u64) -> String {
    signed_narinfo_for(STORE_HASH, nar_hash, nar_size)
}

fn published_transaction_bytes(temporary: &str, destination: &str) -> Vec<u8> {
    // Postcard enum discriminants: TransactionRecord::V1 = 0, Published = 4.
    postcard::to_allocvec(&(0_u32, temporary, 4_u32, destination))
        .expect("published recovery fixture should encode")
}

fn read_http_response_headers(stream: &mut impl BufRead) -> Vec<u8> {
    let mut headers = Vec::new();
    loop {
        let mut line = Vec::new();
        let count = stream
            .read_until(b'\n', &mut line)
            .expect("response headers should be readable");
        assert_ne!(count, 0, "response ended before its headers");
        headers.extend_from_slice(&line);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    headers
}

fn read_http_response(stream: &mut impl BufRead) -> Vec<u8> {
    let headers = read_http_response_headers(stream);
    let header_text = std::str::from_utf8(&headers).expect("response headers should be UTF-8");
    let content_length = header_text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map(|value| value.trim().parse::<usize>().expect("valid Content-Length"))
        .expect("response should declare its body length");
    let mut response = headers;
    let body_start = response.len();
    stream
        .take(content_length as u64)
        .read_to_end(&mut response)
        .expect("response body should be readable");
    assert_eq!(
        response.len() - body_start,
        content_length,
        "response ended before its declared body"
    );
    response
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

fn http_request_body_start(request: &[u8]) -> usize {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("request should contain headers")
        + 4
}

fn assert_http_request_has_no_authorization(request: &[u8]) {
    let header_end = http_request_body_start(request);
    assert!(
        !String::from_utf8_lossy(&request[..header_end])
            .lines()
            .any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            }),
        "plain HTTP request must not contain an Authorization header"
    );
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
    let executable = std::env::var_os("NARJAR_TEST_EXECUTABLE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_narjar").into());
    let mut command = Command::new(executable);
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
fn discovery_configuration_is_offline_repeatable_and_keeps_notices_off_stdout() {
    let key = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
    let arguments = [
        "discover",
        "config",
        "--url",
        "https://offline.example",
        "--trusted-public-key",
        key,
        "--format",
        "nix-conf",
    ];
    let first = run(&arguments);
    let second = run(&arguments);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    let text = String::from_utf8(first.stdout).unwrap();
    assert!(text.starts_with("extra-substituters = https://offline.example?priority=30\n"));
    assert!(!text.contains("SHA-256"));
    assert!(String::from_utf8_lossy(&first.stderr).contains("SHA-256 of public-key line"));
    assert_eq!(
        run(&["discover", "config", "--url", "https://offline.example"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        run(&["discover", "browse", "--timeout-seconds", "0"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        run(&["discover", "browse", "--max-results", "65"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn cli_help_and_version_work_for_the_packaged_binary() {
    for arguments in [&["--help"][..], &["-h"][..]] {
        let output = run(arguments);
        assert!(
            output.status.success(),
            "help should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let help = String::from_utf8(output.stdout).expect("help should be UTF-8");
        assert!(help.contains("Usage: narjar <COMMAND>"), "{help}");
        assert!(help.contains("setup"), "{help}");
    }

    for arguments in [&["--version"][..], &["-V"][..]] {
        let output = run(arguments);
        assert!(
            output.status.success(),
            "version should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("version should be UTF-8"),
            format!("narjar {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    for subcommand in [
        "serve",
        "init",
        "setup",
        "key",
        "reconcile",
        "cleanup",
        "verify",
        "gc",
        "list-orphans",
        "delete",
        "stats",
        "doctor",
        "token",
        "push",
    ] {
        let output = run(&[subcommand, "--help"]);
        assert!(
            output.status.success(),
            "{subcommand} help should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let help = String::from_utf8(output.stdout).expect("subcommand help should be UTF-8");
        assert!(
            help.contains(&format!("Usage: narjar {subcommand}")),
            "{subcommand} help omitted its usage: {help}"
        );
    }

    let invalid_argument = run(&["serve", "--unknown"]);
    assert_eq!(invalid_argument.status.code(), Some(2));
    let error = String::from_utf8(invalid_argument.stderr).expect("error should be UTF-8");
    assert!(error.contains("error:"), "{error}");
    assert!(error.contains("Usage: narjar serve"), "{error}");
}

#[test]
fn serve_help_advertises_native_store_source_and_explicit_configuration() {
    let output = run(&["serve", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("native-store"), "{help}");
    for flag in [
        "--native-store-dir",
        "--native-state-dir",
        "--native-roots-dir",
        "--native-min-lease-seconds",
        "--native-signing-key-file",
    ] {
        assert!(help.contains(flag), "{help}");
    }
}

#[cfg(unix)]
#[path = "support/native_push.rs"]
mod native_push;

fn native_nar_bytes() -> Vec<u8> {
    native_nar_bytes_with_contents(NAR_BYTES)
}

fn native_nar_bytes_with_contents(contents: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output).expect("create native NAR fixture encoder");
    encoder
        .push(NarEvent::BeginFile {
            executable: false,
            size: contents.len() as u64,
        })
        .expect("begin native NAR fixture file");
    encoder
        .push(NarEvent::FileChunk(contents))
        .expect("write native NAR fixture file");
    encoder
        .push(NarEvent::EndFile)
        .expect("finish native NAR fixture file");
    encoder.finish().expect("finish native NAR fixture encoder");
    output
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
    // Long diagnostic prefixes can exhaust macOS's Unix socket pathname limit.
    let prefix = if cfg!(target_os = "macos") {
        "nj-".to_owned()
    } else {
        format!("narjar-{test}-")
    };
    let directory = tempfile::Builder::new()
        .prefix(&prefix)
        .tempdir()
        .expect("test data directory should be created");
    crate::cache::test_support::private_directory(directory.path())
        .expect("test data directory should be private to this account");
    TestDir(directory)
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
        "error: the following required arguments were not provided:\n  --data-dir <DATA_DIR>\n\nUsage: narjar serve --data-dir <DATA_DIR>\n\nFor more information, try '--help'.\n"
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

    assert_incomplete_cache_rejected_without_creating_entries(&data_dir, &[], output);
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

    assert_incomplete_cache_rejected_without_creating_entries(
        &data_dir,
        &[".tmp", "auth", "nar", "realisations"],
        output,
    );
}

fn assert_incomplete_cache_rejected_without_creating_entries(
    root: &Path,
    expected_names: &[&str],
    output: Output,
) {
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "an incomplete cache must not start listening"
    );
    let error = String::from_utf8(output.stderr).unwrap();
    // Unix leases DATA itself; Windows first needs an existing lease file.
    assert!(
        error.contains("missing its storage-layout descriptor") || error.contains("lock:"),
        "{error}"
    );
    let mut names = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        expected_names
            .iter()
            .map(|name| std::ffi::OsString::from(*name))
            .collect::<Vec<_>>()
    );
}

#[test]
fn serve_requires_each_startup_policy_file_without_recreating_it() {
    for relative in ["nix-cache-info", "trusted-public-keys", "auth/write.tokens"] {
        let root = init_data_dir("missing-startup-policy");
        let missing = root.join(relative);
        fs::remove_file(&missing).unwrap();
        let output = run(&[
            "serve",
            "--data-dir",
            root.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains(relative.rsplit('/').next().unwrap())
        );
        assert!(
            !missing.exists(),
            "opening cannot silently replace {relative}"
        );
    }
}

#[cfg(unix)]
#[test]
fn initialization_creates_a_private_root_even_with_a_group_writable_umask() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    let parent = data_dir("group-writable-umask");
    let root = parent.join("cache");
    let mut child = command();
    child.args(["init", "--data-dir", root.to_str().unwrap()]);
    // SAFETY: pre_exec changes only the child process; umask is an async-signal-safe
    // syscall with no allocation or access to inherited locks. The parent and
    // parallel tests retain their own masks.
    unsafe {
        child.pre_exec(|| {
            rustix::process::umask(rustix::fs::Mode::WOTH);
            Ok(())
        });
    }
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let opened = crate::cache::storage::Directory::open(&root).unwrap();
    assert!(
        crate::cache::storage::Storage::open(
            &opened,
            crate::cache::storage::SupportedStorageBackend::FLAT
        )
        .is_ok()
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
        "error: invalid value 'not-an-address' for '--listen <LISTEN>': invalid socket address syntax\n\nFor more information, try '--help'.\n"
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
        "error: invalid value '0' for '--workers <WORKERS>': number would be zero for non-zero type\n\nFor more information, try '--help'.\n"
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
        "error: invalid value '0' for '--workers <WORKERS>': number would be zero for non-zero type\n\nFor more information, try '--help'.\n"
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
        "error: the argument '--workers <WORKERS>' cannot be used multiple times\n\nUsage: narjar serve [OPTIONS] --data-dir <DATA_DIR>\n\nFor more information, try '--help'.\n"
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
        "error: invalid value '0' for '--max-in-flight <MAX_IN_FLIGHT>': number would be zero for non-zero type\n\nFor more information, try '--help'.\n"
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
        "error: invalid value '0' for '--max-nar-bytes <MAX_NAR_BYTES>': number would be zero for non-zero type\n\nFor more information, try '--help'.\n"
    );
}

struct RunningServer {
    child: Option<Child>,
    data_dir: PathBuf,
    temp_dir: Option<TestDir>,
    startup_line: String,
    address: String,
}

#[test]
fn online_gc_uses_the_running_flat_daemon_without_interrupting_cache_reads() {
    assert_online_gc_preserves_new_publication("online-gc-flat", "flat");
}

#[test]
fn gc_delete_older_than_deletes_old_payloads_and_preserves_recent_ones() {
    let data = data_dir("gc-age-days");
    let initialized = run(&["init", "--data-dir", data.to_str().unwrap()]);
    assert!(initialized.status.success());
    let old_payload = data.join(format!("nar/{NARJAR_HASH}.nar"));
    fs::write(&old_payload, NAR_BYTES).unwrap();
    let old_time = std::time::SystemTime::now() - Duration::from_secs(14 * 24 * 60 * 60);
    crate::cache::test_support::set_fixture_modified_time(&old_payload, old_time).unwrap();
    let recent_bytes = b"recent NAR payload";
    let recent_payload = data.join(format!("nar/{}.nar", nix32_sha256(recent_bytes)));
    fs::write(&recent_payload, recent_bytes).unwrap();

    let args = [
        "gc",
        "--data-dir",
        data.to_str().unwrap(),
        "--delete-older-than",
        "7d",
        "--json",
    ];
    let preview = run(&args);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["candidates"], 1);
    assert!(
        old_payload.exists(),
        "GC defaults to a non-deleting preview"
    );
    assert!(recent_payload.exists());

    let applied = run(&[args.as_slice(), &["--apply"]].concat());
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(report["deleted_orphans"], 1);
    assert!(
        !old_payload.exists(),
        "the fourteen-day-old payload is collected"
    );
    assert_eq!(fs::read(&recent_payload).unwrap(), recent_bytes);
}

#[test]
fn gc_delete_older_than_rejects_invalid_periods_and_conflicting_age_units() {
    for age_args in [
        vec!["--delete-older-than", "18446744073709551615d"],
        vec!["--delete-older-than", "-1d"],
        vec!["--delete-older-than", "1.5d"],
        vec!["--delete-older-than", "7"],
        vec!["--delete-older-than", "7h"],
        vec!["--delete-older-than", "7d", "--max-age-seconds", "1"],
    ] {
        let result = run(&[vec!["gc", "--data-dir", "/unused-cache"], age_args].concat());
        assert_eq!(result.status.code(), Some(2));
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("unexpected argument"),
            "the days flag must be recognized; invalid values fail during argument parsing"
        );
    }
}

#[test]
fn online_gc_reads_protected_roots_from_the_clients_stdin_not_the_daemons() {
    let server = RunningServer::start("gc-stdin");
    let mut client = command()
        .args([
            "gc",
            "--online",
            "--data-dir",
            server.data_dir.to_str().unwrap(),
            "--protected-roots",
            "-",
            "--target-bytes",
            "0",
            "--dry-run",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    client
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{ABSENT_STORE_HASH}\n").as_bytes())
        .unwrap();
    let result = client.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        report["missing_roots"], 1,
        "the caller's explicit root must reach the daemon even when its stdin is null"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn online_gc_resolves_non_utf8_roots_filenames_in_the_client() {
    use std::os::unix::ffi::OsStringExt;
    let server = RunningServer::start("gc-bytes");
    let directory = tempfile::tempdir_in("/dev/shm").unwrap();
    let source = directory
        .path()
        .join(std::ffi::OsString::from_vec(b"roots-\xff".to_vec()));
    fs::write(&source, format!("{ABSENT_STORE_HASH}\n")).unwrap();
    let result = command()
        .args(["gc", "--online", "--data-dir"])
        .arg(&server.data_dir)
        .args(["--protected-roots"])
        .arg(&source)
        .args(["--target-bytes", "0", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["missing_roots"], 1);
}

#[test]
fn invalid_protected_roots_abort_before_an_online_collector_can_be_contacted() {
    let directory = data_dir("gc-invalid");
    let source = directory.join("roots");
    fs::write(&source, "not-a-root\n").unwrap();
    let result = command()
        .args(["gc", "--online", "--data-dir"])
        .arg(directory.path())
        .args(["--protected-roots"])
        .arg(&source)
        .args(["--target-bytes", "0", "--apply"])
        .output()
        .unwrap();
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success());
    assert!(error.contains("invalid protected root"), "{error}");
    assert!(
        !error.contains("cannot connect"),
        "invalid roots must be checked locally before opening the control connection"
    );
}

#[test]
fn unattended_retention_rejects_partial_unbounded_and_invalid_cli_policies() {
    for policy in [
        vec!["--min-free-bytes", "10"],
        vec!["--min-free-bytes", "10", "--target-free-bytes", "20"],
        vec!["--max-deletions", "0"],
        vec!["--eviction-order", "unknown"],
        vec!["--online", "--retry-attempts", "0"],
        vec!["--online", "--retry-attempts", "17"],
        vec!["--online", "--retry-delay-millis", "30001"],
        vec!["--retry-attempts", "2"],
        vec![
            "--min-free-bytes",
            "20",
            "--target-free-bytes",
            "10",
            "--max-deletions",
            "1",
        ],
    ] {
        let result = run(&[
            vec!["gc", "--data-dir", "/unused-cache", "--target-bytes", "0"],
            policy,
        ]
        .concat());
        assert!(!result.status.success());
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("unexpected argument"),
            "every retention option must be recognized"
        );
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("No such file"),
            "invalid policy must fail before opening storage"
        );
    }
}

#[test]
fn read_use_hints_are_only_created_for_successfully_resolved_http_payloads() {
    let server = RunningServer::start_with_args("read-use-hints", &["--track-access"]);
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let upload = server.request_with_body("PUT", &path, &[], NAR_BYTES);
    assert!(
        upload.starts_with(b"HTTP/1.1 201"),
        "{}",
        String::from_utf8_lossy(&upload)
    );
    let hint = server
        .data_dir
        .join(".narjar-access")
        .join(format!("{NARJAR_HASH}.nar"));
    assert!(!hint.exists(), "upload and validation are not reads");
    let rejected = server.request_with_headers("GET", &path, &[("Range", "bytes=99-100")]);
    assert!(rejected.starts_with(b"HTTP/1.1 416"));
    assert!(!hint.exists(), "unsatisfiable range must not record use");
    let head = server.request("HEAD", &path);
    assert!(head.starts_with(b"HTTP/1.1 200"));
    assert_eq!(fs::metadata(&hint).unwrap().len(), 0);
    let previous = fs::metadata(&hint).unwrap().modified().unwrap();
    let get = server.request("GET", &path);
    assert!(get.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        fs::metadata(&hint).unwrap().modified().unwrap(),
        previous,
        "a repeated request is coalesced"
    );
    let range = server.request_with_headers("GET", &path, &[("Range", "bytes=1-2")]);
    assert!(range.starts_with(b"HTTP/1.1 206"));
    assert_eq!(fs::metadata(&hint).unwrap().modified().unwrap(), previous);
}

#[test]
fn gc_delete_older_than_preserves_protected_and_recent_publications_and_shared_payloads() {
    let data = init_data_dir("gc-age-publications");
    write_test_trusted_public_keys(data.join("trusted-public-keys"));
    let payload = data.join(format!("nar/{NARJAR_HASH}.nar"));
    fs::write(&payload, NAR_BYTES).unwrap();
    let recent_store = "22222222222222222222222222222222";
    let old_time = std::time::SystemTime::now() - Duration::from_secs(14 * 24 * 60 * 60);
    for store in [STORE_HASH, ABSENT_STORE_HASH, recent_store] {
        let metadata = data.join(format!("{store}.narinfo"));
        fs::write(
            &metadata,
            signed_narinfo_for(store, NARJAR_HASH, NAR_BYTES.len() as u64),
        )
        .unwrap();
        if store != recent_store {
            crate::cache::test_support::set_fixture_modified_time(metadata, old_time).unwrap();
        }
    }
    let roots = data.join("protected-roots");
    fs::write(&roots, format!("{ABSENT_STORE_HASH}\n")).unwrap();
    let result = run(&[
        "gc",
        "--data-dir",
        data.to_str().unwrap(),
        "--delete-older-than",
        "7d",
        "--protected-roots",
        roots.to_str().unwrap(),
        "--apply",
        "--json",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["deleted_narinfos"], 1);
    assert_eq!(report["deleted_nars"], 0);
    assert!(!data.join(format!("{STORE_HASH}.narinfo")).exists());
    assert!(
        data.join(format!("{ABSENT_STORE_HASH}.narinfo")).exists(),
        "age cannot override an explicitly protected root"
    );
    assert!(
        data.join(format!("{recent_store}.narinfo")).exists(),
        "a recent publication cannot be evicted by the age-only policy"
    );
    assert_eq!(
        fs::read(payload).unwrap(),
        NAR_BYTES,
        "retained publications still reference the shared canonical payload"
    );
}

#[test]
fn a_long_data_directory_does_not_prevent_the_cache_server_from_starting() {
    let owner = data_dir("long-control-path");
    let data = owner.join("long-cache-root-".repeat(12));
    fs::create_dir(&data).unwrap();
    let init = run(&["init", "--data-dir", data.to_str().unwrap()]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    write_test_trusted_public_keys(data.join("trusted-public-keys"));
    let server = RunningServer::start_with_existing_path(data, owner, &[]);
    assert!(
        response_parts(&server.request("GET", "/healthz"))
            .0
            .starts_with("HTTP/1.1 200")
    );
    let gc = run(&[
        "gc",
        "--data-dir",
        server.data_dir.to_str().unwrap(),
        "--online",
        "--target-bytes",
        "0",
        "--json",
    ]);
    #[cfg(not(target_os = "macos"))]
    assert!(
        gc.status.success(),
        "{}",
        String::from_utf8_lossy(&gc.stderr)
    );
    #[cfg(target_os = "macos")]
    {
        assert!(!gc.status.success());
        assert!(String::from_utf8_lossy(&gc.stderr).contains("socket pathname"));
    }
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
#[cfg(unix)]
fn systemd_readiness_is_sent_only_when_the_http_workers_and_online_gc_socket_are_available() {
    use std::os::unix::net::UnixDatagram;
    let owner = data_dir("notify");
    let data = owner.join("cache");
    fs::create_dir(&data).unwrap();
    assert!(
        run(&["init", "--data-dir", data.to_str().unwrap()])
            .status
            .success()
    );
    write_test_trusted_public_keys(data.join("trusted-public-keys"));
    let notify_path = owner.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let child = command()
        .env("NOTIFY_SOCKET", &notify_path)
        .args([
            "serve",
            "--data-dir",
            data.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--min-free-bytes",
            "0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = RunningServer {
        child: Some(child),
        data_dir: data,
        temp_dir: Some(owner),
        startup_line: String::new(),
        address: String::new(),
    };
    let mut message = [0; 128];
    let received = notify
        .recv(&mut message)
        .expect("the daemon must report application readiness, not just execute successfully");
    assert_eq!(&message[..received], b"READY=1");
    BufReader::new(server.child.as_mut().unwrap().stdout.take().unwrap())
        .read_line(&mut server.startup_line)
        .unwrap();
    server.address = server
        .startup_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .strip_prefix("http://")
        .unwrap()
        .to_owned();
    assert!(
        response_parts(&server.request("GET", "/healthz"))
            .0
            .starts_with("HTTP/1.1 200")
    );
    let gc = run(&[
        "gc",
        "--data-dir",
        server.data_dir.to_str().unwrap(),
        "--online",
        "--target-bytes",
        "0",
        "--json",
    ]);
    assert!(
        gc.status.success(),
        "readiness must include the maintenance socket: {}",
        String::from_utf8_lossy(&gc.stderr)
    );
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
#[cfg(target_os = "linux")]
fn online_gc_uses_the_running_chunked_daemon_without_interrupting_cache_reads() {
    assert_online_gc_preserves_new_publication("online-gc-chunked", "chunked");
}

fn assert_online_gc_preserves_new_publication(test: &str, backend: &str) {
    let server = RunningServer::start_with_args(test, &["--storage-backend", backend]);
    let payload_path = format!("/nar/{NARJAR_HASH}.nar");
    let metadata_path = format!("/{STORE_HASH}.narinfo");
    let metadata = signed_narinfo_for(STORE_HASH, NARJAR_HASH, NAR_BYTES.len() as u64);
    assert!(
        response_parts(&server.request_with_body("PUT", &payload_path, &[], NAR_BYTES))
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    assert!(
        response_parts(&server.request_with_body("PUT", &metadata_path, &[], metadata.as_bytes()))
            .0
            .starts_with("HTTP/1.1 201 Created\r\n")
    );
    let process = server.child.as_ref().unwrap().id();
    for mode in ["--dry-run", "--apply"] {
        let output = run(&[
            "gc",
            "--online",
            "--data-dir",
            server.data_dir.to_str().unwrap(),
            "--storage-backend",
            backend,
            mode,
            "--target-bytes",
            "0",
            "--json",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["protected"], 1,
            "recent upload/advertisement is protected"
        );
        assert_eq!(report["deleted_narinfos"], 0);
        assert_eq!(
            report["target_met"], false,
            "grace takes precedence over the target"
        );
        assert_eq!(server.child.as_ref().unwrap().id(), process);
        assert_eq!(
            response_parts(&server.request("GET", &payload_path)).1,
            NAR_BYTES
        );
        assert!(
            response_parts(&server.request("HEAD", &payload_path))
                .0
                .starts_with("HTTP/1.1 200 OK\r\n")
        );
        let range = server.request_with_headers("GET", &payload_path, &[("Range", "bytes=1-3")]);
        assert!(
            response_parts(&range)
                .0
                .starts_with("HTTP/1.1 206 Partial Content\r\n")
        );
        assert_eq!(response_parts(&range).1, b"arj");
        for path in [&*metadata_path, "/healthz", "/readyz", "/metrics"] {
            assert!(
                response_parts(&server.request("GET", path))
                    .0
                    .starts_with("HTTP/1.1 200 OK\r\n"),
                "{path}"
            );
        }
    }
    let exposition = response_parts(&server.request("GET", "/metrics")).1;
    assert!(
        String::from_utf8_lossy(&exposition)
            .contains("narjar_online_gc_requests_total{outcome=\"target_not_reached\"} 2")
    );
    let root = server.data_dir.clone();
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
    assert!(!root.join(".narjar-control/gc.sock").exists());
}

#[test]
fn online_gc_reports_active_upload_without_stopping_or_using_offline_collection() {
    let server = RunningServer::start("online-gc-active-upload");
    let upload =
        server.open_upload_after_continue(&format!("/nar/{NARJAR_HASH}.nar"), NAR_BYTES.len());
    let output = run(&[
        "gc",
        "--online",
        "--data-dir",
        server.data_dir.to_str().unwrap(),
        "--apply",
        "--target-bytes",
        "0",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("busy"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        response_parts(&server.request("GET", "/healthz"))
            .0
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let exposition = response_parts(&server.request("GET", "/metrics")).1;
    assert!(
        String::from_utf8_lossy(&exposition)
            .contains("narjar_online_gc_requests_total{outcome=\"busy\"} 1")
    );
    drop(upload);
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn online_gc_resolves_a_relative_root_list_in_the_clients_working_directory() {
    let server = RunningServer::start("online-gc-relative-roots");
    let client = tempfile::tempdir().unwrap();
    fs::write(
        client.path().join("roots.txt"),
        format!("{ABSENT_STORE_HASH}\n"),
    )
    .unwrap();
    let output = command()
        .current_dir(client.path())
        .args([
            "gc",
            "--online",
            "--data-dir",
            server.data_dir.to_str().unwrap(),
            "--target-bytes",
            "0",
            "--protected-roots",
            "roots.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["missing_roots"], 1,
        "the daemon must read the client's root list"
    );
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

struct HttpExchange {
    request: Vec<u8>,
    response: Vec<u8>,
}

#[test]
fn onboarding_is_served_by_the_binary_without_external_services() {
    let server = RunningServer::start_with_args(
        "onboarding-native",
        &["--public-url", "https://cache.example:8443", "--onboarding"],
    );
    let (headers, body) = response_parts(&server.request("GET", "/"));
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains("Cache-Control: no-store\r\n"));
    assert!(headers.contains("Content-Security-Policy:"));
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("https://cache.example:8443"));
    assert!(text.contains(test_trusted_public_key().trim()));
    assert!(text.contains("extra-substituters"));
    assert!(!text.contains("href=\"/metrics\""));
    assert!(text.contains("http://127.0.0.1:5000?priority=30"));
    assert!(!text.contains(&format!("http://{}", server.address)));
    assert!(!text.contains("producer.sec"));
    let (head, body) = response_parts(&server.request("HEAD", "/"));
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(body.is_empty());
    assert_eq!(
        response_parts(&server.request("GET", "/nix-cache-info")).1,
        CACHE_INFO
    );
    for path in ["/index.html", "/?ignored=1", "/main/", "/setup"] {
        assert!(
            !response_parts(&server.request("GET", path))
                .0
                .starts_with("HTTP/1.1 200")
        );
    }
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn private_onboarding_does_not_grant_cache_or_metrics_access() {
    let server = RunningServer::start_with_auth(
        "private-onboarding",
        &[
            "--public-url",
            "https://private.example",
            "--onboarding",
            "--onboarding-diagnostics",
        ],
        Some(TEST_WRITE_TOKEN),
        None,
    );
    let (headers, body) = response_parts(&server.request("GET", "/"));
    assert!(headers.starts_with("HTTP/1.1 200"));
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("netrc"));
    assert!(text.contains("href=\"/metrics\""));
    assert!(!text.contains("local-edge"));
    assert!(!text.contains("test-write-token"));
    for path in ["/metrics", "/readyz", "/nix-cache-info"] {
        assert!(
            response_parts(&server.request("GET", path))
                .0
                .starts_with("HTTP/1.1 401")
        );
    }
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn onboarding_is_disabled_by_default_and_requires_an_explicit_origin() {
    let server = RunningServer::start("no-onboarding");
    assert!(
        response_parts(&server.request("GET", "/"))
            .0
            .starts_with("HTTP/1.1 404")
    );
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
    let output = run(&["serve", "--data-dir", "not-opened", "--onboarding"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--public-url"));
}

#[test]
fn onboarding_rejects_incompatible_retention_before_opening_storage() {
    let output = run(&[
        "serve",
        "--data-dir",
        "not-opened",
        "--serve-source",
        "read-through",
        "--edge-upstream",
        "https://upstream.example",
        "--edge-lease-seconds",
        "600",
        "--public-url",
        "https://cache.example",
        "--onboarding",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least 900 seconds"));
    let server = RunningServer::start_with_workers(
        "onboarding-retention",
        2,
        &[
            "--serve-source",
            "read-through",
            "--edge-upstream",
            "https://upstream.example",
            "--edge-lease-seconds",
            "900",
            "--public-url",
            "https://cache.example",
            "--onboarding",
        ],
    );
    let (_, body) = response_parts(&server.request("GET", "/"));
    assert!(String::from_utf8_lossy(&body).contains("minimum advertisement lease is 900 seconds"));
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
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
        let mut init_args = vec![
            "init",
            "--data-dir",
            data_dir.to_str().expect("temporary path should be UTF-8"),
        ];
        if let Some(index) = extra_args
            .iter()
            .position(|argument| *argument == "--storage-backend")
        {
            init_args.extend(["--storage-backend", extra_args[index + 1]]);
        }
        let output = run(&init_args);
        assert!(
            output.status.success(),
            "test data initialization failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let auth_dir = data_dir.path().join("auth");
        let write_tokens = auth_dir.join("write.tokens");
        fs::write(&write_tokens, TEST_WRITE_TOKEN).expect("test write token should be written");
        crate::cache::test_support::make_private_file(&write_tokens)
            .expect("test write token should be private");
        if let Some(contents) = read_tokens {
            let read_tokens = auth_dir.join("read.tokens");
            fs::write(&read_tokens, contents).expect("test read tokens should be written");
            crate::cache::test_support::make_private_file(&read_tokens)
                .expect("test read tokens should be private");
        }
        let trusted_key = trusted_keys
            .map(str::to_owned)
            .unwrap_or_else(test_trusted_public_key);
        fs::write(data_dir.path().join("trusted-public-keys"), trusted_key)
            .expect("test trusted key should be written");

        Self::start_in_with_workers(data_dir, workers, extra_args)
    }

    fn start_in(temp_dir: TestDir, extra_args: &[&str]) -> Self {
        Self::start_in_with_workers(temp_dir, 1, extra_args)
    }

    fn start_in_with_workers(temp_dir: TestDir, workers: usize, extra_args: &[&str]) -> Self {
        let data_dir = temp_dir.path().to_owned();
        Self::start_path_with_owner(data_dir, temp_dir, workers, extra_args)
    }

    fn start_with_existing_path(data_dir: PathBuf, owner: TestDir, extra_args: &[&str]) -> Self {
        Self::start_path_with_owner(data_dir, owner, 1, extra_args)
    }

    fn start_path_with_owner(
        data_dir: PathBuf,
        owner: TestDir,
        workers: usize,
        extra_args: &[&str],
    ) -> Self {
        let mut child = Self::spawn(&data_dir, workers, extra_args);
        let mut startup_line = String::new();
        BufReader::new(child.stdout.take().expect("stdout should be piped"))
            .read_line(&mut startup_line)
            .expect("startup line should be readable");
        let address = startup_line
            .split_whitespace()
            .nth(1)
            .and_then(|url| url.strip_prefix("http://"))
            .unwrap_or_else(|| {
                let mut stderr = String::new();
                child
                    .stderr
                    .take()
                    .expect("stderr should be piped")
                    .read_to_string(&mut stderr)
                    .expect("startup error should be readable");
                panic!("startup line should contain listener address: {startup_line:?}; {stderr}");
            })
            .to_owned();

        Self {
            child: Some(child),
            data_dir,
            temp_dir: Some(owner),
            startup_line,
            address,
        }
    }

    fn spawn(data_dir: &Path, workers: usize, extra_args: &[&str]) -> Child {
        let mut process = command();
        platform::configure_server_process(&mut process).expect("configure server process");
        if extra_args.contains(&"--onboarding") {
            process.env("PATH", "");
        }
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
            .stdin(Stdio::null())
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

    #[cfg(target_os = "linux")]
    fn peak_rss_bytes(&self) -> u64 {
        let process_id = self.child.as_ref().expect("server is running").id();
        let status = fs::read_to_string(format!("/proc/{process_id}/status"))
            .expect("kernel reports the server process status");
        let peak_kib = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .expect("kernel reports the server's peak resident memory");
        peak_kib * 1024
    }

    #[cfg(target_os = "linux")]
    fn peak_virtual_memory_bytes(&self) -> u64 {
        let process_id = self.child.as_ref().expect("server is running").id();
        let status = fs::read_to_string(format!("/proc/{process_id}/status"))
            .expect("kernel reports the server process status");
        let peak_kib = status
            .lines()
            .find_map(|line| line.strip_prefix("VmPeak:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .expect("kernel reports the server's peak virtual memory");
        peak_kib * 1024
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

    fn open_upload_after_continue(&self, path: &str, length: usize) -> TcpStream {
        let length = length.to_string();
        let mut stream = self.open_request(
            "PUT",
            path,
            &[("Content-Length", &length), ("Expect", "100-continue")],
        );
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut interim = [0; 25];
        stream
            .read_exact(&mut interim)
            .expect("publication worker must admit the upload before the test proceeds");
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        stream
    }

    fn wait_until_listener_is_closed(&self) {
        wait_for_connection_refusal(Instant::now() + Duration::from_secs(5), || {
            TcpStream::connect(&self.address)
        });
    }

    fn wait_for_metrics_containing(&self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        for response in std::iter::repeat_with(|| self.request("GET", "/metrics")) {
            let metrics = String::from_utf8(response_parts(&response).1).unwrap();
            if metrics.contains(expected) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "metric never reached {expected:?}: {metrics}"
            );
            thread::yield_now();
        }
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

    fn stop(mut self) -> (std::io::Result<()>, ExitStatus) {
        self.stop_process()
    }

    fn stop_preserving(mut self) -> (TestDir, std::io::Result<()>, ExitStatus) {
        let (signal, status) = self.stop_process();
        let temp_dir = self
            .temp_dir
            .take()
            .expect("running server should own its data directory");
        (temp_dir, signal, status)
    }

    fn stop_process(&mut self) -> (std::io::Result<()>, ExitStatus) {
        let child = self
            .child
            .as_mut()
            .expect("running server should own its child");
        let signal = platform::request_shutdown(child.id());

        let status = wait_for_server_shutdown(child);
        self.child.take();

        (signal, status)
    }
}

fn wait_for_server_shutdown(child: &mut Child) -> ExitStatus {
    let shutdown_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            return status;
        }
        if Instant::now() >= shutdown_deadline {
            child.kill().expect("hung child should be killed");
            return child.wait().expect("killed child should be reaped");
        }
        thread::sleep(Duration::from_millis(20));
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
fn process_lock_is_released_when_its_daemon_owner_is_killed() {
    use crate::cache::storage::{CacheCreation, Directory, StorageError, SupportedStorageBackend};

    let mut server = RunningServer::start("process-lease-owner-death");
    let opened = Directory::open(&server.data_dir).unwrap();
    assert!(matches!(
        CacheCreation::prepare(&opened, SupportedStorageBackend::FLAT),
        Err(StorageError::Locked)
    ));

    let child = server.child.as_mut().expect("fixture owns the daemon");
    assert!(
        child.try_wait().unwrap().is_none(),
        "the lease owner is running"
    );
    child
        .kill()
        .expect("terminate the owned daemon without cleanup");
    assert!(!child.wait().unwrap().success());
    server.child.take();

    CacheCreation::prepare(&opened, SupportedStorageBackend::FLAT)
        .expect("owner death releases the lease even with a retained directory handle");
}

#[test]
fn serve_reports_listener_and_stops_on_sigterm() {
    let server =
        RunningServer::start_with_args("lifecycle", &["--stats-inventory-interval-seconds", "900"]);

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
            " workers=1 max_in_flight=64 max_nar_bytes=17179869184 max_encoded_nar_bytes=17179869184 max_decoder_memory_bytes=134217728 max_concurrent_decoders=1 min_free_bytes=1073741824 shutdown_grace_seconds=30 io_timeout_seconds=30\n"
        ),
        "startup line omits effective limits: {:?}",
        server.startup_line
    );

    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
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
    let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
        .expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_connections_total{outcome=\"timeout\"} 1"),
        "{metrics}"
    );
    let (_, status) = server.stop();
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn malformed_request_headers_are_counted_without_a_route_label() {
    let server = RunningServer::start("malformed-request-headers");
    let mut stream = TcpStream::connect(&server.address).expect("connect to narjar");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\ninvalid header\r\n\r\n")
        .expect("write malformed request");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("configure client timeout");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("malformed request should close");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

    let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
        .expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_connections_total{outcome=\"malformed_request\"} 1"),
        "{metrics}"
    );
    assert!(
        !metrics.contains(
            "narjar_http_requests_total{method=\"GET\",route=\"healthz\",status=\"400\"}"
        ),
        "malformed requests must not be assigned a parsed route: {metrics}"
    );

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
    let (_, metrics_body) = response_parts(&server.request("GET", "/metrics"));
    let metrics = String::from_utf8(metrics_body).expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_connections_total{outcome=\"timeout\"} 1"),
        "stalled upload body should count as a timed-out connection: {metrics}"
    );
    let (_, status) = server.stop();
    assert!(status.success(), "narjar should shut down cleanly");
}

#[test]
fn second_sigterm_exits_a_stalled_request_immediately() {
    let mut server =
        RunningServer::start_with_args("second-sigterm", &["--shutdown-grace-seconds", "30"]);
    let _stalled = server.open_upload_after_continue(&format!("/nar/{NAR_ID}.nar"), 1);

    let pid = server
        .child
        .as_ref()
        .expect("server child should exist")
        .id();
    platform::request_shutdown(pid).expect("first shutdown request should be sent");
    server.wait_until_listener_is_closed();
    let started = Instant::now();
    platform::request_shutdown(pid).expect("second shutdown request should be sent");
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
fn shutdown_closes_idle_keep_alive_connections_without_waiting_for_the_io_timeout() {
    let server = RunningServer::start_with_args(
        "shutdown-idle-keep-alive",
        &[
            "--shutdown-grace-seconds",
            "1",
            "--io-timeout-seconds",
            "30",
        ],
    );
    let mut connection = BufReader::new(TcpStream::connect(&server.address).unwrap());
    connection
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    connection
        .get_mut()
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let response = read_http_response(&mut connection);
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
    let mut after_shutdown = Vec::new();
    connection.read_to_end(&mut after_shutdown).unwrap();
    assert!(after_shutdown.is_empty());
}

#[test]
fn shutdown_rejects_keep_alive_uploads_and_finishes_already_admitted_uploads() {
    let mut server = RunningServer::start_with_workers(
        "shutdown-keep-alive-upload",
        2,
        &["--shutdown-grace-seconds", "5"],
    );
    let mut active =
        server.open_upload_after_continue(&format!("/nar/{NARJAR_HASH}.nar"), NAR_BYTES.len());
    let mut connection = BufReader::new(TcpStream::connect(&server.address).unwrap());
    connection
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    connection
        .get_mut()
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    assert!(read_http_response(&mut connection).starts_with(b"HTTP/1.1 200 OK\r\n"));
    let pid = server.child.as_ref().unwrap().id();
    platform::request_shutdown(pid).unwrap();
    server.wait_until_listener_is_closed();

    let request = format!(
        "PUT /nix-cache-info HTTP/1.1\r\nHost: test\r\nAuthorization: {TEST_AUTHORIZATION}\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        CACHE_INFO.len()
    );
    match connection.get_mut().write_all(request.as_bytes()) {
        Ok(()) => {
            let mut response = [0; 256];
            match connection.read(&mut response) {
                Ok(0) => {}
                Ok(count) => assert!(
                    response[..count].starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"),
                    "shutdown must not acknowledge another upload: {}",
                    String::from_utf8_lossy(&response[..count])
                ),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                Err(error) => panic!("reading draining connection: {error}"),
            }
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) => {}
        Err(error) => panic!("writing draining connection: {error}"),
    }
    drop(connection);
    active.write_all(NAR_BYTES).unwrap();
    let response = read_http_response(&mut BufReader::new(active));
    assert!(
        response.starts_with(b"HTTP/1.1 201 Created\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(
        fs::read(server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"))).unwrap(),
        NAR_BYTES
    );
    let status = server.child.take().unwrap().wait().unwrap();
    assert!(
        status.success(),
        "already-admitted uploads must drain cleanly"
    );
}

#[test]
fn shutdown_grace_deadline_terminates_a_stalled_request() {
    let mut server =
        RunningServer::start_with_args("shutdown-deadline", &["--shutdown-grace-seconds", "1"]);
    let _stalled = server.open_upload_after_continue(&format!("/nar/{NAR_ID}.nar"), 1);

    let pid = server
        .child
        .as_ref()
        .expect("server child should exist")
        .id();
    platform::request_shutdown(pid).expect("shutdown request should be sent");
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
fn shutdown_drains_active_and_already_queued_publications() {
    let mut server = RunningServer::start_with_args(
        "shutdown-drains-publication-queue",
        &["--max-in-flight", "3", "--shutdown-grace-seconds", "5"],
    );
    let mut active =
        server.open_upload_after_continue(&format!("/nar/{NARJAR_HASH}.nar"), NAR_BYTES.len());
    let length = CACHE_INFO.len().to_string();
    let mut queued = server.open_request(
        "PUT",
        "/nix-cache-info",
        &[("Content-Length", &length), ("Expect", "100-continue")],
    );
    queued
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    server.wait_for_metrics_containing("narjar_publication_queue_depth 1");
    let pid = server.child.as_ref().unwrap().id();
    platform::request_shutdown(pid).unwrap();
    server.wait_until_listener_is_closed();
    active.write_all(NAR_BYTES).unwrap();
    assert!(
        read_http_response(&mut BufReader::new(active)).starts_with(b"HTTP/1.1 201 Created\r\n")
    );
    let mut interim = [0; 25];
    queued.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    queued.write_all(CACHE_INFO).unwrap();
    assert!(read_http_response(&mut BufReader::new(queued)).starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(server.child.take().unwrap().wait().unwrap().success());
}

#[test]
fn shutdown_grace_deadline_covers_a_queued_publication() {
    let mut server = RunningServer::start_with_args(
        "shutdown-queued-publication",
        &["--max-in-flight", "3", "--shutdown-grace-seconds", "1"],
    );
    let path = format!("/nar/{NAR_ID}.nar");
    let _active = server.open_upload_after_continue(&path, 1);
    let _queued = server.open_request("PUT", &path, &[("Content-Length", "1")]);
    server.wait_for_metrics_containing("narjar_publication_queue_depth 1");

    let pid = server
        .child
        .as_ref()
        .expect("server child should exist")
        .id();
    platform::request_shutdown(pid).expect("shutdown request should be sent");
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

    assert_clean_shutdown(signal, status);

    let body = "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";
    for response in [&get, &head, &legacy_get, &legacy_head] {
        assert_http_status_line(response, "200 OK");
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
fn wrong_sized_cache_info_uploads_are_rejected_without_continuation() {
    let server = RunningServer::start("cache-info-length-before-continue");
    for path in ["/nix-cache-info", "/main/nix-cache-info"] {
        let mut stream = server.open_request(
            "PUT",
            path,
            &[("Content-Length", "1"), ("Expect", "100-continue")],
        );
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 409 Conflict\r\n"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            fs::read(server.data_dir.join("nix-cache-info")).unwrap(),
            CACHE_INFO
        );
    }
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn operator_responses_are_not_cacheable_and_private_readiness_varies_on_authorization() {
    let public = RunningServer::start("operator-no-store");
    for method in ["GET", "HEAD"] {
        for path in ["/healthz", "/readyz", "/metrics"] {
            let response = public.request(method, path);
            let headers = response_parts(&response).0;
            assert!(
                headers.contains("Cache-Control: no-store\r\n"),
                "{method} {path}: {headers}"
            );
        }
    }
    let (signal, status) = public.stop();
    assert_clean_shutdown(signal, status);
    let private =
        RunningServer::start_with_read_tokens("private-readiness-no-store", TEST_WRITE_TOKEN);
    for method in ["GET", "HEAD"] {
        for headers in [vec![], vec![("Authorization", TEST_AUTHORIZATION)]] {
            let response = private.request_with_headers(method, "/readyz", &headers);
            let response_headers = response_parts(&response).0;
            assert!(
                response_headers.contains("Cache-Control: no-store\r\n"),
                "{response_headers}"
            );
            assert!(
                response_headers.contains("Vary: Authorization\r\n"),
                "{response_headers}"
            );
        }
    }
    let (signal, status) = private.stop();
    assert_clean_shutdown(signal, status);
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

    assert_clean_shutdown(signal, status);
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

    assert_clean_shutdown(signal, status);
    assert!(response.ends_with("\r\n\r\nStoreDir: /nix/store\nWantMassQuery: 0\nPriority: 17\n"));
}

#[test]
fn idle_http11_connection_does_not_occupy_the_only_request_worker() {
    let server = RunningServer::start_with_workers(
        "idle-connection-fairness",
        1,
        &["--io-timeout-seconds", "30"],
    );
    let mut idle = BufReader::new(TcpStream::connect(&server.address).unwrap());
    idle.get_mut()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    idle.get_mut()
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: test\r\n\r\n")
        .unwrap();
    assert!(read_http_response(&mut idle).starts_with(b"HTTP/1.1 200 OK\r\n"));

    let mut other = BufReader::new(TcpStream::connect(&server.address).unwrap());
    other
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    other
        .get_mut()
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .unwrap();
    assert!(read_http_response(&mut other).starts_with(b"HTTP/1.1 200 OK\r\n"));

    // The original connection remains reusable after another client was served.
    idle.get_mut()
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .unwrap();
    assert!(read_http_response(&mut idle).starts_with(b"HTTP/1.1 200 OK\r\n"));
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn http11_connection_serves_two_sequential_requests() {
    let server = RunningServer::start("http11-keep-alive");
    let stream = TcpStream::connect(&server.address).expect("connect to narjar");
    let mut writer = stream.try_clone().expect("clone client stream");
    let mut stream = BufReader::new(stream);

    for request_number in 0..2 {
        writer
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
        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "request {request_number}: {response:?}"
        );
        assert!(
            response.contains("Connection: keep-alive\r\n"),
            "{response:?}"
        );
        assert!(
            response.ends_with("\r\n\r\nStoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n"),
            "{response:?}"
        );
    }

    drop(writer);
    drop(stream);
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn published_narinfo_and_nar_get_head_are_served() {
    let server = RunningServer::start("published-pair");
    let nar_bytes = b"known NAR bytes";
    let nar_hash = nix32_sha256(nar_bytes);
    let narinfo = signed_narinfo(&nar_hash, nar_bytes.len() as u64);
    let _absent_metadata = server.request("GET", &format!("/{ABSENT_STORE_HASH}.narinfo"));
    let _missing_nar = server.request("GET", &format!("/nar/{nar_hash}.nar"));

    fs::write(
        server.data_dir.join(format!("nar/{nar_hash}.nar")),
        nar_bytes,
    )
    .expect("write NAR fixture");
    fs::write(
        server.data_dir.join(format!("{STORE_HASH}.narinfo")),
        &narinfo,
    )
    .expect("write narinfo fixture");

    let narinfo_get = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let narinfo_head = server.request("HEAD", &format!("/{STORE_HASH}.narinfo"));
    let nar_get = server.request("GET", &format!("/nar/{nar_hash}.nar"));
    let nar_head = server.request("HEAD", &format!("/nar/{nar_hash}.nar"));
    let (_, metrics_body) = response_parts(&server.request("GET", "/metrics"));
    let metrics = String::from_utf8(metrics_body).expect("metrics response should be UTF-8");
    let (signal, status) = server.stop();

    assert_clean_shutdown(signal, status);
    for series in [
        "narjar_cache_lookup_outcomes_total{object=\"narinfo\",method=\"GET\",outcome=\"hit\"} 1",
        "narjar_cache_lookup_outcomes_total{object=\"narinfo\",method=\"GET\",outcome=\"miss\"} 1",
        "narjar_cache_lookup_outcomes_total{object=\"narinfo\",method=\"HEAD\",outcome=\"hit\"} 1",
        "narjar_cache_lookup_outcomes_total{object=\"nar\",method=\"GET\",outcome=\"hit\"} 1",
        "narjar_cache_lookup_outcomes_total{object=\"nar\",method=\"GET\",outcome=\"miss\"} 1",
        "narjar_cache_lookup_outcomes_total{object=\"nar\",method=\"HEAD\",outcome=\"hit\"} 1",
    ] {
        assert!(metrics.contains(series), "missing {series}: {metrics}");
    }
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
    assert_eq!(
        metric_value(&metrics, "narjar_http_bytes_out_total"),
        (narinfo_get.len() - narinfo_get_body + nar_get.len() - nar_get_body) as u64,
        "HEAD and /metrics bodies are control traffic, not artifact bytes"
    );
    let narinfo_get_headers =
        String::from_utf8_lossy(&narinfo_get[..narinfo_get_body]).into_owned();
    let narinfo_head_headers =
        String::from_utf8_lossy(&narinfo_head[..narinfo_head_body]).into_owned();
    let nar_get_headers = String::from_utf8_lossy(&nar_get[..nar_get_body]).into_owned();
    let nar_head_headers = String::from_utf8_lossy(&nar_head[..nar_head_body]).into_owned();

    for headers in [&narinfo_get_headers, &narinfo_head_headers] {
        assert_http_status_line(headers, "200 OK");
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
        assert_http_status_line(headers, "200 OK");
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

#[test]
fn narinfo_get_trusts_immutable_disk_contents_without_revalidation() {
    let server = RunningServer::start("narinfo-disk-trust");
    let nar_hash = nix32_sha256(b"NAR is not re-opened for this metadata GET");
    let narinfo = signed_narinfo(&nar_hash, 37).replace("Sig: narjar-test:", "Sig: untrusted:");
    fs::write(
        server.data_dir.join(format!("{STORE_HASH}.narinfo")),
        &narinfo,
    )
    .expect("on-disk narinfo fixture should be written");

    let response = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let (headers, body) = response_parts(&response);
    let (signal, status) = server.stop();

    assert_clean_shutdown(signal, status);
    assert_http_status_line(&headers, "200 OK");
    assert_eq!(body, narinfo.as_bytes());
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

#[track_caller]
fn assert_http_status_line(headers: &str, status: &str) {
    assert!(
        headers.starts_with(&format!("HTTP/1.1 {status}\r\n")),
        "{headers:?}"
    );
}

#[track_caller]
fn assert_empty_http_response(response: &[u8], status: &str) {
    let (headers, body) = response_parts(response);
    assert_http_status_line(&headers, status);
    assert!(body.is_empty(), "unexpected response body: {body:?}");
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

fn metric_value(exposition: &str, name: &str) -> u64 {
    exposition
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .expect("metric should be present")
        .trim()
        .parse()
        .expect("metric value should be an integer")
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
fn nar_get_supports_ranges_and_head_ignores_them() {
    let server = RunningServer::start("nar-ranges");
    let nar_bytes = b"0123456789";
    let nar_hash = nix32_sha256(nar_bytes);
    fs::write(
        server.data_dir.join(format!("nar/{nar_hash}.nar")),
        nar_bytes,
    )
    .expect("write NAR fixture");
    let path = format!("/nar/{nar_hash}.nar");
    let request = |method, range| server.request_with_headers(method, &path, &[("Range", range)]);

    let full = server.request("GET", &path);
    let closed = request("GET", "bytes=2-5");
    let open = request("GET", "bytes=5-");
    let suffix = request("GET", "bytes=-4");
    let heads = ["bytes=2-5", "bytes=20-", "bytes=wat", "bytes=0-1,4-5"]
        .map(|range| request("HEAD", range));
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

    assert_clean_shutdown(signal, status);

    assert_eq!(response_parts(&full).1, nar_bytes);

    for (response, content_range, body) in [
        (&closed, "bytes 2-5/10", &b"2345"[..]),
        (&open, "bytes 5-9/10", &b"56789"[..]),
        (&suffix, "bytes 6-9/10", &b"6789"[..]),
    ] {
        let (headers, actual_body) = response_parts(response);
        assert_http_status_line(&headers, "206 Partial Content");
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

    for head in heads {
        let (headers, body) = response_parts(&head);
        assert_http_status_line(&headers, "200 OK");
        assert!(headers.contains("Content-Length: 10\r\n"), "{headers:?}");
        assert!(!headers.contains("Content-Range:"), "{headers:?}");
        assert!(body.is_empty());
    }

    for response in [&unsatisfiable, &reversed] {
        let (headers, body) = response_parts(response);
        assert_http_status_line(&headers, "416 Range Not Satisfiable");
        assert!(
            headers.contains("Content-Range: bytes */10\r\n"),
            "{headers:?}"
        );
        assert!(body.is_empty());
    }

    for response in [&multiple, &malformed, &empty, &overflow, &duplicate] {
        let (headers, body) = response_parts(response);
        assert_http_status_line(&headers, "400 Bad Request");
        assert!(body.is_empty());
    }
    assert!(
        metrics.contains("narjar_http_bytes_out_total 23"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("narjar_http_requests_total{method=\"GET\",route=\"nar\",status=\"206\"} 3"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("narjar_http_requests_total{method=\"HEAD\",route=\"nar\",status=\"200\"} 4"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("narjar_http_requests_total{method=\"GET\",route=\"nar\",status=\"416\"} 2"),
        "{metrics}"
    );
    for expected in [
        "narjar_nar_range_requests_total{method=\"GET\",outcome=\"full\"} 1",
        "narjar_nar_range_requests_total{method=\"GET\",outcome=\"partial\"} 3",
        "narjar_nar_range_requests_total{method=\"HEAD\",outcome=\"full\"} 4",
        "narjar_nar_range_requests_total{method=\"GET\",outcome=\"unsatisfiable\"} 2",
        "narjar_nar_range_requests_total{method=\"GET\",outcome=\"invalid\"} 5",
    ] {
        assert!(metrics.contains(expected), "missing {expected}: {metrics}");
    }
}

#[test]
fn read_routes_distinguish_bad_methods_names_and_unsupported_surfaces() {
    let server = RunningServer::start("read-negatives");

    let wrong_method = server.request("POST", "/nix-cache-info");
    let nar_read_misses = [
        format!("/nar/{}.nar", &NAR_ID[..NAR_ID.len() - 1]),
        format!("/nar/{NAR_ID}.nar/extra"),
    ]
    .map(|path| server.request("GET", &path));
    let invalid_routes = [
        format!("/{}.narinfo", &STORE_HASH[..STORE_HASH.len() - 1]),
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

    assert_clean_shutdown(signal, status);

    let (headers, body) = response_parts(&wrong_method);
    assert_http_status_line(&headers, "405 Method Not Allowed");
    assert!(headers.contains("Allow: GET, HEAD, PUT\r\n"), "{headers:?}");
    assert!(body.is_empty());

    for response in nar_read_misses {
        assert_empty_http_response(&response, "404 Not Found");
    }

    for response in invalid_routes {
        assert_empty_http_response(&response, "400 Bad Request");
    }

    for response in unsupported_routes {
        assert_empty_http_response(&response, "404 Not Found");
    }
}

#[test]
fn nar_reads_survive_unlink_without_exposing_temps() {
    let server = RunningServer::start("nar-read-races");
    let nar_bytes = vec![0x5a; 128 * 1024];
    let nar_hash = nix32_sha256(&nar_bytes);
    let nar_path = server.data_dir.join(format!("nar/{nar_hash}.nar"));
    fs::write(&nar_path, &nar_bytes).expect("write large NAR fixture");
    let path = format!("/nar/{nar_hash}.nar");

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
    assert_http_status_line(&headers, "206 Partial Content");
    assert_eq!(body.len(), nar_bytes.len());
    assert!(body.iter().all(|&byte| byte == 0x5a));

    let missing = server.request("GET", &path);
    assert_empty_http_response(&missing, "404 Not Found");

    fs::write(
        server.data_dir.join(".tmp/read-race-unvalidated"),
        b"temporary bytes",
    )
    .expect("write temporary fixture");
    for temp_path in [
        "/.tmp/read-race-unvalidated",
        &format!("/nar/{nar_hash}.nar.tmp"),
    ] {
        let response = server.request("GET", temp_path);
        let (headers, _) = response_parts(&response);
        assert!(!headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers:?}");
    }

    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn nar_reads_reject_content_that_does_not_match_its_filename() {
    let server = RunningServer::start("nar-read-hash-mismatch");
    let path = format!("/nar/{NARJAR_HASH}.nar");
    fs::write(server.data_dir.join(&path[1..]), b"wrong!")
        .expect("write same-size corrupt NAR fixture");

    for method in ["HEAD", "GET"] {
        let response = server.request(method, &path);
        assert_empty_http_response(&response, "500 Internal Server Error");
    }
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn nar_reads_release_the_worker_after_a_client_aborts_a_valid_transfer() {
    let server = RunningServer::start("nar-read-client-abort");
    let nar_bytes = vec![0; 8 * 1024 * 1024];
    let path = format!("/nar/{}.nar", nix32_sha256(&nar_bytes));
    fs::write(server.data_dir.join(&path[1..]), &nar_bytes)
        .expect("write valid NAR larger than the socket send buffer");

    // Complete validation before testing delivery, not the speed of hashing in
    // an unoptimized build on a shared runner.
    let head = server.request("HEAD", &path);
    let (head_headers, head_body) = response_parts(&head);
    assert_http_status_line(&head_headers, "200 OK");
    assert!(head_headers.contains(&format!("Content-Length: {}\r\n", nar_bytes.len())));
    assert!(head_body.is_empty());

    let aborted = server.open_request("GET", &path, &[]);
    aborted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut aborted = BufReader::new(aborted);
    let headers = read_http_response_headers(&mut aborted);
    let headers = std::str::from_utf8(&headers).expect("response headers should be UTF-8");
    assert_http_status_line(headers, "200 OK");
    assert!(headers.contains(&format!("Content-Length: {}\r\n", nar_bytes.len())));
    drop(aborted);

    let after_abort = server.request("GET", "/nix-cache-info");
    let (after_abort_headers, _) = response_parts(&after_abort);
    let metrics = server.request("GET", "/metrics");
    let (_, metrics_body) = response_parts(&metrics);
    let metrics = std::str::from_utf8(&metrics_body).expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_responses_aborted_total 1\n"),
        "{metrics}"
    );
    let (signal, status) = server.stop();

    assert_http_status_line(&after_abort_headers, "200 OK");
    assert_clean_shutdown(signal, status);
}

#[test]
fn narinfo_reads_trust_immutable_metadata_and_reject_symlinked_nars() {
    let server = RunningServer::start("read-errors");
    let narinfo_path = server.data_dir.join(format!("{STORE_HASH}.narinfo"));
    fs::write(&narinfo_path, [0xff]).expect("write corrupt narinfo");

    let corrupt_narinfo = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let (corrupt_headers, corrupt_body) = response_parts(&corrupt_narinfo);
    assert_http_status_line(&corrupt_headers, "200 OK");
    assert_eq!(corrupt_body, [0xff]);
    fs::remove_file(narinfo_path).expect("remove corrupt narinfo");

    let nar_path = server.data_dir.join(format!("nar/{NAR_ID}.nar"));
    symlink(nar_path.file_name().expect("NAR file name"), &nar_path)
        .expect("create unreadable final");
    let unreadable_nar = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    assert_empty_http_response(&unreadable_nar, "500 Internal Server Error");
    fs::remove_file(&nar_path).expect("remove unreadable final");

    let missing_nar = server.request("GET", &format!("/nar/{NAR_ID}.nar"));
    let (missing_headers, missing_body) = response_parts(&missing_nar);
    let (signal, status) = server.stop();

    assert_http_status_line(&missing_headers, "404 Not Found");
    assert!(missing_body.is_empty());
    assert_clean_shutdown(signal, status);
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

    assert_http_status_line(&headers, "500 Internal Server Error");
    assert!(body.is_empty());
    assert_eq!(
        fs::read(&external_path).expect("read external target"),
        external_bytes
    );
    assert_clean_shutdown(signal, status);
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

    assert_http_status_line(&headers, "500 Internal Server Error");
    assert!(body.is_empty());
    assert_eq!(
        fs::read(&external_nar).expect("read external NAR"),
        NAR_BYTES
    );
    fs::remove_dir_all(&external_dir).expect("remove external directory");
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
}

#[test]
fn nar_put_normalizes_xz_to_raw_bytes() {
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
    let uploaded = server.request_with_body("PUT", &path, &[], &compressed);
    let downloaded = server.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
    let stored = fs::read(server.data_dir.join(format!("nar/{NARJAR_HASH}.nar")))
        .expect("read stored raw NAR");
    let (signal, status) = server.stop();

    let (upload_headers, upload_body) = response_parts(&uploaded);
    assert_empty_http_response(&wrong, "422 Unprocessable Entity");
    assert_http_status_line(&upload_headers, "201 Created");
    assert!(upload_body.is_empty());
    let (download_headers, download_body) = response_parts(&downloaded);
    assert_http_status_line(&download_headers, "200 OK");
    assert_eq!(download_body, NAR_BYTES);
    assert_eq!(stored, NAR_BYTES);
    assert_clean_shutdown(signal, status);
}

#[test]
fn nar_put_normalizes_zstd_to_raw_bytes() {
    let server = RunningServer::start("nar-put-zstd");
    let mut compressed = Vec::new();
    compress(
        std::io::Cursor::new(NAR_BYTES),
        &mut compressed,
        CompressionLevel::Fastest,
    );

    let file_hash = nix32_sha256(&compressed);
    let path = format!("/nar/{file_hash}.nar.zst");
    let uploaded = server.request_with_body("PUT", &path, &[], &compressed);
    let downloaded = server.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
    let stored = fs::read(server.data_dir.join(format!("nar/{NARJAR_HASH}.nar")))
        .expect("read stored raw NAR");
    let (signal, status) = server.stop();

    assert_empty_http_response(&uploaded, "201 Created");
    let (download_headers, download_body) = response_parts(&downloaded);
    assert_http_status_line(&download_headers, "200 OK");
    assert_eq!(download_body, NAR_BYTES);
    assert_eq!(stored, NAR_BYTES);
    assert_clean_shutdown(signal, status);
}

#[test]
fn compressed_upload_memory_limits_return_422_without_publishing() {
    for (index, encoding) in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ]
    .into_iter()
    .enumerate()
    {
        let server = RunningServer::start_with_args(
            &format!("decoder-memory-{index}"),
            &["--max-decoder-memory-bytes", "131071"],
        );
        let compressed = encode_test_nar_with(encoding);
        let path = format!(
            "/nar/{}{}",
            nix32_sha256(&compressed),
            compressed_test_suffix(encoding)
        );
        let response = server.request_with_body("PUT", &path, &[], &compressed);
        let published_raw = server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
        let temporary = fs::read_dir(server.data_dir.join(".tmp"))
            .expect("temporary directory exists")
            .count();
        let (signal, status) = server.stop();

        let (headers, body) = response_parts(&response);
        assert!(
            headers.starts_with("HTTP/1.1 422 Unprocessable Entity\r\n"),
            "{encoding:?}: {headers:?}"
        );
        assert!(body.is_empty());
        assert!(
            !published_raw.exists(),
            "{encoding:?} was rejected before commit"
        );
        assert_eq!(temporary, 0, "{encoding:?} staging file was removed");
        assert_clean_shutdown(signal, status);
    }
}

#[test]
fn decoded_size_limit_returns_422_for_a_large_raw_upload() {
    const UPLOAD_BYTES: usize = 100_000;

    let server = RunningServer::start_with_args("decoded-size-limit", &["--max-nar-bytes", "5"]);
    let raw = vec![0; UPLOAD_BYTES];
    let path = format!("/nar/{}.nar", nix32_sha256(&raw));
    let response = server.request_with_body("PUT", &path, &[], &raw);
    let published = server
        .data_dir
        .join(format!("nar/{}.nar", nix32_sha256(&raw)));
    let temporary = fs::read_dir(server.data_dir.join(".tmp"))
        .expect("temporary directory exists")
        .count();
    let (signal, status) = server.stop();

    assert_empty_http_response(&response, "422 Unprocessable Entity");
    assert!(
        !published.exists(),
        "oversized decoded NAR was not published"
    );
    assert_eq!(temporary, 0, "staging file was removed");
    assert_clean_shutdown(signal, status);
}

#[test]
#[cfg(target_os = "linux")]
fn malicious_xz_index_cannot_allocate_from_its_declared_block_count() {
    const DECLARED_BLOCK_COUNT: u64 = 16_777_216;
    const ALLOWED_VIRTUAL_MEMORY_GROWTH: u64 = 64 * 1024 * 1024;

    let server = RunningServer::start_with_args(
        "xz-index-block-count",
        &["--max-decoder-memory-bytes", "16777216"],
    );
    let _ = server.request("GET", "/metrics");

    let warmup = encode_xz_payload(b"warmup");
    let warmup_path = format!("/nar/{}.nar.xz", nix32_sha256(&warmup));
    let warmup_response = server.request_with_body("PUT", &warmup_path, &[], &warmup);
    assert!(
        warmup_response.starts_with(b"HTTP/1.1 201 Created\r\n"),
        "valid XZ warm-up upload should succeed: {:?}",
        String::from_utf8_lossy(&warmup_response)
    );

    let baseline_peak = server.peak_virtual_memory_bytes();

    let mut compressed = encode_test_nar_with(WireEncoding::Compressed(CompressionCodec::Xz));
    let footer_start = compressed.len() - 12;
    let backward_size = u32::from_le_bytes(
        compressed[footer_start + 4..footer_start + 8]
            .try_into()
            .expect("XZ footer contains its backward size"),
    ) as usize;
    let index_start = footer_start - (backward_size + 1) * 4;
    assert_eq!(
        compressed[index_start], 0,
        "XZ index starts with its marker"
    );
    assert_eq!(compressed[index_start + 1], 1, "fixture has one XZ block");
    compressed.splice(
        index_start + 1..index_start + 2,
        encode_xz_variable_integer(DECLARED_BLOCK_COUNT),
    );

    let path = format!("/nar/{}.nar.xz", nix32_sha256(&compressed));
    let response = server.request_with_body("PUT", &path, &[], &compressed);
    let peak_virtual_memory = server.peak_virtual_memory_bytes();
    let nar_published = server
        .data_dir
        .join(format!("nar/{}.nar", NARJAR_HASH))
        .exists();
    let (signal, status) = server.stop();

    assert_empty_http_response(&response, "422 Unprocessable Entity");
    assert!(
        peak_virtual_memory <= baseline_peak + ALLOWED_VIRTUAL_MEMORY_GROWTH,
        "malformed XZ index grew VmPeak from {baseline_peak} to {peak_virtual_memory} bytes"
    );
    assert!(!nar_published, "malformed XZ input must not publish a NAR");
    assert_clean_shutdown(signal, status);
}

#[test]
#[cfg(target_os = "linux")]
fn concurrent_compressed_uploads_stay_within_the_worker_memory_ceiling() {
    const PUBLICATION_WORKERS: usize = 2;
    const UPLOAD_COUNT: usize = 4;
    const DECODER_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
    const ALLOWED_FIXED_PROCESS_OVERHEAD: u64 = 32 * 1024 * 1024;
    const DICTIONARY_SIZE: usize = 16 * 1024 * 1024;

    let server = RunningServer::start_with_workers(
        "concurrent-decoder-memory",
        PUBLICATION_WORKERS,
        &["--max-decoder-memory-bytes", "67108864"],
    );
    let baseline_peak_bytes = server.peak_rss_bytes();
    let raw_nars = [0x1234_5678_u32, 0x9abc_def0, 0x1357_9bdf, 0x2468_ace0]
        .iter()
        .map(|seed| {
            let mut state = *seed;
            let mut raw = (0..DICTIONARY_SIZE)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect::<Vec<_>>();
            raw.extend_from_within(..);
            raw
        })
        .collect::<Vec<_>>();
    let uploads = raw_nars
        .iter()
        .map(|raw| {
            let mut compressed = Vec::new();
            compress(
                std::io::Cursor::new(raw),
                &mut compressed,
                CompressionLevel::Fastest,
            );
            let path = format!("/nar/{}.nar.zst", nix32_sha256(&compressed));
            (compressed, path)
        })
        .collect::<Vec<_>>();

    let start = Barrier::new(UPLOAD_COUNT + 1);
    let uploads_finished = AtomicBool::new(false);
    let maximum_active_workers = AtomicU64::new(0);
    let maximum_queue_depth = AtomicU64::new(0);
    let responses = std::thread::scope(|scope| {
        let observer_finished = &uploads_finished;
        let observer_active_workers = &maximum_active_workers;
        let observer_queue_depth = &maximum_queue_depth;
        let metrics_server = &server;
        let observer = scope.spawn(move || {
            while !observer_finished.load(Ordering::Acquire) {
                let (_, metrics) = response_parts(&metrics_server.request("GET", "/metrics"));
                let metrics = String::from_utf8_lossy(&metrics);
                observer_active_workers.fetch_max(
                    metric_value(&metrics, "narjar_publication_workers_active"),
                    Ordering::Relaxed,
                );
                observer_queue_depth.fetch_max(
                    metric_value(&metrics, "narjar_publication_queue_depth"),
                    Ordering::Relaxed,
                );
                thread::sleep(Duration::from_millis(2));
            }
        });
        let mut requests = Vec::with_capacity(UPLOAD_COUNT);
        for (compressed, path) in &uploads {
            let start = &start;
            let upload_server = &server;
            requests.push(scope.spawn(move || {
                start.wait();
                upload_server.request_with_body("PUT", path, &[], compressed)
            }));
        }
        start.wait();
        let upload_results = requests
            .into_iter()
            .map(|request| request.join())
            .collect::<Vec<_>>();
        uploads_finished.store(true, Ordering::Release);
        observer.join().expect("metrics observer should complete");
        upload_results
            .into_iter()
            .map(|result| result.expect("upload thread should complete"))
            .collect::<Vec<_>>()
    });
    let maximum_active_workers = maximum_active_workers.load(Ordering::Relaxed);
    let maximum_queue_depth = maximum_queue_depth.load(Ordering::Relaxed);
    let peak_rss_bytes = server.peak_rss_bytes();
    eprintln!(
        "compressed upload RSS: baseline={baseline_peak_bytes} B peak={peak_rss_bytes} B, \
         decoder_limit={DECODER_LIMIT_BYTES} B × {PUBLICATION_WORKERS} publication workers, \
         observed active={maximum_active_workers}, queued={maximum_queue_depth}"
    );
    let (signal, status) = server.stop();

    for response in responses {
        assert_empty_http_response(&response, "201 Created");
    }
    let configured_peak_bytes = baseline_peak_bytes
        + DECODER_LIMIT_BYTES * PUBLICATION_WORKERS as u64
        + ALLOWED_FIXED_PROCESS_OVERHEAD;
    assert_eq!(maximum_active_workers, PUBLICATION_WORKERS as u64);
    assert!(maximum_queue_depth > 0, "excess uploads should queue");
    assert!(
        peak_rss_bytes <= configured_peak_bytes,
        "observed server peak RSS {peak_rss_bytes} B exceeded baseline {baseline_peak_bytes} B + \
         {PUBLICATION_WORKERS} × {DECODER_LIMIT_BYTES} B decoder budget + \
         {ALLOWED_FIXED_PROCESS_OVERHEAD} B fixed overhead"
    );
    assert_clean_shutdown(signal, status);
}

#[test]
#[cfg(target_os = "linux")]
fn chunked_backend_serves_the_reconstructed_raw_nar() {
    let server =
        RunningServer::start_with_args("chunked-raw-read", &["--storage-backend", "chunked"]);
    let path = format!("/nar/{NARJAR_HASH}.nar");
    let uploaded = server.request_with_body("PUT", &path, &[], NAR_BYTES);
    let full = server.request("GET", &path);
    let range = server.request_with_headers("GET", &path, &[("Range", "bytes=1-3")]);
    assert!(
        !server
            .data_dir
            .join(format!("nar/{NARJAR_HASH}.nar"))
            .exists()
    );
    assert!(
        fs::read_dir(server.data_dir.join(".narjar-manifests"))
            .expect("manifest directory should be readable")
            .any(|entry| entry.is_ok())
    );

    assert!(
        response_parts(&uploaded)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n"),
        "{uploaded:?}"
    );
    let (full_headers, full_body) = response_parts(&full);
    assert!(
        full_headers.starts_with("HTTP/1.1 200 OK\r\n"),
        "{full_headers}"
    );
    assert_eq!(full_body, NAR_BYTES);
    let (range_headers, range_body) = response_parts(&range);
    assert!(
        range_headers.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{range_headers}"
    );
    assert_eq!(range_body, &NAR_BYTES[1..4]);
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
#[cfg(target_os = "linux")]
fn chunked_narinfo_publication_rejects_missing_and_truncated_chunks() {
    for remove in [true, false] {
        let server = RunningServer::start_with_args(
            "chunked-bind-availability",
            &["--storage-backend", "chunked"],
        );
        let uploaded = server
            .exchange(
                "PUT",
                &format!("/nar/{NARJAR_HASH}.nar"),
                &[],
                Some(NAR_BYTES),
            )
            .response;
        assert_http_status_line(&response_parts(&uploaded).0, "201 Created");
        let chunk = fs::read_dir(server.data_dir.join(".narjar-chunks"))
            .unwrap()
            .flat_map(|shard| fs::read_dir(shard.unwrap().path()).unwrap())
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_file())
            .expect("fixture has a chunk");
        if remove {
            fs::remove_file(chunk).unwrap();
        } else {
            fs::OpenOptions::new()
                .write(true)
                .open(chunk)
                .unwrap()
                .set_len(1)
                .unwrap();
        }
        let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
        let response = server
            .exchange(
                "PUT",
                &format!("/{STORE_HASH}.narinfo"),
                &[],
                Some(narinfo.as_bytes()),
            )
            .response;
        let headers = response_parts(&response).0;
        assert!(
            !headers.starts_with("HTTP/1.1 2"),
            "unavailable chunk must prevent publication: {headers}"
        );
        assert!(
            !server
                .data_dir
                .join(format!("{STORE_HASH}.narinfo"))
                .exists()
        );
        let (signal, status) = server.stop();
        assert_clean_shutdown(signal, status);
    }
}

#[test]
fn accepted_upload_sends_continue_before_reading_the_body() {
    let server = RunningServer::start("expect-continue");
    let mut stream =
        server.open_upload_after_continue(&format!("/nar/{NARJAR_HASH}.nar"), NAR_BYTES.len());
    stream.write_all(NAR_BYTES).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert_http_status_line(&response_parts(&response).0, "201 Created");
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn unsupported_upload_expectation_is_rejected_before_body_delivery() {
    let server = RunningServer::start("expect-rejected");
    let mut stream = server.open_request(
        "PUT",
        &format!("/nar/{NARJAR_HASH}.nar"),
        &[("Content-Length", "6"), ("Expect", "unrecognized")],
    );
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("unsupported expectation must receive an immediate final response");
    assert_http_status_line(&response_parts(&response).0, "417 Expectation Failed");
    assert!(
        !server
            .data_dir
            .join(format!("nar/{NARJAR_HASH}.nar"))
            .exists()
    );
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn rejected_uploads_do_not_grant_continue_or_wait_for_the_body() {
    let server =
        RunningServer::start_with_args("expect-admission", &["--max-encoded-nar-bytes", "5"]);
    for (authorization, length, expected_status) in [
        ("wrong-token", "4", "401 Unauthorized"),
        (TEST_AUTHORIZATION, "6", "413 Payload Too Large"),
    ] {
        let mut stream = server.open_raw_request(
            "PUT",
            &format!("/nar/{NARJAR_HASH}.nar"),
            &[
                ("Content-Length", length),
                ("Expect", "100-continue"),
                ("Authorization", authorization),
            ],
        );
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("reject before the client sends a body");
        assert_http_status_line(&response_parts(&response).0, expected_status);
        assert!(!String::from_utf8_lossy(&response).contains("100 Continue"));
    }
    assert!(
        !server
            .data_dir
            .join(format!("nar/{NARJAR_HASH}.nar"))
            .exists()
    );
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
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
                "narjar_operation_duration_seconds_count{{operation=\"publication_queue_wait\"}} {concurrency}"
            )),
            "{metrics}"
        );

        let (signal, status) = server.stop();
        assert_clean_shutdown(signal, status);
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
    let stalled = server.open_request("PUT", &path, &[("Content-Length", "6")]);
    let mut stalled = BufReader::new(stalled);
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

        for _ in 0..500 {
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
            .get_mut()
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
        metrics.contains(
            "narjar_operation_duration_seconds_count{operation=\"publication_queue_wait\"} 2"
        ),
        "{metrics}"
    );

    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn xz_narinfo_is_published_as_the_canonical_raw_pair() {
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
    let optional_fields = format!("Deriver: unknown-deriver\nCA: fixed:r:sha256:{NARJAR_HASH}\n");
    let narinfo = narinfo + &optional_fields;

    let nar_path = format!("/nar/{file_hash}.nar.xz");
    let uploaded = server.request_with_body("PUT", &nar_path, &[], &compressed);
    let published = server.request_with_body(
        "PUT",
        &format!("/{STORE_HASH}.narinfo"),
        &[],
        narinfo.as_bytes(),
    );
    let narinfo_get = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let nar_get = server.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
    let (signal, status) = server.stop();

    for response in [&uploaded, &published, &narinfo_get, &nar_get] {
        assert!(
            String::from_utf8_lossy(response).starts_with("HTTP/1.1 2"),
            "{response:?}"
        );
    }
    let (_, narinfo_body) = response_parts(&narinfo_get);
    assert_eq!(
        narinfo_body,
        (signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64) + &optional_fields).as_bytes(),
        "raw projection must preserve signatures and optional fields exactly"
    );
    let (_, nar_body) = response_parts(&nar_get);
    assert_eq!(nar_body, NAR_BYTES);
    assert_clean_shutdown(signal, status);
}

#[test]
fn zstd_narinfo_is_published_as_the_canonical_raw_pair() {
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
    let nar_get = server.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
    let (signal, status) = server.stop();

    assert_empty_http_response(&wrong, "422 Unprocessable Entity");
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
    assert_eq!(
        narinfo_body,
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64).as_bytes()
    );
    let (_, nar_body) = response_parts(&nar_get);
    assert_eq!(nar_body, NAR_BYTES);
    assert_clean_shutdown(signal, status);
}

#[test]
fn configured_compressed_egress_is_independent_of_ingress_encoding() {
    for (output_encoding, input_encoding) in [
        (
            WireEncoding::Compressed(CompressionCodec::Zstd),
            WireEncoding::Compressed(CompressionCodec::Xz),
        ),
        (
            WireEncoding::Compressed(CompressionCodec::Xz),
            WireEncoding::Compressed(CompressionCodec::Zstd),
        ),
        (
            WireEncoding::Compressed(CompressionCodec::Xz),
            WireEncoding::Raw,
        ),
        (
            WireEncoding::Compressed(CompressionCodec::Zstd),
            WireEncoding::Raw,
        ),
        (
            WireEncoding::Raw,
            WireEncoding::Compressed(CompressionCodec::Zstd),
        ),
    ] {
        let output_name = compression_name(output_encoding);
        let input_suffix = test_nar_suffix(input_encoding);
        let output_suffix = test_nar_suffix(output_encoding);
        let server = RunningServer::start_with_args(
            &format!(
                "egress-{}-to-{output_name}",
                test_encoding_name(input_encoding)
            ),
            &["--egress-compression", output_name],
        );
        let compressed = encode_test_nar(input_encoding);
        let input_hash = nix32_sha256(&compressed);
        let uploaded = server.request_with_body(
            "PUT",
            &format!("/nar/{input_hash}{input_suffix}"),
            &[],
            &compressed,
        );
        let narinfo = signed_narinfo_for_encoding(
            input_encoding,
            &input_hash,
            NARJAR_HASH,
            NAR_BYTES.len() as u64,
            compressed.len() as u64,
        );
        let published = server.request_with_body(
            "PUT",
            &format!("/{STORE_HASH}.narinfo"),
            &[],
            narinfo.as_bytes(),
        );
        let repeated = server.request_with_body(
            "PUT",
            &format!("/{STORE_HASH}.narinfo"),
            &[],
            narinfo.as_bytes(),
        );
        let narinfo_response = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
        let (_, narinfo_body) = response_parts(&narinfo_response);
        let narinfo_text = String::from_utf8(narinfo_body.to_vec()).expect("narinfo is UTF-8");
        let output_url = narinfo_text
            .lines()
            .find_map(|line| line.strip_prefix("URL: "))
            .expect("projected narinfo has a URL");
        let output_bytes = encode_test_nar(output_encoding);
        let output_hash = nix32_sha256(&output_bytes);
        assert_eq!(output_url, format!("nar/{output_hash}{output_suffix}"));
        assert!(narinfo_text.contains(&format!(
            "Compression: {}",
            compression_name(output_encoding)
        )));
        assert_eq!(
            narinfo_text,
            rewrite_transport_fields(&narinfo, output_encoding, &output_hash, output_bytes.len())
        );
        let output_response = server.request("GET", &format!("/{output_url}"));
        let (_, output_body) = response_parts(&output_response);
        let output_path = server
            .data_dir
            .join(format!("nar/{output_hash}{output_suffix}"));
        let raw_path = server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
        assert!(output_path.is_file());
        assert!(raw_path.is_file());
        let (temp_dir, signal, status) = server.stop_preserving();

        assert!(uploaded.starts_with(b"HTTP/1.1 201 Created\r\n"));
        assert!(published.starts_with(b"HTTP/1.1 201 Created\r\n"));
        assert!(repeated.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(output_response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(output_body, output_bytes);
        assert_clean_shutdown(signal, status);

        let gc = run(&[
            "gc",
            "--data-dir",
            temp_dir
                .path()
                .to_str()
                .expect("temporary path should be UTF-8"),
            "--target-bytes",
            "0",
            "--min-age-seconds",
            "0",
            "--dry-run",
            "--json",
        ]);
        assert!(gc.status.success(), "GC should inspect compressed egress");
        assert!(
            String::from_utf8_lossy(&gc.stdout).contains("\"orphaned\":0"),
            "compressed output and its raw source should both be referenced: {}",
            String::from_utf8_lossy(&gc.stdout)
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn chunked_backend_materializes_compressed_egress_from_chunks() {
    let server = RunningServer::start_with_args(
        "chunked-zstd-egress",
        &[
            "--storage-backend",
            "chunked",
            "--egress-compression",
            "zstd",
        ],
    );
    let uploaded =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
    let repeated_upload =
        server.request_with_body("PUT", &format!("/nar/{NARJAR_HASH}.nar"), &[], NAR_BYTES);
    let narinfo = signed_narinfo_for_encoding(
        WireEncoding::Raw,
        NARJAR_HASH,
        NARJAR_HASH,
        NAR_BYTES.len() as u64,
        NAR_BYTES.len() as u64,
    );
    let published = server.request_with_body(
        "PUT",
        &format!("/{STORE_HASH}.narinfo"),
        &[],
        narinfo.as_bytes(),
    );
    let repeated_publication = server.request_with_body(
        "PUT",
        &format!("/{STORE_HASH}.narinfo"),
        &[],
        narinfo.as_bytes(),
    );
    let narinfo_response = server.request("GET", &format!("/{STORE_HASH}.narinfo"));
    let (_, narinfo_body) = response_parts(&narinfo_response);
    let projected = String::from_utf8(narinfo_body.to_vec()).expect("narinfo should be UTF-8");
    let output_url = projected
        .lines()
        .find_map(|line| line.strip_prefix("URL: "))
        .expect("projected narinfo should contain an output URL");
    let output = server.request("GET", &format!("/{output_url}"));
    let expected = encode_test_nar(WireEncoding::Compressed(CompressionCodec::Zstd));
    let (output_headers, output_body) = response_parts(&output);

    assert!(
        response_parts(&uploaded)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n"),
        "{uploaded:?}"
    );
    assert!(
        response_parts(&repeated_upload)
            .0
            .starts_with("HTTP/1.1 200 OK\r\n"),
        "{repeated_upload:?}"
    );
    assert!(
        response_parts(&repeated_publication)
            .0
            .starts_with("HTTP/1.1 200 OK\r\n"),
        "{repeated_publication:?}"
    );
    assert!(
        response_parts(&published)
            .0
            .starts_with("HTTP/1.1 201 Created\r\n"),
        "{published:?}"
    );
    assert!(projected.contains("Compression: zstd\n"), "{projected}");
    assert!(!projected.contains("Compression: none\n"));
    assert!(
        output_headers.starts_with("HTTP/1.1 200 OK\r\n"),
        "{output_headers}"
    );
    assert_eq!(output_body, expected);

    let metrics = String::from_utf8(response_parts(&server.request("GET", "/metrics")).1)
        .expect("metrics should be UTF-8");
    assert!(
        metrics.contains("narjar_egress_derivatives_total{outcome=\"generation_succeeded\"} 1")
    );
    assert!(metrics.contains("narjar_egress_derivatives_total{outcome=\"reused\"} 1"));
    assert!(metrics.contains("narjar_chunks_total{outcome=\"created\"} 1"));
    assert!(metrics.contains("narjar_chunks_total{outcome=\"reused\"} 1"));
    assert!(metrics.contains("narjar_chunk_bytes_total{outcome=\"created\"} 6"));
    assert!(metrics.contains("narjar_chunk_bytes_total{outcome=\"reused\"} 6"));
    assert!(
        !server
            .data_dir
            .join(format!("nar/{NARJAR_HASH}.nar"))
            .exists()
    );
    assert!(server.data_dir.join(".narjar-egress").is_dir());
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

fn encode_test_nar(encoding: WireEncoding) -> Vec<u8> {
    match encoding {
        WireEncoding::Raw => NAR_BYTES.to_vec(),
        WireEncoding::Compressed(CompressionCodec::Zstd) => {
            let mut compressed = Vec::new();
            let mut encoder = StreamingEncoder::new(&mut compressed, CompressionLevel::Fastest);
            encoder.write_all(NAR_BYTES).expect("compress NAR");
            encoder.finish().expect("finish zstd stream");
            compressed
        }
        WireEncoding::Compressed(CompressionCodec::Xz) => {
            let mut compressed = Vec::new();
            let mut writer = XzWriter::new(&mut compressed, XzOptions::with_preset(1))
                .expect("create XZ writer");
            writer.write_all(NAR_BYTES).expect("compress NAR");
            writer.finish().expect("finish XZ stream");
            compressed
        }
    }
}

fn rewrite_transport_fields(
    narinfo: &str,
    encoding: WireEncoding,
    file_hash: &str,
    file_size: usize,
) -> String {
    narinfo
        .lines()
        .map(|line| match line.split_once(": ") {
            Some(("URL", _)) => format!("URL: nar/{file_hash}{}", test_nar_suffix(encoding)),
            Some(("Compression", _)) => {
                format!("Compression: {}", compression_name(encoding))
            }
            Some(("FileHash", _)) => format!("FileHash: sha256:{file_hash}"),
            Some(("FileSize", _)) => format!("FileSize: {file_size}"),
            _ => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn compression_name(encoding: WireEncoding) -> &'static str {
    match encoding {
        WireEncoding::Compressed(CompressionCodec::Xz) => "xz",
        WireEncoding::Compressed(CompressionCodec::Zstd) => "zstd",
        WireEncoding::Raw => "none",
    }
}

fn test_nar_suffix(encoding: WireEncoding) -> &'static str {
    match encoding {
        WireEncoding::Raw => ".nar",
        WireEncoding::Compressed(CompressionCodec::Xz) => ".nar.xz",
        WireEncoding::Compressed(CompressionCodec::Zstd) => ".nar.zst",
    }
}

#[test]
fn compressed_ingestion_receipts_survive_restart_before_narinfo_publication() {
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
        let server =
            RunningServer::start(&format!("receipt-restart-{}", test_encoding_name(encoding)));
        let (compressed, narinfo, suffix) = compressed_upload_fixture(encoding);
        let encoded_hash = nix32_sha256(&compressed);
        let uploaded = server.request_with_body(
            "PUT",
            &format!("/nar/{encoded_hash}{suffix}"),
            &[],
            &compressed,
        );
        assert!(
            response_parts(&uploaded)
                .0
                .starts_with("HTTP/1.1 201 Created\r\n"),
            "{encoding:?} upload should be accepted: {uploaded:?}"
        );

        let (data_dir, signal, status) = server.stop_preserving();
        assert!(signal.is_ok(), "{encoding:?} server should stop cleanly");
        assert!(status.success(), "{encoding:?} server should stop cleanly");

        let restarted = RunningServer::start_in(data_dir, &[]);
        let published = restarted.request_with_body(
            "PUT",
            &format!("/{STORE_HASH}.narinfo"),
            &[],
            narinfo.as_bytes(),
        );
        assert!(
            response_parts(&published)
                .0
                .starts_with("HTTP/1.1 201 Created\r\n"),
            "{encoding:?} narinfo should use the durable receipt: {published:?}"
        );
        let served = restarted.request("GET", &format!("/nar/{NARJAR_HASH}.nar"));
        assert_eq!(response_parts(&served).1, NAR_BYTES);
        let (signal, status) = restarted.stop();
        assert!(signal.is_ok(), "{encoding:?} server should stop cleanly");
        assert!(status.success(), "{encoding:?} server should stop cleanly");
    }
}

#[test]
fn compressed_publication_rejects_a_receipt_for_a_different_nar_identity() {
    let different_nar = b"different-nar";
    let different_hash = nix32_sha256(different_nar);
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
        let server = RunningServer::start(&format!(
            "receipt-mismatch-{}",
            test_encoding_name(encoding)
        ));
        let (compressed, _, suffix) = compressed_upload_fixture(encoding);
        let encoded_hash = nix32_sha256(&compressed);
        let mismatched_narinfo = signed_narinfo_for_encoding(
            encoding,
            &encoded_hash,
            &different_hash,
            different_nar.len() as u64,
            compressed.len() as u64,
        );

        let uploaded = server.request_with_body(
            "PUT",
            &format!("/nar/{encoded_hash}{suffix}"),
            &[],
            &compressed,
        );
        assert!(
            response_parts(&uploaded)
                .0
                .starts_with("HTTP/1.1 201 Created\r\n")
        );
        let rejected = server.request_with_body(
            "PUT",
            &format!("/{STORE_HASH}.narinfo"),
            &[],
            mismatched_narinfo.as_bytes(),
        );
        assert!(
            response_parts(&rejected)
                .0
                .starts_with("HTTP/1.1 422 Unprocessable Entity\r\n"),
            "{encoding:?} metadata must remain bound to the decoded NAR: {rejected:?}"
        );
        assert!(
            !server
                .data_dir
                .join(format!("{STORE_HASH}.narinfo"))
                .exists()
        );
        let (signal, status) = server.stop();
        assert!(signal.is_ok(), "{encoding:?} server should stop cleanly");
        assert!(status.success(), "{encoding:?} server should stop cleanly");
    }
}

#[test]
fn an_ingestion_receipt_cannot_bind_a_missing_or_wrong_sized_raw_payload() {
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
        let server = RunningServer::start("receipt-needs-raw-payload");
        let (compressed, narinfo, suffix) = compressed_upload_fixture(encoding);
        let uploaded = server.request_with_body(
            "PUT",
            &format!("/nar/{}{suffix}", nix32_sha256(&compressed)),
            &[],
            &compressed,
        );
        assert!(response_parts(&uploaded).0.starts_with("HTTP/1.1 201"));
        let raw_path = server.data_dir.join(format!("nar/{NARJAR_HASH}.nar"));
        fs::write(&raw_path, b"truncated").unwrap();
        let metadata_path = format!("/{STORE_HASH}.narinfo");
        let wrong_size = server.request_with_body("PUT", &metadata_path, &[], narinfo.as_bytes());
        assert!(
            response_parts(&wrong_size).0.starts_with("HTTP/1.1 422"),
            "{encoding:?}: a receipt must not replace checking the raw file size"
        );

        fs::remove_file(&raw_path).unwrap();
        let missing = server.request_with_body("PUT", &metadata_path, &[], narinfo.as_bytes());
        assert!(
            response_parts(&missing).0.starts_with("HTTP/1.1 422"),
            "{encoding:?}: a receipt must not replace opening the raw file"
        );
        assert!(
            !server
                .data_dir
                .join(format!("{STORE_HASH}.narinfo"))
                .exists()
        );
        let (signal, status) = server.stop();
        assert_clean_shutdown(signal, status);
    }
}

fn compressed_upload_fixture(encoding: WireEncoding) -> (Vec<u8>, String, &'static str) {
    let compressed = encode_test_nar_with(encoding);
    let encoded_hash = nix32_sha256(&compressed);
    let narinfo = signed_narinfo_for_encoding(
        encoding,
        &encoded_hash,
        NARJAR_HASH,
        NAR_BYTES.len() as u64,
        compressed.len() as u64,
    );
    let suffix = compressed_test_suffix(encoding);
    (compressed, narinfo, suffix)
}

fn encode_test_nar_with(encoding: WireEncoding) -> Vec<u8> {
    match encoding {
        WireEncoding::Compressed(CompressionCodec::Xz) => encode_test_nar_as_xz(),
        WireEncoding::Compressed(CompressionCodec::Zstd) => encode_test_nar_as_zstd(),
        WireEncoding::Raw => panic!("raw is not a compressed test encoding"),
    }
}

fn encode_test_nar_as_xz() -> Vec<u8> {
    encode_xz_payload(NAR_BYTES)
}

fn encode_xz_payload(payload: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    let mut writer = XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ");
    writer.write_all(payload).expect("compress payload");
    writer.finish().expect("finish XZ");
    compressed
}

fn encode_test_nar_as_zstd() -> Vec<u8> {
    let mut compressed = Vec::new();
    compress(
        std::io::Cursor::new(NAR_BYTES),
        &mut compressed,
        CompressionLevel::Fastest,
    );
    compressed
}

fn signed_narinfo_for_encoding(
    encoding: WireEncoding,
    encoded_hash: &str,
    nar_hash: &str,
    nar_size: u64,
    encoded_size: u64,
) -> String {
    match encoding {
        WireEncoding::Raw => signed_narinfo(nar_hash, nar_size),
        WireEncoding::Compressed(CompressionCodec::Xz) => {
            signed_xz_narinfo(encoded_hash, nar_hash, nar_size, encoded_size)
        }
        WireEncoding::Compressed(CompressionCodec::Zstd) => {
            signed_zstd_narinfo(encoded_hash, nar_hash, nar_size, encoded_size)
        }
    }
}

fn test_encoding_name(encoding: WireEncoding) -> &'static str {
    match encoding {
        WireEncoding::Raw => "raw",
        WireEncoding::Compressed(CompressionCodec::Xz) => "xz",
        WireEncoding::Compressed(CompressionCodec::Zstd) => "zstd",
    }
}

#[cfg(target_os = "linux")]
fn encode_xz_variable_integer(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 0x80 {
        bytes.push(value as u8 | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

fn compressed_test_suffix(encoding: WireEncoding) -> &'static str {
    match encoding {
        WireEncoding::Compressed(CompressionCodec::Xz) => ".nar.xz",
        WireEncoding::Compressed(CompressionCodec::Zstd) => ".nar.zst",
        WireEncoding::Raw => panic!("raw is not a compressed test encoding"),
    }
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
    assert_empty_http_response(&rejected, "422 Unprocessable Entity");
    assert!(!published.exists());
    assert_clean_shutdown(signal, status);
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
    assert_http_status_line(&headers, "200 OK");
    assert_eq!(body, narinfo.as_bytes());
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);

    let restarted = RunningServer::start_in(data_dir, &[]);
    assert!(
        response_parts(&restarted.request("GET", &path))
            .0
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let (data_dir, signal, status) = restarted.stop_preserving();
    assert_clean_shutdown(signal, status);

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
        stderr.contains("published inventory contains an invalid narinfo/NAR pair"),
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
    let (_, metrics_body) = response_parts(&server.request("GET", "/metrics"));
    let metrics = String::from_utf8(metrics_body).expect("metrics should be UTF-8");
    let (signal, status) = server.stop();

    let limited =
        RunningServer::start_with_args("nar-put-oversized", &["--max-encoded-nar-bytes", "5"]);
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
    assert!(
        metrics.contains("narjar_connections_total{outcome=\"disconnected\"} 1"),
        "truncated upload body should count as a disconnected connection: {metrics}"
    );
    assert!(temp_is_empty);
    assert!(!oversized_path.exists());
    assert_clean_shutdown(signal, status);
    assert!(limited_signal.is_ok(), "shutdown request should be sent");
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
    assert_empty_http_response(&response, "507 Insufficient Storage");
    assert!(!final_path.exists());
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
}

#[test]
fn reads_continue_while_a_publication_waits_for_its_body() {
    let server = RunningServer::start_with_args("publication-lane", &["--max-in-flight", "2"]);
    let nar_bytes = b"0123456789";
    let nar_hash = nix32_sha256(nar_bytes);
    let path = format!("/nar/{nar_hash}.nar");
    fs::write(
        server.data_dir.join(format!("nar/{nar_hash}.nar")),
        nar_bytes,
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
    assert_http_status_line(&headers, "206 Partial Content");
    assert_eq!(body, b"2345");

    drop(stalled);
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
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
        assert_http_status_line(&headers, "401 Unauthorized");
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
    assert_clean_shutdown(signal, status);
}

#[test]
fn configured_empty_read_token_set_stays_private() {
    let server = RunningServer::start_with_read_tokens("empty-private-read", "");
    let response = server.request("GET", "/nix-cache-info");
    let (signal, status) = server.stop();
    let (headers, body) = response_parts(&response);

    assert_http_status_line(&headers, "401 Unauthorized");
    assert!(
        headers.contains("WWW-Authenticate: Basic realm=\"narjar\"\r\n"),
        "{headers:?}"
    );
    assert!(body.is_empty());
    assert_clean_shutdown(signal, status);
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
    assert_private_path(&token_path);

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
    assert_clean_shutdown(signal, status);

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
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
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
#[cfg(not(target_os = "linux"))]
fn unsupported_backends_fail_before_commands_create_or_modify_cache_data() {
    let parent = tempfile::tempdir().unwrap();
    let cache = parent.path().join("cache");
    let credentials = parent.path().join("credentials");
    for operation in [
        "init",
        "setup",
        "serve",
        "reconcile",
        "cleanup",
        "verify",
        "doctor",
    ] {
        let mut process = command();
        process
            .args([operation, "--storage-backend", "chunked", "--data-dir"])
            .arg(&cache);
        if operation == "setup" {
            process
                .arg("--credentials-dir")
                .arg(&credentials)
                .arg("--yes");
        }
        let output = process.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{operation} must reject unsupported storage as a usage error"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("chunked storage"),
            "{operation}: {output:?}"
        );
        assert!(!cache.exists(), "{operation} must not create cache data");
        assert!(
            !credentials.exists(),
            "{operation} must not create credentials"
        );
    }

    let directory = crate::cache::test_support::private_directory(&cache).unwrap();
    fs::write(cache.join("sentinel"), b"existing data").unwrap();
    let before = crate::cache::filesystem::FileStamp::from_file(&directory).unwrap();
    let output = command()
        .args(["init", "--storage-backend", "chunked", "--data-dir"])
        .arg(&cache)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("chunked storage"));
    assert_eq!(fs::read(cache.join("sentinel")).unwrap(), b"existing data");
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 1);
    assert_eq!(
        crate::cache::filesystem::FileStamp::from_file(&directory).unwrap(),
        before
    );
}

#[test]
fn init_and_key_generate_create_secure_operator_material() {
    let data_dir = init_data_dir("operator-init");
    for directory in ["nar", ".tmp", "realisations", "auth"] {
        assert!(data_dir.join(directory).is_dir(), "{directory}");
    }
    for file in ["nix-cache-info", "trusted-public-keys", "auth/write.tokens"] {
        assert!(data_dir.join(file).is_file(), "{file}");
    }
    assert_private_path(data_dir.path());

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
    assert_private_path(&secret);
}

#[test]
fn setup_creates_a_ready_cache_and_separate_private_credentials() {
    for backend in SUPPORTED_STORAGE_BACKENDS {
        assert_setup_creates_ready_cache_and_private_credentials(backend);
    }
}

fn assert_setup_creates_ready_cache_and_private_credentials(backend: &str) {
    let setup_root = data_dir("setup-root");
    let cache_path = setup_root.path().join("cache");
    let credentials_dir = setup_root.path().join("credentials");
    let output = run(&[
        "setup",
        "--data-dir",
        cache_path.to_str().expect("data path should be UTF-8"),
        "--credentials-dir",
        credentials_dir
            .to_str()
            .expect("credentials path should be UTF-8"),
        "--cache-url",
        "https://cache.example/cache",
        "--listen",
        "127.0.0.1:0",
        "--key-name",
        "test-producer",
        "--priority",
        "17",
        "--storage-backend",
        backend,
        "--private-read",
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output_text = String::from_utf8(output.stdout).expect("setup output should be UTF-8");
    let secret_key = credentials_dir.join("producer.sec");
    let public_key = credentials_dir.join("producer.pub");
    let netrc = credentials_dir.join("narjar.netrc");
    let write_token = credentials_dir.join("write.token");
    let read_token = credentials_dir.join("read.token");
    let write_token_text = fs::read_to_string(&write_token).expect("write token should exist");
    let read_token_text = fs::read_to_string(&read_token).expect("read token should exist");
    let netrc_text = fs::read_to_string(&netrc).expect("netrc should exist");

    assert!(output_text.contains("Narjar setup complete"));
    let upload_instruction = if cfg!(windows) {
        "Upload from a Linux or macOS Nix host with narjar push to https://cache.example/cache."
    } else {
        "narjar push --to 'https://cache.example/cache'"
    };
    assert!(output_text.contains(upload_instruction), "{output_text}");
    assert!(!output_text.contains(write_token_text.trim()));
    assert!(!output_text.contains(read_token_text.trim()));
    assert_eq!(
        fs::read(&public_key).expect("public key should exist"),
        fs::read(cache_path.join("trusted-public-keys"))
            .expect("public key should be trusted by this cache")
    );
    assert!(netrc_text.contains("machine cache.example login narjar password "));
    assert!(netrc_text.contains(write_token_text.trim()));
    assert_eq!(
        fs::read_to_string(cache_path.join("nix-cache-info")).expect("cache info should exist"),
        "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 17\n"
    );
    let descriptor =
        fs::read_to_string(cache_path.join(".narjar-layout")).expect("layout should exist");
    assert!(
        descriptor.contains(&format!("backend={backend}\n")),
        "{descriptor}"
    );
    for path in [
        &secret_key,
        &write_token,
        &read_token,
        &netrc,
        &credentials_dir,
    ] {
        assert_private_path(path);
    }
    assert!(!cache_path.join("producer.sec").exists());

    let server = RunningServer::start_with_existing_path(
        cache_path,
        setup_root,
        &["--storage-backend", backend],
    );
    assert!(
        server
            .startup_line
            .starts_with("listening http://127.0.0.1:"),
        "setup output should be directly servable: {:?}",
        server.startup_line
    );
}

#[test]
fn setup_refuses_existing_destinations_before_creating_the_other_one() {
    let parent = data_dir("setup-conflict");
    let existing_credentials = parent.path().join("credentials");
    fs::create_dir(&existing_credentials).expect("preexisting credentials directory");
    fs::write(existing_credentials.join("keep"), b"do not change")
        .expect("write protected fixture");
    let new_data_dir = parent.path().join("cache");

    let output = run(&[
        "setup",
        "--data-dir",
        new_data_dir.to_str().expect("data path should be UTF-8"),
        "--credentials-dir",
        existing_credentials
            .to_str()
            .expect("credentials path should be UTF-8"),
        "--cache-url",
        "https://cache.example",
        "--yes",
    ]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("setup destination already exists"),
        "expected an explicit destination conflict: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !new_data_dir.exists(),
        "conflict must be found before mutation"
    );
    assert_eq!(
        fs::read(existing_credentials.join("keep")).expect("existing file should remain"),
        b"do not change"
    );
}

#[test]
fn inventory_scan_recognizes_formats_and_keeps_trusted_references() {
    use crate::cache::{
        inventory::{Inventory, InventoryClass as Class, VerificationMode as Mode},
        narinfo::TrustedPublicKeys,
        storage::Directory,
    };
    let mut xz = Vec::new();
    let mut writer = XzWriter::new(&mut xz, XzOptions::with_preset(1)).unwrap();
    writer.write_all(NAR_BYTES).unwrap();
    writer.finish().unwrap();
    let mut zstd = Vec::new();
    compress(
        std::io::Cursor::new(NAR_BYTES),
        &mut zstd,
        CompressionLevel::Fastest,
    );

    for (suffix, bytes) in [
        (".nar", NAR_BYTES.to_vec()),
        (".nar.xz", xz),
        (".nar.zst", zstd),
    ] {
        let directory = TempDir::new().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("nar")).unwrap();
        let key_path = root.join("trusted-public-keys");
        write_test_trusted_public_keys(&key_path);
        let root_directory = Directory::open(root).unwrap();
        let trusted = TrustedPublicKeys::load(&root_directory).unwrap();
        let hash = nix32_sha256(&bytes);
        let metadata = match suffix {
            ".nar" => signed_narinfo(&hash, NAR_BYTES.len() as u64),
            ".nar.xz" => signed_xz_narinfo(
                &hash,
                NARJAR_HASH,
                NAR_BYTES.len() as u64,
                bytes.len() as u64,
            ),
            ".nar.zst" => signed_zstd_narinfo(
                &hash,
                NARJAR_HASH,
                NAR_BYTES.len() as u64,
                bytes.len() as u64,
            ),
            _ => unreachable!(),
        };
        let payload = root.join(format!("nar/{hash}{suffix}"));
        let narinfo = root.join(format!("{STORE_HASH}.narinfo"));
        fs::write(&payload, &bytes).unwrap();
        let canonical_raw = root.join(format!("nar/{NARJAR_HASH}.nar"));
        if suffix != ".nar" {
            fs::write(&canonical_raw, NAR_BYTES).unwrap();
        }
        fs::write(&narinfo, &metadata).unwrap();
        let scan = |mode| {
            Inventory::scan(&root_directory, &trusted, mode)
                .unwrap()
                .entries()
                .iter()
                .map(|entry| (entry.class(), entry.identifier().to_owned()))
                .collect::<Vec<_>>()
        };
        let assert_metadata_trusted = |expected| {
            assert_eq!(
                Inventory::can_serve_streaming(&root_directory, &trusted).unwrap(),
                expected
            );
        };
        assert_metadata_trusted(true);
        assert_eq!(
            scan(Mode::Content),
            [(Class::ValidPair, STORE_HASH.into())],
            "{suffix}"
        );

        fs::write(&payload, vec![0; bytes.len()]).unwrap();
        assert_metadata_trusted(true);
        assert_eq!(
            scan(Mode::Availability),
            [(Class::ValidPair, STORE_HASH.into())]
        );
        assert_eq!(
            scan(Mode::Content),
            [(Class::HashOrSizeMismatch, STORE_HASH.into())]
        );
        fs::write(&payload, b"x").unwrap();
        assert_eq!(
            scan(Mode::Availability),
            [(Class::HashOrSizeMismatch, STORE_HASH.into())]
        );
        fs::remove_file(&payload).unwrap();
        assert_metadata_trusted(true);
        assert_eq!(
            scan(Mode::Content),
            [(Class::MissingNar, STORE_HASH.into())]
        );

        // References remain object-ID based even when the requested encoding is absent.
        let alternate_suffix = if suffix == ".nar" { ".nar.xz" } else { ".nar" };
        let alternate = root.join(format!("nar/{hash}{alternate_suffix}"));
        fs::write(&alternate, &bytes).unwrap();
        assert_eq!(
            scan(Mode::Content),
            [(Class::MissingNar, STORE_HASH.into())]
        );
        fs::remove_file(alternate).unwrap();

        fs::write(&payload, &bytes).unwrap();
        if suffix != ".nar" {
            fs::write(&canonical_raw, vec![0; NAR_BYTES.len()]).unwrap();
            assert_eq!(
                scan(Mode::Availability),
                [(Class::ValidPair, STORE_HASH.into())]
            );
            assert_eq!(
                scan(Mode::Content),
                [(Class::HashOrSizeMismatch, STORE_HASH.into())]
            );
            fs::write(&canonical_raw, b"x").unwrap();
            assert_eq!(
                scan(Mode::Availability),
                [(Class::HashOrSizeMismatch, STORE_HASH.into())]
            );
            fs::remove_file(&canonical_raw).unwrap();
            assert_eq!(
                scan(Mode::Content),
                [(Class::MissingNar, STORE_HASH.into())]
            );
            fs::write(&canonical_raw, NAR_BYTES).unwrap();
        }
        fs::write(
            &narinfo,
            metadata.replace("Sig: narjar-test:", "Sig: unknown:"),
        )
        .unwrap();
        assert_metadata_trusted(false);
        let mut expected = vec![
            (Class::OrphanNar, hash.clone()),
            (Class::UntrustedSignature, STORE_HASH.into()),
        ];
        if suffix != ".nar" {
            expected.push((Class::OrphanNar, NARJAR_HASH.into()));
        }
        expected.sort();
        assert_eq!(scan(Mode::Content), expected);
        fs::write(&narinfo, b"malformed\n").unwrap();
        assert_metadata_trusted(false);
        let mut expected = vec![
            (Class::OrphanNar, hash.clone()),
            (Class::MalformedNarInfo, STORE_HASH.into()),
        ];
        if suffix != ".nar" {
            expected.push((Class::OrphanNar, NARJAR_HASH.into()));
        }
        expected.sort();
        assert_eq!(scan(Mode::Content), expected);
        fs::remove_file(&narinfo).unwrap();
        assert_metadata_trusted(true);
        let mut expected = vec![(Class::OrphanNar, hash)];
        if suffix != ".nar" {
            expected.push((Class::OrphanNar, NARJAR_HASH.into()));
        }
        expected.sort();
        assert_eq!(scan(Mode::Content), expected);
    }
}

#[test]
fn metadata_readiness_ignores_unrelated_names_without_opening_payload_directory() {
    use crate::cache::{inventory::Inventory, narinfo::TrustedPublicKeys, storage::Directory};
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let trusted = TrustedPublicKeys::default();
    fs::write(root.join("unrelated"), b"ignored").unwrap();
    fs::write(root.join("bad.narinfo"), b"ignored").unwrap();
    // Readiness neither requires nor opens a payload directory.
    fs::write(root.join("nar"), b"not a directory").unwrap();
    let root_directory = Directory::open(root).unwrap();
    assert!(Inventory::can_serve_streaming(&root_directory, &trusted).unwrap());

    let metadata = root.join(format!("{STORE_HASH}.narinfo"));
    fs::create_dir(&metadata).unwrap();
    assert!(!Inventory::can_serve_streaming(&root_directory, &trusted).unwrap());
    fs::remove_dir(&metadata).unwrap();
    symlink(root.join("unrelated"), &metadata).unwrap();
    assert!(!Inventory::can_serve_streaming(&root_directory, &trusted).unwrap());
}

#[test]
fn metadata_readiness_remains_false_after_any_invalid_narinfo() {
    use crate::cache::{inventory::Inventory, narinfo::TrustedPublicKeys, storage::Directory};

    const OTHER_STORE_HASH: &str = "11111111111111111111111111111111";
    let trusted = TrustedPublicKeys::parse(&format!(
        "narjar-test:{}\n",
        BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
    ))
    .unwrap();
    let valid = signed_narinfo_for(OTHER_STORE_HASH, NARJAR_HASH, NAR_BYTES.len() as u64);

    for entries in [
        [
            (format!("{STORE_HASH}.narinfo"), "malformed\n".to_owned()),
            (format!("{OTHER_STORE_HASH}.narinfo"), valid.clone()),
        ],
        [
            (format!("{OTHER_STORE_HASH}.narinfo"), valid.clone()),
            (format!("{STORE_HASH}.narinfo"), "malformed\n".to_owned()),
        ],
    ] {
        let directory = TempDir::new().unwrap();
        for (name, contents) in entries {
            fs::write(directory.path().join(name), contents).unwrap();
        }
        let root = Directory::open(directory.path()).unwrap();
        assert!(!Inventory::can_serve_streaming(&root, &trusted).unwrap());
    }
}

#[test]
fn inventory_and_trust_keep_using_the_directory_opened_by_run() {
    use crate::cache::{
        inventory::{Inventory, InventoryClass, VerificationMode},
        narinfo::TrustedPublicKeys,
        storage::Directory,
    };
    let directory = TempDir::new().unwrap();
    let root = directory.path().join("cache");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nar")).unwrap();
    write_test_trusted_public_keys(root.join("trusted-public-keys"));
    fs::write(root.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES).unwrap();
    fs::write(
        root.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .unwrap();

    let opened_root = Directory::open(&root).unwrap();
    fs::rename(&root, directory.path().join("moved-cache")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nar")).unwrap();
    fs::write(root.join("trusted-public-keys"), []).unwrap();

    let trusted = TrustedPublicKeys::load(&opened_root).unwrap();
    let inventory = Inventory::scan(&opened_root, &trusted, VerificationMode::Content).unwrap();
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.entries()[0].class(), InventoryClass::ValidPair);
}

#[test]
fn inventory_scan_classifies_names_and_files_before_inspection() {
    use crate::cache::{
        inventory::{Inventory, InventoryClass as Class, VerificationMode},
        narinfo::TrustedPublicKeys,
        storage::Directory,
    };
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("nar")).unwrap();
    fs::write(root.join("unrelated"), b"ignored").unwrap();
    fs::write(root.join("bad.narinfo"), b"invalid name").unwrap();
    fs::create_dir(root.join(format!("{STORE_HASH}.narinfo"))).unwrap();
    let symlink_store = "1".repeat(32);
    symlink(
        root.join("unrelated"),
        root.join(format!("{symlink_store}.narinfo")),
    )
    .unwrap();
    let malformed_store = "2".repeat(32);
    fs::write(
        root.join(format!("{malformed_store}.narinfo")),
        b"malformed",
    )
    .unwrap();
    fs::write(root.join("nar/bad.nar"), []).unwrap();
    let unreadable_orphan = root.join(format!("nar/{NARJAR_HASH}.nar.xz"));
    fs::write(&unreadable_orphan, b"discovery does not read contents").unwrap();
    let _unreadable = deny_fixture_data_reads(&unreadable_orphan);
    fs::write(root.join(format!("nar/{NAR_ID}.unknown")), []).unwrap();
    fs::create_dir(root.join(format!("nar/{NAR_ID}.nar"))).unwrap();
    symlink(
        root.join("unrelated"),
        root.join(format!("nar/{NAR_ID}.nar.zst")),
    )
    .unwrap();
    let inventory = Inventory::scan(
        &Directory::open(root).unwrap(),
        &TrustedPublicKeys::default(),
        VerificationMode::Content,
    )
    .unwrap();
    let actual = inventory
        .entries()
        .iter()
        .map(|entry| (entry.class(), entry.identifier().to_owned()))
        .collect::<Vec<_>>();
    let mut expected = vec![
        (Class::OrphanNar, NARJAR_HASH.into()),
        (Class::MalformedNarInfo, STORE_HASH.into()),
        (Class::MalformedNarInfo, symlink_store),
        (Class::MalformedNarInfo, malformed_store),
        (Class::InvalidFilename, "bad.narinfo".into()),
        (Class::InvalidFilename, "bad.nar".into()),
        (Class::InvalidFilename, format!("{NAR_ID}.unknown")),
        (Class::InvalidFilename, format!("{NAR_ID}.nar")),
        (Class::InvalidFilename, format!("{NAR_ID}.nar.zst")),
    ];
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn inventory_scan_propagates_payload_open_errors() {
    use crate::cache::{
        inventory::{Inventory, VerificationMode},
        narinfo::TrustedPublicKeys,
        storage::Directory,
    };
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("nar")).unwrap();
    let key_path = root.join("trusted-public-keys");
    write_test_trusted_public_keys(&key_path);
    let root_directory = Directory::open(root).unwrap();
    let trusted = TrustedPublicKeys::load(&root_directory).unwrap();
    fs::write(
        root.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .unwrap();
    let payload = root.join(format!("nar/{NARJAR_HASH}.nar"));
    fs::write(&payload, NAR_BYTES).unwrap();
    let _unreadable = deny_fixture_data_reads(&payload);
    let expected = crate::cache::filesystem::open_regular(&payload)
        .unwrap_err()
        .raw_os_error();
    for mode in [VerificationMode::Availability, VerificationMode::Content] {
        let error = Inventory::scan(&root_directory, &trusted, mode).unwrap_err();
        assert_eq!(error.raw_os_error(), expected);
    }
}

#[test]
fn reconcile_and_verify_classify_operator_findings() {
    let data_dir = init_data_dir("operator-verify");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));

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
    fs::write(
        data_dir.join(format!("nar/{NAR_ID}.nar.zst")),
        b"compressed NAR",
    )
    .expect("zstd NAR should be written");
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
    assert_structural_json_entry(&report, "temp_young", ".tmp/nar-young.part", "inspect");
    for path in [
        ".tmp/cache-info-young.part",
        "nar/.tmp/nar-young.part",
        "realisations/.tmp/realisation-young.part",
    ] {
        assert_structural_json_entry(&report, "temp_young", path, "inspect");
    }
    assert_structural_json_entry(&report, "invalid_filename", ".tmp/not-a-temp", "inspect");
    assert_structural_json_entry(
        &report,
        "unexpected_type",
        ".tmp/nar-directory.part",
        "inspect",
    );
    assert_structural_json_entry(
        &report,
        "nar_object",
        &format!("nar/{NAR_ID}.nar.zst"),
        "inspect",
    );
}

fn assert_structural_json_entry(report: &str, class: &str, path: &str, action: &str) {
    let entry = report
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|record| {
            record["class"] == class
                && record["action"] == action
                && record["path"].as_str().map(Path::new) == Some(Path::new(path))
        })
        .unwrap_or_else(|| panic!("missing {class} {action} for {path}: {report}"));
    assert_eq!(entry.as_object().unwrap().len(), 3);
}

#[test]
fn read_through_doctor_checks_trusted_keys_without_contacting_an_upstream() {
    let data_dir = init_data_dir("read-through-doctor-trust");
    let path = data_dir.to_str().unwrap();
    for contents in ["", "not-a-public-key\n"] {
        fs::write(data_dir.join("trusted-public-keys"), contents).unwrap();
        let output = run(&[
            "doctor",
            "--data-dir",
            path,
            "--serve-source",
            "read-through",
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(1), "{contents:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["source"]["name"], "read-through");
        assert_eq!(report["source"]["severity"], "error");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("not-a-public-key"));
    }
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    let output = run(&[
        "doctor",
        "--data-dir",
        path,
        "--serve-source",
        "read-through",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"]["name"], "read-through");
    assert_eq!(report["source"]["severity"], "ok");
}

#[test]
fn doctor_returns_failure_for_invalid_layout() {
    let data_dir = init_data_dir("operator-doctor-failure");
    fs::remove_file(data_dir.join("trusted-public-keys"))
        .expect("required trust file should be removed");
    let path = data_dir.to_str().expect("temporary path should be UTF-8");

    let output = run(&["doctor", "--data-dir", path, "--json"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"severity\":\"error\""));
    assert!(String::from_utf8_lossy(&output.stderr).contains("doctor found errors"));
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
    assert_structural_json_entry(&report, "temp_stale", ".tmp/nar-stale.part", "deleted");
    assert_structural_json_entry(&report, "unknown_file", "unknown-file", "kept");
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
    assert_clean_shutdown(signal, status);
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
        "narjar_http_upload_declared_bytes_total",
        "narjar_http_upload_received_bytes_total",
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

    let (metrics_headers, metrics_body) = response_parts(&server.request("GET", "/metrics"));
    assert!(
        metrics_headers.starts_with("HTTP/1.1 200"),
        "{metrics_headers}"
    );
    assert!(metrics_headers.contains("Content-Type: text/plain"));
    assert!(metrics_headers.contains("Cache-Control: no-store"));
    let metrics = String::from_utf8(metrics_body).expect("metrics should be UTF-8");
    assert!(metrics.contains("narjar_cache_lookup_outcomes_total"));
    assert!(metrics.contains("narjar_ready 1"));
    let (removed_stats_headers, _) = response_parts(&server.request("GET", "/stats"));
    assert!(removed_stats_headers.starts_with("HTTP/1.1 404"));
    let (head_headers, head_body) = response_parts(&server.request("HEAD", "/main/metrics"));
    assert!(head_headers.starts_with("HTTP/1.1 200"), "{head_headers}");
    assert!(head_headers.contains("Content-Length:"));
    assert!(head_body.is_empty());

    let url = format!("http://{}", server.address);
    let stats = run(&["stats", "--url", &url]);
    assert!(
        stats.status.success(),
        "stats failed: {}",
        String::from_utf8_lossy(&stats.stderr)
    );
    assert!(String::from_utf8_lossy(&stats.stdout).contains("narjar_ready 1"));
    assert!(String::from_utf8_lossy(&stats.stdout).contains("narjar_cache_lookup_outcomes_total"));

    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
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
    assert_clean_shutdown(signal, status);
}

#[test]
fn metrics_keep_the_last_capacity_sample_when_the_payload_directory_is_unavailable() {
    let server = RunningServer::start("metrics-cached-capacity");
    let (_, first) = response_parts(&server.request("GET", "/metrics"));
    let first = String::from_utf8(first).unwrap();
    assert!(first.contains("narjar_storage_capacity_sample_state{state=\"measured\"} 1\n"));
    assert!(first.contains("narjar_storage_capacity_bytes{kind=\"available\"} "));

    // Break future descriptor-relative capacity probes without touching the
    // server's cached observation or any production cache.
    let payloads = server.data_dir.join("nar");
    let parked = server.data_dir.join("parked-nar");
    fs::rename(&payloads, &parked).unwrap();
    let (headers, body) = response_parts(&server.request("GET", "/metrics"));
    let (ready, _) = response_parts(&server.request("GET", "/readyz"));
    fs::rename(&parked, &payloads).unwrap();
    let (signal, status) = server.stop();

    assert_clean_shutdown(signal, status);
    assert_http_status_line(&headers, "200 OK");
    assert_http_status_line(&ready, "503 Service Unavailable");
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("narjar_storage_capacity_bytes{kind=\"available\"} "));
    assert!(body.contains("narjar_storage_capacity_sample_timestamp_seconds "));
}

#[test]
fn readiness_fails_without_affecting_liveness_when_space_is_reserved() {
    let server = RunningServer::start_with_args(
        "operator-not-ready",
        &["--min-free-bytes", "18446744073709551615"],
    );

    let health = response_parts(&server.request("GET", "/healthz")).0;
    let (ready, reason) = response_parts(&server.request("GET", "/readyz"));
    let (_, metrics_body) = response_parts(&server.request("GET", "/metrics"));
    let metrics = String::from_utf8(metrics_body).expect("metrics should be UTF-8");
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(ready.starts_with("HTTP/1.1 503"), "{ready}");
    assert_eq!(reason, b"insufficient_space\n");
    assert!(metrics.contains("narjar_ready 0"));

    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn restored_cache_verifies_before_serving() {
    let source = init_data_dir("backup-source");
    write_test_trusted_public_keys(source.join("trusted-public-keys"));
    fs::write(source.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        source.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("narinfo should be written");

    let restored = init_data_dir("backup-restored");
    for relative in [
        ".narjar-clean",
        ".narjar-layout",
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
    assert!(
        signal.is_ok(),
        "restored server should receive a shutdown request"
    );
    assert!(status.success(), "restored server should shut down cleanly");
}

#[test]
fn dirty_start_rejects_a_malformed_published_narinfo() {
    let data_dir = init_data_dir("dirty-start-malformed-narinfo");
    fs::remove_file(data_dir.join(".narjar-clean")).expect("clean marker should exist");
    let recovery = data_dir.join(".narjar-recovery");
    fs::write(&recovery, b"").expect("recovery marker should be created");
    crate::cache::test_support::make_private_file(&recovery)
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
        String::from_utf8_lossy(&output.stderr)
            .contains("published inventory contains an invalid narinfo/NAR pair"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("recovery required; checking published narinfo references"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        data_dir.join(".narjar-recovery").exists(),
        "failed recovery must retain its marker"
    );
}

#[test]
fn gc_recovers_a_published_nar_before_eviction_and_restart() {
    let data_dir = init_data_dir("gc-recovers-before-eviction");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("published NAR should be written");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("signed narinfo should be written");
    let staging = data_dir.join(".tmp/gc-pending.part");
    fs::write(&staging, b"transaction staging").expect("staging should be written");
    let transaction = data_dir.join(".narjar-transactions/gc-pending.txn");
    fs::write(
        &transaction,
        published_transaction_bytes(".tmp/gc-pending.part", &format!("nar/{NARJAR_HASH}.nar")),
    )
    .expect("published transaction should be written");
    crate::cache::test_support::make_private_file(&transaction)
        .expect("transaction should be private");
    let recovery_marker = data_dir.join(".narjar-recovery");
    fs::write(&recovery_marker, b"interrupted\n").expect("recovery marker should be written");
    crate::cache::test_support::make_private_file(&recovery_marker)
        .expect("recovery marker should be private");

    let output = run(&[
        "gc",
        "--data-dir",
        data_dir.to_str().expect("data dir should be UTF-8"),
        "--target-bytes",
        "0",
        "--apply",
    ]);
    assert!(
        output.status.success(),
        "GC failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
    assert!(!data_dir.join(format!("nar/{NARJAR_HASH}.nar")).exists());
    assert!(
        !transaction.exists(),
        "recovery journal should be completed"
    );
    assert!(!staging.exists(), "recovery staging should be removed");
    assert!(
        !recovery_marker.exists(),
        "recovery marker should be cleared"
    );

    let root = crate::cache::storage::Directory::open(data_dir.path())
        .expect("cache root should reopen after GC");
    let storage = crate::cache::storage::CacheCreation::prepare(
        &root,
        crate::cache::storage::SupportedStorageBackend::FLAT,
    )
    .and_then(|creation| creation.create_or_complete())
    .expect("cache storage should restart after GC");
    assert!(
        !storage
            .recovery_required()
            .expect("recovery state should read"),
        "restart must not find a pending transaction whose destination GC evicted"
    );
}

#[test]
fn delete_recovers_a_published_narinfo_before_removing_it() {
    let data_dir = init_data_dir("delete-recovers-before-removal");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("published NAR should be written");
    let narinfo = data_dir.join(format!("{STORE_HASH}.narinfo"));
    fs::write(
        &narinfo,
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("signed narinfo should be written");
    let staging = data_dir.join(".tmp/delete-pending.part");
    fs::write(&staging, b"transaction staging").expect("staging should be written");
    let transaction = data_dir.join(".narjar-transactions/delete-pending.txn");
    fs::write(
        &transaction,
        published_transaction_bytes(".tmp/delete-pending.part", &format!("{STORE_HASH}.narinfo")),
    )
    .expect("published transaction should be written");
    crate::cache::test_support::make_private_file(&transaction)
        .expect("transaction should be private");
    let recovery_marker = data_dir.join(".narjar-recovery");
    fs::write(&recovery_marker, b"interrupted\n").expect("recovery marker should be written");
    crate::cache::test_support::make_private_file(&recovery_marker)
        .expect("recovery marker should be private");

    let output = run(&[
        "delete",
        "--data-dir",
        data_dir.to_str().expect("data dir should be UTF-8"),
        "--store-hash",
        STORE_HASH,
    ]);
    assert!(
        output.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !narinfo.exists(),
        "delete should remove the selected metadata"
    );
    assert!(
        data_dir.join(format!("nar/{NARJAR_HASH}.nar")).exists(),
        "delete should retain the payload"
    );
    assert!(
        !transaction.exists(),
        "recovery journal should be completed"
    );
    assert!(!staging.exists(), "recovery staging should be removed");
    assert!(
        !recovery_marker.exists(),
        "recovery marker should be cleared"
    );

    let root = crate::cache::storage::Directory::open(data_dir.path())
        .expect("cache root should reopen after delete");
    let storage = crate::cache::storage::CacheCreation::prepare(
        &root,
        crate::cache::storage::SupportedStorageBackend::FLAT,
    )
    .and_then(|creation| creation.create_or_complete())
    .expect("cache storage should restart after delete");
    assert!(
        !storage
            .recovery_required()
            .expect("recovery state should read"),
        "restart must not find a pending transaction whose destination delete removed"
    );
}

#[test]
fn dirty_start_rejects_a_published_narinfo_without_its_nar() {
    let data_dir = init_data_dir("dirty-start-missing-nar");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::remove_file(data_dir.join(".narjar-clean")).expect("clean marker should be removed");
    let recovery = data_dir.join(".narjar-recovery");
    fs::write(&recovery, b"").expect("recovery marker should be created");
    crate::cache::test_support::make_private_file(&recovery)
        .expect("recovery marker should be private");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("signed narinfo should be written");

    let output = run(&[
        "serve",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--listen",
        "127.0.0.1:0",
    ]);
    assert!(!output.status.success(), "dirty start must fail closed");
    assert!(
        data_dir.join(".narjar-recovery").exists(),
        "failed recovery must retain its marker"
    );
}

#[test]
fn dirty_start_checks_payload_availability_without_hashing_it() {
    let data_dir = init_data_dir("dirty-start-availability");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64),
    )
    .expect("signed narinfo should be written");
    fs::write(
        data_dir.join(format!("nar/{NARJAR_HASH}.nar")),
        vec![b'x'; NAR_BYTES.len()],
    )
    .expect("same-sized payload should be written");
    let recovery = data_dir.join(".narjar-recovery");
    fs::write(&recovery, b"").expect("recovery marker should be created");
    crate::cache::test_support::make_private_file(&recovery)
        .expect("recovery marker should be private");
    let server = RunningServer::start_in(data_dir, &[]);
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn dirty_start_rejects_a_published_narinfo_with_the_wrong_nar_size() {
    let data_dir = init_data_dir("dirty-start-wrong-nar-size");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("NAR should be written");
    fs::write(
        data_dir.join(format!("{STORE_HASH}.narinfo")),
        signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64 + 1),
    )
    .expect("signed narinfo should be written");
    fs::remove_file(data_dir.join(".narjar-clean")).expect("clean marker should be removed");
    let recovery = data_dir.join(".narjar-recovery");
    fs::write(&recovery, b"").expect("recovery marker should be created");
    crate::cache::test_support::make_private_file(&recovery)
        .expect("recovery marker should be private");

    let output = run(&[
        "serve",
        "--data-dir",
        data_dir.to_str().expect("temporary path should be UTF-8"),
        "--listen",
        "127.0.0.1:0",
    ]);
    assert!(!output.status.success(), "dirty start must fail closed");
    assert!(
        data_dir.join(".narjar-recovery").exists(),
        "failed recovery must retain its marker"
    );
}

#[test]
fn gc_dry_run_preserves_and_apply_removes_old_pair() {
    let data_dir = init_data_dir("operator-gc");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
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
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
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
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
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
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
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
fn interrupted_gc_deletion_is_recovered_before_serving_shared_payloads() {
    let data_dir = init_data_dir("operator-gc-interrupted-deletion");
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("shared NAR should be written");
    for index in 0..2 {
        let store = format!("{index:032o}");
        fs::write(
            data_dir.join(format!("{store}.narinfo")),
            signed_narinfo_for(&store, NARJAR_HASH, NAR_BYTES.len() as u64),
        )
        .expect("narinfo should be written");
    }

    // State after syncing one metadata deletion, before completing GC.
    fs::remove_file(data_dir.join(format!("{STORE_HASH}.narinfo")))
        .expect("first metadata entry should be deleted");
    let marker = data_dir.join(".narjar-recovery");
    fs::write(&marker, b"").expect("GC recovery marker should be written");
    crate::cache::test_support::make_private_file(marker)
        .expect("GC recovery marker should be private");

    let server = RunningServer::start_in(data_dir, &[]);
    assert!(
        !server.data_dir.join(".narjar-recovery").exists(),
        "server recovery should clear the marker after a valid inventory"
    );
    let (ready, _) = response_parts(&server.request("GET", "/readyz"));
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
    let (metadata, _) =
        response_parts(&server.request("GET", "/00000000000000000000000000000001.narinfo"));
    assert!(metadata.starts_with("HTTP/1.1 200"), "{metadata}");
    let (payload, bytes) =
        response_parts(&server.request("GET", &format!("/nar/{NARJAR_HASH}.nar")));
    assert!(payload.starts_with("HTTP/1.1 200"), "{payload}");
    assert_eq!(bytes, NAR_BYTES);
    let (signal, status) = server.stop();
    assert_clean_shutdown(signal, status);
}

#[test]
fn gc_reclaims_old_orphan_nars() {
    let data_dir = init_data_dir("operator-gc-orphan");
    fs::write(data_dir.join(".tmp/incomplete"), b"temp")
        .expect("temporary entry should be written");
    fs::write(data_dir.join(format!("nar/{NAR_ID}.nar")), b"orphan")
        .expect("orphan NAR should be written");
    fs::write(
        data_dir.join(format!("nar/{NARJAR_HASH}.nar.zst")),
        b"zstd orphan",
    )
    .expect("zstd orphan NAR should be written");
    fs::write(
        data_dir
            .join(".narjar-validation")
            .join(format!("{NARJAR_HASH}.nar.zst.validation")),
        b"stale evidence",
    )
    .expect("zstd orphan evidence should be written");

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
    assert!(
        !data_dir
            .join(".narjar-validation")
            .join(format!("{NARJAR_HASH}.nar.zst.validation"))
            .exists()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"deleted_orphans\":2"));
    assert!(stdout.contains("\"temporary\":1"));
    assert!(stdout.contains("\"orphaned_bytes\":17"));
    assert!(stdout.contains("\"temporary_bytes\":4"));
}

#[test]
fn gc_dry_run_and_apply_agree_on_partial_orphan_cleanup() {
    let data_dir = init_data_dir("operator-gc-retained-orphan");
    let retained_orphan_nar = "1".repeat(52);
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
    fs::write(data_dir.join(format!("nar/{NAR_ID}.nar")), b"old-orphan")
        .expect("old orphan should be written");
    fs::write(
        data_dir.join(format!("nar/{retained_orphan_nar}.nar")),
        b"new-orphan",
    )
    .expect("new orphan should be written");

    // Explicit timestamps order the orphans without depending on scheduler delays.
    for (name, seconds) in [(NAR_ID, 1), (retained_orphan_nar.as_str(), 2)] {
        crate::cache::test_support::set_fixture_modified_time(
            data_dir.join(format!("nar/{name}.nar")),
            std::time::UNIX_EPOCH + Duration::from_secs(seconds),
        )
        .unwrap();
    }
    let narinfo = signed_narinfo(NARJAR_HASH, NAR_BYTES.len() as u64);
    let narinfo_bytes = narinfo.len() as u64;
    fs::write(data_dir.join(format!("{STORE_HASH}.narinfo")), narinfo)
        .expect("published narinfo should be written");
    fs::write(data_dir.join(format!("nar/{NARJAR_HASH}.nar")), NAR_BYTES)
        .expect("published NAR should be written");

    let published_bytes = narinfo_bytes + NAR_BYTES.len() as u64;
    let retained_orphan_bytes = b"new-orphan".len() as u64;
    let target_bytes = published_bytes + retained_orphan_bytes;
    let roots = data_dir.join("protected-roots");
    fs::write(&roots, format!("/nix/store/{STORE_HASH}-narjar\n")).unwrap();
    let path = data_dir.to_str().expect("temporary path should be UTF-8");
    let dry_run = command()
        .args(["gc", "--data-dir", path, "--target-bytes"])
        .arg(target_bytes.to_string())
        .args(["--min-age-seconds", "0", "--protected-roots"])
        .arg(&roots)
        .arg("--json")
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
        .args(["--min-age-seconds", "0", "--protected-roots"])
        .arg(&roots)
        .args(["--apply", "--json"])
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
    write_test_trusted_public_keys(data_dir.join("trusted-public-keys"));
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
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("malformed_narinfo"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(data_dir.join(format!("{STORE_HASH}.narinfo")).exists());
}

#[test]
fn library_gc_requires_the_same_private_policies_as_startup_before_either_mode() {
    let data_dir = init_data_dir("library-gc-required-policies");
    let collect = |mode| {
        crate::cache::storage::gc::run(
            data_dir.path(),
            GcOptions {
                retention: Default::default(),
                max_bytes: None,
                target_bytes: Some(0),
                max_age: None,
                min_age: Duration::ZERO,
                protected_roots: Default::default(),
                mode,
                backend: crate::cache::storage::StorageBackend::Flat,
            },
        )
    };
    let clean = data_dir.join(".narjar-clean");
    let original_marker = fs::read(&clean).unwrap();
    for name in crate::cache::storage::CACHE_POLICY_FILES {
        let path = data_dir.join(name);
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        for mode in [GcMode::DryRun, GcMode::Apply] {
            assert!(collect(mode).is_err(), "{mode:?} accepted missing {name}");
            assert!(!path.exists(), "GC must not recreate {name}");
            assert_eq!(fs::read(&clean).unwrap(), original_marker);
            assert!(!data_dir.join(".narjar-recovery").exists());
        }
        fs::write(&path, original).unwrap();
        crate::cache::test_support::make_public_file(&path).unwrap();
        for mode in [GcMode::DryRun, GcMode::Apply] {
            assert!(
                collect(mode).is_err(),
                "{mode:?} accepted non-private {name}"
            );
            assert_eq!(fs::read(&clean).unwrap(), original_marker);
            assert!(!data_dir.join(".narjar-recovery").exists());
        }
        crate::cache::test_support::make_private_file(path).unwrap();
    }
    for mode in [GcMode::DryRun, GcMode::Apply] {
        assert!(
            collect(mode).is_ok(),
            "{mode:?} should accept complete private policies"
        );
    }
}

#[test]
fn library_gc_dry_run_preserves_pending_recovery_state() {
    let data_dir = init_data_dir("library-gc-dry-run-recovery");
    let staging = data_dir.join(".tmp/gc-pending.part");
    fs::write(&staging, b"pending publication staging")
        .expect("transaction staging should be written");
    let transaction = data_dir.join(".narjar-transactions/gc-pending.txn");
    fs::write(
        &transaction,
        published_transaction_bytes(".tmp/gc-pending.part", "nix-cache-info"),
    )
    .expect("published transaction should be written");
    crate::cache::test_support::make_private_file(&transaction)
        .expect("transaction should be private");
    let recovery_marker = data_dir.join(".narjar-recovery");
    fs::write(&recovery_marker, b"interrupted\n").expect("recovery marker should be written");
    crate::cache::test_support::make_private_file(&recovery_marker)
        .expect("recovery marker should be private");

    let report = crate::cache::storage::gc::run(
        data_dir.path(),
        GcOptions {
            retention: Default::default(),
            max_bytes: None,
            target_bytes: Some(0),
            max_age: None,
            min_age: Duration::ZERO,
            protected_roots: Default::default(),
            mode: GcMode::DryRun,
            backend: crate::cache::storage::StorageBackend::Flat,
        },
    )
    .expect("library dry-run should inspect without completing recovery");

    assert!(report.dry_run);
    assert!(transaction.exists(), "dry-run must preserve the journal");
    assert!(
        staging.exists(),
        "dry-run must preserve transaction staging"
    );
    assert!(
        recovery_marker.exists(),
        "dry-run must preserve the recovery marker"
    );
}
