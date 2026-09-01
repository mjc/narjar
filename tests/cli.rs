use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
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
        let data_dir = data_dir(test);
        let mut child = command()
            .args([
                "serve",
                "--data-dir",
                data_dir.to_str().expect("temporary path should be UTF-8"),
                "--listen",
                "127.0.0.1:0",
                "--workers",
                "1",
            ])
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
        let mut stream = TcpStream::connect(&self.address).expect("connect to narjar");
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.address
        )
        .expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        response
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
