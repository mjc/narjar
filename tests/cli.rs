use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Output, Stdio},
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
    fs::remove_dir(data_dir).expect("test data directory should be removed");

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
    fs::remove_dir(data_dir).expect("test data directory should be removed");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        "narjar: --workers must be greater than zero\n"
    );
}

#[test]
fn serve_rejects_zero_workers_from_environment() {
    let missing = data_dir("environment-zero-workers");
    fs::remove_dir(&missing).expect("test data directory should be removed");
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
    fs::remove_dir(&missing).expect("test data directory should be removed");
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
    fs::remove_dir(&missing).expect("test data directory should be removed");
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
    fs::remove_dir(&missing).expect("test data directory should be removed");
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
    fs::remove_dir(&missing).expect("test data directory should be removed");
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

#[test]
fn serve_reports_listener_and_stops_on_sigterm() {
    let data_dir = data_dir("lifecycle");
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

    let mut first_line = String::new();
    BufReader::new(child.stdout.take().expect("stdout should be piped"))
        .read_line(&mut first_line)
        .expect("startup line should be readable");

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

    if status.is_none() {
        child.kill().expect("hung child should be killed");
        let _ = child.wait();
    }
    fs::remove_dir(data_dir).expect("test data directory should be removed");

    assert!(signal.success(), "SIGTERM should be sent");
    assert!(
        status.expect("narjar should stop after SIGTERM").success(),
        "narjar should shut down cleanly"
    );
    assert!(
        first_line.starts_with("listening http://127.0.0.1:"),
        "unexpected startup line: {first_line:?}"
    );
    assert!(
        first_line.ends_with(
            " workers=1 max_in_flight=64 max_nar_bytes=17179869184 min_free_bytes=1073741824\n"
        ),
        "startup line omits effective limits: {first_line:?}"
    );
}
