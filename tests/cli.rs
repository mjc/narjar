use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, SystemTime},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_narjar"))
        .args(args)
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
fn serve_reports_listener_and_stops_on_sigterm() {
    let data_dir = data_dir("lifecycle");
    let mut child = Command::new(env!("CARGO_BIN_EXE_narjar"))
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
    assert!(
        first_line.starts_with("listening http://127.0.0.1:"),
        "unexpected startup line: {first_line:?}"
    );

    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill should run");
    assert!(signal.success(), "SIGTERM should be sent");

    for _ in 0..100 {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            fs::remove_dir(data_dir).expect("test data directory should be removed");
            assert!(
                status.success(),
                "narjar should shut down cleanly: {status}"
            );
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }

    child.kill().expect("hung child should be killed");
    let _ = child.wait();
    let _ = fs::remove_dir_all(data_dir);
    panic!("narjar did not stop after SIGTERM");
}
