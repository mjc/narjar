#![cfg(target_os = "linux")]

use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const NAR_BYTES: &[u8] = b"narjar";
const NAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";

struct Measurement {
    wall_ms: f64,
    peak_rss_kib: u64,
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_narjar"))
}

fn run(command: &mut Command) {
    let output = command.output().expect("narjar should run");
    assert!(
        output.status.success(),
        "narjar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn store_hash(index: usize) -> String {
    format!("{index:032o}")
}

fn signed_narinfo(store_hash: &str) -> String {
    let store_path = format!("/nix/store/{store_hash}-gc-scale");
    let fingerprint = format!("1;{store_path};sha256:{NAR_HASH};{};", NAR_BYTES.len());
    let signature = SigningKey::from_bytes(&[7; 32]).sign(fingerprint.as_bytes());
    format!(
        "StorePath: {store_path}\nURL: nar/{NAR_HASH}.nar\nCompression: none\nFileHash: sha256:{NAR_HASH}\nFileSize: {}\nNarHash: sha256:{NAR_HASH}\nNarSize: {}\nReferences: \nSig: narjar-test:{}\n",
        NAR_BYTES.len(),
        NAR_BYTES.len(),
        BASE64.encode(&signature.to_bytes())
    )
}

fn fixture(paths: usize) -> TempDir {
    let directory = tempfile::tempdir().expect("fixture directory should be created");
    run(command().args([
        "init",
        "--data-dir",
        directory
            .path()
            .to_str()
            .expect("fixture path should be UTF-8"),
    ]));
    fs::write(
        directory.path().join("trusted-public-keys"),
        format!(
            "narjar-test:{}\n",
            BASE64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes())
        ),
    )
    .expect("trusted key should be written");
    if paths != 0 {
        fs::write(
            directory.path().join(format!("nar/{NAR_HASH}.nar")),
            NAR_BYTES,
        )
        .expect("shared NAR should be written");
    }
    for index in 0..paths {
        let store_hash = store_hash(index);
        fs::write(
            directory.path().join(format!("{store_hash}.narinfo")),
            signed_narinfo(&store_hash),
        )
        .expect("narinfo should be written");
    }
    directory
}

fn rss_kib(pid: u32) -> Option<u64> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_ascii_whitespace()
        .next()?
        .parse()
        .ok()
}

fn measure(command: &mut Command) -> Measurement {
    let started = Instant::now();
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("narjar should start");
    let mut peak_rss_kib = rss_kib(child.id()).unwrap_or_default();
    loop {
        peak_rss_kib = peak_rss_kib.max(rss_kib(child.id()).unwrap_or_default());
        if let Some(status) = child.try_wait().expect("narjar should be waitable") {
            assert!(status.success(), "GC command should succeed: {status}");
            return Measurement {
                wall_ms: started.elapsed().as_secs_f64() * 1_000.0,
                peak_rss_kib,
            };
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn gc(data_dir: &Path, paths: usize, operation: &str, arguments: &[&str]) -> Measurement {
    let mut command = command();
    command
        .args(["gc", "--data-dir"])
        .arg(data_dir)
        .args(arguments);
    let measurement = measure(&mut command);
    println!(
        "{{\"paths\":{},\"operation\":\"{operation}\",\"wall_ms\":{:.3},\"peak_rss_kib\":{}}}",
        paths, measurement.wall_ms, measurement.peak_rss_kib,
    );
    measurement
}

#[test]
#[ignore = "manual scale measurement; run with --ignored --nocapture"]
fn gc_scale_fixtures() {
    for paths in [0, 100, 1_000, 10_000] {
        let data_dir = fixture(paths);
        let path = data_dir.path();
        gc(
            path,
            paths,
            "inventory",
            &["--max-age-seconds", "3153600000", "--dry-run"],
        );
        gc(
            path,
            paths,
            "dry_run",
            &["--target-bytes", "0", "--dry-run"],
        );
        let apply = gc(path, paths, "apply", &["--target-bytes", "0", "--apply"]);
        assert!(
            fs::read_dir(path)
                .expect("fixture should be readable")
                .all(|entry| {
                    entry
                        .expect("fixture entry should be readable")
                        .path()
                        .extension()
                        .is_none_or(|extension| extension != "narinfo")
                }),
            "apply should remove every selected narinfo"
        );
        assert!(
            paths == 0 || !path.join(format!("nar/{NAR_HASH}.nar")).exists(),
            "apply should remove the shared NAR after its final reference"
        );
        if paths == 10_000 {
            assert!(
                apply.peak_rss_kib > 0,
                "Linux peak RSS sampling should work"
            );
        }
    }
}
