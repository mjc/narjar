use std::{
    io::Write,
    num::NonZeroUsize,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
};

use clap::Args;

use crate::error::Error;

#[derive(Debug, Args)]
pub(crate) struct Push {
    /// Destination binary cache store URI.
    #[arg(long, value_parser = non_empty)]
    to: String,

    /// Maximum number of native `nix copy` workers.
    #[arg(long, default_value_t = NonZeroUsize::new(8).unwrap())]
    jobs: NonZeroUsize,

    /// Netrc file passed to Nix for HTTP authentication.
    #[arg(long)]
    netrc_file: Option<PathBuf>,

    /// Secret key file used to sign the local store paths before copying.
    #[arg(long)]
    signing_key_file: Option<PathBuf>,

    /// Re-check and re-upload paths already present at the destination.
    #[arg(long)]
    refresh: bool,

    /// Store paths or installables whose closure should be pushed.
    #[arg(value_name = "INSTALLABLE", required = true, num_args = 1..)]
    paths: Vec<String>,
}

pub(crate) fn run(args: Push) -> Result<(), Error> {
    let paths = closure_paths(&args.paths)?;
    if let Some(key_file) = args.signing_key_file.as_deref() {
        sign_paths(key_file, &paths)?;
    }
    let worker_count = args.jobs.get().min(paths.len());
    let chunk_size = paths.len().div_ceil(worker_count);
    let mut workers = Vec::with_capacity(worker_count);

    for chunk in paths.chunks(chunk_size) {
        let target = args.to.clone();
        let netrc_file = args.netrc_file.clone();
        let refresh = args.refresh;
        let paths = chunk.to_vec();
        workers.push(thread::spawn(move || {
            copy_paths(&target, netrc_file.as_deref(), refresh, &paths)
        }));
    }

    let mut failures = 0;
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(message)) => {
                eprintln!("narjar push: {message}");
                failures += 1;
            }
            Err(_) => {
                eprintln!("narjar push: worker panicked");
                failures += 1;
            }
        }
    }

    if failures == 0 {
        println!("pushed {} paths with {worker_count} workers", paths.len());
        Ok(())
    } else {
        Err(Error::runtime(format!("{failures} push workers failed")))
    }
}

fn sign_paths(key_file: &std::path::Path, paths: &[String]) -> Result<(), Error> {
    let mut child = Command::new("nix")
        .arg("store")
        .arg("sign")
        .arg("--key-file")
        .arg(key_file)
        .arg("--stdin")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| Error::runtime(format!("failed to run nix store sign: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::runtime("nix store sign stdin was not piped"))?;
    for path in paths {
        writeln!(stdin, "{path}")
            .map_err(|error| Error::runtime(format!("failed to write signing paths: {error}")))?;
    }
    drop(stdin);
    let status = child
        .wait()
        .map_err(|error| Error::runtime(format!("failed to wait for nix store sign: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::runtime(format!(
            "nix store sign exited with {status}"
        )))
    }
}

fn closure_paths(installables: &[String]) -> Result<Vec<String>, Error> {
    let output = Command::new("nix")
        .arg("path-info")
        .arg("--recursive")
        .arg("--")
        .args(installables)
        .output()
        .map_err(|error| Error::runtime(format!("failed to run nix path-info: {error}")))?;

    if !output.status.success() {
        return Err(Error::runtime(format_command_failure(
            "nix path-info",
            &output.stderr,
        )));
    }

    let mut paths: Vec<_> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect();
    paths.sort_unstable();
    paths.dedup();

    if paths.is_empty() {
        Err(Error::runtime("nix path-info returned no store paths"))
    } else {
        Ok(paths)
    }
}

fn copy_paths(
    target: &str,
    netrc_file: Option<&std::path::Path>,
    refresh: bool,
    paths: &[String],
) -> Result<(), String> {
    let mut command = Command::new("nix");
    command.arg("copy").arg("--to").arg(target);
    if refresh {
        command.arg("--refresh");
    }
    if let Some(netrc_file) = netrc_file {
        command.arg("--option").arg("netrc-file").arg(netrc_file);
    }
    let mut child = command
        .arg("--stdin")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdin = child.stdin.take().ok_or("nix stdin was not piped")?;
    for path in paths {
        writeln!(stdin, "{path}").map_err(|error| error.to_string())?;
    }
    drop(stdin);
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("nix copy exited with {status}"))
    }
}

fn format_command_failure(command: &str, stderr: &[u8]) -> String {
    let detail = String::from_utf8_lossy(stderr).trim().to_owned();
    if detail.is_empty() {
        format!("{command} failed")
    } else {
        format!("{command} failed: {detail}")
    }
}

fn non_empty(value: &str) -> Result<String, String> {
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or_else(|| "must not be empty".to_owned())
}
