use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
};

use serde::Deserialize;

use crate::error::Error;

use super::PathInfo;

#[derive(Deserialize)]
struct RawPathInfo {
    ca: Option<String>,
    deriver: Option<String>,
    #[serde(rename = "narHash")]
    nar_hash: String,
    #[serde(rename = "narSize")]
    nar_size: u64,
    references: Vec<String>,
    signatures: Vec<String>,
}

pub(super) fn parse_path_info(bytes: &[u8]) -> Result<Vec<PathInfo>, String> {
    let entries: BTreeMap<String, RawPathInfo> = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid nix path-info JSON: {error}"))?;
    Ok(entries
        .into_iter()
        .map(|(path, info)| PathInfo {
            path,
            ca: info.ca,
            deriver: info.deriver,
            nar_hash: info.nar_hash,
            nar_size: info.nar_size,
            references: info.references,
            signatures: info.signatures,
        })
        .collect())
}

pub(super) fn sign_paths(key_file: &std::path::Path, paths: &[String]) -> Result<(), Error> {
    let mut command = Command::new("nix");
    command
        .arg("store")
        .arg("sign")
        .arg("--key-file")
        .arg(key_file);
    run_path_command(command, paths, "nix store sign").map_err(Error::runtime)
}

pub(super) fn closure_paths(installables: &[String]) -> Result<Vec<PathInfo>, Error> {
    let output = Command::new("nix")
        .arg("path-info")
        .arg("--recursive")
        .arg("--json")
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

    let paths = parse_path_info(&output.stdout).map_err(Error::runtime)?;

    if paths.is_empty() {
        Err(Error::runtime("nix path-info returned no store paths"))
    } else {
        Ok(paths)
    }
}

fn run_path_command(mut command: Command, paths: &[String], name: &str) -> Result<(), String> {
    let mut child = command
        .arg("--stdin")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run {name}: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("{name} stdin was not piped"))?;
    for path in paths {
        writeln!(stdin, "{path}")
            .map_err(|error| format!("failed to write {name} paths: {error}"))?;
    }
    drop(stdin);
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for {name}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{name} exited with {status}"))
    }
}

pub(super) fn format_command_failure(command: &str, stderr: &[u8]) -> String {
    let detail = String::from_utf8_lossy(stderr).trim().to_owned();
    if detail.is_empty() {
        format!("{command} failed")
    } else {
        format!("{command} failed: {detail}")
    }
}
