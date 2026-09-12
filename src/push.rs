use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    thread,
    time::Duration,
};

use clap::Args;
use data_encoding::{BASE64, BitOrder, Encoding, Specification};
use lzma_rust2::{XzOptions, XzWriter};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};
use tempfile::NamedTempFile;
use ureq::Agent;

use crate::{error::Error, operator::netrc_authorization};

#[derive(Debug, Args)]
pub(crate) struct Push {
    /// Destination binary cache store URI.
    #[arg(long, value_parser = non_empty)]
    to: String,

    /// Maximum number of native HTTP upload workers.
    #[arg(long, default_value_t = NonZeroUsize::new(1).unwrap())]
    jobs: NonZeroUsize,

    /// NAR representation requested from the destination cache.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    compression: Compression,

    /// Netrc file used for HTTP authentication.
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathInfo {
    path: String,
    ca: Option<String>,
    deriver: Option<String>,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    signatures: Vec<String>,
}

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

fn parse_path_info(bytes: &[u8]) -> Result<Vec<PathInfo>, String> {
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

fn nix32_encoding() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut specification = Specification::new();
        specification
            .symbols
            .push_str("0123456789abcdfghijklmnpqrsvwxyz");
        specification.bit_order = BitOrder::LeastSignificantFirst;
        specification
            .encoding()
            .expect("Nix base32 specification is valid")
    })
}

fn nix32_sha256_from_sri(value: &str) -> Result<String, String> {
    let (algorithm, encoded) = value
        .split_once('-')
        .ok_or_else(|| format!("unsupported Nix hash: {value}"))?;
    if algorithm != "sha256" {
        return Err(format!("unsupported Nix hash algorithm: {algorithm}"));
    }
    let digest = BASE64
        .decode(encoded.as_bytes())
        .map_err(|error| format!("invalid Nix hash {value}: {error}"))?;
    if digest.len() != 32 {
        return Err(format!(
            "invalid SHA-256 length in Nix hash: {}",
            digest.len()
        ));
    }
    let encoding = nix32_encoding();
    let mut output = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(&digest, &mut output);
    output.reverse();
    String::from_utf8(output).map_err(|error| format!("invalid Nix base32 output: {error}"))
}

fn serialize_narinfo(
    info: &PathInfo,
    file_hash: &str,
    file_size: u64,
    compression: Compression,
) -> Result<Vec<u8>, String> {
    info.path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| format!("invalid store path: {}", info.path))?;
    let nar_hash = nix32_sha256_from_sri(&info.nar_hash)?;
    let mut references = info
        .references
        .iter()
        .map(|reference| {
            reference
                .strip_prefix("/nix/store/")
                .ok_or_else(|| format!("invalid reference path: {reference}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    references.sort_unstable();
    references.dedup();

    let mut output = format!(
        "StorePath: {}\nURL: nar/{}{}\nCompression: {}\nFileHash: sha256:{}\nFileSize: {}\nNarHash: sha256:{}\nNarSize: {}\nReferences: {}\n",
        info.path,
        file_hash,
        compression.suffix(),
        compression.query_value(),
        file_hash,
        file_size,
        nar_hash,
        info.nar_size,
        references.join(" "),
    );
    for signature in &info.signatures {
        output.push_str("Sig: ");
        output.push_str(signature);
        output.push('\n');
    }
    if let Some(deriver) = &info.deriver {
        if deriver == "unknown-deriver" {
            output.push_str("Deriver: unknown-deriver\n");
        } else {
            let deriver = deriver
                .strip_prefix("/nix/store/")
                .ok_or_else(|| format!("invalid deriver path: {deriver}"))?;
            output.push_str("Deriver: ");
            output.push_str(deriver);
            output.push('\n');
        }
    }
    if let Some(ca) = &info.ca {
        output.push_str("CA: ");
        output.push_str(ca);
        output.push('\n');
    }
    Ok(output.into_bytes())
}

pub(crate) fn run(args: Push) -> Result<(), Error> {
    let mut metadata = closure_paths(&args.paths)?;
    let paths: Vec<_> = metadata.iter().map(|info| info.path.clone()).collect();
    if let Some(key_file) = args.signing_key_file.as_deref() {
        sign_paths(key_file, &paths)?;
        metadata = closure_paths(&args.paths)?;
    }
    let worker_count = args.jobs.get().min(metadata.len());
    let chunk_size = metadata.len().div_ceil(worker_count);
    let mut workers = Vec::with_capacity(worker_count);

    for chunk in metadata.chunks(chunk_size) {
        let target = args.to.clone();
        let netrc_file = args.netrc_file.clone();
        let refresh = args.refresh;
        let compression = args.compression;
        let metadata = chunk.to_vec();
        workers.push(thread::spawn(move || {
            native_copy_paths(
                &target,
                netrc_file.as_deref(),
                refresh,
                compression,
                &metadata,
            )
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
        println!(
            "pushed {} paths with {worker_count} workers",
            metadata.len()
        );
        Ok(())
    } else {
        Err(Error::runtime(format!("{failures} push workers failed")))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum Compression {
    None,
    Zstd,
    Xz,
}

impl Compression {
    const fn query_value(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Xz => "xz",
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::None => ".nar",
            Self::Zstd => ".nar.zst",
            Self::Xz => ".nar.xz",
        }
    }
}

fn target_with_compression(target: &str, compression: Compression) -> String {
    let value = compression.query_value();
    if let Some(query) = target.split_once('?').map(|(_, query)| query)
        && query
            .split('&')
            .any(|parameter| parameter.starts_with("compression="))
    {
        let mut target = target.to_owned();
        let start = target.find("compression=").expect("compression was found");
        let end = target[start..]
            .find('&')
            .map_or(target.len(), |offset| start + offset);
        target.replace_range(start..end, &format!("compression={value}"));
        return target;
    }
    let separator = if target.contains('?') { '&' } else { '?' };
    format!("{target}{separator}compression={value}")
}

fn sign_paths(key_file: &std::path::Path, paths: &[String]) -> Result<(), Error> {
    let mut command = Command::new("nix");
    command
        .arg("store")
        .arg("sign")
        .arg("--key-file")
        .arg(key_file);
    run_path_command(command, paths, "nix store sign").map_err(Error::runtime)
}

fn closure_paths(installables: &[String]) -> Result<Vec<PathInfo>, Error> {
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

struct PreparedNar {
    file: NamedTempFile,
    file_hash: String,
    file_size: u64,
}

fn native_copy_paths(
    target: &str,
    netrc_file: Option<&Path>,
    refresh: bool,
    compression: Compression,
    metadata: &[PathInfo],
) -> Result<(), String> {
    let target = target_with_compression(target, compression);
    let (base_url, authority) = split_http_target(&target)?;
    let authorization = netrc_file
        .map(|path| netrc_authorization(path, &authority).map_err(|error| error.to_string()))
        .transpose()?;
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();

    for info in metadata {
        let store_hash = store_hash_for_path(&info.path)?;
        let narinfo_url = format!("{base_url}/{store_hash}.narinfo");
        if !refresh {
            match request_status(&agent, &narinfo_url, authorization.as_deref())? {
                200 => continue,
                404 => {}
                status => {
                    return Err(format!(
                        "narinfo lookup for {} returned HTTP {status}",
                        info.path
                    ));
                }
            }
        }

        let prepared = prepare_nar(info, compression)?;
        let nar_url = format!(
            "{base_url}/nar/{}{}",
            prepared.file_hash,
            compression.suffix()
        );
        let nar_status = put_file(
            &agent,
            &nar_url,
            prepared.file.path(),
            authorization.as_deref(),
        )?;
        if !matches!(nar_status, 200 | 201) {
            return Err(format!(
                "NAR upload for {} returned HTTP {nar_status}",
                info.path
            ));
        }

        let narinfo =
            serialize_narinfo(info, &prepared.file_hash, prepared.file_size, compression)?;
        let narinfo_status = put_bytes(&agent, &narinfo_url, &narinfo, authorization.as_deref())?;
        if !matches!(narinfo_status, 200 | 201) {
            return Err(format!(
                "narinfo upload for {} returned HTTP {narinfo_status}",
                info.path
            ));
        }
    }
    Ok(())
}

fn split_http_target(target: &str) -> Result<(String, String), String> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .ok_or_else(|| "--to must be an http:// or https:// URL".to_owned())?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())
        .ok_or_else(|| "--to must include a host".to_owned())?;
    let base = target
        .split(['?', '#'])
        .next()
        .unwrap_or(target)
        .trim_end_matches('/');
    if base.is_empty() {
        return Err("--to must include a host".to_owned());
    }
    Ok((base.to_owned(), authority.to_owned()))
}

fn store_hash_for_path(path: &str) -> Result<&str, String> {
    let basename = path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| format!("invalid store path: {path}"))?;
    let (hash, _name) = basename
        .split_once('-')
        .filter(|(hash, name)| hash.len() == 32 && !name.is_empty())
        .ok_or_else(|| format!("invalid store path: {path}"))?;
    if hash
        .bytes()
        .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
    {
        Ok(hash)
    } else {
        Err(format!("invalid store hash in path: {path}"))
    }
}

const MAX_ATTEMPTS: usize = 3;

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

fn retry_sleep(attempt: usize) {
    let multiplier = 1u64 << attempt.min(6);
    thread::sleep(Duration::from_millis(100 * multiplier));
}

fn request_status(agent: &Agent, url: &str, authorization: Option<&str>) -> Result<u16, String> {
    for attempt in 0..MAX_ATTEMPTS {
        let mut request = agent.get(url);
        if let Some(authorization) = authorization {
            request = request.header("Authorization", format!("Basic {authorization}"));
        }
        match request.call() {
            Ok(response) => {
                let status = response.status().as_u16();
                let mut body = response.into_body().into_reader();
                io::copy(&mut body, &mut io::sink())
                    .map_err(|error| format!("reading GET {url} response failed: {error}"))?;
                if is_retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                    retry_sleep(attempt);
                    continue;
                }
                return Ok(status);
            }
            Err(_error) if attempt + 1 < MAX_ATTEMPTS => retry_sleep(attempt),
            Err(error) => return Err(format!("GET {url} failed: {error}")),
        }
    }
    unreachable!("retry loop always returns")
}

fn put_file(
    agent: &Agent,
    url: &str,
    path: &Path,
    authorization: Option<&str>,
) -> Result<u16, String> {
    for attempt in 0..MAX_ATTEMPTS {
        let file = File::open(path)
            .map_err(|error| format!("opening NAR for PUT {url} failed: {error}"))?;
        let mut request = agent.put(url);
        if let Some(authorization) = authorization {
            request = request.header("Authorization", format!("Basic {authorization}"));
        }
        match request.send(file) {
            Ok(response) => {
                let status = response.status().as_u16();
                let mut body = response.into_body().into_reader();
                io::copy(&mut body, &mut io::sink())
                    .map_err(|error| format!("reading PUT {url} response failed: {error}"))?;
                if is_retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                    retry_sleep(attempt);
                    continue;
                }
                return Ok(status);
            }
            Err(_error) if attempt + 1 < MAX_ATTEMPTS => retry_sleep(attempt),
            Err(error) => return Err(format!("PUT {url} failed: {error}")),
        }
    }
    unreachable!("retry loop always returns")
}

fn put_bytes(
    agent: &Agent,
    url: &str,
    bytes: &[u8],
    authorization: Option<&str>,
) -> Result<u16, String> {
    for attempt in 0..MAX_ATTEMPTS {
        let mut request = agent.put(url);
        if let Some(authorization) = authorization {
            request = request.header("Authorization", format!("Basic {authorization}"));
        }
        match request.send(bytes) {
            Ok(response) => {
                let status = response.status().as_u16();
                let mut body = response.into_body().into_reader();
                io::copy(&mut body, &mut io::sink())
                    .map_err(|error| format!("reading PUT {url} response failed: {error}"))?;
                if is_retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                    retry_sleep(attempt);
                    continue;
                }
                return Ok(status);
            }
            Err(_error) if attempt + 1 < MAX_ATTEMPTS => retry_sleep(attempt),
            Err(error) => return Err(format!("PUT {url} failed: {error}")),
        }
    }
    unreachable!("retry loop always returns")
}

fn prepare_nar(info: &PathInfo, compression: Compression) -> Result<PreparedNar, String> {
    let mut raw =
        NamedTempFile::new().map_err(|error| format!("creating NAR temporary: {error}"))?;
    let stdout = raw
        .as_file()
        .try_clone()
        .map_err(|error| format!("opening NAR temporary: {error}"))?;
    let output = Command::new("nix")
        .arg("store")
        .arg("dump-path")
        .arg("--")
        .arg(&info.path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run nix store dump-path: {error}"))?
        .wait_with_output()
        .map_err(|error| format!("failed to wait for nix store dump-path: {error}"))?;
    if !output.status.success() {
        return Err(format_command_failure(
            "nix store dump-path",
            &output.stderr,
        ));
    }
    raw.as_file_mut()
        .sync_all()
        .map_err(|error| format!("syncing NAR temporary: {error}"))?;
    let raw_size = raw
        .as_file()
        .metadata()
        .map_err(|error| format!("statting NAR temporary: {error}"))?
        .len();
    if raw_size != info.nar_size {
        return Err(format!(
            "NAR size mismatch for {}: expected {}, got {raw_size}",
            info.path, info.nar_size
        ));
    }
    let expected_hash = nix32_sha256_from_sri(&info.nar_hash)?;
    let actual_hash = sha256_file(raw.as_file())?;
    if actual_hash != expected_hash {
        return Err(format!(
            "NAR hash mismatch for {}: expected {expected_hash}, got {actual_hash}",
            info.path
        ));
    }

    if compression == Compression::None {
        return Ok(PreparedNar {
            file: raw,
            file_hash: actual_hash,
            file_size: raw_size,
        });
    }

    raw.as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewinding NAR temporary: {error}"))?;
    let mut encoded =
        NamedTempFile::new().map_err(|error| format!("creating encoded NAR temporary: {error}"))?;
    match compression {
        Compression::None => unreachable!(),
        Compression::Zstd => {
            let mut encoder =
                StreamingEncoder::new(encoded.as_file_mut(), CompressionLevel::Fastest);
            io::copy(raw.as_file_mut(), &mut encoder)
                .map_err(|error| format!("compressing NAR with zstd: {error}"))?;
            encoder
                .finish()
                .map_err(|error| format!("finishing zstd NAR: {error}"))?;
        }
        Compression::Xz => {
            let mut encoder = XzWriter::new(encoded.as_file_mut(), XzOptions::with_preset(1))
                .map_err(|error| format!("creating XZ encoder: {error}"))?;
            io::copy(raw.as_file_mut(), &mut encoder)
                .map_err(|error| format!("compressing NAR with XZ: {error}"))?;
            encoder
                .finish()
                .map_err(|error| format!("finishing XZ NAR: {error}"))?;
        }
    }
    encoded
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("syncing encoded NAR temporary: {error}"))?;
    let file_size = encoded
        .as_file()
        .metadata()
        .map_err(|error| format!("statting encoded NAR temporary: {error}"))?
        .len();
    let file_hash = sha256_file(encoded.as_file())?;
    Ok(PreparedNar {
        file: encoded,
        file_hash,
        file_size,
    })
}

fn sha256_file(file: &File) -> Result<String, String> {
    let mut file = file
        .try_clone()
        .map_err(|error| format!("cloning NAR file for hashing: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewinding NAR file for hashing: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("hashing NAR file: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let encoding = nix32_encoding();
    let mut output = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(&digest, &mut output);
    output.reverse();
    String::from_utf8(output).map_err(|error| format!("invalid Nix base32 output: {error}"))
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

#[cfg(test)]
mod tests {
    use clap::{Args, Command, FromArgMatches};

    use super::{
        Agent, Compression, PathInfo, Push, is_retryable_status, parse_path_info, serialize_narinfo,
    };

    #[test]
    fn parses_nix_path_info_metadata() {
        let metadata = parse_path_info(
            br#"{
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package": {
                    "ca": null,
                    "deriver": "/nix/store/abcdefghijklmnopqrstuvwxyz0123456789.drv",
                    "narHash": "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY=",
                    "narSize": 289656,
                    "references": [
                        "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency"
                    ],
                    "signatures": ["cache.example:signature"],
                    "ultimate": true
                }
            }"#,
        )
        .expect("valid path-info JSON");

        assert_eq!(metadata.len(), 1);
        let info = &metadata[0];
        assert_eq!(
            info.path,
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package"
        );
        assert_eq!(
            info.nar_hash,
            "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY="
        );
        assert_eq!(info.nar_size, 289656);
        assert_eq!(
            info.references,
            vec!["/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency"]
        );
        assert_eq!(info.signatures, vec!["cache.example:signature"]);
        assert_eq!(
            info.deriver.as_deref(),
            Some("/nix/store/abcdefghijklmnopqrstuvwxyz0123456789.drv")
        );
    }

    #[test]
    fn serializes_signed_narinfo_from_path_info() {
        let info = PathInfo {
            path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package".to_owned(),
            deriver: Some("/nix/store/abcdefghijklmnopqrstuvwxyz0123456789.drv".to_owned()),
            nar_hash: "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY=".to_owned(),
            nar_size: 289656,
            references: vec![
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency".to_owned(),
                "/nix/store/11111111111111111111111111111111-dependency".to_owned(),
            ],
            signatures: vec!["cache.example:signature".to_owned()],
            ca: Some("fixed:sha256:0123456789abcdef".to_owned()),
        };

        let bytes = serialize_narinfo(
            &info,
            "01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai",
            289656,
            Compression::None,
        )
        .expect("path-info metadata should serialize");
        assert_eq!(
            String::from_utf8(bytes).expect("narinfo should be UTF-8"),
            "StorePath: /nix/store/0123456789abcdfghijklmnpqrsvwxyz-package\n\
             URL: nar/01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai.nar\n\
             Compression: none\n\
             FileHash: sha256:01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai\n\
             FileSize: 289656\n\
             NarHash: sha256:01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai\n\
             NarSize: 289656\n\
             References: 11111111111111111111111111111111-dependency zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency\n\
             Sig: cache.example:signature\n\
             Deriver: abcdefghijklmnopqrstuvwxyz0123456789.drv\n\
             CA: fixed:sha256:0123456789abcdef\n"
        );
    }

    #[test]
    fn retries_only_transient_http_failures() {
        for status in [429, 500, 502, 503, 504] {
            assert!(is_retryable_status(status), "HTTP {status} should retry");
        }
        for status in [200, 201, 400, 401, 404, 409, 413, 422] {
            assert!(
                !is_retryable_status(status),
                "HTTP {status} should not retry"
            );
        }
    }

    #[test]
    fn retries_a_429_before_returning_success() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind retry test listener");
        let address = listener.local_addr().expect("inspect retry test listener");
        let server = thread::spawn(move || {
            for status in [429, 200] {
                let (mut stream, _) = listener.accept().expect("accept retry test request");
                let mut request = [0; 4096];
                let _ = stream.read(&mut request).expect("read retry test request");
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write retry test response");
            }
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        assert_eq!(
            super::request_status(&agent, &format!("http://{address}/narinfo"), None)
                .expect("retry should eventually succeed"),
            200
        );
        server.join().expect("retry test server should exit");
    }

    #[test]
    fn push_defaults_to_one_copy_worker() {
        let matches = Push::augment_args(Command::new("push"))
            .try_get_matches_from([
                "push",
                "--to",
                "https://cache.example",
                "/run/current-system",
            ])
            .expect("push options should parse");
        let push = Push::from_arg_matches(&matches).expect("push arguments should parse");

        assert_eq!(push.jobs.get(), 1);
    }

    #[test]
    fn compression_is_explicitly_added_to_destination_uri() {
        assert_eq!(
            super::target_with_compression("https://cache.example", super::Compression::None),
            "https://cache.example?compression=none"
        );
        assert_eq!(
            super::target_with_compression(
                "https://cache.example?priority=10",
                super::Compression::Zstd
            ),
            "https://cache.example?priority=10&compression=zstd"
        );
        assert_eq!(
            super::target_with_compression(
                "https://cache.example?compression=xz&priority=10",
                super::Compression::None
            ),
            "https://cache.example?compression=none&priority=10"
        );
    }
}
