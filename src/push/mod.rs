use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use clap::Args;
use ureq::Agent;

use crate::{error::Error, http_url::HttpUrl, operator::netrc_authorization};

mod narinfo;
mod nix;
mod payload;
mod plan;
mod transfer;
use narinfo::{nix32_encoding, nix32_sha256_from_sri, serialize_narinfo};
use nix::{closure_paths, format_command_failure, sign_paths};
use payload::prepare_nar;
use plan::dependency_waves;
use transfer::{put_bytes, put_file, request_status};

#[derive(Debug, Args)]
pub(crate) struct Push {
    /// Destination binary cache store URI.
    #[arg(long)]
    to: HttpUrl,

    /// Maximum number of native HTTP upload workers.
    #[arg(long, default_value_t = NonZeroUsize::new(1).unwrap())]
    jobs: NonZeroUsize,

    /// Compression used for the uploaded NAR payload; the cache independently selects its served representation.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    compression: Compression,

    /// Maximum time allowed for each native HTTP request.
    #[arg(long, env = "NARJAR_PUSH_TIMEOUT_SECONDS", default_value_t = NonZeroU64::new(30).unwrap())]
    timeout_seconds: NonZeroU64,

    /// Netrc file used for HTTP authentication.
    #[arg(long)]
    netrc_file: Option<PathBuf>,

    /// Permit sending netrc credentials over plain HTTP.
    #[arg(long)]
    insecure_http: bool,

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingNarinfo {
    Skip,
    Refresh,
}

impl From<bool> for ExistingNarinfo {
    fn from(refresh: bool) -> Self {
        match refresh {
            true => Self::Refresh,
            false => Self::Skip,
        }
    }
}

impl ExistingNarinfo {
    const fn should_upload(self) -> bool {
        matches!(self, Self::Refresh)
    }
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

pub(crate) fn run(args: Push) -> Result<(), Error> {
    let mut metadata = closure_paths(&args.paths)?;
    let paths: Vec<_> = metadata.iter().map(|info| info.path.clone()).collect();
    if let Some(key_file) = args.signing_key_file.as_deref() {
        sign_paths(key_file, &paths)?;
        metadata = closure_paths(&args.paths)?;
    }
    let waves = dependency_waves(metadata)?;
    let total_paths = waves.iter().map(Vec::len).sum::<usize>();
    let worker_count = args.jobs.get().min(total_paths);
    let existing_narinfo = ExistingNarinfo::from(args.refresh);

    let mut failures = 0;
    for wave in waves {
        let wave_worker_count = args.jobs.get().min(wave.len());
        let chunk_size = wave.len().div_ceil(wave_worker_count);
        let mut workers = Vec::with_capacity(wave_worker_count);

        for chunk in wave.chunks(chunk_size) {
            let target = args.to.clone();
            let netrc_file = args.netrc_file.clone();
            let insecure_http = args.insecure_http;
            let compression = args.compression;
            let timeout_seconds = args.timeout_seconds;
            let metadata = chunk.to_vec();
            workers.push(thread::spawn(move || {
                native_copy_paths(
                    &target,
                    netrc_file.as_deref(),
                    insecure_http,
                    existing_narinfo,
                    compression,
                    timeout_seconds,
                    &metadata,
                )
            }));
        }

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
        if failures != 0 {
            break;
        }
    }

    if failures == 0 {
        println!("pushed {total_paths} paths with {worker_count} workers");
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

fn native_copy_paths(
    target: &HttpUrl,
    netrc_file: Option<&Path>,
    insecure_http: bool,
    existing_narinfo: ExistingNarinfo,
    compression: Compression,
    timeout_seconds: NonZeroU64,
    metadata: &[PathInfo],
) -> Result<(), String> {
    let authorization = netrc_file
        .map(|path| {
            netrc_authorization(path, target, insecure_http).map_err(|error| error.to_string())
        })
        .transpose()?
        .flatten();
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(timeout_seconds.get())))
        .build()
        .into();

    for info in metadata {
        let store_hash = store_hash_for_path(&info.path)?;
        let narinfo_name = format!("{store_hash}.narinfo");
        let narinfo_url = target.endpoint(&[&narinfo_name]);
        if !existing_narinfo.should_upload() {
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
        let nar_name = format!("{}{}", prepared.file_hash, compression.suffix());
        let nar_url = target.endpoint(&["nar", &nar_name]);
        let nar_status = put_file(
            &agent,
            &nar_url,
            prepared.file.path(),
            "application/x-nix-nar",
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
        let narinfo_status = put_bytes(
            &agent,
            &narinfo_url,
            &narinfo,
            "text/x-nix-narinfo",
            authorization.as_deref(),
        )?;
        if !matches!(narinfo_status, 200 | 201) {
            return Err(format!(
                "narinfo upload for {} returned HTTP {narinfo_status}",
                info.path
            ));
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use clap::{Args, Command, FromArgMatches};

    use super::nix::parse_path_info;
    use super::transfer::{is_retryable_status, retry_after_delay};
    use super::{Agent, Compression, PathInfo, Push, dependency_waves, serialize_narinfo};
    use crate::http_url::HttpUrl;

    fn http_url(value: impl AsRef<str>) -> HttpUrl {
        value.as_ref().parse().expect("test HTTP URL should parse")
    }
    use std::time::Duration;

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
        for status in [408, 429, 500, 502, 503, 504] {
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
    fn retry_after_delay_accepts_seconds_and_has_a_bound() {
        assert_eq!(
            retry_after_delay("3"),
            Some(Duration::from_secs(3)),
            "valid Retry-After seconds should be honored"
        );
        assert_eq!(
            retry_after_delay("3600"),
            Some(Duration::from_secs(60)),
            "server-provided delays must remain bounded"
        );
        assert_eq!(retry_after_delay("invalid"), None);
        assert_eq!(retry_after_delay(""), None);
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
                let retry_after = if status == 429 {
                    "Retry-After: 0\r\n"
                } else {
                    ""
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\n{retry_after}Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write retry test response");
            }
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        assert_eq!(
            super::request_status(&agent, &http_url(format!("http://{address}/narinfo")), None)
                .expect("retry should eventually succeed"),
            200
        );
        server.join().expect("retry test server should exit");
    }

    #[test]
    fn follows_authenticated_get_redirects_without_leaving_the_cache() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
        };

        fn read_headers(stream: &mut TcpStream) -> String {
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let read = stream.read(&mut buffer).expect("read GET request");
                assert_ne!(read, 0, "GET request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    return String::from_utf8(request).expect("GET request should be UTF-8");
                }
            }
        }

        fn has_authorization(request: &str) -> bool {
            request.lines().any(|line| {
                let Some((name, value)) = line.split_once(':') else {
                    return false;
                };
                name.eq_ignore_ascii_case("authorization") && value.trim() == "Basic dXNlcjpwYXNz"
            })
        }

        for redirect_status in [307, 308] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind GET redirect listener");
            let address = listener
                .local_addr()
                .expect("inspect GET redirect listener");
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept initial GET request");
                let request = read_headers(&mut stream);
                assert!(request.starts_with("GET /narinfo HTTP/1.1"));
                assert!(has_authorization(&request));
                write!(
                    stream,
                    "HTTP/1.1 {redirect_status} Temporary Redirect\r\nLocation: /redirected/narinfo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write GET redirect response");

                let (mut stream, _) = listener.accept().expect("accept redirected GET request");
                let request = read_headers(&mut stream);
                assert!(request.starts_with("GET /redirected/narinfo HTTP/1.1"));
                assert!(has_authorization(&request));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write redirected GET response");
            });
            let agent: Agent = Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into();

            assert_eq!(
                super::request_status(
                    &agent,
                    &http_url(format!("http://{address}/narinfo")),
                    Some("dXNlcjpwYXNz"),
                )
                .expect("authenticated GET redirect should succeed"),
                200
            );
            server.join().expect("GET redirect server should exit");
        }
    }

    #[test]
    fn retries_a_429_during_file_upload() {
        use std::{
            fs,
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let payload = tempfile::NamedTempFile::new().expect("create upload test file");
        fs::write(payload.path(), b"retryable NAR payload").expect("write upload test file");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upload test listener");
        let address = listener.local_addr().expect("inspect upload test listener");
        let server = thread::spawn(move || {
            for (attempt, status) in [(0, 429), (1, 201)] {
                let (mut stream, _) = listener.accept().expect("accept upload request");
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let read = stream.read(&mut buffer).expect("read upload request");
                    assert_ne!(read, 0, "upload request ended before its body");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let content_length = request[..header_end]
                        .split(|&byte| byte == b'\n')
                        .find_map(|line| {
                            let separator = line.iter().position(|&byte| byte == b':')?;
                            let (name, value) = line.split_at(separator);
                            name.eq_ignore_ascii_case(b"content-length")
                                .then(|| &value[1..])
                                .and_then(|value| std::str::from_utf8(value).ok())
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .expect("upload should have a Content-Length");
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
                if attempt == 1 {
                    assert!(
                        request.ends_with(b"retryable NAR payload"),
                        "retry should resend the complete body"
                    );
                }
                let retry_after = if status == 429 {
                    "Retry-After: 0\r\n"
                } else {
                    ""
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\n{retry_after}Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write upload test response");
            }
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        assert_eq!(
            super::put_file(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload.path(),
                "application/x-nix-nar",
                None
            )
            .expect("upload retry should eventually succeed"),
            201
        );
        server.join().expect("upload retry test server should exit");
    }

    #[test]
    fn follows_a_307_during_file_upload() {
        use std::{
            fs,
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
        };

        fn read_request(stream: &mut TcpStream) -> Vec<u8> {
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).expect("read redirect request");
                assert_ne!(read, 0, "redirect request ended before its body");
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let content_length = request[..header_end]
                    .split(|&byte| byte == b'\n')
                    .find_map(|line| {
                        let separator = line.iter().position(|&byte| byte == b':')?;
                        let (name, value) = line.split_at(separator);
                        name.eq_ignore_ascii_case(b"content-length")
                            .then(|| &value[1..])
                            .and_then(|value| std::str::from_utf8(value).ok())
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .expect("redirect request should have a Content-Length");
                if request.len() >= header_end + 4 + content_length {
                    return request;
                }
            }
        }

        let payload = tempfile::NamedTempFile::new().expect("create redirect test file");
        fs::write(payload.path(), b"redirected NAR payload").expect("write redirect test file");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect test listener");
        let address = listener
            .local_addr()
            .expect("inspect redirect test listener");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept initial redirect request");
            let request = read_request(&mut stream);
            assert!(
                String::from_utf8_lossy(&request).starts_with("PUT /nar/test.nar HTTP/1.1"),
                "initial upload should use the requested path"
            );
            assert!(
                request.ends_with(b"redirected NAR payload"),
                "initial upload should contain the complete body"
            );
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: /redirect-target/nar/test.nar\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write redirect response");

            let (mut stream, _) = listener.accept().expect("accept redirected request");
            let request = read_request(&mut stream);
            assert!(
                String::from_utf8_lossy(&request)
                    .starts_with("PUT /redirect-target/nar/test.nar HTTP/1.1"),
                "redirected upload should use the Location path"
            );
            assert!(
                request.ends_with(b"redirected NAR payload"),
                "redirected upload should replay the complete body"
            );
            write!(
                stream,
                "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write redirected upload response");
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        assert_eq!(
            super::put_file(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload.path(),
                "application/x-nix-nar",
                None
            )
            .expect("redirected upload should succeed"),
            201
        );
        server.join().expect("redirect test server should exit");
    }

    #[test]
    fn uploads_set_protocol_content_types() {
        use std::{
            fs,
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
        };

        let payload = tempfile::NamedTempFile::new().expect("create content-type test file");
        fs::write(payload.path(), b"NAR payload").expect("write content-type test file");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind content-type listener");
        let address = listener
            .local_addr()
            .expect("inspect content-type listener");
        let server = thread::spawn(move || {
            fn read_request(stream: &mut TcpStream) -> Vec<u8> {
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let read = stream.read(&mut buffer).expect("read content-type request");
                    assert_ne!(read, 0, "content-type request ended before its headers");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let content_length = request[..header_end]
                        .split(|&byte| byte == b'\n')
                        .find_map(|line| {
                            let separator = line.iter().position(|&byte| byte == b':')?;
                            let (name, value) = line.split_at(separator);
                            name.eq_ignore_ascii_case(b"content-length")
                                .then(|| &value[1..])
                                .and_then(|value| std::str::from_utf8(value).ok())
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .expect("content-type request should have a Content-Length");
                    if request.len() >= header_end + 4 + content_length {
                        return request;
                    }
                }
            }

            for expected_content_type in ["application/x-nix-nar", "text/x-nix-narinfo"] {
                let (mut stream, _) = listener.accept().expect("accept content-type request");
                let request = read_request(&mut stream);
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .expect("content-type request should contain headers");
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let expected_header = format!("content-type: {expected_content_type}");
                assert!(
                    headers
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case(&expected_header)),
                    "upload should identify its media type: {headers}"
                );
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write content-type response");
            }
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        assert_eq!(
            super::put_file(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload.path(),
                "application/x-nix-nar",
                None
            )
            .expect("content-type upload should succeed"),
            201
        );
        assert_eq!(
            super::put_bytes(
                &agent,
                &http_url(format!("http://{address}/store.narinfo")),
                b"StorePath: /nix/store/test\n",
                "text/x-nix-narinfo",
                None
            )
            .expect("narinfo content-type upload should succeed"),
            201
        );
        server.join().expect("content-type server should exit");
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
    fn push_accepts_an_http_timeout() {
        let matches = Push::augment_args(Command::new("push"))
            .try_get_matches_from([
                "push",
                "--to",
                "https://cache.example",
                "--timeout-seconds",
                "7",
                "/run/current-system",
            ])
            .expect("push timeout should parse");
        let push = Push::from_arg_matches(&matches).expect("push arguments should parse");

        assert_eq!(push.timeout_seconds.get(), 7);
    }

    #[test]
    fn dependency_waves_put_references_before_dependents() {
        let dependency = PathInfo {
            path: "/nix/store/00000000000000000000000000000000-dependency".to_owned(),
            ca: None,
            deriver: None,
            nar_hash: "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY=".to_owned(),
            nar_size: 289656,
            references: Vec::new(),
            signatures: Vec::new(),
        };
        let dependent = PathInfo {
            path: "/nix/store/11111111111111111111111111111111-dependent".to_owned(),
            references: vec![dependency.path.clone()],
            ..dependency.clone()
        };

        let waves = dependency_waves(vec![dependent, dependency]).expect("acyclic closure");
        let paths = waves
            .into_iter()
            .map(|wave| wave.into_iter().map(|info| info.path).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                vec!["/nix/store/00000000000000000000000000000000-dependency".to_owned()],
                vec!["/nix/store/11111111111111111111111111111111-dependent".to_owned()],
            ]
        );
    }

    #[test]
    fn dependency_waves_ignore_self_references() {
        let path = "/nix/store/00000000000000000000000000000000-self-referencing";
        let info = PathInfo {
            path: path.to_owned(),
            ca: None,
            deriver: None,
            nar_hash: "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY=".to_owned(),
            nar_size: 289656,
            references: vec![path.to_owned()],
            signatures: Vec::new(),
        };

        let waves =
            dependency_waves(vec![info]).expect("self references are not dependency cycles");
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 1);
        assert_eq!(waves[0][0].path, path);
    }

    #[test]
    fn dependency_waves_reject_missing_references() {
        let info = PathInfo {
            path: "/nix/store/11111111111111111111111111111111-dependent".to_owned(),
            ca: None,
            deriver: None,
            nar_hash: "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY=".to_owned(),
            nar_size: 289656,
            references: vec!["/nix/store/00000000000000000000000000000000-missing".to_owned()],
            signatures: Vec::new(),
        };

        let error = dependency_waves(vec![info]).expect_err("missing references must fail");
        assert!(
            error.to_string().contains("missing referenced store path"),
            "unexpected error: {error}"
        );
    }
}
