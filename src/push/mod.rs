use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    thread,
    time::Duration,
};

use clap::Args;
use ureq::Agent;

use crate::{
    error::Error,
    http_url::HttpUrl,
    object::{EncodedSize, FileHash, NarIdentity},
    operator::netrc_authorization,
};

mod nar_stream;
mod narinfo;
mod payload;
mod plan;
mod root;
mod signing;
mod store;
mod transfer;
mod upstream;
use nar_stream::{open_verified_encoded_nar_reader, open_verified_nar_reader};
use narinfo::serialize_narinfo;
use payload::prepare_nar;
use plan::dependency_waves;
use root::StoreRoots;
use signing::sign_metadata;
use store::closure_paths;
#[cfg(test)]
use transfer::{get_bounded, put_file, request_status};
use transfer::{put_bytes, put_reader};
use upstream::{CacheLookup, PushDisposition, TrustedUpstreams};

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

    /// Trusted binary cache consulted before generating an upload. Repeat in lookup order.
    #[arg(long = "trusted-upstream", value_name = "URL")]
    trusted_upstreams: Vec<HttpUrl>,

    /// Nix public key trusted for one upstream: UPSTREAM#NAME:BASE64. Repeat for key rotation.
    #[arg(long = "trusted-upstream-key", value_name = "UPSTREAM#NAME:BASE64")]
    trusted_upstream_keys: Vec<String>,

    /// Concrete local store paths whose closures should be pushed.
    #[arg(value_name = "STORE_PATH", required = true, num_args = 1..)]
    paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingNarinfo {
    Skip,
    Refresh,
}

enum NarinfoUpload {
    Skip,
    Required,
}

impl From<bool> for ExistingNarinfo {
    fn from(refresh: bool) -> Self {
        match refresh {
            true => Self::Refresh,
            false => Self::Skip,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PushReport {
    uploaded: usize,
    destination_present: usize,
    trusted_upstream_present: usize,
}

impl PushReport {
    fn merge(&mut self, other: Self) {
        self.uploaded += other.uploaded;
        self.destination_present += other.destination_present;
        self.trusted_upstream_present += other.trusted_upstream_present;
    }
}

#[derive(Clone)]
struct NativeCopyOptions {
    target: HttpUrl,
    netrc_file: Option<PathBuf>,
    insecure_http: bool,
    existing_narinfo: ExistingNarinfo,
    compression: Compression,
    timeout_seconds: NonZeroU64,
    trusted_upstreams: TrustedUpstreams,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathInfo {
    path: String,
    ca: Option<String>,
    deriver: Option<String>,
    nar: NarIdentity,
    references: Vec<String>,
    signatures: Vec<String>,
}

pub(crate) fn run(args: Push) -> Result<(), Error> {
    let trusted_upstreams =
        TrustedUpstreams::from_configuration(&args.trusted_upstreams, &args.trusted_upstream_keys)
            .map_err(Error::runtime)?;
    let mut metadata = closure_paths(&args.paths).map_err(Error::runtime)?;
    let _roots = StoreRoots::hold(&args.paths).map_err(Error::runtime)?;
    if let Some(key_file) = args.signing_key_file.as_deref() {
        sign_metadata(key_file, &mut metadata).map_err(Error::runtime)?;
    }
    let waves = dependency_waves(metadata)?;
    let total_paths = waves.iter().map(Vec::len).sum::<usize>();
    let worker_count = args.jobs.get().min(total_paths);
    let copy_options = NativeCopyOptions {
        target: args.to,
        netrc_file: args.netrc_file,
        insecure_http: args.insecure_http,
        existing_narinfo: ExistingNarinfo::from(args.refresh),
        compression: args.compression,
        timeout_seconds: args.timeout_seconds,
        trusted_upstreams,
    };

    let mut failures = 0;
    let mut report = PushReport::default();
    for wave in waves {
        let wave_worker_count = args.jobs.get().min(wave.len());
        let chunk_size = wave.len().div_ceil(wave_worker_count);
        let mut workers = Vec::with_capacity(wave_worker_count);

        for chunk in wave.chunks(chunk_size) {
            let copy_options = copy_options.clone();
            let metadata = chunk.to_vec();
            workers.push(thread::spawn(move || {
                native_copy_paths(&copy_options, &metadata)
            }));
        }

        for worker in workers {
            match worker.join() {
                Ok(Ok(worker_report)) => report.merge(worker_report),
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
        println!(
            "push complete: uploaded {}, destination-present {}, trusted-upstream-present {}; {worker_count} workers",
            report.uploaded, report.destination_present, report.trusted_upstream_present
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

fn native_copy_paths(
    options: &NativeCopyOptions,
    metadata: &[PathInfo],
) -> Result<PushReport, String> {
    let authorization = options
        .netrc_file
        .as_deref()
        .map(|path| {
            netrc_authorization(path, &options.target, options.insecure_http)
                .map_err(|error| error.to_string())
        })
        .transpose()?
        .flatten();
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(options.timeout_seconds.get())))
        .build()
        .into();
    let lookup = CacheLookup::new(
        &agent,
        &options.target,
        authorization.as_deref(),
        options.existing_narinfo,
        &options.trusted_upstreams,
    );

    let mut report = PushReport::default();
    for info in metadata {
        match lookup.classify(info)? {
            PushDisposition::DestinationPresent => report.destination_present += 1,
            PushDisposition::TrustedUpstreamPresent(upstream) => {
                println!(
                    "skipped {}: trusted upstream {}",
                    info.path,
                    upstream.identity()
                );
                report.trusted_upstream_present += 1;
            }
            PushDisposition::UploadRequired => {
                upload_path(
                    &agent,
                    &options.target,
                    authorization.as_deref(),
                    options.compression,
                    info,
                )?;
                report.uploaded += 1;
            }
        }
    }
    Ok(report)
}

fn upload_path(
    agent: &Agent,
    target: &HttpUrl,
    authorization: Option<&str>,
    compression: Compression,
    info: &PathInfo,
) -> Result<(), String> {
    let store_hash = store_hash_for_path(&info.path)?;
    let narinfo_url = target.endpoint(&[&format!("{store_hash}.narinfo")]);
    if compression == Compression::None {
        let nar_name = format!("{}{}", info.nar.hash(), Compression::None.suffix());
        let nar_url = target.endpoint(&["nar", &nar_name]);
        let nar_status = put_reader(
            agent,
            &nar_url,
            info.nar.size().get(),
            "application/x-nix-nar",
            authorization,
            || open_verified_nar_reader(info),
        )?;
        require_successful_upload("NAR", info, nar_status)?;
        let narinfo = serialize_narinfo(
            info,
            FileHash::from_nar_hash(info.nar.hash()),
            EncodedSize::new(info.nar.size().get()),
            compression,
        )?;
        return upload_narinfo(agent, &narinfo_url, authorization, info, &narinfo);
    }

    let prepared = prepare_nar(info, compression)?;
    let nar_name = format!("{}{}", prepared.identity.hash(), compression.suffix());
    let nar_url = target.endpoint(&["nar", &nar_name]);
    let nar_status = put_reader(
        agent,
        &nar_url,
        prepared.identity.size().get(),
        "application/x-nix-nar",
        authorization,
        || open_verified_encoded_nar_reader(info, compression, prepared.identity),
    )?;
    require_successful_upload("NAR", info, nar_status)?;

    let narinfo = serialize_narinfo(
        info,
        prepared.identity.hash(),
        prepared.identity.size(),
        compression,
    )?;
    upload_narinfo(agent, &narinfo_url, authorization, info, &narinfo)
}

fn upload_narinfo(
    agent: &Agent,
    narinfo_url: &HttpUrl,
    authorization: Option<&str>,
    info: &PathInfo,
    narinfo: &[u8],
) -> Result<(), String> {
    let status = put_bytes(
        agent,
        narinfo_url,
        narinfo,
        "text/x-nix-narinfo",
        authorization,
    )?;
    require_successful_upload("narinfo", info, status)
}

fn require_successful_upload(kind: &str, info: &PathInfo, status: u16) -> Result<(), String> {
    match status {
        200 | 201 => Ok(()),
        _ => Err(format!(
            "{kind} upload for {} returned HTTP {status}",
            info.path
        )),
    }
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

    use super::transfer::{is_retryable_status, retry_after_delay};
    use super::{
        Agent, Compression, PathInfo, Push, TrustedUpstreams, dependency_waves, serialize_narinfo,
    };
    use crate::http_url::HttpUrl;
    use crate::object::{EncodedSize, FileHash, NarHash, NarIdentity, NarSize};

    fn http_url(value: impl AsRef<str>) -> HttpUrl {
        value.as_ref().parse().expect("test HTTP URL should parse")
    }

    fn test_nar_identity() -> NarIdentity {
        NarIdentity::new(
            NarHash::parse("01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai")
                .expect("test NAR hash should parse"),
            NarSize::new(289_656),
        )
    }
    use std::time::Duration;

    #[test]
    fn serializes_signed_narinfo_from_path_info() {
        let info = PathInfo {
            path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package".to_owned(),
            deriver: Some("/nix/store/abcdefghijklmnopqrstuvwxyz0123456789.drv".to_owned()),
            nar: test_nar_identity(),
            references: vec![
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency".to_owned(),
                "/nix/store/11111111111111111111111111111111-dependency".to_owned(),
            ],
            signatures: vec!["cache.example:signature".to_owned()],
            ca: Some("fixed:sha256:0123456789abcdef".to_owned()),
        };

        let bytes = serialize_narinfo(
            &info,
            FileHash::from_nar_hash(info.nar.hash()),
            EncodedSize::new(info.nar.size().get()),
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
    fn bounded_get_rejects_an_oversized_response() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bounded GET listener");
        let address = listener.local_addr().expect("inspect bounded GET listener");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept bounded GET request");
            let mut request = [0];
            stream
                .read_exact(&mut request)
                .expect("read bounded GET request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345"
            )
            .expect("write oversized GET response");
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        let error = super::get_bounded(
            &agent,
            &http_url(format!("http://{address}/narinfo")),
            None,
            4,
        )
        .expect_err("oversized GET response must be rejected");
        assert!(error.contains("exceeded 4 bytes"));
        server.join().expect("bounded GET server should exit");
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

        for redirect_status in [301, 302, 303, 307, 308] {
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
                    "HTTP/1.1 {redirect_status} Redirect\r\nLocation: /redirected/narinfo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
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
        let payload_size = fs::metadata(payload.path())
            .expect("stat upload test file")
            .len();
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
            super::put_reader(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload_size,
                "application/x-nix-nar",
                None,
                || {
                    std::fs::File::open(payload.path())
                        .map(|file| Box::new(file) as Box<dyn std::io::Read + Send>)
                        .map_err(|error| error.to_string())
                }
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
    fn trusted_upstream_urls_and_keys_must_be_configured_together() {
        for arguments in [
            [
                "push",
                "--to",
                "https://cache.example",
                "--trusted-upstream",
                "https://cache.nixos.org",
                "/run/current-system",
            ]
            .as_slice(),
            [
                "push",
                "--to",
                "https://cache.example",
                "--trusted-upstream-key",
                "https://cache.example#cache.example:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "/run/current-system",
            ]
            .as_slice(),
        ] {
            let matches = Push::augment_args(Command::new("push"))
                .try_get_matches_from(arguments)
                .expect("individual upstream options should parse");
            let push = Push::from_arg_matches(&matches).expect("push arguments should parse");
            assert!(
                TrustedUpstreams::from_configuration(
                    &push.trusted_upstreams,
                    &push.trusted_upstream_keys,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn trusted_upstream_keys_must_name_each_configured_upstream() {
        let urls = [
            http_url("https://first.example"),
            http_url("https://second.example"),
        ];
        let first_key =
            "https://first.example#first:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
        assert!(TrustedUpstreams::from_configuration(&urls, &[first_key]).is_err());

        let unknown_key =
            "https://unknown.example#unknown:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .to_owned();
        assert!(TrustedUpstreams::from_configuration(&urls, &[unknown_key]).is_err());
    }

    #[test]
    fn dependency_waves_put_references_before_dependents() {
        let dependency = PathInfo {
            path: "/nix/store/00000000000000000000000000000000-dependency".to_owned(),
            ca: None,
            deriver: None,
            nar: test_nar_identity(),
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
            nar: test_nar_identity(),
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
            nar: test_nar_identity(),
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
