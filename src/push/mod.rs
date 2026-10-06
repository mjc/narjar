use std::{
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    thread,
    time::Duration,
};

use clap::Args;
use narjar::{
    __private::narinfo::{MAX_NARINFO_BYTES, NarInfoClaims, NarInfoMetadata},
    object::{NarRepresentation, WireEncoding},
};
use ureq::{Agent, http::StatusCode};

use crate::{error::Error, http_url::HttpUrl, operator::netrc_authorization};

mod nar_stream;
mod payload;
mod plan;
mod root;
mod signing;
mod store;
mod transfer;
mod upstream;
use nar_stream::open_upload_reader;
use payload::measure_encoded_nar;
use plan::dependency_waves;
use root::StoreRoots;
use signing::sign_metadata;
use store::LocalStore;
#[cfg(test)]
use transfer::request_status;
use transfer::{LookupPurpose, get_bounded, put};
use upstream::{CacheLookup, PushDisposition, TrustedUpstreams};

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("{message}")]
pub(super) struct PushError {
    message: String,
}

impl PushError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[cfg(test)]
    fn contains(&self, needle: &str) -> bool {
        self.message.contains(needle)
    }
}

impl From<String> for PushError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for PushError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

impl From<crate::http_url::HttpUrlError> for PushError {
    fn from(error: crate::http_url::HttpUrlError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<PushError> for String {
    fn from(error: PushError) -> Self {
        error.message
    }
}

#[derive(Debug, Args)]
pub(crate) struct Push {
    /// Destination binary cache store URI.
    #[arg(long)]
    to: HttpUrl,

    /// Maximum number of native HTTP upload workers.
    #[arg(long, default_value_t = NonZeroUsize::new(1).unwrap())]
    jobs: NonZeroUsize,

    /// Compression used for the uploaded NAR payload; the cache independently selects its served representation.
    #[arg(long, default_value = "none")]
    compression: WireEncoding,

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

    /// Keep publishing when a destination already has different immutable metadata.
    #[arg(long)]
    ignore_conflicts: bool,

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
enum DestinationNarinfoPolicy {
    ReuseExisting,
    Refresh,
}

impl DestinationNarinfoPolicy {
    const fn from_refresh_flag(refresh: bool) -> Self {
        match refresh {
            true => Self::Refresh,
            false => Self::ReuseExisting,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PushReport {
    uploaded: usize,
    destination_present: usize,
    trusted_upstream_present: usize,
    conflicts: usize,
}

impl PushReport {
    fn merge(&mut self, other: Self) {
        self.uploaded += other.uploaded;
        self.destination_present += other.destination_present;
        self.trusted_upstream_present += other.trusted_upstream_present;
        self.conflicts += other.conflicts;
    }

    fn record(&mut self, outcome: PushOutcome) {
        match outcome {
            PushOutcome::Uploaded => self.uploaded += 1,
            PushOutcome::DestinationPresent => self.destination_present += 1,
            PushOutcome::TrustedUpstreamPresent => self.trusted_upstream_present += 1,
            PushOutcome::Conflict => self.conflicts += 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushOutcome {
    Uploaded,
    DestinationPresent,
    TrustedUpstreamPresent,
    Conflict,
}

#[derive(Clone)]
struct NativeCopyOptions {
    target: HttpUrl,
    netrc_file: Option<PathBuf>,
    insecure_http: bool,
    destination_narinfo: DestinationNarinfoPolicy,
    ignore_conflicts: bool,
    compression: WireEncoding,
    timeout_seconds: NonZeroU64,
    trusted_upstreams: TrustedUpstreams,
}

impl NativeCopyOptions {
    fn from_args(args: &Push) -> Result<Self, Error> {
        let trusted_upstreams = TrustedUpstreams::from_configuration(
            &args.trusted_upstreams,
            &args.trusted_upstream_keys,
        )
        .map_err(Error::runtime)?;
        Ok(Self {
            target: args.to.clone(),
            netrc_file: args.netrc_file.clone(),
            insecure_http: args.insecure_http,
            destination_narinfo: DestinationNarinfoPolicy::from_refresh_flag(args.refresh),
            ignore_conflicts: args.ignore_conflicts,
            compression: args.compression,
            timeout_seconds: args.timeout_seconds,
            trusted_upstreams,
        })
    }
}

struct PreparedPush {
    _roots: StoreRoots,
    waves: Vec<Vec<NarInfoMetadata>>,
}

impl PreparedPush {
    fn total_paths(&self) -> usize {
        self.waves.iter().map(Vec::len).sum()
    }
}

pub(crate) fn run(args: Push) -> Result<(), Error> {
    let copy_options = NativeCopyOptions::from_args(&args)?;
    let prepared = prepare_push(&args)?;
    let worker_count = args.jobs.get().min(prepared.total_paths());
    let report = run_dependency_waves(&prepared.waves, &copy_options, args.jobs)?;
    println!(
        "push complete: uploaded {}, destination-present {}, trusted-upstream-present {}; {worker_count} workers",
        report.uploaded, report.destination_present, report.trusted_upstream_present
    );
    if report.conflicts > 0 {
        eprintln!(
            "narjar push: skipped {} immutable destination conflict(s)",
            report.conflicts
        );
    }
    Ok(())
}

fn prepare_push(args: &Push) -> Result<PreparedPush, Error> {
    let (roots, mut metadata) = StoreRoots::hold_while_reading_metadata(&args.paths, |state_dir| {
        LocalStore::open(state_dir)?.closure_paths(&args.paths)
    })
    .map_err(Error::runtime)?;
    if let Some(key_file) = args.signing_key_file.as_deref() {
        sign_metadata(key_file, &mut metadata).map_err(Error::runtime)?;
    }
    Ok(PreparedPush {
        _roots: roots,
        waves: dependency_waves(metadata)?,
    })
}

fn run_dependency_waves(
    waves: &[Vec<NarInfoMetadata>],
    copy_options: &NativeCopyOptions,
    jobs: NonZeroUsize,
) -> Result<PushReport, Error> {
    waves
        .iter()
        .try_fold(PushReport::default(), |mut report, wave| {
            report.merge(run_dependency_wave(wave, copy_options, jobs)?);
            Ok(report)
        })
}

fn run_dependency_wave(
    wave: &[NarInfoMetadata],
    copy_options: &NativeCopyOptions,
    jobs: NonZeroUsize,
) -> Result<PushReport, Error> {
    let worker_count = jobs.get().min(wave.len());
    let chunk_size = wave.len().div_ceil(worker_count);
    let workers = wave
        .chunks(chunk_size)
        .map(|metadata| spawn_copy_worker(copy_options, metadata))
        .collect::<Vec<_>>();
    collect_copy_worker_results(workers)
}

fn spawn_copy_worker(copy_options: &NativeCopyOptions, metadata: &[NarInfoMetadata]) -> CopyWorker {
    let copy_options = copy_options.clone();
    let metadata = metadata.to_vec();
    thread::spawn(move || native_copy_paths(&copy_options, &metadata))
}

fn collect_copy_worker_results(workers: Vec<CopyWorker>) -> Result<PushReport, Error> {
    let mut report = PushReport::default();
    let mut failures = 0;
    for worker in workers {
        match join_copy_worker(worker) {
            Ok(worker_report) => report.merge(worker_report),
            Err(failure) => {
                eprintln!("narjar push: {failure}");
                failures += 1;
            }
        }
    }
    match failures {
        0 => Ok(report),
        failures => Err(Error::runtime(format!("{failures} push workers failed"))),
    }
}

type CopyWorker = thread::JoinHandle<Result<PushReport, PushError>>;

#[derive(Debug, Eq, PartialEq)]
enum CopyWorkerFailure {
    Push(PushError),
    Panicked,
}

impl fmt::Display for CopyWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push(message) => message.fmt(formatter),
            Self::Panicked => formatter.write_str("worker panicked"),
        }
    }
}

fn join_copy_worker(worker: CopyWorker) -> Result<PushReport, CopyWorkerFailure> {
    match worker.join() {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(message)) => Err(CopyWorkerFailure::Push(message)),
        Err(_) => Err(CopyWorkerFailure::Panicked),
    }
}

fn native_copy_paths(
    options: &NativeCopyOptions,
    metadata: &[NarInfoMetadata],
) -> Result<PushReport, PushError> {
    let client = DestinationClient::new(options)?;
    let lookup = CacheLookup::new(
        &client,
        options.destination_narinfo,
        &options.trusted_upstreams,
    );

    metadata
        .iter()
        .try_fold(PushReport::default(), |mut report, info| {
            report.record(copy_path(&lookup, &client, options, info)?);
            Ok(report)
        })
}

struct DestinationClient {
    base_url: HttpUrl,
    agent: Agent,
    authorization: Option<String>,
}

impl DestinationClient {
    fn new(options: &NativeCopyOptions) -> Result<Self, PushError> {
        let authorization = authorization_for_destination(options)?;
        let agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(options.timeout_seconds.get())))
            .build()
            .into();
        Ok(Self {
            base_url: options.target.clone(),
            agent,
            authorization,
        })
    }

    fn upload_path(
        &self,
        compression: WireEncoding,
        info: &NarInfoMetadata,
    ) -> Result<PushOutcome, PushError> {
        let narinfo_url = narinfo_url(&self.base_url, info);
        let payload = prepare_nar_upload(info, compression)?;
        let nar_name = payload.file_name().to_string();
        let nar_url = self.base_url.endpoint(&["nar", &nar_name]);
        let nar_status = put(
            &self.agent,
            &nar_url,
            payload.encoded_size().get(),
            "application/x-nix-nar",
            self.authorization.as_deref(),
            || open_upload_reader(payload, info).map(ureq::SendBody::from_owned_reader),
        )?;
        self.accept_upload_response(UploadArtifact::Nar, info, nar_status)?;

        let narinfo = info.serialize(payload).map_err(|error| error.to_string())?;
        let narinfo_status = put(
            &self.agent,
            &narinfo_url,
            narinfo.len() as u64,
            "text/x-nix-narinfo",
            self.authorization.as_deref(),
            || Ok(narinfo.as_slice()),
        )?;
        self.accept_upload_response(UploadArtifact::Narinfo, info, narinfo_status)
    }

    fn accept_upload_response(
        &self,
        artifact: UploadArtifact,
        info: &NarInfoMetadata,
        status: StatusCode,
    ) -> Result<PushOutcome, PushError> {
        match (artifact, status) {
            (_, StatusCode::OK | StatusCode::CREATED) => Ok(PushOutcome::Uploaded),
            (UploadArtifact::Narinfo, StatusCode::CONFLICT) => match self.narinfo_state(info)? {
                DestinationNarinfoState::Present => Ok(PushOutcome::DestinationPresent),
                DestinationNarinfoState::DifferentStorePath
                | DestinationNarinfoState::Unusable
                | DestinationNarinfoState::Missing => Ok(PushOutcome::Conflict),
            },
            _ => Err(format!(
                "{artifact} upload for {} returned HTTP {status}",
                info.claims().store_path()
            )
            .into()),
        }
    }

    fn narinfo_state(&self, info: &NarInfoMetadata) -> Result<DestinationNarinfoState, PushError> {
        let response = get_bounded(
            &self.agent,
            &narinfo_url(&self.base_url, info),
            self.authorization.as_deref(),
            MAX_NARINFO_BYTES,
            LookupPurpose::Destination,
        )?;
        match response {
            transfer::GetResponse::Found(body) => {
                let state = match NarInfoClaims::parse_external_narinfo(info.claims().store(), body)
                {
                    Ok(claims) => {
                        if claims.store_path() == info.claims().store_path() {
                            DestinationNarinfoState::Present
                        } else {
                            DestinationNarinfoState::DifferentStorePath
                        }
                    }
                    Err(_) => DestinationNarinfoState::Unusable,
                };
                Ok(state)
            }
            transfer::GetResponse::Missing => Ok(DestinationNarinfoState::Missing),
            transfer::GetResponse::UnexpectedStatus(status) => Err(format!(
                "narinfo lookup for {} returned HTTP {status}",
                info.claims().store_path()
            )
            .into()),
        }
    }
}

fn narinfo_url(base_url: &HttpUrl, info: &NarInfoMetadata) -> HttpUrl {
    base_url.endpoint(&[&format!("{}.narinfo", info.claims().store().as_str())])
}

fn authorization_for_destination(options: &NativeCopyOptions) -> Result<Option<String>, PushError> {
    match options.netrc_file.as_deref() {
        Some(path) => Ok(
            netrc_authorization(path, &options.target, options.insecure_http)
                .map_err(|error| error.to_string())?,
        ),
        None => Ok(None),
    }
}

fn copy_path(
    lookup: &CacheLookup<'_>,
    client: &DestinationClient,
    options: &NativeCopyOptions,
    info: &NarInfoMetadata,
) -> Result<PushOutcome, PushError> {
    let outcome = match lookup.classify(info)? {
        PushDisposition::DestinationPresent => PushOutcome::DestinationPresent,
        PushDisposition::DestinationConflict => PushOutcome::Conflict,
        PushDisposition::TrustedUpstreamPresent(upstream) => {
            println!(
                "skipped {}: trusted upstream {upstream}",
                info.claims().store_path()
            );
            PushOutcome::TrustedUpstreamPresent
        }
        PushDisposition::UploadRequired => client.upload_path(options.compression, info)?,
    };
    match outcome {
        PushOutcome::Conflict if options.ignore_conflicts => {
            eprintln!(
                "narjar push: skipping immutable conflict for {}",
                info.claims().store_path()
            );
            Ok(PushOutcome::Conflict)
        }
        PushOutcome::Conflict => Err(format!(
            "immutable destination conflict for {}",
            info.claims().store_path()
        )
        .into()),
        outcome => Ok(outcome),
    }
}

fn prepare_nar_upload(
    info: &NarInfoMetadata,
    encoding: WireEncoding,
) -> Result<NarRepresentation, PushError> {
    match encoding {
        WireEncoding::Raw => Ok(NarRepresentation::Raw(info.claims().identity())),
        WireEncoding::Compressed(codec) => measure_encoded_nar(info, codec)
            .map(|encoded| NarRepresentation::compressed(encoded, info.claims().identity())),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UploadArtifact {
    Nar,
    Narinfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationNarinfoState {
    Present,
    DifferentStorePath,
    Unusable,
    Missing,
}

impl fmt::Display for UploadArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nar => formatter.write_str("NAR"),
            Self::Narinfo => formatter.write_str("narinfo"),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{Args, Command, FromArgMatches};

    use super::transfer::retry_after_delay;
    use super::{
        Agent, DestinationClient, NarInfoMetadata, Push, TrustedUpstreams, dependency_waves,
    };
    use crate::http_url::HttpUrl;
    use narjar::object::{NarHash, NarIdentity, NarRepresentation, NarSize};
    use ureq::http::StatusCode;

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

    fn test_narinfo_metadata(path: &str, references: Vec<String>) -> NarInfoMetadata {
        NarInfoMetadata::from_store_metadata(
            path.to_owned(),
            None,
            None,
            test_nar_identity(),
            references,
            Vec::new(),
        )
        .expect("valid narinfo metadata fixture")
    }
    use std::time::Duration;

    fn accept_http_test_connection(listener: &std::net::TcpListener) -> std::net::TcpStream {
        use std::{io::ErrorKind, thread, time::Instant};

        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (stream, _) = std::iter::repeat_with(|| {
            thread::sleep(Duration::from_millis(1));
            listener.accept()
        })
        .take_while(|_| Instant::now() < deadline)
        .find_map(|result| match result {
            Ok(connection) => Some(connection),
            Err(error) if error.kind() == ErrorKind::WouldBlock => None,
            Err(error) => panic!("accept test HTTP request: {error}"),
        })
        .expect("push must make its HTTP request before the deadline");
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    #[test]
    fn an_existing_store_path_wins_without_reading_or_uploading_another_build() {
        use super::{
            CacheLookup, DestinationNarinfoPolicy, NativeCopyOptions, PushOutcome, copy_path,
        };
        use narjar::object::{CompressionCodec, WireEncoding};
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            num::NonZeroU64,
            path::Path,
            thread,
        };

        let path = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package";
        assert!(
            !Path::new(path).exists(),
            "the test must not have a NAR to read"
        );
        let info = test_narinfo_metadata(path, Vec::new());
        let different = NarInfoMetadata::from_store_metadata(
            path.to_owned(),
            None,
            None,
            NarIdentity::new(NarHash::parse(&"0".repeat(52)).unwrap(), NarSize::new(123)),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let body = different
            .serialize(NarRepresentation::Raw(different.claims().identity()))
            .unwrap();

        for compression in [
            WireEncoding::Raw,
            WireEncoding::Compressed(CompressionCodec::Xz),
            WireEncoding::Compressed(CompressionCodec::Zstd),
        ] {
            for ignore_conflicts in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let target = http_url(format!("http://{}", listener.local_addr().unwrap()));
                let response_body = body.clone();
                let server = thread::spawn(move || {
                    let mut stream = accept_http_test_connection(&listener);
                    let headers: Vec<_> = BufReader::new(&mut stream)
                        .lines()
                        .map(Result::unwrap)
                        .take_while(|line| !line.is_empty())
                        .collect();
                    assert_eq!(
                        headers[0],
                        "GET /0123456789abcdfghijklmnpqrsvwxyz.narinfo HTTP/1.1"
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_body.len()
                    )
                    .unwrap();
                    stream.write_all(&response_body).unwrap();
                    listener
                });
                let options = NativeCopyOptions {
                    target: target.clone(),
                    netrc_file: None,
                    insecure_http: true,
                    destination_narinfo: DestinationNarinfoPolicy::ReuseExisting,
                    ignore_conflicts,
                    compression,
                    timeout_seconds: NonZeroU64::new(5).unwrap(),
                    trusted_upstreams: TrustedUpstreams::from_configuration(&[], &[]).unwrap(),
                };
                let client = DestinationClient {
                    base_url: target,
                    agent: Agent::config_builder()
                        .timeout_global(Some(Duration::from_secs(5)))
                        .http_status_as_error(false)
                        .build()
                        .into(),
                    authorization: None,
                };
                let lookup = CacheLookup::new(
                    &client,
                    options.destination_narinfo,
                    &options.trusted_upstreams,
                );
                let outcome = copy_path(&lookup, &client, &options, &info);
                let listener = server.join().unwrap();
                listener.set_nonblocking(true).unwrap();
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "an existing publication must never trigger another PUT"
                );
                assert_eq!(outcome.unwrap(), PushOutcome::DestinationPresent);
            }
        }
    }

    #[test]
    fn serializes_signed_narinfo_from_shared_metadata() {
        let info = NarInfoMetadata::from_store_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package".to_owned(),
            Some(format!("fixed:sha256:{}", "0".repeat(64))),
            Some("/nix/store/11111111111111111111111111111111-deriver.drv".to_owned()),
            test_nar_identity(),
            vec![
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency".to_owned(),
                "/nix/store/11111111111111111111111111111111-dependency".to_owned(),
            ],
            vec!["cache.example:signature".to_owned()],
        )
        .expect("valid narinfo metadata fixture");

        let bytes = info
            .serialize(NarRepresentation::Raw(info.claims().identity()))
            .expect("narinfo metadata should serialize");
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
             Deriver: 11111111111111111111111111111111-deriver.drv\n\
             CA: fixed:sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        );
    }

    #[test]
    fn accepts_matching_narinfo_after_immutable_conflict() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let info = test_narinfo_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package",
            Vec::new(),
        );
        let body = info
            .serialize(NarRepresentation::Raw(info.claims().identity()))
            .expect("narinfo fixture should serialize");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind narinfo conflict listener");
        let address = listener
            .local_addr()
            .expect("inspect narinfo conflict listener");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept narinfo verification GET");
            let mut request = [0; 1024];
            let read = stream
                .read(&mut request)
                .expect("read narinfo verification GET");
            assert!(
                String::from_utf8_lossy(&request[..read])
                    .starts_with("GET /0123456789abcdfghijklmnpqrsvwxyz.narinfo HTTP/1.1")
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write narinfo verification headers");
            stream
                .write_all(&body)
                .expect("write narinfo verification body");
        });

        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let client = DestinationClient {
            base_url: http_url(format!("http://{address}")),
            agent,
            authorization: None,
        };
        let result = client.accept_upload_response(
            super::UploadArtifact::Narinfo,
            &info,
            StatusCode::CONFLICT,
        );

        assert!(
            result.is_ok(),
            "matching immutable narinfo should be accepted"
        );
        server
            .join()
            .expect("narinfo verification server should exit");
    }

    #[test]
    fn narinfo_conflict_verification_preserves_unexpected_http_statuses() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let info = test_narinfo_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package",
            Vec::new(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind status test listener");
        let address = listener.local_addr().expect("inspect status test listener");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept status verification GET");
            let mut request = [0; 1024];
            let read = stream
                .read(&mut request)
                .expect("read status verification GET");
            assert!(
                String::from_utf8_lossy(&request[..read])
                    .starts_with("GET /0123456789abcdfghijklmnpqrsvwxyz.narinfo HTTP/1.1")
            );
            stream
                .write_all(
                    b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write unexpected status response");
        });
        let client = DestinationClient {
            base_url: http_url(format!("http://{address}")),
            agent: Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
            authorization: None,
        };

        let error = client
            .narinfo_state(&info)
            .expect_err("unexpected verification status should propagate");
        assert!(error.contains("HTTP 418"));
        server
            .join()
            .expect("status verification server should exit");
    }

    #[test]
    fn preflight_and_publication_races_agree_that_the_first_store_path_publication_wins() {
        use super::{CacheLookup, DestinationNarinfoPolicy, PushDisposition, PushOutcome};
        use narjar::object::{CompressionCodec, EncodedIdentity, EncodedSize, FileHash};
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            thread,
        };

        let path = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package";
        let info = test_narinfo_metadata(path, Vec::new());
        let different = test_narinfo_metadata(
            path,
            vec!["/nix/store/11111111111111111111111111111111-dependency".to_owned()],
        );
        let another_build = NarInfoMetadata::from_store_metadata(
            path.to_owned(),
            None,
            None,
            NarIdentity::new(NarHash::from_digest([0; 32]), NarSize::new(123)),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let another_name = test_narinfo_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-other-package",
            Vec::new(),
        );
        let raw = NarRepresentation::Raw(info.claims().identity());
        let compressed = |codec| {
            NarRepresentation::compressed(
                EncodedIdentity::new(
                    codec,
                    FileHash::parse(&"0".repeat(52)).unwrap(),
                    EncodedSize::new(123),
                ),
                info.claims().identity(),
            )
        };
        for (status, body, preflight, conflict) in [
            (
                200,
                info.serialize(raw).unwrap(),
                PushDisposition::DestinationPresent,
                PushOutcome::DestinationPresent,
            ),
            (
                200,
                info.serialize(compressed(CompressionCodec::Xz)).unwrap(),
                PushDisposition::DestinationPresent,
                PushOutcome::DestinationPresent,
            ),
            (
                200,
                info.serialize(compressed(CompressionCodec::Zstd)).unwrap(),
                PushDisposition::DestinationPresent,
                PushOutcome::DestinationPresent,
            ),
            (
                200,
                different.serialize(raw).unwrap(),
                PushDisposition::DestinationPresent,
                PushOutcome::DestinationPresent,
            ),
            (
                200,
                another_build
                    .serialize(NarRepresentation::Raw(another_build.claims().identity()))
                    .unwrap(),
                PushDisposition::DestinationPresent,
                PushOutcome::DestinationPresent,
            ),
            (
                200,
                another_name.serialize(raw).unwrap(),
                PushDisposition::DestinationConflict,
                PushOutcome::Conflict,
            ),
            (
                200,
                b"invalid narinfo".to_vec(),
                PushDisposition::UploadRequired,
                PushOutcome::Conflict,
            ),
            (
                404,
                Vec::new(),
                PushDisposition::UploadRequired,
                PushOutcome::Conflict,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                for _ in 0..2 {
                    let mut stream = accept_http_test_connection(&listener);
                    let headers: Vec<_> = BufReader::new(&mut stream)
                        .lines()
                        .map(Result::unwrap)
                        .take_while(|line| !line.is_empty())
                        .collect();
                    assert_eq!(
                        headers[0],
                        "GET /cache/0123456789abcdfghijklmnpqrsvwxyz.narinfo HTTP/1.1"
                    );
                    assert!(headers.iter().any(|line| {
                        line.eq_ignore_ascii_case("Authorization: Basic dGVzdDp0b2tlbg==")
                    }));
                    write!(
                        stream,
                        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
            });
            let client = DestinationClient {
                base_url: http_url(format!("http://{address}/cache")),
                agent: Agent::config_builder()
                    .timeout_global(Some(Duration::from_secs(5)))
                    .build()
                    .into(),
                authorization: Some("dGVzdDp0b2tlbg==".to_owned()),
            };
            let upstreams = TrustedUpstreams::from_configuration(&[], &[]).unwrap();
            let lookup =
                CacheLookup::new(&client, DestinationNarinfoPolicy::ReuseExisting, &upstreams);
            let preflight_result = lookup.classify(&info);
            let conflict_result = client.accept_upload_response(
                super::UploadArtifact::Narinfo,
                &info,
                StatusCode::CONFLICT,
            );
            server.join().unwrap();
            assert_eq!(preflight_result.unwrap(), preflight);
            assert_eq!(conflict_result.unwrap(), conflict);
        }
    }

    #[test]
    fn a_different_destination_store_path_never_queries_trusted_upstreams() {
        use super::{CacheLookup, DestinationNarinfoPolicy, PushDisposition};
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            thread,
        };

        let info = test_narinfo_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package",
            Vec::new(),
        );
        let different = test_narinfo_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-other-package",
            Vec::new(),
        );
        let body = different
            .serialize(NarRepresentation::Raw(different.claims().identity()))
            .unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = destination.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = destination.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            BufReader::new(&mut stream)
                .lines()
                .map(Result::unwrap)
                .take_while(|line| !line.is_empty())
                .for_each(drop);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream_listener.set_nonblocking(true).unwrap();
        let upstream = http_url(format!(
            "http://{}",
            upstream_listener.local_addr().unwrap()
        ));
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let keys = [format!(
            "{upstream}#test:{}",
            data_encoding::BASE64.encode(key.as_bytes())
        )];
        let upstreams = TrustedUpstreams::from_configuration(&[upstream], &keys).unwrap();
        let client = DestinationClient {
            base_url: http_url(format!("http://{address}")),
            agent: Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(5)))
                .build()
                .into(),
            authorization: None,
        };
        let lookup = CacheLookup::new(&client, DestinationNarinfoPolicy::ReuseExisting, &upstreams);
        let result = lookup.classify(&info);
        server.join().unwrap();
        assert_eq!(result.unwrap(), PushDisposition::DestinationConflict);
        assert_eq!(
            upstream_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "an upstream must never hide a conflicting destination entry"
        );
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
    fn retries_through_a_cache_restart_longer_than_the_request_burst() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind restart retry listener");
        let address = listener
            .local_addr()
            .expect("inspect restart retry listener");
        let server = thread::spawn(move || {
            let mut responses = [502, 502, 502, 502, 502, 502, 502, 200].into_iter();
            loop {
                let (mut stream, _) = listener.accept().expect("accept retry request");
                let mut request = [0; 1024];
                let read = stream.read(&mut request).expect("read retry request");
                if request[..read].starts_with(b"GET /stop") {
                    break;
                }
                let status = responses.next().expect("test sent too many requests");
                let retry_after = if status == 502 {
                    "Retry-After: 0\r\n"
                } else {
                    ""
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\n{retry_after}Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write retry response");
            }
        });
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        let status =
            super::request_status(&agent, &http_url(format!("http://{address}/narinfo")), None)
                .expect("restart retry should reach the recovered cache");
        let mut stop = TcpStream::connect(address).expect("connect to stop retry server");
        stop.write_all(b"GET /stop HTTP/1.1\r\n\r\n")
            .expect("stop retry server");
        server.join().expect("restart retry server should exit");
        assert_eq!(status, 200);
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
            super::LookupPurpose::Destination,
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
            super::put(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload_size,
                "application/x-nix-nar",
                None,
                || {
                    std::fs::File::open(payload.path())
                        .map(ureq::SendBody::from_owned_reader)
                        .map_err(|error| super::PushError::new(error.to_string()))
                }
            )
            .expect("upload retry should eventually succeed"),
            StatusCode::CREATED
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
            super::put(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload.as_file().metadata().unwrap().len(),
                "application/x-nix-nar",
                None,
                || std::fs::File::open(payload.path())
                    .map_err(|error| super::PushError::new(error.to_string()))
            )
            .expect("redirected upload should succeed"),
            StatusCode::CREATED
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
            super::put(
                &agent,
                &http_url(format!("http://{address}/nar/test.nar")),
                payload.as_file().metadata().unwrap().len(),
                "application/x-nix-nar",
                None,
                || std::fs::File::open(payload.path())
                    .map_err(|error| super::PushError::new(error.to_string()))
            )
            .expect("content-type upload should succeed"),
            StatusCode::CREATED
        );
        assert_eq!(
            super::put(
                &agent,
                &http_url(format!("http://{address}/store.narinfo")),
                b"StorePath: /nix/store/test\n".len() as u64,
                "text/x-nix-narinfo",
                None,
                || Ok(b"StorePath: /nix/store/test\n".as_slice())
            )
            .expect("narinfo content-type upload should succeed"),
            StatusCode::CREATED
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
    fn push_can_explicitly_skip_immutable_conflicts() {
        let matches = Push::augment_args(Command::new("push"))
            .try_get_matches_from([
                "push",
                "--to",
                "https://cache.example",
                "--ignore-conflicts",
                "/run/current-system",
            ])
            .expect("push options should parse");
        let push = Push::from_arg_matches(&matches).expect("push arguments should parse");

        assert!(push.ignore_conflicts);
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
        let dependency = test_narinfo_metadata(
            "/nix/store/00000000000000000000000000000000-dependency",
            Vec::new(),
        );
        let dependent = test_narinfo_metadata(
            "/nix/store/11111111111111111111111111111111-dependent",
            vec![dependency.claims().store_path().to_owned()],
        );

        let waves = dependency_waves(vec![dependent, dependency]).expect("acyclic closure");
        let paths = waves
            .into_iter()
            .map(|wave| {
                wave.into_iter()
                    .map(|info| info.claims().store_path().to_owned())
                    .collect::<Vec<_>>()
            })
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
        let info = test_narinfo_metadata(path, vec![path.to_owned()]);

        let waves =
            dependency_waves(vec![info]).expect("self references are not dependency cycles");
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 1);
        assert_eq!(waves[0][0].claims().store_path(), path);
    }

    #[test]
    fn dependency_waves_reject_missing_references() {
        let info = test_narinfo_metadata(
            "/nix/store/11111111111111111111111111111111-dependent",
            vec!["/nix/store/00000000000000000000000000000000-missing".to_owned()],
        );

        let error = dependency_waves(vec![info]).expect_err("missing references must fail");
        assert!(
            error.to_string().contains("missing referenced store path"),
            "unexpected error: {error}"
        );
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (&PushError::from("detail"), "detail"),
            (
                &PushError::from(String::from("owned detail")),
                "owned detail",
            ),
            (
                &PushError::from(crate::http_url::HttpUrlError::MissingHost),
                "URL must include a host",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }
}
