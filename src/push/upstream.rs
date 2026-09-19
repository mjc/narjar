use std::{fmt, sync::Arc};

use data_encoding::BASE64;
use fluent_uri::UriRef;
use narjar::{
    narinfo::{MAX_NARINFO_BYTES, TrustedPublicKeys},
    object::{FileHash, NarHash},
    storage::StoreHash,
};
use ureq::Agent;

use super::{
    ExistingNarinfo, PathInfo,
    narinfo::normalized_references,
    store_hash_for_path,
    transfer::{get_bounded, request_status},
};
use crate::http_url::HttpUrl;

#[derive(Clone)]
pub(super) struct TrustedUpstreams {
    entries: Arc<[ConfiguredUpstream]>,
}

impl TrustedUpstreams {
    pub(super) fn from_configuration(
        urls: &[HttpUrl],
        key_values: &[String],
    ) -> Result<Self, String> {
        if urls.is_empty() && key_values.is_empty() {
            return Ok(Self {
                entries: Arc::from([]),
            });
        }
        if urls.is_empty() {
            return Err("--trusted-upstream-key requires --trusted-upstream".to_owned());
        }
        if key_values.is_empty() {
            return Err("--trusted-upstream requires --trusted-upstream-key".to_owned());
        }

        let mut keys_by_url = vec![Vec::new(); urls.len()];
        for value in key_values {
            let (upstream, key) = value
                .split_once('#')
                .ok_or_else(|| "trusted upstream keys must use UPSTREAM#NAME:BASE64".to_owned())?;
            let upstream = upstream
                .parse::<HttpUrl>()
                .map_err(|error| format!("invalid trusted upstream URL in key: {error}"))?;
            let index = urls
                .iter()
                .position(|configured| configured == &upstream)
                .ok_or_else(|| {
                    format!("trusted upstream key is scoped to unconfigured upstream {upstream}")
                })?;
            keys_by_url[index].push(key.to_owned());
        }

        let mut entries = Vec::with_capacity(urls.len());
        for (url, keys) in urls.iter().cloned().zip(keys_by_url) {
            if keys.is_empty() {
                return Err(format!("no trusted upstream key configured for {url}"));
            }
            let keys = TrustedPublicKeys::parse(&keys.join(" "))
                .map_err(|error| format!("invalid trusted upstream key for {url}: {error}"))?;
            entries.push(ConfiguredUpstream {
                url,
                keys: Arc::new(keys),
            });
        }
        Ok(Self {
            entries: Arc::from(entries),
        })
    }
}

#[derive(Clone)]
struct ConfiguredUpstream {
    url: HttpUrl,
    keys: Arc<TrustedPublicKeys>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UpstreamIdentity(HttpUrl);

impl fmt::Display for UpstreamIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PushDisposition {
    DestinationPresent,
    TrustedUpstreamPresent(MatchedUpstream),
    UploadRequired,
}

pub(super) struct CacheLookup<'a> {
    agent: &'a Agent,
    destination: &'a HttpUrl,
    destination_authorization: Option<&'a str>,
    existing_narinfo: ExistingNarinfo,
    upstreams: &'a TrustedUpstreams,
}

impl<'a> CacheLookup<'a> {
    pub(super) fn new(
        agent: &'a Agent,
        destination: &'a HttpUrl,
        destination_authorization: Option<&'a str>,
        existing_narinfo: ExistingNarinfo,
        upstreams: &'a TrustedUpstreams,
    ) -> Self {
        Self {
            agent,
            destination,
            destination_authorization,
            existing_narinfo,
            upstreams,
        }
    }

    pub(super) fn classify(&self, info: &PathInfo) -> Result<PushDisposition, String> {
        match self.existing_narinfo {
            ExistingNarinfo::Refresh => return Ok(PushDisposition::UploadRequired),
            ExistingNarinfo::Skip => {}
        }

        let store_hash = store_hash_for_path(&info.path)?;
        let route = StoreHash::parse(store_hash).map_err(|error| error.to_string())?;
        let narinfo_name = format!("{store_hash}.narinfo");
        let destination_url = self.destination.endpoint(&[&narinfo_name]);
        match request_status(self.agent, &destination_url, self.destination_authorization)? {
            200 => return Ok(PushDisposition::DestinationPresent),
            404 => {}
            status => {
                return Err(format!(
                    "narinfo lookup for {} returned HTTP {status}",
                    info.path
                ));
            }
        }

        self.classify_upstream(&route, &narinfo_name, info)
    }

    fn classify_upstream(
        &self,
        route: &StoreHash,
        narinfo_name: &str,
        info: &PathInfo,
    ) -> Result<PushDisposition, String> {
        for upstream in self.upstreams.entries.iter() {
            match self.lookup_upstream(route, upstream, narinfo_name, info)? {
                UpstreamLookup::Matched(matched) => {
                    return Ok(PushDisposition::TrustedUpstreamPresent(matched));
                }
                UpstreamLookup::Rejected(reason) => eprintln!(
                    "narjar push: trusted upstream {} rejected for {}: {reason}; checking next source",
                    upstream.url, info.path
                ),
                UpstreamLookup::Missing => {}
            }
        }
        if !self.upstreams.entries.is_empty() {
            eprintln!(
                "narjar push: no trusted upstream matched {}; uploading instead",
                info.path
            );
        }
        Ok(PushDisposition::UploadRequired)
    }

    fn lookup_upstream(
        &self,
        route: &StoreHash,
        upstream: &ConfiguredUpstream,
        narinfo_name: &str,
        info: &PathInfo,
    ) -> Result<UpstreamLookup, String> {
        let url = upstream.url.endpoint(&[narinfo_name]);
        let response = match get_bounded(self.agent, &url, None, MAX_NARINFO_BYTES) {
            Ok(response) => response,
            Err(error) => {
                return Ok(UpstreamLookup::Rejected(format!("lookup failed: {error}")));
            }
        };
        match response.status {
            404 => return Ok(UpstreamLookup::Missing),
            200 => {}
            status => {
                return Ok(UpstreamLookup::Rejected(format!(
                    "lookup returned HTTP {status}"
                )));
            }
        }

        let parsed = match UnverifiedUpstreamNarInfo::parse(route, response.body) {
            Ok(parsed) => parsed,
            Err(error) => return Ok(UpstreamLookup::Rejected(error.to_string())),
        };
        let verified = match parsed.verify(&upstream.keys) {
            Ok(verified) => verified,
            Err(error) => return Ok(UpstreamLookup::Rejected(error.to_string())),
        };
        let expected_references = normalized_references(info)?;
        match compare_logical_claims(info, &expected_references, &verified) {
            Ok(()) => Ok(UpstreamLookup::Matched(MatchedUpstream {
                identity: UpstreamIdentity(upstream.url.clone()),
                claims: verified.claims,
            })),
            Err(mismatch) => Ok(UpstreamLookup::Rejected(mismatch.to_string())),
        }
    }
}

enum UpstreamLookup {
    Missing,
    Rejected(String),
    Matched(MatchedUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MatchedUpstream {
    identity: UpstreamIdentity,
    claims: UpstreamClaims,
}

impl MatchedUpstream {
    pub(super) fn identity(&self) -> &UpstreamIdentity {
        &self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UpstreamClaims {
    store_path: String,
    identity: UpstreamNarIdentity,
    references: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UpstreamNarIdentity {
    hash: NarHash,
    size: u64,
}

struct UnverifiedUpstreamNarInfo {
    claims: UpstreamClaims,
    fingerprint: String,
    signatures: Vec<UpstreamSignature>,
}

struct UpstreamSignature {
    name: String,
    bytes: Vec<u8>,
}

impl UnverifiedUpstreamNarInfo {
    fn parse(route: &StoreHash, bytes: Vec<u8>) -> Result<Self, UpstreamNarInfoError> {
        let text = String::from_utf8(bytes).map_err(|_| UpstreamNarInfoError::Malformed)?;
        if !text.ends_with('\n') || text.contains('\r') {
            return Err(UpstreamNarInfoError::Malformed);
        }

        let mut fields = Vec::with_capacity(11);
        let mut signatures = Vec::new();
        for line in text
            .strip_suffix('\n')
            .ok_or(UpstreamNarInfoError::Malformed)?
            .split('\n')
        {
            let (name, value) = line
                .split_once(": ")
                .ok_or(UpstreamNarInfoError::Malformed)?;
            if name == "Sig" {
                signatures.push(parse_upstream_signature(value)?);
                continue;
            }
            if !is_supported_upstream_field(name) || fields.iter().any(|(field, _)| *field == name)
            {
                return Err(UpstreamNarInfoError::Malformed);
            }
            fields.push((name, value));
        }

        let field = |name: &str| {
            fields
                .iter()
                .find_map(|(field, value)| (*field == name).then_some(*value))
        };
        let store_path = field("StorePath").ok_or(UpstreamNarInfoError::Malformed)?;
        let store_path = validate_upstream_store_path(route, store_path)?;
        let url = field("URL").ok_or(UpstreamNarInfoError::Malformed)?;
        validate_upstream_url(url)?;
        require_supported_compression(field("Compression"))?;
        validate_optional_transport_fields(field("FileHash"), field("FileSize"))?;
        let nar_hash = field("NarHash")
            .and_then(|value| value.strip_prefix("sha256:"))
            .and_then(|value| NarHash::parse(value).ok())
            .ok_or(UpstreamNarInfoError::Malformed)?;
        let nar_size = field("NarSize")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|size| *size != 0)
            .ok_or(UpstreamNarInfoError::Malformed)?;
        let references = normalize_upstream_references(
            field("References").ok_or(UpstreamNarInfoError::Malformed)?,
        )?;
        if signatures.is_empty() {
            return Err(UpstreamNarInfoError::Malformed);
        }

        let fingerprint = build_upstream_fingerprint(store_path, nar_hash, nar_size, &references);
        Ok(Self {
            claims: UpstreamClaims {
                store_path: store_path.to_owned(),
                identity: UpstreamNarIdentity {
                    hash: nar_hash,
                    size: nar_size,
                },
                references,
            },
            fingerprint,
            signatures,
        })
    }

    fn verify(
        self,
        keys: &TrustedPublicKeys,
    ) -> Result<TrustedUpstreamNarInfo, UpstreamNarInfoError> {
        if self.signatures.iter().any(|signature| {
            keys.verify_signature(
                &signature.name,
                self.fingerprint.as_bytes(),
                &signature.bytes,
            )
        }) {
            Ok(TrustedUpstreamNarInfo {
                claims: self.claims,
            })
        } else {
            Err(UpstreamNarInfoError::UntrustedSignature)
        }
    }
}

struct TrustedUpstreamNarInfo {
    claims: UpstreamClaims,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpstreamNarInfoError {
    Malformed,
    UnsupportedCompression,
    InvalidUrl,
    InvalidTransport,
    UntrustedSignature,
}

impl fmt::Display for UpstreamNarInfoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("invalid or untrusted narinfo"),
            Self::UnsupportedCompression => {
                formatter.write_str("upstream narinfo uses unsupported compression")
            }
            Self::InvalidUrl => formatter.write_str("upstream narinfo has an invalid URL"),
            Self::InvalidTransport => {
                formatter.write_str("upstream narinfo has invalid transport fields")
            }
            Self::UntrustedSignature => formatter.write_str("invalid or untrusted narinfo"),
        }
    }
}

fn is_supported_upstream_field(name: &str) -> bool {
    const SUPPORTED_FIELDS: &[&str] = &[
        "StorePath",
        "URL",
        "Compression",
        "FileHash",
        "FileSize",
        "NarHash",
        "NarSize",
        "References",
        "Deriver",
        "System",
        "CA",
    ];
    SUPPORTED_FIELDS.contains(&name)
}

fn require_supported_compression(value: Option<&str>) -> Result<(), UpstreamNarInfoError> {
    match value {
        Some("none" | "xz" | "zstd") => Ok(()),
        Some(_) | None => Err(UpstreamNarInfoError::UnsupportedCompression),
    }
}

fn validate_upstream_url(value: &str) -> Result<(), UpstreamNarInfoError> {
    if value.is_empty() {
        return Err(UpstreamNarInfoError::InvalidUrl);
    }
    let uri = UriRef::parse(value).map_err(|_| UpstreamNarInfoError::InvalidUrl)?;
    if uri.has_fragment() {
        return Err(UpstreamNarInfoError::InvalidUrl);
    }
    let scheme = uri.scheme();
    if scheme.is_some_and(|scheme| !["http", "https"].contains(&scheme.as_str())) {
        return Err(UpstreamNarInfoError::InvalidUrl);
    }
    Ok(())
}

fn validate_optional_transport_fields(
    file_hash: Option<&str>,
    file_size: Option<&str>,
) -> Result<(), UpstreamNarInfoError> {
    match (file_hash, file_size) {
        (None, None) => Ok(()),
        (Some(file_hash), Some(file_size)) => {
            let file_hash = file_hash
                .strip_prefix("sha256:")
                .ok_or(UpstreamNarInfoError::InvalidTransport)?;
            FileHash::parse(file_hash).map_err(|_| UpstreamNarInfoError::InvalidTransport)?;
            file_size
                .parse::<u64>()
                .ok()
                .filter(|size| *size != 0)
                .ok_or(UpstreamNarInfoError::InvalidTransport)?;
            Ok(())
        }
        _ => Err(UpstreamNarInfoError::InvalidTransport),
    }
}

fn validate_upstream_store_path<'a>(
    route: &StoreHash,
    value: &'a str,
) -> Result<&'a str, UpstreamNarInfoError> {
    let basename = value
        .strip_prefix("/nix/store/")
        .ok_or(UpstreamNarInfoError::Malformed)?;
    let (hash, name) = basename
        .split_once('-')
        .filter(|(_, name)| !name.is_empty())
        .ok_or(UpstreamNarInfoError::Malformed)?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
    {
        return Err(UpstreamNarInfoError::Malformed);
    }
    let parsed = StoreHash::parse(hash).map_err(|_| UpstreamNarInfoError::Malformed)?;
    if &parsed != route {
        return Err(UpstreamNarInfoError::Malformed);
    }
    Ok(value)
}

fn normalize_upstream_references(value: &str) -> Result<String, UpstreamNarInfoError> {
    let mut references = value.split_ascii_whitespace().collect::<Vec<_>>();
    for reference in &references {
        let (hash, name) = reference
            .split_once('-')
            .filter(|(_, name)| !name.is_empty())
            .ok_or(UpstreamNarInfoError::Malformed)?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
            || StoreHash::parse(hash).is_err()
        {
            return Err(UpstreamNarInfoError::Malformed);
        }
    }
    references.sort_unstable();
    references.dedup();
    Ok(references.join(" "))
}

fn parse_upstream_signature(value: &str) -> Result<UpstreamSignature, UpstreamNarInfoError> {
    let (name, encoded) = value
        .split_once(':')
        .filter(|(name, encoded)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                && !encoded.is_empty()
        })
        .ok_or(UpstreamNarInfoError::Malformed)?;
    let bytes = BASE64
        .decode(encoded.as_bytes())
        .ok()
        .filter(|bytes| bytes.len() == 64)
        .ok_or(UpstreamNarInfoError::Malformed)?;
    Ok(UpstreamSignature {
        name: name.to_owned(),
        bytes,
    })
}

fn build_upstream_fingerprint(
    store_path: &str,
    nar_hash: NarHash,
    nar_size: u64,
    references: &str,
) -> String {
    let references = references
        .split_ascii_whitespace()
        .map(|reference| format!("/nix/store/{reference}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("1;{store_path};sha256:{nar_hash};{nar_size};{references}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicalClaimsMismatch {
    StorePath,
    NarIdentity,
    References,
}

impl fmt::Display for LogicalClaimsMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorePath => formatter.write_str("store path differs"),
            Self::NarIdentity => formatter.write_str("NAR hash or size differs"),
            Self::References => formatter.write_str("references differ"),
        }
    }
}

fn compare_logical_claims(
    local: &PathInfo,
    local_references: &str,
    upstream: &TrustedUpstreamNarInfo,
) -> Result<(), LogicalClaimsMismatch> {
    if upstream.claims.store_path != local.path {
        return Err(LogicalClaimsMismatch::StorePath);
    }
    let local_hash = NarHash::parse(&local.nar.hash().to_string())
        .map_err(|_| LogicalClaimsMismatch::NarIdentity)?;
    if upstream.claims.identity
        != (UpstreamNarIdentity {
            hash: local_hash,
            size: local.nar.size().get(),
        })
    {
        return Err(LogicalClaimsMismatch::NarIdentity);
    }
    if upstream.claims.references != local_references {
        return Err(LogicalClaimsMismatch::References);
    }
    Ok(())
}
