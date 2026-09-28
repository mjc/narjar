use std::{fmt, sync::Arc};

use narjar::narinfo::{MAX_NARINFO_BYTES, TrustedNarInfoClaims, TrustedPublicKeys};
use ureq::{Agent, http::StatusCode};

use super::{DestinationNarinfoPolicy, NarInfoMetadata, PushError, transfer::get_bounded};
use crate::http_url::HttpUrl;

#[derive(Clone)]
pub(super) struct TrustedUpstreams {
    entries: Arc<[ConfiguredUpstream]>,
}

impl TrustedUpstreams {
    pub(super) fn from_configuration(
        urls: &[HttpUrl],
        key_values: &[String],
    ) -> Result<Self, PushError> {
        if urls.is_empty() && key_values.is_empty() {
            return Ok(Self {
                entries: Arc::from([]),
            });
        }
        if urls.is_empty() {
            return Err("--trusted-upstream-key requires --trusted-upstream".into());
        }
        if key_values.is_empty() {
            return Err("--trusted-upstream requires --trusted-upstream-key".into());
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
                return Err(format!("no trusted upstream key configured for {url}").into());
            }
            let keys = TrustedPublicKeys::parse(&keys.join(" "))
                .map_err(|error| format!("invalid trusted upstream key for {url}: {error}"))?;
            entries.push(ConfiguredUpstream { url, keys });
        }
        Ok(Self {
            entries: Arc::from(entries),
        })
    }
}

struct ConfiguredUpstream {
    url: HttpUrl,
    keys: TrustedPublicKeys,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PushDisposition {
    DestinationPresent,
    TrustedUpstreamPresent(HttpUrl),
    UploadRequired,
}

pub(super) struct CacheLookup<'a> {
    agent: &'a Agent,
    destination: &'a HttpUrl,
    destination_authorization: Option<&'a str>,
    destination_narinfo: DestinationNarinfoPolicy,
    upstreams: &'a TrustedUpstreams,
}

impl<'a> CacheLookup<'a> {
    pub(super) fn new(
        agent: &'a Agent,
        destination: &'a HttpUrl,
        destination_authorization: Option<&'a str>,
        destination_narinfo: DestinationNarinfoPolicy,
        upstreams: &'a TrustedUpstreams,
    ) -> Self {
        Self {
            agent,
            destination,
            destination_authorization,
            destination_narinfo,
            upstreams,
        }
    }

    pub(super) fn classify(&self, info: &NarInfoMetadata) -> Result<PushDisposition, PushError> {
        match self.destination_narinfo {
            DestinationNarinfoPolicy::Refresh => return Ok(PushDisposition::UploadRequired),
            DestinationNarinfoPolicy::ReuseExisting => {}
        }

        let route = info.claims().store();
        let narinfo_name = format!("{}.narinfo", route.as_str());
        let destination_url = self.destination.endpoint(&[&narinfo_name]);
        let response = get_bounded(
            self.agent,
            &destination_url,
            self.destination_authorization,
            MAX_NARINFO_BYTES,
        )?;
        match response {
            super::transfer::GetResponse::Found(body) => {
                let matches_expected = info.claims().matches_external_narinfo(route, body);
                if matches_expected {
                    return Ok(PushDisposition::DestinationPresent);
                }
            }
            super::transfer::GetResponse::Missing => {}
            super::transfer::GetResponse::UnexpectedStatus(status) => {
                return Err(format!(
                    "narinfo lookup for {} returned HTTP {status}",
                    info.claims().store_path()
                )
                .into());
            }
        }

        self.classify_upstream(route, &narinfo_name, info)
    }

    fn classify_upstream(
        &self,
        route: &narjar::storage::StoreHash,
        narinfo_name: &str,
        info: &NarInfoMetadata,
    ) -> Result<PushDisposition, PushError> {
        let matched_upstream = self.upstreams.entries.iter().find_map(|upstream| {
            match self.lookup_upstream(route, upstream, narinfo_name, info) {
                UpstreamLookup::Matched(matched) => Some(matched),
                UpstreamLookup::Rejected(reason) => {
                    eprintln!(
                        "narjar push: trusted upstream {} rejected for {}: {reason}; checking next source",
                        upstream.url,
                        info.claims().store_path()
                    );
                    None
                }
                UpstreamLookup::Missing => None,
            }
        });
        match matched_upstream {
            Some(upstream) => Ok(PushDisposition::TrustedUpstreamPresent(upstream)),
            None => {
                if !self.upstreams.entries.is_empty() {
                    eprintln!(
                        "narjar push: no trusted upstream matched {}; uploading instead",
                        info.claims().store_path()
                    );
                }
                Ok(PushDisposition::UploadRequired)
            }
        }
    }

    fn lookup_upstream(
        &self,
        route: &narjar::storage::StoreHash,
        upstream: &ConfiguredUpstream,
        narinfo_name: &str,
        info: &NarInfoMetadata,
    ) -> UpstreamLookup {
        let url = upstream.url.endpoint(&[narinfo_name]);
        let response = match get_bounded(self.agent, &url, None, MAX_NARINFO_BYTES) {
            Ok(response) => response,
            Err(error) => return UpstreamLookup::Rejected(UpstreamRejection::LookupFailed(error)),
        };
        let body = match response {
            super::transfer::GetResponse::Found(body) => body,
            super::transfer::GetResponse::Missing => return UpstreamLookup::Missing,
            super::transfer::GetResponse::UnexpectedStatus(status) => {
                return UpstreamLookup::Rejected(UpstreamRejection::UnexpectedStatus(status));
            }
        };
        let claims = match upstream.keys.verify_external_narinfo(route, body) {
            Ok(verified) => verified,
            Err(error) => {
                return UpstreamLookup::Rejected(UpstreamRejection::InvalidNarInfo(
                    error.to_string(),
                ));
            }
        };
        match compare_logical_claims(info, &claims) {
            Ok(()) => UpstreamLookup::Matched(upstream.url.clone()),
            Err(mismatch) => UpstreamLookup::Rejected(UpstreamRejection::ClaimsMismatch(mismatch)),
        }
    }
}

enum UpstreamLookup {
    Missing,
    Rejected(UpstreamRejection),
    Matched(HttpUrl),
}

enum UpstreamRejection {
    LookupFailed(PushError),
    UnexpectedStatus(StatusCode),
    InvalidNarInfo(String),
    ClaimsMismatch(LogicalClaimsMismatch),
}

impl fmt::Display for UpstreamRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LookupFailed(error) => write!(formatter, "lookup failed: {error}"),
            Self::UnexpectedStatus(status) => write!(formatter, "lookup returned HTTP {status}"),
            Self::InvalidNarInfo(error) => formatter.write_str(error),
            Self::ClaimsMismatch(mismatch) => mismatch.fmt(formatter),
        }
    }
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
    local: &NarInfoMetadata,
    upstream: &TrustedNarInfoClaims,
) -> Result<(), LogicalClaimsMismatch> {
    let upstream = upstream.claims();
    let local = local.claims();
    if upstream.store_path() != local.store_path() {
        return Err(LogicalClaimsMismatch::StorePath);
    }
    if upstream.identity() != local.identity() {
        return Err(LogicalClaimsMismatch::NarIdentity);
    }
    if upstream.reference_paths().ne(local.reference_paths()) {
        return Err(LogicalClaimsMismatch::References);
    }
    Ok(())
}
