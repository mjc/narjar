use std::{fmt, sync::Arc};

use narjar::{
    narinfo::{MAX_NARINFO_BYTES, TrustedPublicKeys, ValidatedNarInfo},
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
    urls: Arc<[HttpUrl]>,
    keys: Arc<TrustedPublicKeys>,
}

impl TrustedUpstreams {
    pub(super) fn from_configuration(
        urls: &[HttpUrl],
        key_values: &[String],
    ) -> Result<Self, String> {
        match (urls.is_empty(), key_values.is_empty()) {
            (true, true) => Ok(Self {
                urls: Arc::from([]),
                keys: Arc::new(TrustedPublicKeys::default()),
            }),
            (false, false) => {
                let keys = TrustedPublicKeys::parse(&key_values.join(" "))
                    .map_err(|error| format!("invalid trusted upstream key: {error}"))?;
                Ok(Self {
                    urls: Arc::from(urls),
                    keys: Arc::new(keys),
                })
            }
            (true, false) => Err("--trusted-upstream-key requires --trusted-upstream".to_owned()),
            (false, true) => Err("--trusted-upstream requires --trusted-upstream-key".to_owned()),
        }
    }
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
    TrustedUpstreamPresent(UpstreamIdentity),
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
        let expected_references = normalized_references(info)?;
        for upstream in self.upstreams.urls.iter() {
            let url = upstream.endpoint(&[narinfo_name]);
            let response = match get_bounded(self.agent, &url, None, MAX_NARINFO_BYTES) {
                Ok(response) => response,
                Err(error) => {
                    eprintln!(
                        "narjar push: trusted upstream {upstream} lookup for {} failed; uploading instead: {error}",
                        info.path
                    );
                    continue;
                }
            };
            match response.status {
                404 => continue,
                200 => {}
                status => {
                    eprintln!(
                        "narjar push: trusted upstream {upstream} lookup for {} returned HTTP {status}; uploading instead",
                        info.path
                    );
                    continue;
                }
            }

            let validated = match self.upstreams.keys.validate(route, response.body) {
                Ok(validated) => validated,
                Err(_) => {
                    eprintln!(
                        "narjar push: trusted upstream {upstream} returned invalid or untrusted narinfo for {}; uploading instead",
                        info.path
                    );
                    continue;
                }
            };
            match compare_logical_claims(info, &expected_references, &validated) {
                Ok(()) => {
                    return Ok(PushDisposition::TrustedUpstreamPresent(UpstreamIdentity(
                        upstream.clone(),
                    )));
                }
                Err(mismatch) => eprintln!(
                    "narjar push: trusted upstream {upstream} metadata for {} does not match the local store path ({mismatch}); uploading instead",
                    info.path
                ),
            }
        }
        Ok(PushDisposition::UploadRequired)
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
    local: &PathInfo,
    local_references: &str,
    upstream: &ValidatedNarInfo,
) -> Result<(), LogicalClaimsMismatch> {
    if upstream.store_path() != local.path {
        return Err(LogicalClaimsMismatch::StorePath);
    }
    if !has_same_logical_nar_identity(local, upstream) {
        return Err(LogicalClaimsMismatch::NarIdentity);
    }
    if upstream.references() != local_references {
        return Err(LogicalClaimsMismatch::References);
    }
    Ok(())
}

fn has_same_logical_nar_identity(local: &PathInfo, upstream: &ValidatedNarInfo) -> bool {
    let upstream_nar = upstream.decoded_identity();
    upstream_nar.hash().to_string() == local.nar.hash().to_string()
        && upstream_nar.size().get() == local.nar.size().get()
}
