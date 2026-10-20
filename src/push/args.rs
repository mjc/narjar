use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use clap::Args;
use narjar::object::WireEncoding;

use crate::http_url::HttpUrl;

#[derive(Debug, Args)]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows parses push options but rejects the unsupported local Nix source before execution"
    )
)]
pub(crate) struct Push {
    /// Destination binary cache store URI.
    #[arg(long)]
    pub(super) to: HttpUrl,

    /// Maximum number of native HTTP upload workers.
    #[arg(long, default_value_t = NonZeroUsize::new(1).unwrap())]
    pub(super) jobs: NonZeroUsize,

    /// Compression used for the uploaded NAR payload; the cache independently selects its served representation.
    #[arg(long, default_value = "none")]
    pub(super) compression: WireEncoding,

    /// Timeout for native HTTP DNS/connect and inactive network I/O, in seconds.
    #[arg(long, env = "NARJAR_PUSH_TIMEOUT_SECONDS", default_value_t = NonZeroU64::new(30).unwrap())]
    pub(super) timeout_seconds: NonZeroU64,

    /// Netrc file used for HTTP authentication.
    #[arg(long)]
    pub(super) netrc_file: Option<PathBuf>,

    /// Permit sending netrc credentials over plain HTTP.
    #[arg(long)]
    pub(super) insecure_http: bool,

    /// Secret key file used to sign the local store paths before copying.
    #[arg(long)]
    pub(super) signing_key_file: Option<PathBuf>,

    /// Re-check and re-upload paths already present at the destination.
    #[arg(long)]
    pub(super) refresh: bool,

    /// Keep publishing when a destination already has different immutable metadata.
    #[arg(long)]
    pub(super) ignore_conflicts: bool,

    /// Trusted binary cache consulted before generating an upload. Repeat in lookup order.
    #[arg(long = "trusted-upstream", value_name = "URL")]
    pub(super) trusted_upstreams: Vec<HttpUrl>,

    /// Nix public key trusted for one upstream: UPSTREAM#NAME:BASE64. Repeat for key rotation.
    #[arg(long = "trusted-upstream-key", value_name = "UPSTREAM#NAME:BASE64")]
    pub(super) trusted_upstream_keys: Vec<String>,

    /// Concrete local store paths whose closures should be pushed.
    #[arg(value_name = "STORE_PATH", required = true, num_args = 1..)]
    pub(super) paths: Vec<String>,
}
