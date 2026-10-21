use std::io::{self, Write};

use clap::{Args, ValueEnum};
use sha2::{Digest, Sha256};

use crate::{cache::narinfo::TrustedPublicKeys, error::Error};

use super::{advertisement::CacheOrigin, runtime};

#[derive(Args)]
pub(super) struct Configure {
    #[arg(long)]
    url: CacheOrigin,
    /// A producer public key obtained through a trusted operator channel. Repeat for multiple keys.
    #[arg(long = "trusted-public-key", required = true)]
    keys: Vec<String>,
    #[arg(long, value_enum, default_value = "nixos")]
    format: Format,
    #[arg(long, value_enum)]
    /// Local-edge requires public reads; use direct with separately provisioned credentials for private caches.
    mode: Option<ClientMode>,
    /// Match the operator's retention policy; it must cover twice this TTL plus 300 seconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..=86400))]
    positive_ttl_seconds: u32,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Nixos,
    NixConf,
}

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum ClientMode {
    Direct,
    LocalEdge,
}

#[derive(Clone, Copy)]
pub(super) enum ConfigurationTarget {
    Nixos(ClientMode),
    NixConf,
}

impl ConfigurationTarget {
    fn from_options(format: Format, mode: Option<ClientMode>) -> Result<Self, Error> {
        match (format, mode) {
            (Format::Nixos, Some(ClientMode::Direct)) => Ok(Self::Nixos(ClientMode::Direct)),
            (Format::Nixos, None | Some(ClientMode::LocalEdge)) => {
                Ok(Self::Nixos(ClientMode::LocalEdge))
            }
            (Format::NixConf, None | Some(ClientMode::Direct)) => Ok(Self::NixConf),
            (Format::NixConf, Some(ClientMode::LocalEdge)) => Err(Error::usage(
                "local-edge requires --format nixos; nix.conf cannot configure the daemon",
            )),
        }
    }
}

pub(super) struct ExplicitlyTrustedKeys(Vec<String>);

pub(super) struct LocalEdgeUpstream<'a>(&'a CacheOrigin);

impl<'a> LocalEdgeUpstream<'a> {
    pub(super) fn from_origin(origin: &'a CacheOrigin) -> Option<Self> {
        match origin.url().port() != 5000 || origin.is_network_host() {
            true => Some(Self(origin)),
            false => None,
        }
    }
}

impl ExplicitlyTrustedKeys {
    pub(super) fn tokens(&self) -> &[String] {
        &self.0
    }
}

impl TryFrom<Vec<String>> for ExplicitlyTrustedKeys {
    type Error = Error;

    fn try_from(keys: Vec<String>) -> Result<Self, Error> {
        let bounded_tokens = !keys.is_empty()
            && keys.len() <= 32
            && keys
                .iter()
                .all(|key| key.len() <= 512 && !key.chars().any(char::is_whitespace));
        match bounded_tokens {
            true => TrustedPublicKeys::parse(&keys.join("\n"))
                .map(|_| Self(keys))
                .map_err(|_| Error::usage("provide distinct, valid producer public keys")),
            false => Err(Error::usage("provide 1–32 individual producer public keys")),
        }
    }
}

pub(super) fn run(options: Configure) -> Result<(), Error> {
    let target = ConfigurationTarget::from_options(options.format, options.mode)?;
    let keys = ExplicitlyTrustedKeys::try_from(options.keys)?;
    let output = render(&options.url, &keys, target, options.positive_ttl_seconds)?;
    let mut notices = io::stderr().lock();
    writeln!(
        notices,
        "Configuration uses only the keys you supplied; discovery does not establish trust."
    )
    .map_err(runtime)?;
    match target {
        ConfigurationTarget::Nixos(ClientMode::LocalEdge) => {
            writeln!(
                notices,
                "The local-edge example requires Narjar's NixOS module."
            )
            .map_err(runtime)?;
        }
        ConfigurationTarget::Nixos(ClientMode::Direct) | ConfigurationTarget::NixConf => {}
    }
    writeln!(
        notices,
        "Confirm the operator retains advertised payloads for at least {} seconds.",
        2 * u64::from(options.positive_ttl_seconds) + 300
    )
    .map_err(runtime)?;
    keys.0.iter().try_for_each(|key| {
        writeln!(
            notices,
            "SHA-256 of public-key line: {}",
            data_encoding::HEXLOWER.encode(&Sha256::digest(key.as_bytes()))
        )
        .map_err(runtime)
    })?;
    io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(runtime)
}

pub(super) fn render(
    origin: &CacheOrigin,
    keys: &ExplicitlyTrustedKeys,
    target: ConfigurationTarget,
    positive_ttl_seconds: u32,
) -> Result<String, Error> {
    match target {
        ConfigurationTarget::NixConf => Ok(format!(
            "extra-substituters = {}?priority=30\nextra-trusted-public-keys = {}\nnarinfo-cache-positive-ttl = {positive_ttl_seconds}\nnarinfo-cache-negative-ttl = 1\n",
            origin.as_str(),
            keys.0.join(" ")
        )),
        ConfigurationTarget::Nixos(mode) => render_nixos(origin, keys, mode, positive_ttl_seconds),
    }
}

fn render_nixos(
    origin: &CacheOrigin,
    keys: &ExplicitlyTrustedKeys,
    mode: ClientMode,
    positive_ttl_seconds: u32,
) -> Result<String, Error> {
    let keys = keys
        .0
        .iter()
        .map(|key| nix_string(key))
        .collect::<Vec<_>>()
        .join(" ");
    let (substituter, service) = match mode {
        ClientMode::Direct => (origin.as_str(), String::new()),
        ClientMode::LocalEdge => (
            "http://127.0.0.1:5000",
            render_local_edge_service(
                LocalEdgeUpstream::from_origin(origin).ok_or_else(|| Error::usage("local-edge upstream would point at its own HTTP listener on port 5000; use direct mode or another upstream port"))?,
                &keys,
                positive_ttl_seconds,
            ),
        ),
    };
    Ok(format!(
        "{{\n{service}  nix.settings = {{\n    extra-substituters = [ {} ];\n    extra-trusted-public-keys = [ {keys} ];\n    fallback = false;\n    narinfo-cache-positive-ttl = {positive_ttl_seconds};\n    narinfo-cache-negative-ttl = 1;\n  }};\n}}\n",
        nix_string(&format!("{substituter}?priority=30")),
    ))
}

fn render_local_edge_service(
    upstream: LocalEdgeUpstream<'_>,
    keys: &str,
    positive_ttl_seconds: u32,
) -> String {
    format!(
        "  services.narjar = {{\n    enable = true;\n    listen = \"127.0.0.1:5000\";\n    edge = {{\n      enable = true;\n      upstream = {};\n      trustedPublicKeys = [ {keys} ];\n      leaseSeconds = {};\n    }};\n  }};\n",
        nix_string(upstream.0.as_str()),
        5_187_600_u64.max(2 * u64::from(positive_ttl_seconds) + 300),
    )
}

fn nix_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace("${", "\\${")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

    #[test]
    fn configuration_requires_real_explicit_keys_and_retains_other_substituters() {
        let origin = "https://cache.example".parse().unwrap();
        let keys = ExplicitlyTrustedKeys::try_from(vec![KEY.into()]).unwrap();
        let nixos = render(
            &origin,
            &keys,
            ConfigurationTarget::Nixos(ClientMode::LocalEdge),
            300,
        )
        .unwrap();
        assert!(nixos.contains("extra-substituters = [ \"http://127.0.0.1:5000?priority=30\" ];"));
        assert!(nixos.contains("upstream = \"https://cache.example\";"));
        assert!(nixos.contains("narinfo-cache-positive-ttl = 300;"));
        assert!(nixos.contains("leaseSeconds = 5187600;"));
        assert!(!nixos.contains("services.narjar.client"));
        let direct = render(
            &origin,
            &keys,
            ConfigurationTarget::Nixos(ClientMode::Direct),
            86_400,
        )
        .unwrap();
        assert!(!direct.contains("services.narjar"));
        assert!(direct.contains("extra-substituters = [ \"https://cache.example?priority=30\" ];"));
        assert!(direct.contains("narinfo-cache-positive-ttl = 86400;"));
        let conf = render(&origin, &keys, ConfigurationTarget::NixConf, 300).unwrap();
        assert!(conf.starts_with("extra-substituters = https://cache.example?priority=30\n"));
        assert!(conf.contains(KEY));
        assert!(
            render(&origin, &keys, ConfigurationTarget::NixConf, 60)
                .unwrap()
                .contains("positive-ttl = 60\n")
        );
        for keys in [
            vec![],
            vec!["untrusted:AAAA".into()],
            vec![KEY.into(), KEY.into()],
            vec![format!("{KEY}\n{KEY}")],
        ] {
            assert!(ExplicitlyTrustedKeys::try_from(keys).is_err());
        }
    }

    #[test]
    fn local_edge_cannot_upstream_itself_but_direct_substitution_can() {
        let keys = ExplicitlyTrustedKeys::try_from(vec![KEY.into()]).unwrap();
        for url in [
            "http://127.0.0.1:5000",
            "http://localhost:5000",
            "http://cache.localhost:5000",
            "http://[::1]:5000",
            "http://[::ffff:127.0.0.1]:5000",
            "http://0.0.0.0:5000",
            "https://127.0.0.1:5000",
            "https://localhost:5000",
            "https://cache.localhost:5000",
            "https://[::1]:5000",
            "https://[::ffff:127.0.0.1]:5000",
            "https://0.0.0.0:5000",
        ] {
            let origin = url.parse().unwrap();
            assert!(
                render(
                    &origin,
                    &keys,
                    ConfigurationTarget::Nixos(ClientMode::LocalEdge),
                    300
                )
                .is_err(),
                "{url}"
            );
            assert!(
                render(
                    &origin,
                    &keys,
                    ConfigurationTarget::Nixos(ClientMode::Direct),
                    300
                )
                .is_ok(),
                "{url}"
            );
        }
        for url in [
            "http://localhost:8080",
            "https://localhost:8080",
            "https://cache.example",
        ] {
            let origin = url.parse().unwrap();
            assert!(
                render(
                    &origin,
                    &keys,
                    ConfigurationTarget::Nixos(ClientMode::LocalEdge),
                    300
                )
                .is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn nix_conf_cannot_claim_to_configure_a_local_daemon() {
        assert!(
            ConfigurationTarget::from_options(Format::NixConf, Some(ClientMode::LocalEdge))
                .is_err()
        );
        assert_eq!(nix_string("${bad}\\\""), "\"\\${bad}\\\\\\\"\"");
    }
}
