use sha2::{Digest, Sha256};

use super::{
    advertisement::CacheOrigin,
    configuration::{self, ClientMode, ConfigurationTarget, ExplicitlyTrustedKeys},
    hosting::Diagnostics,
};
use crate::{
    cache::{auth::ReadVisibility, narinfo::TrustedPublicKeys},
    error::Error,
};

pub(crate) struct SetupDocument(String);

impl SetupDocument {
    pub(super) fn new(
        origin: &CacheOrigin,
        trusted: &TrustedPublicKeys,
        visibility: ReadVisibility,
        diagnostics: Diagnostics,
        minimum_lease: Option<u64>,
    ) -> Result<Self, Error> {
        let keys =
            ExplicitlyTrustedKeys::try_from(trusted.encoded_keys().take(33).collect::<Vec<_>>())?;
        let key_lines = keys
            .tokens()
            .iter()
            .map(|key| {
                format!(
                    "<pre><code>{}</code></pre><p>SHA-256 of public-key line: <code>{}</code></p>",
                    escape_html(key),
                    data_encoding::HEXLOWER.encode(&Sha256::digest(key.as_bytes()))
                )
            })
            .collect::<String>();
        let nix_conf = configuration::render(origin, &keys, ConfigurationTarget::NixConf, 300)?;
        let nixos = match origin.url().host().contains(':') {
            true => String::new(),
            false => render_nixos_choices(origin, &keys, visibility)?,
        };
        let diagnostics = match diagnostics {
            Diagnostics::Omit => "",
            Diagnostics::Include => {
                "<h2>Diagnostics</h2><p><a href=\"/readyz\">Readiness</a> · <a href=\"/metrics\">Metrics</a>. Existing read authentication applies.</p>"
            }
        };
        let credentials = match visibility {
            ReadVisibility::Public => {
                "Public reads do not require an upload token or private signing key."
            }
            ReadVisibility::Private => {
                "This cache requires read credentials. Ask the operator for a Nix netrc configuration. Use direct substitution; the local edge cannot provide upstream credentials."
            }
        };
        let retention = match minimum_lease {
            Some(seconds) => {
                format!("This cache's minimum advertisement lease is {seconds} seconds.")
            }
            None => "This uploaded cache follows its operator's GC retention policy.".into(),
        };
        Ok(Self(format!(
            r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Use {url}</title><style>:root {{ color-scheme:light dark }} body {{ max-width:56rem;margin:3rem auto;padding:0 1rem;font:1rem/1.6 system-ui,sans-serif }} pre {{ overflow-x:auto;padding:1rem;border:1px solid GrayText }} code {{ overflow-wrap:anywhere }}</style></head>
<body><main><h1>Use this Nix cache</h1><p>{url}</p>
<h2>Verify signing keys first</h2><p>Confirm these keys with the operator through a trusted channel. LAN discovery and this page do not establish trust. Fingerprints hash the exact public-key line without a newline.</p>
{key_lines}<p>{credentials}</p>{nixos}
<h2>nix.conf: direct substitution</h2><pre><code>{nix_conf}</code></pre>
<h2>Retention and removal</h2><p>{retention} These examples use a 300-second positive metadata TTL. Confirm that the operator retains advertised payloads for at least 900 seconds. To stop using this cache, remove its client settings and apply your usual configuration update.</p>
{diagnostics}</main></body></html>"#,
            url = escape_html(origin.as_str()),
            nix_conf = escape_html(&nix_conf)
        )))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn render_nixos_choices(
    origin: &CacheOrigin,
    keys: &ExplicitlyTrustedKeys,
    visibility: ReadVisibility,
) -> Result<String, Error> {
    let direct = configuration::render(
        origin,
        keys,
        ConfigurationTarget::Nixos(ClientMode::Direct),
        300,
    )?;
    let edge = match visibility {
        ReadVisibility::Private => String::new(),
        ReadVisibility::Public => format!(
            "<h2>NixOS: local fail-open edge</h2><p>A local verifying cache returns misses when the remote cache is unavailable. Other configured substituters remain independent.</p><pre><code>{}</code></pre>",
            escape_html(&configuration::render(
                origin,
                keys,
                ConfigurationTarget::Nixos(ClientMode::LocalEdge),
                300
            )?)
        ),
    };
    Ok(format!(
        "<p>Import Narjar's NixOS module to use these NixOS examples.</p>{edge}<h2>NixOS: direct substitution</h2><pre><code>{}</code></pre>",
        escape_html(&direct)
    ))
}

fn escape_html(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            character => character.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_source_and_html_output_are_bounded_and_escaped() {
        assert_eq!(escape_html("<&\"'>"), "&lt;&amp;&quot;&#39;&gt;");
        let origin = "http://[2001:db8::1]:8080".parse().unwrap();
        assert!(
            SetupDocument::new(
                &origin,
                &TrustedPublicKeys::default(),
                ReadVisibility::Public,
                Diagnostics::Omit,
                None
            )
            .is_err()
        );
        let key = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
        let keys = TrustedPublicKeys::parse(key).unwrap();
        let page = SetupDocument::new(
            &origin,
            &keys,
            ReadVisibility::Public,
            Diagnostics::Omit,
            None,
        )
        .unwrap();
        let text = std::str::from_utf8(page.bytes()).unwrap();
        assert!(text.contains(key));
        assert!(text.contains("http://[2001:db8::1]:8080"));
        assert!(text.contains("nix.conf"));
        assert!(!text.contains("services.narjar.client"));
    }
}
