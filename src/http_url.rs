use std::{fmt, str::FromStr};

use fluent_uri::{
    Uri, UriRef,
    component::{Authority, Host},
    pct_enc::{
        EStr, EString,
        encoder::{Data, Path},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpUrl(Uri<String>);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HttpUrlError {
    #[error("{0}")]
    Parse(String),
    #[error("URL must use http:// or https://")]
    UnsupportedScheme,
    #[error("URL must include an authority")]
    MissingAuthority,
    #[error("URL must include a host")]
    MissingHost,
    #[error("URL must not contain credentials; use --netrc-file")]
    Credentials,
    #[error("URL port must fit in 16 bits")]
    InvalidPort,
    #[error("URL must not contain a fragment")]
    Fragment,
    #[error("redirect leaves the trusted cache authority")]
    UntrustedRedirectAuthority,
    #[error("upstream URL leaves the configured cache origin")]
    UntrustedResourceOrigin,
    #[error("upstream URL leaves the configured cache path")]
    UntrustedResourcePath,
}

impl HttpUrl {
    fn authority(&self) -> Authority<'_> {
        self.0
            .authority()
            .expect("validated HTTP URLs always have an authority")
    }

    pub(crate) fn endpoint(&self, segments: &[&str]) -> Self {
        let mut path = EString::<Path>::with_capacity(
            self.0.path().len()
                + segments
                    .iter()
                    .map(|segment| segment.len() + 1)
                    .sum::<usize>(),
        );
        let base_path = self
            .0
            .path()
            .as_str()
            .strip_suffix('/')
            .unwrap_or(self.0.path().as_str());
        path.push_estr(EStr::<Path>::new(base_path).expect("base path was already validated"));
        for segment in segments {
            path.push('/');
            path.encode_str::<Data>(segment);
        }
        let uri = Uri::builder()
            .scheme(self.0.scheme())
            .authority(self.authority())
            .path(&path)
            .build()
            .expect("validated HTTP URL components form a URI");
        Self(uri)
    }

    pub(crate) fn host(&self) -> &str {
        let host = self.authority().host();
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
    }

    pub(crate) fn resolve_trusted_redirect(&self, location: &str) -> Result<Self, HttpUrlError> {
        let reference = UriRef::parse(location.trim()).map_err(|error| {
            HttpUrlError::Parse(format!("{self} redirect has an invalid Location: {error}"))
        })?;
        let mut next = reference.resolve_against(&self.0).map_err(|error| {
            HttpUrlError::Parse(format!("{self} redirect has an invalid Location: {error}"))
        })?;
        next.set_fragment(None);
        let next = Self::try_from_uri(next)
            .map_err(|error| HttpUrlError::Parse(format!("{self} redirect is invalid: {error}")))?;

        let same_authority = self.authority().as_str() == next.authority().as_str();
        let safe_scheme = self.0.scheme() == next.0.scheme()
            || (self.0.scheme().as_str() == "http" && next.0.scheme().as_str() == "https");
        if same_authority && safe_scheme {
            Ok(next)
        } else {
            Err(HttpUrlError::UntrustedRedirectAuthority)
        }
    }

    pub(crate) fn resolve_trusted_cache_resource(
        &self,
        reference: &str,
    ) -> Result<Self, HttpUrlError> {
        let cache_directory = self.endpoint(&[""]);
        let reference = parse_cache_reference(reference)?;
        let resolved = reference
            .resolve_against(&cache_directory.0)
            .map_err(|error| HttpUrlError::Parse(format!("invalid upstream URL: {error}")))?;
        self.validate_cache_resource(resolved)
    }

    pub(crate) fn resolve_trusted_cache_redirect(
        &self,
        current: &Self,
        location: &str,
    ) -> Result<Self, HttpUrlError> {
        let reference = parse_cache_reference(location)?;
        let resolved = reference
            .resolve_against(&current.0)
            .map_err(|error| HttpUrlError::Parse(format!("invalid upstream redirect: {error}")))?;
        self.validate_cache_resource(resolved)
    }

    fn validate_cache_resource(&self, uri: Uri<String>) -> Result<Self, HttpUrlError> {
        let resource = Self::try_from_uri(uri)?;
        if !self.has_same_origin(&resource) {
            return Err(HttpUrlError::UntrustedResourceOrigin);
        }

        let cache_directory = self.endpoint(&[""]);
        let allowed_path = cache_directory.0.path().as_str();
        if !resource.0.path().as_str().starts_with(allowed_path) {
            return Err(HttpUrlError::UntrustedResourcePath);
        }
        Ok(resource)
    }

    fn has_same_origin(&self, other: &Self) -> bool {
        self.0.scheme() == other.0.scheme()
            && self.host().eq_ignore_ascii_case(other.host())
            && self.port() == other.port()
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn is_https(&self) -> bool {
        self.0.scheme().as_str() == "https"
    }

    pub(crate) fn into_origin(self) -> Option<Self> {
        let is_origin =
            (self.0.path().is_empty() || self.0.path().as_str() == "/") && self.0.query().is_none();
        let builder = Uri::builder().scheme(self.0.scheme());
        let builder = match (is_origin, self.authority().host_parsed()) {
            (true, Host::Ipv4(address)) => {
                builder.authority_with(|builder| builder.host(address).port(self.port()))
            }
            (true, Host::Ipv6(address)) => {
                builder.authority_with(|builder| builder.host(address).port(self.port()))
            }
            (true, Host::RegName(name)) => {
                builder.authority_with(|builder| builder.host(name).port(self.port()))
            }
            (false, _) | (true, Host::IpvFuture { .. }) => return None,
        };
        Some(Self(
            builder
                .path(EStr::EMPTY)
                .build()
                .expect("validated origin components form an HTTP URL")
                .normalize(),
        ))
    }

    pub(crate) fn port(&self) -> u16 {
        self.authority()
            .port_to_u16()
            .expect("validated port")
            .unwrap_or(if self.is_https() { 443 } else { 80 })
    }

    fn try_from_uri(uri: Uri<String>) -> Result<Self, HttpUrlError> {
        let uri = uri.normalize();
        match uri.scheme().as_str() {
            "http" | "https" => {}
            _ => return Err(HttpUrlError::UnsupportedScheme),
        }
        let authority = uri.authority().ok_or(HttpUrlError::MissingAuthority)?;
        if authority.host().is_empty() {
            return Err(HttpUrlError::MissingHost);
        }
        if authority.userinfo().is_some() {
            return Err(HttpUrlError::Credentials);
        }
        authority
            .port_to_u16()
            .map_err(|_| HttpUrlError::InvalidPort)?;
        if uri.fragment().is_some() {
            return Err(HttpUrlError::Fragment);
        }
        Ok(Self(uri))
    }
}

fn parse_cache_reference(value: &str) -> Result<UriRef<String>, HttpUrlError> {
    let reference = UriRef::parse(value.trim())
        .map_err(|error| HttpUrlError::Parse(format!("invalid upstream URL reference: {error}")))?;
    let path = reference.path().as_str();
    if reference.has_fragment() || has_ambiguous_path_escape(path) {
        return Err(HttpUrlError::UntrustedResourcePath);
    }
    Ok(reference.to_owned())
}

fn has_ambiguous_path_escape(path: &str) -> bool {
    path.split('/').any(|segment| {
        let decoded_dot = segment.replace("%2e", ".").replace("%2E", ".");
        decoded_dot != segment && (decoded_dot == "." || decoded_dot == "..")
    }) || ["%2f", "%2F", "%5c", "%5C"]
        .iter()
        .any(|escape| path.contains(escape))
}

impl FromStr for HttpUrl {
    type Err = HttpUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uri = Uri::parse(value)
            .map_err(|error| HttpUrlError::Parse(format!("invalid HTTP URL: {error}")))?
            .to_owned();
        Self::try_from_uri(uri)
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::HttpUrl;

    #[test]
    fn endpoints_preserve_the_cache_base_path_and_drop_store_parameters() {
        let cache = HttpUrl::from_str("https://cache.example/base?compression=zstd")
            .expect("cache URL should parse");

        assert_eq!(
            cache.endpoint(&["nar", "object.nar"]).as_str(),
            "https://cache.example/base/nar/object.nar"
        );
    }

    #[test]
    fn redirects_use_standard_relative_reference_resolution() {
        let current = HttpUrl::from_str("http://cache.example/base/nar/object.nar")
            .expect("current URL should parse");

        assert_eq!(
            current
                .resolve_trusted_redirect("../uploaded/object.nar?token=1#ignored")
                .expect("same-cache relative redirect should be trusted")
                .as_str(),
            "http://cache.example/base/uploaded/object.nar?token=1"
        );
    }

    #[test]
    fn redirects_reject_cross_authority_and_https_downgrades() {
        let http = HttpUrl::from_str("http://cache.example/object").expect("HTTP URL should parse");
        let https =
            HttpUrl::from_str("https://cache.example/object").expect("HTTPS URL should parse");

        assert!(
            http.resolve_trusted_redirect("https://other.example/object")
                .is_err()
        );
        assert!(
            https
                .resolve_trusted_redirect("http://cache.example/object")
                .is_err()
        );
    }

    #[test]
    fn upstream_resources_resolve_queries_and_same_origin_absolute_urls() {
        let cache =
            HttpUrl::from_str("https://cache.example/base/cache").expect("cache URL should parse");

        assert_eq!(
            cache
                .resolve_trusted_cache_resource("objects/not-a-hash.nar?token=1")
                .expect("relative object URL should stay in the configured cache path")
                .as_str(),
            "https://cache.example/base/cache/objects/not-a-hash.nar?token=1"
        );
        assert_eq!(
            cache
                .resolve_trusted_cache_resource(
                    "https://cache.example/base/cache/objects/object.nar?token=2"
                )
                .expect("same-origin absolute object URL should be permitted")
                .as_str(),
            "https://cache.example/base/cache/objects/object.nar?token=2"
        );
        assert_eq!(
            cache
                .resolve_trusted_cache_resource("./objects/a.nar")
                .expect("in-scope dot segment should be normalized")
                .as_str(),
            "https://cache.example/base/cache/objects/a.nar"
        );
        assert_eq!(
            cache
                .resolve_trusted_cache_resource("objects/a%20file.nar?token=3")
                .expect("escaped path characters should remain valid")
                .as_str(),
            "https://cache.example/base/cache/objects/a%20file.nar?token=3"
        );
    }

    #[test]
    fn upstream_resources_reject_path_escapes_and_other_origins() {
        let cache =
            HttpUrl::from_str("https://cache.example/base/cache/").expect("cache URL should parse");

        for location in [
            "../outside.nar",
            "%2e%2e/outside.nar",
            "https://cache.example/base/other/object.nar",
            "https://other.example/base/cache/object.nar",
            "https://user:secret@cache.example/base/cache/object.nar",
            "http://cache.example/base/cache/object.nar",
        ] {
            assert!(
                cache.resolve_trusted_cache_resource(location).is_err(),
                "accepted untrusted upstream URL {location}"
            );
        }
    }

    #[test]
    fn upstream_redirects_must_stay_inside_the_configured_path() {
        let cache =
            HttpUrl::from_str("https://cache.example/base/cache/").expect("cache URL should parse");
        let current = cache
            .resolve_trusted_cache_resource("objects/object.nar")
            .expect("initial object should resolve");

        assert_eq!(
            cache
                .resolve_trusted_cache_redirect(&current, "../other/object.nar?token=3")
                .expect("normalized redirect remains within the configured cache path")
                .as_str(),
            "https://cache.example/base/cache/other/object.nar?token=3"
        );
        assert_eq!(
            cache
                .resolve_trusted_cache_redirect(&current, "../../outside.nar")
                .expect_err("redirect escaping the cache path must be rejected"),
            super::HttpUrlError::UntrustedResourcePath
        );
        assert_eq!(
            cache
                .resolve_trusted_cache_redirect(&current, "sibling.nar?token=3")
                .expect("same-scope redirect should resolve")
                .as_str(),
            "https://cache.example/base/cache/objects/sibling.nar?token=3"
        );
    }

    #[test]
    fn parser_rejects_non_http_credentials_and_fragments() {
        for value in [
            "file:///tmp/cache",
            "https://user:secret@cache.example",
            "https://cache.example/#fragment",
        ] {
            assert!(HttpUrl::from_str(value).is_err(), "accepted {value}");
        }
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (&HttpUrlError::Parse("parse detail".into()), "parse detail"),
            (
                &HttpUrlError::UnsupportedScheme,
                "URL must use http:// or https://",
            ),
            (
                &HttpUrlError::MissingAuthority,
                "URL must include an authority",
            ),
            (&HttpUrlError::MissingHost, "URL must include a host"),
            (
                &HttpUrlError::Credentials,
                "URL must not contain credentials; use --netrc-file",
            ),
            (&HttpUrlError::InvalidPort, "URL port must fit in 16 bits"),
            (&HttpUrlError::Fragment, "URL must not contain a fragment"),
            (
                &HttpUrlError::UntrustedRedirectAuthority,
                "redirect leaves the trusted cache authority",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }
}
