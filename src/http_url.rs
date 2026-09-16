use std::{fmt, str::FromStr};

use fluent_uri::{
    Uri, UriRef,
    component::Authority,
    pct_enc::{
        EStr, EString,
        encoder::{Data, Path},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpUrl(Uri<String>);

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

    pub(crate) fn resolve_trusted_redirect(&self, location: &str) -> Result<Self, String> {
        let reference = UriRef::parse(location.trim())
            .map_err(|error| format!("PUT {self} redirect has an invalid Location: {error}"))?;
        let mut next = reference
            .resolve_against(&self.0)
            .map_err(|error| format!("PUT {self} redirect has an invalid Location: {error}"))?;
        next.set_fragment(None);
        let next = Self::try_from_uri(next)
            .map_err(|error| format!("PUT {self} redirect is invalid: {error}"))?;

        let same_authority = self.authority().as_str() == next.authority().as_str();
        let safe_scheme = self.0.scheme() == next.0.scheme()
            || (self.0.scheme().as_str() == "http" && next.0.scheme().as_str() == "https");
        if same_authority && safe_scheme {
            Ok(next)
        } else {
            Err(format!(
                "PUT {self} redirect leaves the trusted cache authority"
            ))
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn is_https(&self) -> bool {
        self.0.scheme().as_str() == "https"
    }

    fn try_from_uri(uri: Uri<String>) -> Result<Self, String> {
        let uri = uri.normalize();
        match uri.scheme().as_str() {
            "http" | "https" => {}
            _ => return Err("URL must use http:// or https://".to_owned()),
        }
        let authority = uri
            .authority()
            .ok_or_else(|| "URL must include an authority".to_owned())?;
        if authority.host().is_empty() {
            return Err("URL must include a host".to_owned());
        }
        if authority.userinfo().is_some() {
            return Err("URL must not contain credentials; use --netrc-file".to_owned());
        }
        authority
            .port_to_u16()
            .map_err(|_| "URL port must fit in 16 bits".to_owned())?;
        if uri.fragment().is_some() {
            return Err("URL must not contain a fragment".to_owned());
        }
        Ok(Self(uri))
    }
}

impl FromStr for HttpUrl {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uri = Uri::parse(value)
            .map_err(|error| format!("invalid HTTP URL: {error}"))?
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
