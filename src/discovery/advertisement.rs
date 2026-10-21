use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use mdns_sd::{ResolvedService, ServiceEvent};

use crate::http_url::HttpUrl;

pub(super) const SERVICE_TYPES: [&str; 2] = ["_http._tcp.local.", "_https._tcp.local."];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CacheOrigin(HttpUrl);

impl FromStr for CacheOrigin {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url: HttpUrl = value.parse().map_err(|error| format!("{error}"))?;
        let host = url.host();
        let supported_host = host.parse::<IpAddr>().is_ok()
            || host.split('.').all(|label| {
                let bytes = label.as_bytes();
                bytes.len() <= 63
                    && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                    && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                    && bytes
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            });
        match url.is_origin() && supported_host && url.port() != 0 && url.as_str().len() <= 251 {
            true => Ok(Self(url)),
            false => Err("cache URL must be an HTTP(S) origin of at most 251 bytes".into()),
        }
    }
}

impl CacheOrigin {
    pub(super) fn url(&self) -> &HttpUrl {
        &self.0
    }

    pub(super) fn as_str(&self) -> &str {
        self.0.as_str().trim_end_matches('/')
    }

    fn is_network_host(&self) -> bool {
        match self.0.host().parse::<IpAddr>() {
            Ok(address) => !address.is_loopback() && !address.is_unspecified(),
            Err(_) => self.0.host() != "localhost" && !self.0.host().ends_with(".localhost"),
        }
    }
}

#[derive(Debug)]
pub(super) struct AdvertisedCache {
    instance: String,
    pub(super) origin: CacheOrigin,
    pub(super) setup: SetupPage,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SetupPage {
    Available,
    NotAdvertised,
}

impl TryFrom<&ResolvedService> for AdvertisedCache {
    type Error = &'static str;

    fn try_from(service: &ResolvedService) -> Result<Self, Self::Error> {
        let required = [("nix-cache", "1"), ("narjar", "1"), ("path", "/")];
        let versioned = required
            .into_iter()
            .all(|(key, value)| service.get_property_val_str(key) == Some(value));
        let origin: CacheOrigin = service
            .get_property_val_str("url")
            .ok_or("missing cache URL")?
            .parse()
            .map_err(|_| "invalid cache origin")?;
        let expected_type = if origin.0.is_https() {
            SERVICE_TYPES[1]
        } else {
            SERVICE_TYPES[0]
        };
        let local_target_matches = !origin.0.host().ends_with(".local")
            || origin
                .0
                .host()
                .eq_ignore_ascii_case(service.get_hostname().trim_end_matches('.'));
        let valid = versioned
            && service.ty_domain == expected_type
            && service.get_port() == origin.0.port()
            && origin.is_network_host()
            && local_target_matches
            && service.is_valid()
            && service.get_fullname().len() <= 255;
        let setup = match service.get_property_val_str("setup") {
            Some("/") => SetupPage::Available,
            None => SetupPage::NotAdvertised,
            Some(_) => return Err("unsupported setup location"),
        };
        match valid {
            true => Ok(Self {
                instance: service.get_fullname().to_owned(),
                origin,
                setup,
            }),
            false => Err("unsupported or inconsistent cache advertisement"),
        }
    }
}

pub(super) struct Catalog {
    instances: BTreeMap<String, AdvertisedCache>,
    limit: usize,
}

impl Catalog {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            instances: BTreeMap::new(),
            limit,
        }
    }

    pub(super) fn record(&mut self, event: ServiceEvent) {
        match event {
            ServiceEvent::ServiceResolved(service) => self.replace_resolved_instance(&service),
            ServiceEvent::ServiceRemoved(_, instance) => {
                self.instances.remove(&instance);
            }
            ServiceEvent::SearchStarted(_)
            | ServiceEvent::ServiceFound(_, _)
            | ServiceEvent::SearchStopped(_) => {}
            // The dependency marks ServiceEvent non-exhaustive.
            _ => {}
        }
    }

    fn replace_resolved_instance(&mut self, service: &ResolvedService) {
        self.instances.remove(service.get_fullname());
        match AdvertisedCache::try_from(service) {
            Ok(cache) if self.instances.len() < self.limit => {
                self.instances.insert(cache.instance.clone(), cache);
            }
            Ok(_) | Err(_) => {}
        }
    }

    pub(super) fn unique_caches(&self) -> BTreeMap<(bool, &str, u16), &AdvertisedCache> {
        self.instances
            .values()
            .map(|cache| {
                (
                    (
                        cache.origin.0.is_https(),
                        cache.origin.0.host(),
                        cache.origin.0.port(),
                    ),
                    cache,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdns_sd::ServiceInfo;

    fn advertisement(name: &str, url: &str) -> ResolvedService {
        ServiceInfo::new(
            SERVICE_TYPES[0],
            name,
            "cache.local.",
            "192.0.2.1",
            8080,
            [
                ("nix-cache", "1"),
                ("narjar", "1"),
                ("url", url),
                ("path", "/"),
                ("setup", "/"),
            ]
            .as_slice(),
        )
        .unwrap()
        .as_resolved_service()
    }

    #[test]
    fn only_consistent_versioned_origins_become_candidates() {
        assert!(
            AdvertisedCache::try_from(&advertisement("cache", "http://cache.local:8080")).is_ok()
        );
        for url in [
            "http://user:pass@cache.local:8080",
            "http://cache.local:8080/x",
            "http://cache.local:8080?x",
            "http://127.0.0.1:8080",
            "http://other.local:8080",
            "https://cache.local:8080",
            "http://cache.local:8081",
        ] {
            assert!(
                AdvertisedCache::try_from(&advertisement("cache", url)).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn catalog_deduplicates_caps_and_removes_instances_without_trusting_names() {
        let mut catalog = Catalog::new(2);
        for name in ["one", "two", "three"] {
            catalog.record(ServiceEvent::ServiceResolved(Box::new(advertisement(
                name,
                "http://cache.local:8080",
            ))));
        }
        assert_eq!(catalog.instances.len(), 2);
        assert_eq!(catalog.unique_caches().len(), 1);
        catalog.record(ServiceEvent::ServiceRemoved(
            SERVICE_TYPES[0].into(),
            "one._http._tcp.local.".into(),
        ));
        assert_eq!(catalog.instances.len(), 1);
        let mut changed = advertisement("two", "http://cache.local:8080");
        changed.port = 9000;
        catalog.record(ServiceEvent::ServiceResolved(Box::new(changed)));
        assert!(
            catalog.unique_caches().is_empty(),
            "invalid updates must remove stale accepted data"
        );
    }

    #[test]
    fn default_ports_and_host_case_do_not_create_duplicate_caches() {
        let mut catalog = Catalog::new(4);
        for (name, url) in [
            ("one", "http://cache.example"),
            ("two", "http://CACHE.EXAMPLE:80/"),
        ] {
            let mut service = advertisement(name, url);
            service.port = 80;
            catalog.record(ServiceEvent::ServiceResolved(Box::new(service)));
        }
        assert_eq!(catalog.unique_caches().len(), 1);
        for url in [
            "http://cache.example.",
            "http://bad_host.example",
            "http://cache.example:0",
            "http://cache.example/\u{1b}",
        ] {
            assert!(url.parse::<CacheOrigin>().is_err(), "{url:?}");
        }
    }
}
