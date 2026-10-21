use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use mdns_sd::{ResolvedService, ServiceEvent};

use crate::http_url::HttpUrl;

pub(super) const SERVICE_TYPES: [&str; 2] = ["_http._tcp.local.", "_https._tcp.local."];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CacheOrigin(HttpUrl);

impl FromStr for CacheOrigin {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url: HttpUrl = value.parse().map_err(|error| format!("{error}"))?;
        url.into_origin()
            .filter(|origin| {
                origin.port() != 0
                    && origin.as_str().len() <= 251
                    && is_unambiguous_network_host(origin.host())
            })
            .map(Self)
            .ok_or_else(|| "cache URL must be an HTTP(S) origin of at most 251 bytes".into())
    }
}

impl CacheOrigin {
    pub(crate) fn url(&self) -> &HttpUrl {
        &self.0
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str().trim_end_matches('/')
    }

    pub(super) fn is_network_host(&self) -> bool {
        match self.0.host().parse::<IpAddr>() {
            Ok(address) => is_permitted_probe_destination(address),
            Err(_) => !(self.0.host() == "localhost" || self.0.host().ends_with(".localhost")),
        }
    }
}

fn is_unambiguous_network_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || (hostname_validator::is_valid(host) && !is_legacy_numeric_host(host))
}

fn is_legacy_numeric_host(host: &str) -> bool {
    host.split('.').all(|label| match label.strip_prefix("0x") {
        Some(hex) => !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()),
    })
}

pub(super) fn is_permitted_probe_destination(address: IpAddr) -> bool {
    let address = address.to_canonical();
    !(address.is_loopback() || address.is_unspecified())
}

#[derive(Debug)]
pub(super) struct AdvertisedCache {
    instance: String,
    pub(super) origin: CacheOrigin,
    pub(super) setup: SetupPage,
    pub(super) addresses: Vec<SocketAddr>,
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
                addresses: service
                    .get_addresses()
                    .iter()
                    .filter_map(|address| scoped_socket_address(address, service.get_port()))
                    .take(16)
                    .collect(),
            }),
            false => Err("unsupported or inconsistent cache advertisement"),
        }
    }
}

fn scoped_socket_address(address: &mdns_sd::ScopedIp, port: u16) -> Option<SocketAddr> {
    match address {
        mdns_sd::ScopedIp::V4(address) => Some(SocketAddr::from((*address.addr(), port))),
        mdns_sd::ScopedIp::V6(address) => Some(
            std::net::SocketAddrV6::new(*address.addr(), port, 0, address.scope_id().index).into(),
        ),
        _ => None,
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
            "http://2130706433:8080",
            "http://127.1:8080",
            "http://0x7f000001:8080",
            "http://0177.0.0.1:8080",
            "http://[::ffff:127.0.0.1]:8080",
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
        assert_eq!(
            "http://cache.example:08081"
                .parse::<CacheOrigin>()
                .unwrap()
                .as_str(),
            "http://cache.example:8081"
        );
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
    fn origin_normalization_preserves_network_identity_without_rebuilding_urls() {
        for (input, expected) in [
            ("HTTP://CACHE.EXAMPLE:80/", "http://cache.example"),
            ("https://CACHE.EXAMPLE:0443", "https://cache.example"),
            ("http://cache.example:08081", "http://cache.example:8081"),
            (
                "http://[2001:0DB8:0:0::1]:08080/",
                "http://[2001:db8::1]:8080",
            ),
            ("https://[2001:db8::1]:443/", "https://[2001:db8::1]"),
        ] {
            assert_eq!(input.parse::<CacheOrigin>().unwrap().as_str(), expected);
        }
        assert!(
            "http://[v1.cache]".parse::<CacheOrigin>().is_err(),
            "an unsupported address family must not become a DNS name"
        );
        assert!(
            format!("http://{}.example", "a".repeat(64))
                .parse::<CacheOrigin>()
                .is_err()
        );
        assert!(
            format!("http://{}.example", "a".repeat(63))
                .parse::<CacheOrigin>()
                .is_ok()
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
