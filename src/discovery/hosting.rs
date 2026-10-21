use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::Args;
use mdns_sd::{
    DaemonEvent, DaemonStatus, IfKind, Receiver, RecvTimeoutError, ServiceDaemon, ServiceInfo,
};
use sha2::{Digest, Sha256};

use super::{
    advertisement::{CacheOrigin, SERVICE_TYPES, SetupPage},
    page::SetupDocument,
    runtime,
};
use crate::{
    cache::{auth::ReadVisibility, narinfo::TrustedPublicKeys},
    error::Error,
};

#[derive(Args, Debug)]
pub(crate) struct HostingArgs {
    /// Public cache origin used in setup instructions and LAN advertisements, never inferred from Host.
    #[arg(long, env = "NARJAR_PUBLIC_URL")]
    public_url: Option<CacheOrigin>,
    /// Advertise the configured public URL with native mDNS/DNS-SD.
    #[arg(long, env = "NARJAR_ADVERTISE", requires = "public_url")]
    advertise: bool,
    /// DNS-SD display name; name conflicts are handled by mDNS probing.
    #[arg(long, env = "NARJAR_DISCOVERY_NAME", requires = "advertise")]
    discovery_name: Option<String>,
    /// Serve client setup instructions at exactly / using this cache's public trust policy.
    #[arg(long, env = "NARJAR_ONBOARDING", requires = "public_url")]
    onboarding: bool,
    /// Include links to existing authenticated diagnostics in the setup page.
    #[arg(long, env = "NARJAR_ONBOARDING_DIAGNOSTICS", requires = "onboarding")]
    onboarding_diagnostics: bool,
}

#[derive(Debug)]
pub(crate) struct HostingConfig(HostingState);

#[derive(Debug)]
enum HostingState {
    Disabled,
    Enabled {
        origin: CacheOrigin,
        setup: SetupPage,
        diagnostics: Diagnostics,
        minimum_lease: Option<u64>,
        advertisement: Option<Box<ServiceInfo>>,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Diagnostics {
    Omit,
    Include,
}

impl HostingArgs {
    pub(crate) fn prepare(self, minimum_lease: Option<u64>) -> Result<HostingConfig, String> {
        match (self.onboarding, minimum_lease) {
            (true, Some(lease)) if lease < 900 => return Err("onboarding's 300-second client TTL requires an advertisement lease of at least 900 seconds".into()),
            (true, Some(_) | None) | (false, _) => {}
        }
        match self.public_url {
            None => Ok(HostingConfig(HostingState::Disabled)),
            Some(origin) => {
                let setup = if self.onboarding {
                    SetupPage::Available
                } else {
                    SetupPage::NotAdvertised
                };
                let advertisement = self
                    .advertise
                    .then(|| make_advertisement(&origin, self.discovery_name.as_deref(), &setup))
                    .transpose()?
                    .map(Box::new);
                Ok(HostingConfig(HostingState::Enabled {
                    origin,
                    setup,
                    advertisement,
                    minimum_lease,
                    diagnostics: if self.onboarding_diagnostics {
                        Diagnostics::Include
                    } else {
                        Diagnostics::Omit
                    },
                }))
            }
        }
    }
}

impl HostingConfig {
    pub(crate) fn setup_document(
        &self,
        trusted: &TrustedPublicKeys,
        visibility: ReadVisibility,
    ) -> Result<Option<SetupDocument>, Error> {
        match &self.0 {
            HostingState::Enabled {
                origin,
                setup: SetupPage::Available,
                diagnostics,
                minimum_lease,
                ..
            } => SetupDocument::new(origin, trusted, visibility, *diagnostics, *minimum_lease)
                .map(Some),
            HostingState::Disabled
            | HostingState::Enabled {
                setup: SetupPage::NotAdvertised,
                ..
            } => Ok(None),
        }
    }

    pub(crate) fn advertise(
        &self,
        listener: SocketAddr,
    ) -> Result<Option<RunningAdvertisement>, Error> {
        match &self.0 {
            HostingState::Enabled {
                advertisement: Some(service),
                origin,
                ..
            } => RunningAdvertisement::start(service.as_ref().clone(), origin, listener).map(Some),
            HostingState::Disabled
            | HostingState::Enabled {
                advertisement: None,
                ..
            } => Ok(None),
        }
    }
}

fn make_advertisement(
    origin: &CacheOrigin,
    name: Option<&str>,
    setup: &SetupPage,
) -> Result<ServiceInfo, String> {
    if !origin.is_network_host() {
        return Err("LAN advertisement requires a non-loopback public origin".into());
    }
    let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(origin.as_str().as_bytes()));
    let default_name = format!(
        "Narjar {} {}",
        origin.url().host().chars().take(32).collect::<String>(),
        &digest[..8]
    );
    let name = name.unwrap_or(&default_name);
    if name.is_empty() || name.len() > 63 || name.chars().any(char::is_control) {
        return Err(
            "discovery name must contain 1–63 UTF-8 bytes without control characters".into(),
        );
    }
    let hostname = match origin.url().host().ends_with(".local") {
        true => format!("{}.", origin.url().host()),
        false => format!("narjar-{}.local.", &digest[..12]),
    };
    let kind = if origin.url().is_https() {
        SERVICE_TYPES[1]
    } else {
        SERVICE_TYPES[0]
    };
    let mut properties = vec![
        ("nix-cache", "1"),
        ("narjar", "1"),
        ("path", "/"),
        ("url", origin.as_str()),
    ];
    if let SetupPage::Available = setup {
        properties.push(("setup", "/"));
    }
    ServiceInfo::new(
        kind,
        name,
        &hostname,
        "",
        origin.url().port(),
        properties.as_slice(),
    )
    .map(ServiceInfo::enable_addr_auto)
    .map_err(|error| error.to_string())
}

pub(crate) struct RunningAdvertisement {
    stopping: Arc<AtomicBool>,
    observer: Option<thread::JoinHandle<()>>,
}

impl RunningAdvertisement {
    fn start(
        service: ServiceInfo,
        origin: &CacheOrigin,
        listener: SocketAddr,
    ) -> Result<Self, Error> {
        Self::register_and_observe(
            service,
            origin,
            listener,
            ServiceDaemon::new().map_err(runtime)?,
        )
    }

    fn register_and_observe(
        mut service: ServiceInfo,
        origin: &CacheOrigin,
        listener: SocketAddr,
        daemon: ServiceDaemon,
    ) -> Result<Self, Error> {
        service.set_interfaces(vec![advertised_interface(listener)]);
        let fullname = service.get_fullname().to_owned();
        let daemon = scopeguard::guard(daemon, move |daemon| {
            let withdrawn = withdraw_advertisement(&daemon, &fullname);
            let stopped = shutdown_daemon(&daemon);
            if let Err(error) = withdrawn.and(stopped) {
                eprintln!("narjar: cannot withdraw LAN advertisement: {error}");
            }
        });
        let fixed_hostname = origin
            .url()
            .host()
            .ends_with(".local")
            .then(|| service.get_hostname().to_owned());
        let events = daemon.monitor().map_err(runtime)?;
        daemon.register(service).map_err(runtime)?;
        await_announcement(
            |wait| events.recv_timeout(wait).map_err(runtime),
            Instant::now() + Duration::from_secs(5),
            fixed_hostname.as_deref(),
        )?;
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stopping);
        let observer = thread::Builder::new()
            .name("narjar-advertisement".into())
            .spawn(move || {
                let _owned_advertisement = daemon;
                if let Err(error) =
                    observe_advertisement(events, &worker_stop, fixed_hostname.as_deref())
                {
                    eprintln!("narjar: LAN advertisement stopped: {error}");
                }
            })
            .map_err(runtime)?;
        Ok(Self {
            stopping,
            observer: Some(observer),
        })
    }
}

enum AnnouncementProgress {
    Waiting,
    Announced,
}

fn classify_advertisement_event(
    event: DaemonEvent,
    fixed_hostname: Option<&str>,
) -> Result<AnnouncementProgress, Error> {
    match event {
        DaemonEvent::Announce(_, _) => Ok(AnnouncementProgress::Announced),
        DaemonEvent::Error(error) => Err(runtime(error)),
        DaemonEvent::NameChange(change)
            if fixed_hostname.is_some_and(|name| name.eq_ignore_ascii_case(&change.original)) =>
        {
            Err(Error::runtime(
                "configured .local cache hostname conflicts with another host; choose a unique --public-url",
            ))
        }
        DaemonEvent::NameChange(_)
        | DaemonEvent::IpAdd(_)
        | DaemonEvent::IpDel(_)
        | DaemonEvent::Respond(_) => Ok(AnnouncementProgress::Waiting),
        _ => Ok(AnnouncementProgress::Waiting),
    }
}

fn await_announcement(
    mut receive: impl FnMut(Duration) -> Result<DaemonEvent, Error>,
    deadline: Instant,
    fixed_hostname: Option<&str>,
) -> Result<(), Error> {
    std::iter::from_fn(|| remaining_announcement_wait(deadline, Instant::now()).map(&mut receive))
        .find_map(|event| {
            match event.and_then(|event| classify_advertisement_event(event, fixed_hostname)) {
                Ok(AnnouncementProgress::Announced) => Some(Ok(())),
                Ok(AnnouncementProgress::Waiting) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .unwrap_or_else(|| {
            Err(Error::runtime(
                "LAN advertisement did not announce within five seconds",
            ))
        })
}

fn remaining_announcement_wait(deadline: Instant, now: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
}

fn observe_advertisement(
    events: Receiver<DaemonEvent>,
    stopping: &AtomicBool,
    fixed_hostname: Option<&str>,
) -> Result<(), Error> {
    std::iter::from_fn(|| {
        (!stopping.load(Ordering::Acquire)).then(|| events.recv_timeout(Duration::from_millis(100)))
    })
    .try_for_each(|event| match event {
        Ok(event) => classify_advertisement_event(event, fixed_hostname).map(|_| ()),
        Err(RecvTimeoutError::Timeout) => Ok(()),
        Err(RecvTimeoutError::Disconnected) => {
            Err(Error::runtime("LAN advertisement daemon stopped"))
        }
    })
}

fn withdraw_advertisement(daemon: &ServiceDaemon, fullname: &str) -> Result<(), Error> {
    daemon
        .unregister(fullname)
        .map_err(runtime)?
        .recv_timeout(Duration::from_millis(500))
        .map(|_| ())
        .map_err(runtime)
}

fn advertised_interface(listener: SocketAddr) -> IfKind {
    match listener.ip() {
        address if address.is_loopback() => IfKind::All,
        std::net::IpAddr::V4(address) if address.is_unspecified() => IfKind::IPv4,
        std::net::IpAddr::V6(address) if address.is_unspecified() => IfKind::IPv6,
        address => IfKind::Addr(address),
    }
}

fn shutdown_daemon(daemon: &ServiceDaemon) -> Result<(), Error> {
    match daemon
        .shutdown()
        .map_err(runtime)?
        .recv_timeout(Duration::from_millis(500))
        .map_err(runtime)?
    {
        DaemonStatus::Shutdown => Ok(()),
        _ => Err(Error::runtime("advertisement daemon did not shut down")),
    }
}

impl Drop for RunningAdvertisement {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(observer) = self.observer.take()
            && observer.join().is_err()
        {
            eprintln!("narjar: advertisement observer panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn native_advertisement_announces_and_withdraws_on_isolated_loopback() {
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let daemon = || {
            let daemon = ServiceDaemon::new_with_port(port).unwrap();
            daemon.disable_interface(IfKind::All).unwrap();
            daemon.enable_interface(IfKind::LoopbackV4).unwrap();
            daemon
        };
        let browser = scopeguard::guard(daemon(), |daemon| {
            shutdown_daemon(&daemon).unwrap();
        });
        let events = browser.browse(SERVICE_TYPES[0]).unwrap();
        let origin: CacheOrigin = format!("http://narjar-test-{port}.local:8080")
            .parse()
            .unwrap();
        let service = make_advertisement(
            &origin,
            Some(&format!("Narjar test {port}")),
            &SetupPage::Available,
        )
        .unwrap();
        let running = RunningAdvertisement::register_and_observe(
            service,
            &origin,
            "127.0.0.1:8080".parse().unwrap(),
            daemon(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let resolved = std::iter::from_fn(|| {
            deadline
                .checked_duration_since(Instant::now())
                .map(|wait| events.recv_timeout(wait).unwrap())
        })
        .find_map(|event| match event {
            mdns_sd::ServiceEvent::ServiceResolved(service) => Some(service),
            _ => None,
        })
        .unwrap();
        assert_eq!(resolved.get_property_val_str("url"), Some(origin.as_str()));
        assert_eq!(resolved.get_property_val_str("setup"), Some("/"));
        drop(running);
        let deadline = Instant::now() + Duration::from_secs(5);
        let removed = std::iter::from_fn(|| {
            deadline
                .checked_duration_since(Instant::now())
                .map(|wait| events.recv_timeout(wait).unwrap())
        })
        .any(|event| matches!(event, mdns_sd::ServiceEvent::ServiceRemoved(_, _)));
        assert!(
            removed,
            "dropping the owned advertisement sends its goodbye"
        );
    }

    #[test]
    fn readiness_requires_an_announcement_and_propagates_socket_errors() {
        let now = Instant::now();
        assert_eq!(remaining_announcement_wait(now, now), None);
        assert_eq!(
            remaining_announcement_wait(now, now + Duration::from_secs(1)),
            None
        );
        assert_eq!(
            remaining_announcement_wait(now + Duration::from_secs(1), now),
            Some(Duration::from_secs(1))
        );
        let ready = await_announcement(
            |_| Ok(DaemonEvent::Announce("cache".into(), "127.0.0.1".into())),
            Instant::now() + Duration::from_secs(1),
            None,
        );
        assert!(ready.is_ok());
        let error = await_announcement(
            |_| Err(Error::runtime("multicast join failed")),
            Instant::now() + Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("multicast join failed"));
        assert!(
            await_announcement(
                |_| panic!("expired startup must not read"),
                Instant::now(),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_host_conflicts_fail_but_display_name_conflicts_do_not_change_the_url() {
        let event = |original: &str| {
            DaemonEvent::NameChange(mdns_sd::DnsNameChange {
                original: original.into(),
                new_name: "renamed.local.".into(),
                rr_type: mdns_sd::RRType::A,
                intf_name: "fixture".into(),
            })
        };
        assert!(classify_advertisement_event(event("cache.local."), Some("cache.local.")).is_err());
        assert!(
            classify_advertisement_event(event("Cache._http._tcp.local."), Some("cache.local."))
                .is_ok()
        );
        assert!(classify_advertisement_event(event("generated.local."), None).is_ok());
    }

    #[test]
    fn native_advertisements_use_the_configured_origin_and_optional_setup_route() {
        for (url, kind, port) in [
            ("http://cache.local:8080", SERVICE_TYPES[0], 8080),
            ("https://cache.example:8443", SERVICE_TYPES[1], 8443),
            ("https://cache.example", SERVICE_TYPES[1], 443),
        ] {
            let origin = url.parse().unwrap();
            let service = make_advertisement(&origin, None, &SetupPage::Available).unwrap();
            assert_eq!(service.get_type(), kind);
            assert_eq!(service.get_port(), port);
            assert_eq!(service.get_property_val_str("url"), Some(url));
            assert_eq!(service.get_property_val_str("setup"), Some("/"));
            assert_eq!(service.get_property_val_str("nix-cache"), Some("1"));
            assert!(service.is_addr_auto());
            assert!(
                service.get_addresses().is_empty(),
                "addresses are chosen by the native runtime, not Nix"
            );
            let without_page =
                make_advertisement(&origin, Some("Other cache"), &SetupPage::NotAdvertised)
                    .unwrap();
            assert_eq!(without_page.get_property_val_str("setup"), None);
        }
    }

    #[test]
    fn advertisement_rejects_unreachable_origins_and_invalid_display_names_before_startup() {
        for url in [
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
        ] {
            assert!(
                make_advertisement(&url.parse().unwrap(), None, &SetupPage::Available).is_err()
            );
        }
        for name in ["".to_owned(), "x".repeat(64), "bad\nname".into()] {
            assert!(
                make_advertisement(
                    &"http://cache.local".parse().unwrap(),
                    Some(&name),
                    &SetupPage::Available
                )
                .is_err()
            );
        }
    }
}
