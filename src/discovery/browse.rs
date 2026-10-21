use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Args;
use mdns_sd::{DaemonEvent, DaemonStatus, Receiver, RecvTimeoutError, ServiceDaemon, ServiceEvent};

use crate::{error::Error, host};

use super::{
    advertisement::{AdvertisedCache, Catalog, SERVICE_TYPES, SetupPage},
    runtime,
};

#[derive(Args)]
pub(super) struct Browse {
    /// Seconds to browse. Does not change Nix configuration or signing trust.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=30))]
    timeout_seconds: u16,
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(1..=64))]
    max_results: u16,
    /// Probe advertised URLs without credentials. Adds at most five seconds overall.
    #[arg(long)]
    probe: bool,
}

pub(super) fn run(options: Browse) -> Result<(), Error> {
    let stopping = Arc::new(AtomicBool::new(false));
    let shutdown = host::install_shutdown(Arc::clone(&stopping)).map_err(runtime)?;
    let result = browse_and_report(options, &stopping);
    shutdown.complete();
    result
}

fn browse_and_report(options: Browse, stopping: &AtomicBool) -> Result<(), Error> {
    let catalog = with_mdns_session(|daemon| {
        let monitor = daemon.monitor().map_err(runtime)?;
        let receivers = SERVICE_TYPES
            .map(|kind| daemon.browse(kind))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(runtime)?;
        let deadline = Instant::now() + Duration::from_secs(u64::from(options.timeout_seconds));
        let mut streams = receivers.iter().cycle();
        collect_until_deadline(
            |wait| {
                monitor
                    .try_iter()
                    .take(100)
                    .try_for_each(check_daemon_event)?;
                receive_service_event(streams.next().expect("two browse subscriptions"), wait)
            },
            deadline,
            stopping,
            usize::from(options.max_results),
        )
    })?;
    report_candidates(&catalog, options.probe, stopping)
}

fn with_mdns_session<T>(
    operation: impl FnOnce(&ServiceDaemon) -> Result<T, Error>,
) -> Result<T, Error> {
    let daemon = scopeguard::guard(ServiceDaemon::new().map_err(runtime)?, |daemon| {
        let _ = stop_mdns(&daemon);
    });
    let result = operation(&daemon);
    let stopped = stop_mdns(&scopeguard::ScopeGuard::into_inner(daemon));
    result.and_then(|value| stopped.map(|()| value))
}

fn stop_mdns(daemon: &ServiceDaemon) -> Result<(), Error> {
    SERVICE_TYPES.iter().for_each(|kind| {
        let _ = daemon.stop_browse(kind);
    });
    let result = daemon
        .shutdown()
        .map_err(runtime)?
        .recv_timeout(Duration::from_millis(500))
        .map_err(runtime)?;
    match result {
        DaemonStatus::Shutdown => Ok(()),
        _ => Err(Error::runtime("discovery daemon did not shut down")),
    }
}

fn collect_until_deadline(
    mut receive: impl FnMut(Duration) -> Result<Option<ServiceEvent>, Error>,
    deadline: Instant,
    stopping: &AtomicBool,
    limit: usize,
) -> Result<Catalog, Error> {
    std::iter::from_fn(|| {
        (Instant::now() < deadline && !stopping.load(Ordering::Acquire)).then(|| {
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50));
            receive(wait)
        })
    })
    .try_fold(Catalog::new(limit), |mut catalog, event| {
        event?.into_iter().for_each(|event| catalog.record(event));
        Ok(catalog)
    })
}

fn receive_service_event(
    receiver: &Receiver<ServiceEvent>,
    wait: Duration,
) -> Result<Option<ServiceEvent>, Error> {
    match receiver.recv_timeout(wait) {
        Ok(event) => Ok(Some(event)),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Err(Error::runtime("discovery event stream closed")),
    }
}

fn check_daemon_event(event: DaemonEvent) -> Result<(), Error> {
    match event {
        DaemonEvent::Error(error) => Err(runtime(error)),
        DaemonEvent::Announce(_, _)
        | DaemonEvent::IpAdd(_)
        | DaemonEvent::IpDel(_)
        | DaemonEvent::NameChange(_)
        | DaemonEvent::Respond(_) => Ok(()),
        _ => Ok(()),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Availability {
    NotProbed,
    Reachable,
    RequiresCredentials,
    Unavailable,
}

fn report_candidates(catalog: &Catalog, probe: bool, stopping: &AtomicBool) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = io::stdout().lock();
    writeln!(io::stderr(), "Advertisements are untrusted. Confirm producer keys with the operator before configuring Nix.").map_err(runtime)?;
    catalog.unique_caches().values().try_for_each(|cache| {
        let availability = if probe && !stopping.load(Ordering::Acquire) {
            probe_cache(cache, deadline)
        } else {
            Availability::NotProbed
        };
        let setup = match cache.setup {
            SetupPage::Available => "setup page advertised",
            SetupPage::NotAdvertised => "no setup page advertised",
        };
        writeln!(
            output,
            "{}\t{availability:?}\t{setup}",
            cache.origin.as_str()
        )
        .map_err(runtime)
    })
}

fn probe_cache(cache: &AdvertisedCache, deadline: Instant) -> Availability {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(2));
    match remaining.is_zero() {
        true => Availability::NotProbed,
        false => match request_cache_info(&cache.origin, remaining) {
            Ok(status) => status,
            Err(_) => Availability::Unavailable,
        },
    }
}

fn request_cache_info(
    origin: &super::advertisement::CacheOrigin,
    timeout: Duration,
) -> Result<Availability, ureq::Error> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .timeout_connect(Some(timeout))
        .timeout_recv_body(Some(timeout))
        .build()
        .into();
    let mut response = agent
        .get(origin.url().endpoint(&["nix-cache-info"]).as_str())
        .call()?;
    match response.status().as_u16() {
        200 => {
            let body = response
                .body_mut()
                .with_config()
                .limit(1024)
                .read_to_string()?;
            Ok(if body.lines().any(|line| line == "StoreDir: /nix/store") {
                Availability::Reachable
            } else {
                Availability::Unavailable
            })
        }
        401 | 403 => Ok(Availability::RequiresCredentials),
        _ => Ok(Availability::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        thread,
    };

    #[test]
    fn cancellation_and_an_expired_deadline_never_receive_an_event() {
        for (stopping, deadline) in [
            (
                AtomicBool::new(true),
                Instant::now() + Duration::from_secs(60),
            ),
            (AtomicBool::new(false), Instant::now()),
        ] {
            let catalog = collect_until_deadline(
                |_| panic!("inactive discovery must not read"),
                deadline,
                &stopping,
                2,
            )
            .unwrap();
            assert!(catalog.unique_caches().is_empty());
        }
    }

    #[test]
    fn a_failed_event_source_is_reported_instead_of_looking_like_an_empty_lan() {
        let result = collect_until_deadline(
            |_| Err(Error::runtime("multicast unavailable")),
            Instant::now() + Duration::from_secs(60),
            &AtomicBool::new(false),
            2,
        );
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("multicast unavailable")
        );
    }

    fn probe_response(
        status: u16,
        body: &str,
        extra_headers: &str,
    ) -> Result<Availability, ureq::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        );
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = BufReader::new(&mut stream)
                .lines()
                .map(Result::unwrap)
                .take_while(|line| !line.is_empty())
                .collect::<Vec<_>>();
            assert!(request[0].starts_with("GET /nix-cache-info "));
            assert!(
                !request
                    .iter()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let result = request_cache_info(&origin, Duration::from_secs(2));
        server.join().unwrap();
        result
    }

    #[test]
    fn probes_bound_the_body_preserve_auth_and_do_not_follow_redirects() {
        assert_eq!(
            probe_response(200, "StoreDir: /nix/store\n", "").unwrap(),
            Availability::Reachable
        );
        assert_eq!(
            probe_response(200, "unrelated service", "").unwrap(),
            Availability::Unavailable
        );
        assert_eq!(
            probe_response(401, "", "").unwrap(),
            Availability::RequiresCredentials
        );
        assert_eq!(
            probe_response(302, "", "Location: http://127.0.0.1:9/untrusted\r\n").unwrap(),
            Availability::Unavailable
        );
        assert!(probe_response(200, &"x".repeat(1025), "").is_err());
    }
}
