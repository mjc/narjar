use std::{
    io::{self, Read},
    ops::Range,
    thread,
    time::Duration,
};

use ureq::{Agent, AsSendBody, RequestBuilder, http::StatusCode};

use super::PushError;
use crate::http_url::HttpUrl;

const MAX_REDIRECTS: usize = 10;
const MAX_RETRY_AFTER_SECONDS: u64 = 60;
const MAX_IGNORED_RESPONSE_BODY_BYTES: u64 = 64 * 1024;

type Response = ureq::http::Response<ureq::Body>;

#[derive(Clone, Copy)]
pub(super) enum LookupPurpose {
    Destination,
    UpstreamProbe,
}

#[derive(Clone, Copy)]
enum RequestKind {
    Get(LookupPurpose),
    Put,
}

struct RetryState {
    status: Range<usize>,
    gateway: Range<usize>,
    transport: Range<usize>,
}

impl RetryState {
    fn new(kind: RequestKind) -> Self {
        let (status, gateway, transport) = match kind {
            RequestKind::Get(LookupPurpose::Destination) => (2, 7, 2),
            RequestKind::Get(LookupPurpose::UpstreamProbe) => (0, 0, 0),
            RequestKind::Put => (2, 2, 2),
        };
        Self {
            status: 0..status,
            gateway: 0..gateway,
            transport: 0..transport,
        }
    }

    fn delay_for(&mut self, result: &Result<Response, PushError>) -> Option<Duration> {
        let (attempt, retry_after) = match result {
            Ok(response) => {
                let attempt = match response.status() {
                    StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => {
                        self.gateway.next()?
                    }
                    StatusCode::REQUEST_TIMEOUT
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::INTERNAL_SERVER_ERROR
                    | StatusCode::GATEWAY_TIMEOUT => self.status.next()?,
                    _ => return None,
                };
                (
                    attempt,
                    response_header(response, "Retry-After").and_then(retry_after_delay),
                )
            }
            Err(_) => (self.transport.next()?, None),
        };
        Some(retry_delay(attempt, retry_after))
    }
}

#[derive(Debug)]
pub(super) enum GetResponse {
    Found(Vec<u8>),
    Missing,
    UnexpectedStatus(StatusCode),
}

impl RequestKind {
    fn redirect_target(
        self,
        url: &HttpUrl,
        response: &Response,
        redirects: usize,
    ) -> Result<Option<HttpUrl>, PushError> {
        match (self, response.status()) {
            (_, StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT)
            | (
                Self::Get(_),
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER,
            ) => resolve_response_redirect(self, url, response, redirects).map(Some),
            (Self::Get(_) | Self::Put, _) => Ok(None),
        }
    }

    fn method(self) -> ureq::http::Method {
        match self {
            Self::Get(_) => ureq::http::Method::GET,
            Self::Put => ureq::http::Method::PUT,
        }
    }

    fn restart_after_delay(self, original: &HttpUrl, current: &mut HttpUrl, delay: Duration) {
        match self {
            Self::Get(_) => current.clone_from(original),
            Self::Put => {}
        }
        thread::sleep(delay);
    }

    fn discard_redirect_body(self, url: &HttpUrl, response: Response) -> Result<(), PushError> {
        match self {
            Self::Get(_) => Ok(()),
            Self::Put => finish_upload_response(url, response).map(|_| ()),
        }
    }
}

pub(super) fn retry_after_delay(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECONDS)))
}

fn retry_delay(retry: usize, retry_after: Option<Duration>) -> Duration {
    let multiplier = 1u64 << retry.min(6);
    retry_after.unwrap_or_else(|| Duration::from_millis(100 * multiplier))
}

fn response_header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response.headers().get(name)?.to_str().ok()
}

fn read_bounded_success_body(
    response: Response,
    request_url: &HttpUrl,
    max_body_bytes: u64,
) -> Result<Vec<u8>, PushError> {
    let mut body = response.into_body().into_reader();
    let mut bytes = Vec::new();
    (&mut body)
        .take(max_body_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading GET {request_url} response failed: {error}"))?;
    if bytes.len() as u64 > max_body_bytes {
        return Err(format!("GET {request_url} response exceeded {max_body_bytes} bytes").into());
    }
    Ok(bytes)
}

fn finish_upload_response(url: &HttpUrl, response: Response) -> Result<StatusCode, PushError> {
    let status = response.status();
    let body = response.into_body().into_reader();
    io::copy(
        &mut body.take(MAX_IGNORED_RESPONSE_BODY_BYTES),
        &mut io::sink(),
    )
    .map_err(|error| format!("reading PUT {url} response failed: {error}"))?;
    Ok(status)
}

#[cfg(test)]
pub(super) fn request_status(
    agent: &Agent,
    url: &HttpUrl,
    authorization: Option<&str>,
) -> Result<u16, PushError> {
    get_bounded(
        agent,
        url,
        authorization,
        MAX_IGNORED_RESPONSE_BODY_BYTES,
        LookupPurpose::Destination,
    )
    .map(|response| match response {
        GetResponse::Found(_) => StatusCode::OK.as_u16(),
        GetResponse::Missing => StatusCode::NOT_FOUND.as_u16(),
        GetResponse::UnexpectedStatus(status) => status.as_u16(),
    })
}

pub(super) fn get_bounded(
    agent: &Agent,
    url: &HttpUrl,
    authorization: Option<&str>,
    max_body_bytes: u64,
    purpose: LookupPurpose,
) -> Result<GetResponse, PushError> {
    let (request_url, response) =
        send_with_retries(RequestKind::Get(purpose), url, |request_url| {
            configure_request(agent.get(request_url.as_str()), authorization)
                .call()
                .map_err(|error| format!("GET {request_url} failed: {error}").into())
        })?;
    match response.status() {
        StatusCode::OK => read_bounded_success_body(response, &request_url, max_body_bytes)
            .map(GetResponse::Found),
        StatusCode::NOT_FOUND => Ok(GetResponse::Missing),
        status => Ok(GetResponse::UnexpectedStatus(status)),
    }
}

fn send_with_retries(
    kind: RequestKind,
    original_url: &HttpUrl,
    mut send: impl FnMut(&HttpUrl) -> Result<Response, PushError>,
) -> Result<(HttpUrl, Response), PushError> {
    let mut request_url = original_url.clone();
    let mut redirects = 0;
    let mut retries = RetryState::new(kind);
    loop {
        let response = send(&request_url);
        match retries.delay_for(&response) {
            Some(delay) => {
                drop(response);
                redirects = 0;
                kind.restart_after_delay(original_url, &mut request_url, delay);
            }
            None => {
                let response = response?;
                match kind.redirect_target(&request_url, &response, redirects)? {
                    Some(next_url) => {
                        kind.discard_redirect_body(&request_url, response)?;
                        request_url = next_url;
                        redirects += 1;
                    }
                    None => return Ok((request_url, response)),
                }
            }
        }
    }
}

fn resolve_response_redirect(
    kind: RequestKind,
    request_url: &HttpUrl,
    response: &Response,
    redirects: usize,
) -> Result<HttpUrl, PushError> {
    let method = kind.method();
    if redirects == MAX_REDIRECTS {
        return Err(format!("{method} {request_url} followed too many redirects").into());
    }
    let location = response_header(response, "Location").ok_or_else(|| {
        format!("{method} {request_url} redirect response had no Location header")
    })?;
    Ok(request_url.resolve_trusted_redirect(location)?)
}

fn configure_request<State>(
    request: RequestBuilder<State>,
    authorization: Option<&str>,
) -> RequestBuilder<State> {
    let request = request
        .config()
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    match authorization {
        Some(authorization) => request.header("Authorization", format!("Basic {authorization}")),
        None => request,
    }
}

pub(super) fn put<Body: AsSendBody>(
    agent: &Agent,
    url: &HttpUrl,
    content_length: u64,
    content_type: &str,
    authorization: Option<&str>,
    mut open: impl FnMut() -> Result<Body, PushError>,
) -> Result<StatusCode, PushError> {
    let (url, response) = send_with_retries(RequestKind::Put, url, |upload_url| {
        let body = open()?;
        configure_request(agent.put(upload_url.as_str()), authorization)
            .header("Content-Type", content_type)
            .header("Content-Length", content_length.to_string())
            .send(body)
            .map_err(|error| PushError::new(format!("PUT {upload_url} failed: {error}")))
    })?;
    finish_upload_response(&url, response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESTINATION_GET: RequestKind = RequestKind::Get(LookupPurpose::Destination);

    #[test]
    fn optional_upstream_probes_never_retry_service_or_transport_failures() {
        let url: HttpUrl = "http://cache.example/probe".parse().unwrap();
        let kind = RequestKind::Get(LookupPurpose::UpstreamProbe);
        for status in [408, 429, 500, 502, 503, 504] {
            let mut requests = 0;
            let (_, result) = send_with_retries(kind, &url, |_| {
                requests += 1;
                Ok(response(status, ""))
            })
            .unwrap();
            assert_eq!(requests, 1);
            assert_eq!(result.status().as_u16(), status);
        }
        let mut requests = 0;
        let error = send_with_retries(kind, &url, |_| {
            requests += 1;
            Err(PushError::new("upstream offline"))
        })
        .unwrap_err();
        assert_eq!(requests, 1);
        assert!(error.contains("upstream offline"));

        let mut retries = RetryState::new(kind);
        let delayed = ureq::http::Response::builder()
            .status(503)
            .header("Retry-After", "60")
            .body(ureq::Body::builder().data(Vec::new()))
            .unwrap();
        assert_eq!(
            retries.delay_for(&Ok(delayed)),
            None,
            "an optional probe must not wait for Retry-After"
        );
    }

    #[test]
    fn exhausted_gateway_retries_do_not_borrow_the_status_budget() {
        for (kind, attempts) in [(DESTINATION_GET, 7), (RequestKind::Put, 2)] {
            let mut retries = RetryState::new(kind);
            for _ in 0..attempts {
                assert!(retries.delay_for(&Ok(response(502, ""))).is_some());
            }
            assert_eq!(
                retries.delay_for(&Ok(response(503, ""))),
                None,
                "502 and 503 share one budget; exhaustion must not fall through to another class"
            );
            assert!(retries.delay_for(&Ok(response(429, ""))).is_some());
        }
    }

    #[test]
    fn retries_only_transient_http_failures() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(
                RetryState::new(DESTINATION_GET)
                    .delay_for(&Ok(response(status, "")))
                    .is_some()
            );
        }
        for status in [200, 201, 301, 307, 400, 401, 404, 409, 413, 422] {
            assert!(
                RetryState::new(DESTINATION_GET)
                    .delay_for(&Ok(response(status, "")))
                    .is_none()
            );
        }
    }

    fn response(status: u16, location: &str) -> Response {
        ureq::http::Response::builder()
            .status(status)
            .header("Location", location)
            .header("Retry-After", "0")
            .body(ureq::Body::builder().data(Vec::new()))
            .unwrap()
    }

    #[test]
    fn get_retries_restart_the_lookup_and_put_retries_keep_the_upload_target() {
        let original: HttpUrl = "http://cache.example/start".parse().unwrap();
        for (kind, last_path) in [(DESTINATION_GET, "start"), (RequestKind::Put, "payload")] {
            let mut script = [
                ("start", response(307, "/payload")),
                ("payload", response(503, "")),
                (last_path, response(200, "")),
            ]
            .into_iter();
            let (final_url, final_response) = send_with_retries(kind, &original, |url| {
                let (path, response) = script
                    .next()
                    .expect("no additional requests should be made");
                assert_eq!(url.as_str(), format!("http://cache.example/{path}"));
                Ok(response)
            })
            .unwrap();
            assert_eq!(script.count(), 0);
            assert_eq!(
                final_url.as_str(),
                format!("http://cache.example/{last_path}")
            );
            assert_eq!(final_response.status(), StatusCode::OK);
        }
    }

    #[test]
    fn redirect_policy_never_changes_an_upload_into_a_get() {
        let original: HttpUrl = "http://cache.example/start".parse().unwrap();
        for status in [301, 302, 303, 307, 308] {
            for (kind, follows) in [(DESTINATION_GET, true), (RequestKind::Put, status >= 307)] {
                let mut requests = 0;
                let (_, result) = send_with_retries(kind, &original, |url| {
                    requests += 1;
                    Ok(match requests {
                        1 => response(status, "/payload"),
                        2 => {
                            assert_eq!(url.as_str(), "http://cache.example/payload");
                            response(200, "")
                        }
                        _ => panic!("unexpected additional redirect"),
                    })
                })
                .unwrap();
                assert_eq!(requests, if follows { 2 } else { 1 });
                assert_eq!(result.status().as_u16(), if follows { 200 } else { status });
            }
        }
    }

    #[test]
    fn both_methods_bound_redirects_and_reject_untrusted_targets_before_sending() {
        let original: HttpUrl = "https://cache.example/start".parse().unwrap();
        for kind in [DESTINATION_GET, RequestKind::Put] {
            let mut requests = 0;
            let error = send_with_retries(kind, &original, |_| {
                requests += 1;
                Ok(response(307, "/cycle"))
            })
            .unwrap_err();
            assert_eq!(requests, MAX_REDIRECTS + 1);
            assert!(error.contains("too many redirects"));

            for target in [
                "https://other.example/secret",
                "http://cache.example/secret",
            ] {
                let mut requests = 0;
                assert!(
                    send_with_retries(kind, &original, |_| {
                        requests += 1;
                        Ok(response(307, target))
                    })
                    .is_err()
                );
                assert_eq!(
                    requests, 1,
                    "credentials must never reach an untrusted target"
                );
            }
        }
    }

    #[test]
    fn persistent_gateway_failure_stops_at_each_methods_own_budget() {
        let url: HttpUrl = "http://cache.example/start".parse().unwrap();
        for (kind, expected_requests) in [(DESTINATION_GET, 8), (RequestKind::Put, 3)] {
            let mut requests = 0;
            let (_, result) = send_with_retries(kind, &url, |_| {
                requests += 1;
                Ok(response(502, ""))
            })
            .unwrap();
            assert_eq!(requests, expected_requests);
            assert_eq!(result.status(), StatusCode::BAD_GATEWAY);
        }
    }
}
