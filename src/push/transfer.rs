use std::{
    io::{self, Read},
    thread,
    time::Duration,
};

#[cfg(test)]
use std::{fs::File, path::Path};

use ureq::{Agent, http::StatusCode};

use super::PushError;
use crate::http_url::HttpUrl;

const MAX_REDIRECTS: usize = 10;
const MAX_RETRY_AFTER_SECONDS: u64 = 60;
const RETRYABLE_STATUSES: &[StatusCode] = &[
    StatusCode::REQUEST_TIMEOUT,
    StatusCode::TOO_MANY_REQUESTS,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
    StatusCode::SERVICE_UNAVAILABLE,
    StatusCode::GATEWAY_TIMEOUT,
];
const GET_REDIRECT_STATUSES: &[StatusCode] = &[
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::FOUND,
    StatusCode::SEE_OTHER,
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
];
const PUT_REDIRECT_STATUSES: &[StatusCode] = &[
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
];
const MAX_IGNORED_RESPONSE_BODY_BYTES: u64 = 64 * 1024;
const GET_RETRIES: RetryBudget = RetryBudget {
    status: 2,
    gateway: 7,
    transport: 2,
};
const PUT_RETRIES: RetryBudget = RetryBudget {
    status: 2,
    gateway: 2,
    transport: 2,
};

#[derive(Clone, Copy)]
struct RetryBudget {
    status: usize,
    gateway: usize,
    transport: usize,
}

#[derive(Default)]
struct RetryState {
    status: usize,
    gateway: usize,
    transport: usize,
}

#[derive(Clone, Copy)]
enum RetryCause {
    Status(StatusCode, Option<Duration>),
    Transport,
}

impl RetryState {
    fn delay(&mut self, budget: RetryBudget, cause: RetryCause) -> Option<Duration> {
        match cause {
            RetryCause::Status(
                StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE,
                retry_after,
            ) if self.gateway < budget.gateway => {
                let attempt = self.gateway;
                self.gateway += 1;
                Some(retry_delay(attempt, retry_after))
            }
            RetryCause::Status(_, retry_after) if self.status < budget.status => {
                let attempt = self.status;
                self.status += 1;
                Some(retry_delay(attempt, retry_after))
            }
            RetryCause::Transport if self.transport < budget.transport => {
                let attempt = self.transport;
                self.transport += 1;
                Some(retry_delay(attempt, None))
            }
            RetryCause::Status(_, _) | RetryCause::Transport => None,
        }
    }
}

#[derive(Debug)]
pub(super) enum GetResponse {
    Found(Vec<u8>),
    Missing,
    UnexpectedStatus(StatusCode),
}

pub(super) fn is_retryable_status(status: StatusCode) -> bool {
    RETRYABLE_STATUSES.contains(&status)
}

fn is_get_redirect_status(status: StatusCode) -> bool {
    GET_REDIRECT_STATUSES.contains(&status)
}

fn is_put_redirect_status(status: StatusCode) -> bool {
    PUT_REDIRECT_STATUSES.contains(&status)
}

pub(super) fn retry_after_delay(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECONDS)))
}

fn retry_delay(retry: usize, retry_after: Option<Duration>) -> Duration {
    let multiplier = 1u64 << retry.min(6);
    retry_after.unwrap_or_else(|| Duration::from_millis(100 * multiplier))
}

fn wait_for_retry(delay: Duration) {
    thread::sleep(delay);
}

fn response_retry_after(response: &ureq::http::Response<ureq::Body>) -> Option<Duration> {
    response
        .headers()
        .get("Retry-After")
        .and_then(|value| value.to_str().ok())
        .and_then(retry_after_delay)
}

fn response_location(response: &ureq::http::Response<ureq::Body>) -> Option<String> {
    response
        .headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn read_bounded_success_body(
    response: ureq::http::Response<ureq::Body>,
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

fn discard_response_body(response: ureq::http::Response<ureq::Body>) -> io::Result<()> {
    let body = response.into_body().into_reader();
    io::copy(
        &mut body.take(MAX_IGNORED_RESPONSE_BODY_BYTES),
        &mut io::sink(),
    )?;
    Ok(())
}

#[cfg(test)]
pub(super) fn request_status(
    agent: &Agent,
    url: &HttpUrl,
    authorization: Option<&str>,
) -> Result<u16, PushError> {
    get_bounded(agent, url, authorization, MAX_IGNORED_RESPONSE_BODY_BYTES).map(|response| {
        match response {
            GetResponse::Found(_) => StatusCode::OK.as_u16(),
            GetResponse::Missing => StatusCode::NOT_FOUND.as_u16(),
            GetResponse::UnexpectedStatus(status) => status.as_u16(),
        }
    })
}

pub(super) fn get_bounded(
    agent: &Agent,
    url: &HttpUrl,
    authorization: Option<&str>,
    max_body_bytes: u64,
) -> Result<GetResponse, PushError> {
    let mut retries = RetryState::default();
    'attempts: loop {
        let mut request_url = url.clone();
        for redirect in 0..=MAX_REDIRECTS {
            let mut request = agent
                .get(request_url.as_str())
                .config()
                .max_redirects(0)
                .http_status_as_error(false)
                .build();
            if let Some(authorization) = authorization {
                request = request.header("Authorization", format!("Basic {authorization}"));
            }
            match request.call() {
                Ok(response) => {
                    let status = response.status();

                    if is_get_redirect_status(status) {
                        if redirect == MAX_REDIRECTS {
                            return Err(format!("GET {url} followed too many redirects").into());
                        }
                        let location = response_location(&response).ok_or_else(|| {
                            format!("GET {request_url} redirect response had no Location header")
                        })?;
                        request_url = request_url.resolve_trusted_redirect(&location)?;
                        continue;
                    }

                    if is_retryable_status(status)
                        && let Some(delay) = retries.delay(
                            GET_RETRIES,
                            RetryCause::Status(status, response_retry_after(&response)),
                        )
                    {
                        wait_for_retry(delay);
                        continue 'attempts;
                    }
                    return match status {
                        StatusCode::OK => {
                            read_bounded_success_body(response, &request_url, max_body_bytes)
                                .map(GetResponse::Found)
                        }
                        StatusCode::NOT_FOUND => Ok(GetResponse::Missing),
                        status => Ok(GetResponse::UnexpectedStatus(status)),
                    };
                }
                Err(error) => match retries.delay(GET_RETRIES, RetryCause::Transport) {
                    Some(delay) => {
                        wait_for_retry(delay);
                        continue 'attempts;
                    }
                    None => return Err(format!("GET {request_url} failed: {error}").into()),
                },
            }
        }
    }
}

fn put_with_redirects<F>(url: &HttpUrl, mut send: F) -> Result<StatusCode, PushError>
where
    F: FnMut(&HttpUrl) -> Result<ureq::http::Response<ureq::Body>, PushError>,
{
    let mut upload_url = url.clone();
    let mut retries = RetryState::default();
    'attempts: loop {
        for redirect in 0..=MAX_REDIRECTS {
            let response = match send(&upload_url) {
                Ok(response) => response,
                Err(error) => match retries.delay(PUT_RETRIES, RetryCause::Transport) {
                    Some(delay) => {
                        wait_for_retry(delay);
                        continue 'attempts;
                    }
                    None => return Err(error),
                },
            };
            let status = response.status();

            if is_put_redirect_status(status) {
                if redirect == MAX_REDIRECTS {
                    return Err(format!("PUT {url} followed too many redirects").into());
                }
                let location = response_location(&response).ok_or_else(|| {
                    format!("PUT {upload_url} redirect response had no Location header")
                })?;
                discard_response_body(response).map_err(|error| {
                    format!("reading PUT {upload_url} response failed: {error}")
                })?;
                upload_url = upload_url.resolve_trusted_redirect(&location)?;
                continue;
            }

            if is_retryable_status(status)
                && let Some(delay) = retries.delay(
                    PUT_RETRIES,
                    RetryCause::Status(status, response_retry_after(&response)),
                )
            {
                wait_for_retry(delay);
                continue 'attempts;
            }
            discard_response_body(response)
                .map_err(|error| format!("reading PUT {upload_url} response failed: {error}"))?;
            return Ok(status);
        }
    }
}

#[cfg(test)]
pub(super) fn put_file(
    agent: &Agent,
    url: &HttpUrl,
    path: &Path,
    content_type: &str,
    authorization: Option<&str>,
) -> Result<StatusCode, PushError> {
    put_with_redirects(url, |upload_url| {
        let file = File::open(path)
            .map_err(|error| format!("opening NAR for PUT {upload_url} failed: {error}"))?;
        let mut request = agent
            .put(upload_url.as_str())
            .config()
            .max_redirects(0)
            .build()
            .header("Content-Type", content_type);
        if let Some(authorization) = authorization {
            request = request.header("Authorization", format!("Basic {authorization}"));
        }
        request
            .send(file)
            .map_err(|error| PushError::new(format!("PUT {upload_url} failed: {error}")))
    })
}

pub(super) fn put_reader<F>(
    agent: &Agent,
    url: &HttpUrl,
    content_length: u64,
    content_type: &str,
    authorization: Option<&str>,
    mut open: F,
) -> Result<StatusCode, PushError>
where
    F: FnMut() -> Result<Box<dyn Read + Send>, PushError>,
{
    put_with_redirects(url, |upload_url| {
        let reader = open()?;
        let mut request = agent
            .put(upload_url.as_str())
            .config()
            .max_redirects(0)
            .build()
            .header("Content-Type", content_type)
            .header("Content-Length", content_length.to_string());
        if let Some(authorization) = authorization {
            request = request.header("Authorization", format!("Basic {authorization}"));
        }
        request
            .send(ureq::SendBody::from_owned_reader(reader))
            .map_err(|error| PushError::new(format!("PUT {upload_url} failed: {error}")))
    })
}

pub(super) fn put_bytes(
    agent: &Agent,
    url: &HttpUrl,
    bytes: &[u8],
    content_type: &str,
    authorization: Option<&str>,
) -> Result<StatusCode, PushError> {
    put_with_redirects(url, |upload_url| {
        let mut request = agent
            .put(upload_url.as_str())
            .config()
            .max_redirects(0)
            .build()
            .header("Content-Type", content_type);
        if let Some(authorization) = authorization {
            request = request.header("Authorization", format!("Basic {authorization}"));
        }
        request
            .send(bytes)
            .map_err(|error| PushError::new(format!("PUT {upload_url} failed: {error}")))
    })
}
