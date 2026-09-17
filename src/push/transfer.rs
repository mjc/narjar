use std::{fs::File, io, path::Path, thread, time::Duration};

use ureq::Agent;

use crate::http_url::HttpUrl;

const MAX_ATTEMPTS: usize = 3;
const MAX_REDIRECTS: usize = 10;
const MAX_RETRY_AFTER_SECONDS: u64 = 60;

pub(super) fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

pub(super) fn retry_after_delay(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECONDS)))
}

fn retry_sleep(attempt: usize, retry_after: Option<Duration>) {
    let multiplier = 1u64 << attempt.min(6);
    thread::sleep(retry_after.unwrap_or_else(|| Duration::from_millis(100 * multiplier)));
}

pub(super) fn request_status(
    agent: &Agent,
    url: &HttpUrl,
    authorization: Option<&str>,
) -> Result<u16, String> {
    'attempts: for attempt in 0..MAX_ATTEMPTS {
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
                    let status = response.status().as_u16();
                    let retry_after = response
                        .headers()
                        .get("Retry-After")
                        .and_then(|value| value.to_str().ok())
                        .and_then(retry_after_delay);
                    let location = response
                        .headers()
                        .get("Location")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    let mut body = response.into_body().into_reader();
                    io::copy(&mut body, &mut io::sink()).map_err(|error| {
                        format!("reading GET {request_url} response failed: {error}")
                    })?;

                    if matches!(status, 307 | 308) {
                        if redirect == MAX_REDIRECTS {
                            return Err(format!("GET {url} followed too many redirects"));
                        }
                        let location = location.ok_or_else(|| {
                            format!("GET {request_url} redirect response had no Location header")
                        })?;
                        request_url = request_url.resolve_trusted_redirect(&location)?;
                        continue;
                    }

                    if is_retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                        retry_sleep(attempt, retry_after);
                        continue 'attempts;
                    }
                    return Ok(status);
                }
                Err(_error) if attempt + 1 < MAX_ATTEMPTS => {
                    retry_sleep(attempt, None);
                    continue 'attempts;
                }
                Err(error) => return Err(format!("GET {request_url} failed: {error}")),
            }
        }
    }
    unreachable!("retry loop always returns")
}

fn put_with_redirects<F>(url: &HttpUrl, mut send: F) -> Result<u16, String>
where
    F: FnMut(&HttpUrl) -> Result<ureq::http::Response<ureq::Body>, String>,
{
    let mut upload_url = url.clone();
    'attempts: for attempt in 0..MAX_ATTEMPTS {
        for redirect in 0..=MAX_REDIRECTS {
            let response = match send(&upload_url) {
                Ok(response) => response,
                Err(_error) if attempt + 1 < MAX_ATTEMPTS => {
                    retry_sleep(attempt, None);
                    continue 'attempts;
                }
                Err(error) => return Err(error),
            };
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|value| value.to_str().ok())
                .and_then(retry_after_delay);
            let location = response
                .headers()
                .get("Location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut body = response.into_body().into_reader();
            io::copy(&mut body, &mut io::sink())
                .map_err(|error| format!("reading PUT {upload_url} response failed: {error}"))?;

            if matches!(status, 307 | 308) {
                if redirect == MAX_REDIRECTS {
                    return Err(format!("PUT {url} followed too many redirects"));
                }
                let location = location.ok_or_else(|| {
                    format!("PUT {upload_url} redirect response had no Location header")
                })?;
                upload_url = upload_url.resolve_trusted_redirect(&location)?;
                continue;
            }

            if is_retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                retry_sleep(attempt, retry_after);
                continue 'attempts;
            }
            return Ok(status);
        }
        unreachable!("redirect loop always returns")
    }
    unreachable!("retry loop always returns")
}

pub(super) fn put_file(
    agent: &Agent,
    url: &HttpUrl,
    path: &Path,
    content_type: &str,
    authorization: Option<&str>,
) -> Result<u16, String> {
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
            .map_err(|error| format!("PUT {upload_url} failed: {error}"))
    })
}

pub(super) fn put_bytes(
    agent: &Agent,
    url: &HttpUrl,
    bytes: &[u8],
    content_type: &str,
    authorization: Option<&str>,
) -> Result<u16, String> {
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
            .map_err(|error| format!("PUT {upload_url} failed: {error}"))
    })
}
