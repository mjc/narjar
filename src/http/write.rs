use std::{
    io::{self, Read},
    net::TcpStream,
    time::Instant,
};

use crate::{
    auth::{Authorizer, Permission},
    http_server::{BodyReader, BodyReaderError, BodyState, Request, Response, StatusCode},
    metrics::{Metrics, RequestGuard, RequestMethod, ValidationClass},
    narinfo::{MAX_NARINFO_BYTES, TrustedPublicKeys},
    object::{NarFileName, WireEncoding},
    storage::{
        CapacityErrorKind, NarUploadPolicy, PublishOutcome, StagingReservation, Storage,
        StorageError, StoreHash, capacity_error_kind,
    },
};

use super::read::{
    CacheRoute, RouteMatch, has_header, header, not_found, request_route, send_response,
};

struct UploadRequest {
    request: Request,
    length: usize,
}

struct CountedUploadReader<'a> {
    body: BodyReader<'a>,
    metrics: &'a Metrics,
}

impl Read for CountedUploadReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.body.read(buffer)?;
        self.metrics.received_upload_body_bytes(bytes_read);
        Ok(bytes_read)
    }
}

pub struct PublicationRequest {
    upload: UploadRequest,
    route: CacheRoute,
}

impl PublicationRequest {
    pub fn reject(self, metrics: &Metrics, status: StatusCode) {
        let guard = metrics.request(RequestMethod::Put, request_route(self.upload.request.url()));
        let _ = self.upload.respond(&guard, status);
    }

    pub fn staging_bytes(&self, max_nar_bytes: u64) -> Option<u64> {
        let length = u64::try_from(self.upload.length()).ok()?;
        match &self.route {
            CacheRoute::Nar(_) if length <= max_nar_bytes => Some(length),
            CacheRoute::Nar(_) => None,
            CacheRoute::NarInfo(_) => Some(length.min(MAX_NARINFO_BYTES)),
            CacheRoute::CacheInfo => Some(0),
        }
    }

    pub fn respond(
        self,
        storage: &Storage,
        trusted: &TrustedPublicKeys,
        policy: NarUploadPolicy,
        egress_compression: WireEncoding,
        metrics: &Metrics,
        staging: StagingReservation,
    ) {
        let guard = metrics.request(RequestMethod::Put, request_route(self.upload.request.url()));
        let Self { upload, route } = self;
        let _ = match route {
            CacheRoute::Nar(name) => respond_nar_put(
                upload,
                NarPutContext {
                    storage,
                    name,
                    policy,
                    metrics,
                    guard: &guard,
                    staging,
                },
            ),
            CacheRoute::NarInfo(store) => {
                let result = respond_narinfo_put(
                    upload,
                    NarInfoPutContext {
                        storage,
                        store: &store,
                        trusted,
                        egress_compression,
                        policy,
                        metrics,
                        guard: &guard,
                    },
                );
                drop(staging);
                result
            }
            CacheRoute::CacheInfo => {
                drop(staging);
                respond_cache_info_put(upload, storage, metrics, &guard)
            }
        };
    }
}

pub fn prepare_publication(
    mut request: Request,
    authorizer: &Authorizer,
    metrics: &Metrics,
) -> Option<PublicationRequest> {
    request.close_after_response();
    if !authorizer.allows(&request, Permission::Write) {
        metrics.auth_failure(true);
        let guard = metrics.request(RequestMethod::Put, request_route(request.url()));
        let _ = unauthorized(&guard, request);
        return None;
    }

    let route = match CacheRoute::classify(request.url()) {
        RouteMatch::Found(route) => route,
        RouteMatch::InvalidNarPath | RouteMatch::Invalid => {
            let guard = metrics.request(RequestMethod::Put, request_route(request.url()));
            let _ = send_response(&guard, request, Response::empty(StatusCode::BAD_REQUEST));
            return None;
        }
        RouteMatch::Missing => {
            let guard = metrics.request(RequestMethod::Put, request_route(request.url()));
            let _ = not_found(&guard, request);
            return None;
        }
    };

    let upload = UploadRequest::accept(request, metrics)?;
    Some(PublicationRequest { upload, route })
}

impl UploadRequest {
    fn accept(request: Request, metrics: &Metrics) -> Option<Self> {
        match Self::validate_headers_and_length(&request) {
            Ok(length) => Some(Self { request, length }),
            Err(status) => {
                metrics.validation_failure(ValidationClass::Body);
                let guard = metrics.request(RequestMethod::Put, request_route(request.url()));
                let _ = send_response(&guard, request, Response::empty(status));
                None
            }
        }
    }

    fn validate_headers_and_length(request: &Request) -> Result<usize, StatusCode> {
        if has_header(request, "Transfer-Encoding") {
            return Err(StatusCode::BAD_REQUEST);
        }
        if has_header(request, "Content-Encoding") {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        request.body_length().ok_or(StatusCode::LENGTH_REQUIRED)
    }

    const fn length(&self) -> usize {
        self.length
    }

    fn body_state(&self) -> BodyState {
        self.request.body_state()
    }

    fn reader<'a>(
        &'a mut self,
        metrics: &'a Metrics,
    ) -> Result<CountedUploadReader<'a>, BodyReaderError> {
        Ok(CountedUploadReader {
            body: self.request.as_reader()?,
            metrics,
        })
    }

    fn read_body(&mut self, max_bytes: usize, metrics: &Metrics) -> Result<Vec<u8>, StatusCode> {
        if self.length > max_bytes {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let length = self.length;
        let mut bytes = Vec::with_capacity(length);
        let read = self
            .reader(metrics)
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?
            .take(length as u64 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() != length {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        Ok(bytes)
    }

    fn respond(self, guard: &RequestGuard<'_>, status: StatusCode) -> Option<TcpStream> {
        send_response(guard, self.request, Response::empty(status))
    }
}

fn capacity_status(error: &io::Error) -> Option<StatusCode> {
    match error.raw_os_error().map(capacity_error_kind) {
        Some(CapacityErrorKind::NoSpace | CapacityErrorKind::Quota) => {
            Some(StatusCode::INSUFFICIENT_STORAGE)
        }
        Some(CapacityErrorKind::ReadOnly) => Some(StatusCode::SERVICE_UNAVAILABLE),
        Some(CapacityErrorKind::Inodes | CapacityErrorKind::Other) | None => None,
    }
}

fn record_capacity_error(metrics: &Metrics, error: &StorageError) {
    let kind = match error {
        StorageError::InsufficientSpace => CapacityErrorKind::NoSpace,
        StorageError::InsufficientInodes => CapacityErrorKind::Inodes,
        StorageError::Io(error) => error
            .raw_os_error()
            .map(capacity_error_kind)
            .unwrap_or(CapacityErrorKind::Other),
        _ => CapacityErrorKind::Other,
    };
    metrics.capacity_failure(kind);
}

fn respond_cache_info_put(
    mut upload: UploadRequest,
    storage: &Storage,
    metrics: &Metrics,
    guard: &RequestGuard<'_>,
) -> Option<TcpStream> {
    let cache_info = match storage.cache_info() {
        Ok(cache_info) => cache_info,
        Err(_) => return upload.respond(guard, StatusCode::INTERNAL_SERVER_ERROR),
    };
    let _upload = metrics.upload(upload.length() as u64);
    if upload.length() != cache_info.len() {
        metrics.validation_failure(ValidationClass::Body);
        return upload.respond(guard, StatusCode::CONFLICT);
    }
    let bytes = match upload.read_body(cache_info.len(), metrics) {
        Ok(bytes) => bytes,
        Err(status) => {
            metrics.validation_failure(ValidationClass::Body);
            return upload.respond(guard, status);
        }
    };
    if bytes != cache_info {
        metrics.validation_failure(ValidationClass::Body);
        return upload.respond(guard, StatusCode::CONFLICT);
    }

    let started = Instant::now();
    let result = storage.publish_cache_info(bytes.as_slice());
    metrics.publication(started.elapsed());
    metrics.record_publication_result(&result);
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => StatusCode::CREATED,
        Ok(PublishOutcome::Identical) => StatusCode::OK,
        Err(StorageError::Conflict) => StatusCode::CONFLICT,
        Err(StorageError::Io(error)) => {
            capacity_status(&error).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    upload.respond(guard, status)
}

struct NarPutContext<'storage, 'request> {
    storage: &'storage Storage,
    name: NarFileName,
    policy: NarUploadPolicy,
    metrics: &'storage Metrics,
    guard: &'request RequestGuard<'storage>,
    staging: StagingReservation,
}

fn respond_nar_put(mut upload: UploadRequest, context: NarPutContext<'_, '_>) -> Option<TcpStream> {
    let NarPutContext {
        storage,
        name,
        policy,
        metrics,
        guard,
        staging,
    } = context;
    let length = upload.length();
    let _upload = metrics.upload(length as u64);
    let started = Instant::now();
    let reader = match upload.reader(metrics) {
        Ok(reader) => reader,
        Err(_) => {
            metrics.validation_failure(ValidationClass::Nar);
            guard.record_aborted_response();
            return None;
        }
    };
    let result = storage.publish_nar_with_staging(name, reader, length as u64, policy, staging);
    metrics.publication(started.elapsed());
    metrics.record_publication_result(&result);
    if matches!(upload.body_state(), BodyState::Reading | BodyState::Failed)
        && !matches!(result, Err(StorageError::UploadTooLarge))
    {
        metrics.validation_failure(ValidationClass::Nar);
        guard.record_aborted_response();
        return None;
    }
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => StatusCode::CREATED,
        Ok(PublishOutcome::Identical) => StatusCode::OK,
        Err(StorageError::Conflict) => StatusCode::CONFLICT,
        Err(StorageError::UploadTooLarge) => StatusCode::PAYLOAD_TOO_LARGE,
        Err(StorageError::InsufficientSpace | StorageError::InsufficientInodes) => {
            StatusCode::INSUFFICIENT_STORAGE
        }
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        Err(StorageError::Io(error)) => {
            capacity_status(&error).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    upload.respond(guard, status)
}

struct NarInfoPutContext<'storage, 'request> {
    storage: &'storage Storage,
    store: &'storage StoreHash,
    trusted: &'storage TrustedPublicKeys,
    egress_compression: WireEncoding,
    policy: NarUploadPolicy,
    metrics: &'storage Metrics,
    guard: &'request RequestGuard<'storage>,
}

fn respond_narinfo_put(
    mut upload: UploadRequest,
    context: NarInfoPutContext<'_, '_>,
) -> Option<TcpStream> {
    let NarInfoPutContext {
        storage,
        store,
        trusted,
        egress_compression,
        policy,
        metrics,
        guard,
    } = context;
    let _upload = metrics.upload(upload.length() as u64);
    let bytes = match upload.read_body(MAX_NARINFO_BYTES as usize, metrics) {
        Ok(bytes) => bytes,
        Err(status) => {
            metrics.validation_failure(ValidationClass::Body);
            return upload.respond(guard, status);
        }
    };
    let validated = match trusted.validate(store, bytes) {
        Ok(validated) => validated,
        Err(_) => {
            metrics.validation_failure(ValidationClass::NarInfo);
            return upload.respond(guard, StatusCode::UNPROCESSABLE_ENTITY);
        }
    };
    let started = Instant::now();
    let result = storage
        .bind_narinfo(validated, egress_compression, policy)
        .and_then(|bound| bound.publish());
    metrics.publication(started.elapsed());
    metrics.record_publication_result(&result);
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => StatusCode::CREATED,
        Ok(PublishOutcome::Identical) => StatusCode::OK,
        Err(StorageError::Conflict) => StatusCode::CONFLICT,
        Err(StorageError::MissingNar | StorageError::NarMismatch) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        Err(StorageError::InsufficientSpace | StorageError::InsufficientInodes) => {
            StatusCode::INSUFFICIENT_STORAGE
        }
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        Err(StorageError::Io(error)) => {
            capacity_status(&error).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    upload.respond(guard, status)
}

pub(super) fn unauthorized(guard: &RequestGuard<'_>, request: Request) -> Option<TcpStream> {
    let challenge = header("WWW-Authenticate", "Basic realm=\"narjar\"");
    send_response(
        guard,
        request,
        Response::empty(StatusCode::UNAUTHORIZED).with_header(challenge),
    )
}
