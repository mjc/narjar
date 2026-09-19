use std::{
    io::{self, Read},
    net::TcpStream,
    time::Instant,
};

use crate::{
    auth::{Authorizer, Permission},
    http_server::{BodyReaderError, Request, Response, StatusCode},
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

pub struct PublicationRequest {
    upload: UploadRequest,
    route: CacheRoute,
}

impl PublicationRequest {
    pub fn reject(self, metrics: &Metrics, status: u16) {
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
        RouteMatch::Invalid => {
            let guard = metrics.request(RequestMethod::Put, request_route(request.url()));
            let _ = send_response(
                &guard,
                request,
                400,
                Response::empty(StatusCode::BAD_REQUEST),
                0,
            );
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
                let _ = send_response(
                    &guard,
                    request,
                    status,
                    Response::empty(
                        StatusCode::new(status).expect("upload response status is valid"),
                    ),
                    0,
                );
                None
            }
        }
    }

    fn validate_headers_and_length(request: &Request) -> Result<usize, u16> {
        if has_header(request, "Transfer-Encoding") {
            return Err(400);
        }
        if has_header(request, "Content-Encoding") {
            return Err(415);
        }
        request.body_length().ok_or(411)
    }

    const fn length(&self) -> usize {
        self.length
    }

    fn body_complete(&self) -> bool {
        self.request.body_complete()
    }

    fn reader(&mut self) -> Result<impl Read + '_, BodyReaderError> {
        self.request.as_reader()
    }

    fn read_body(&mut self, max_bytes: usize) -> Result<Vec<u8>, u16> {
        if self.length > max_bytes {
            return Err(413);
        }
        let length = self.length;
        let mut bytes = Vec::with_capacity(length);
        let read = self
            .reader()
            .map_err(|_| 422u16)?
            .take(length as u64 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() != length {
            return Err(422);
        }
        Ok(bytes)
    }

    fn respond(self, guard: &RequestGuard<'_>, status: u16) -> Option<TcpStream> {
        send_response(
            guard,
            self.request,
            status,
            Response::empty(StatusCode::new(status).expect("upload response status is valid")),
            0,
        )
    }
}

fn capacity_status(error: &io::Error) -> Option<u16> {
    match error.raw_os_error().map(capacity_error_kind) {
        Some(CapacityErrorKind::NoSpace | CapacityErrorKind::Quota) => Some(507),
        Some(CapacityErrorKind::ReadOnly) => Some(503),
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
        Err(_) => return upload.respond(guard, 500),
    };
    let _upload = metrics.upload(upload.length() as u64);
    if upload.length() != cache_info.len() {
        metrics.validation_failure(ValidationClass::Body);
        return upload.respond(guard, 409);
    }
    let bytes = match upload.read_body(cache_info.len()) {
        Ok(bytes) => bytes,
        Err(status) => {
            metrics.validation_failure(ValidationClass::Body);
            return upload.respond(guard, status);
        }
    };
    if bytes != cache_info {
        metrics.validation_failure(ValidationClass::Body);
        return upload.respond(guard, 409);
    }

    let started = Instant::now();
    let result = storage.publish_cache_info(bytes.as_slice());
    metrics.publication(started.elapsed());
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => 201,
        Ok(PublishOutcome::Identical) => 200,
        Err(StorageError::Conflict) => 409,
        Err(StorageError::Io(error)) => capacity_status(&error).unwrap_or(500),
        Err(_) => 500,
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
    let reader = match upload.reader() {
        Ok(reader) => reader,
        Err(_) => {
            metrics.validation_failure(ValidationClass::Nar);
            guard.record_response(0, 0);
            return None;
        }
    };
    let result = storage.publish_nar_with_staging(name, reader, length as u64, policy, staging);
    metrics.publication(started.elapsed());
    if !upload.body_complete() {
        metrics.validation_failure(ValidationClass::Nar);
        guard.record_response(0, 0);
        return None;
    }
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => 201,
        Ok(PublishOutcome::Identical) => 200,
        Err(StorageError::Conflict) => 409,
        Err(StorageError::UploadTooLarge) => 413,
        Err(StorageError::InsufficientSpace) => 507,
        Err(StorageError::InsufficientInodes) => 507,
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => 422,
        Err(StorageError::Io(error)) => capacity_status(&error).unwrap_or(500),
        Err(_) => 500,
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
    let bytes = match upload.read_body(MAX_NARINFO_BYTES as usize) {
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
            return upload.respond(guard, 422);
        }
    };
    let started = Instant::now();
    let result = storage
        .bind_narinfo(validated, egress_compression, policy)
        .and_then(|bound| bound.publish());
    metrics.publication(started.elapsed());
    if let Err(error) = &result {
        record_capacity_error(metrics, error);
    }
    let status = match result {
        Ok(PublishOutcome::Created) => 201,
        Ok(PublishOutcome::Identical) => 200,
        Err(StorageError::Conflict) => 409,
        Err(StorageError::MissingNar | StorageError::NarMismatch) => 422,
        Err(StorageError::InsufficientSpace | StorageError::InsufficientInodes) => 507,
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => 422,
        Err(StorageError::Io(error)) => capacity_status(&error).unwrap_or(500),
        Err(_) => 500,
    };
    upload.respond(guard, status)
}

pub(super) fn unauthorized(guard: &RequestGuard<'_>, request: Request) -> Option<TcpStream> {
    let challenge = header("WWW-Authenticate", "Basic realm=\"narjar\"");
    send_response(
        guard,
        request,
        401,
        Response::empty(StatusCode::UNAUTHORIZED).with_header(challenge),
        0,
    )
}
