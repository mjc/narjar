use std::{
    cell::RefCell,
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

use lzma_rust2::XzReader;
use sha2::{Digest, Sha256};
use structured_zstd::decoding::StreamingDecoder as StructuredZstdDecoder;

use crate::narinfo::{CompressedNarExpectation, NarEncoding, NarExpectation};
use crate::object::{
    EncodedIdentity, EncodedSize, FileHash, NarHash, NarIdentity, NarSize, Sha256Digest,
};

use super::{
    fs::filesystem_space,
    publication::{StagingReservation, StorageError},
};

const INGESTION_RECEIPT_VERSION: u8 = 1;
const RAW_STAGING_GROWTH_BYTES: u64 = 64 * 1024 * 1024;

struct Sha256Hasher {
    hasher: Option<Sha256>,
}

impl Sha256Hasher {
    fn new() -> Self {
        Self {
            hasher: Some(Sha256::new()),
        }
    }

    fn new_if(enabled: bool) -> Self {
        Self {
            hasher: enabled.then(Sha256::new),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
    }

    fn matches<H: Sha256Digest>(&self, expected: &H) -> bool {
        self.hasher
            .as_ref()
            .is_some_and(|hasher| expected.matches_sha256_digest(&hasher.clone().finalize()))
    }

    fn finish(self) -> [u8; 32] {
        self.hasher
            .expect("a disabled SHA-256 hasher cannot be finished")
            .finalize()
            .into()
    }
}

pub(super) struct CheckedUploadReader<'a, R> {
    inner: R,
    expected_hash: &'a FileHash,
    expected_length: u64,
    bytes_read: u64,
    hasher: Sha256Hasher,
    upload_end_validated: bool,
}

pub(super) struct CompleteUpload<R> {
    inner: R,
}

impl<'a, R> CheckedUploadReader<'a, R> {
    pub(super) fn new(inner: R, expected_hash: &'a FileHash, expected_length: u64) -> Self {
        Self {
            inner,
            expected_hash,
            expected_length,
            bytes_read: 0,
            hasher: Sha256Hasher::new(),
            upload_end_validated: false,
        }
    }

    fn validate_observed_upload_hash_and_length(&self) -> io::Result<()> {
        if self.bytes_read != self.expected_length || !self.hasher.matches(self.expected_hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR hash or size mismatch",
            ));
        }
        Ok(())
    }

    pub(super) fn finish(self) -> io::Result<CompleteUpload<R>>
    where
        R: Read,
    {
        let mut receiving = self;
        receiving.ensure_upload_end_was_consumed()?;
        Ok(CompleteUpload {
            inner: receiving.inner,
        })
    }

    fn ensure_upload_end_was_consumed(&mut self) -> io::Result<()>
    where
        R: Read,
    {
        if self.upload_end_validated {
            return Ok(());
        }

        let mut buffer = [0; 64 * 1024];
        if self.inner.read(&mut buffer)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded upload has trailing bytes",
            ));
        }
        self.record_validated_upload_end()
    }

    fn record_validated_upload_end(&mut self) -> io::Result<()> {
        self.validate_observed_upload_hash_and_length()?;
        self.upload_end_validated = true;
        Ok(())
    }
}

impl<R> CompleteUpload<R> {
    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CheckedUploadReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.upload_end_validated {
            return Ok(0);
        }
        let read = self.inner.read(buffer)?;
        if read == 0 {
            self.record_validated_upload_end()?;
            return Ok(0);
        }

        self.bytes_read = self
            .bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        if self.bytes_read > self.expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR exceeds declared length",
            ));
        }
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

pub(super) struct RawStagingWriter<'a> {
    file: &'a mut File,
    reservation: &'a mut StagingReservation,
    min_free_bytes: u64,
    bytes_written: u64,
}

impl<'a> RawStagingWriter<'a> {
    pub(super) fn new(
        file: &'a mut File,
        reservation: &'a mut StagingReservation,
        min_free_bytes: u64,
    ) -> Self {
        Self {
            file,
            reservation,
            min_free_bytes,
            bytes_written: 0,
        }
    }

    fn reserve_before_write(&mut self, next_size: u64) -> io::Result<()> {
        let required_bytes = next_size
            .div_ceil(RAW_STAGING_GROWTH_BYTES)
            .saturating_mul(RAW_STAGING_GROWTH_BYTES);
        if required_bytes <= self.reservation.reserved_bytes() {
            return Ok(());
        }
        let available_bytes = filesystem_space(self.file)?.available_bytes;
        self.reservation
            .grow_to(available_bytes, self.min_free_bytes, required_bytes)
            .map_err(storage_capacity_error)
    }
}

impl Write for RawStagingWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_size = self
            .bytes_written
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        self.reserve_before_write(next_size)?;
        let written = self.file.write(buffer)?;
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn storage_capacity_error(error: StorageError) -> io::Error {
    match error {
        StorageError::InsufficientSpace | StorageError::InsufficientInodes => {
            io::Error::from_raw_os_error(libc::ENOSPC)
        }
        StorageError::Io(error) => error,
        error => io::Error::other(error),
    }
}

struct HashingWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    hasher: Sha256Hasher,
    bytes_written: u64,
    max_bytes: u64,
}

impl<'a, W: Write + ?Sized> HashingWriter<'a, W> {
    fn new(inner: &'a mut W, max_bytes: u64) -> Self {
        Self {
            inner,
            hasher: Sha256Hasher::new(),
            bytes_written: 0,
            max_bytes,
        }
    }

    fn finish(self) -> DecodedValidation {
        DecodedValidation {
            hash: NarHash::from_digest(self.hasher.finish()),
            size: NarSize::new(self.bytes_written),
        }
    }
}

impl<W: Write + ?Sized> Write for HashingWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_size = self
            .bytes_written
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        if next_size > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed NAR exceeds configured size limit",
            ));
        }
        let written = self.inner.write(buffer)?;
        self.bytes_written += written as u64;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) fn write_uploaded_representation_as_raw_nar<W: Write>(
    source: impl Read,
    encoding: NarEncoding,
    expectation: EncodedUploadExpectation<'_>,
    destination: &mut W,
) -> io::Result<DecodedValidation> {
    match encoding {
        NarEncoding::Raw => copy_raw_upload_to_raw_staging(source, expectation, destination),
        NarEncoding::Xz => decode_xz_upload_to_raw_staging(source, expectation, destination),
        NarEncoding::Zstd => decode_zstd_upload_to_raw_staging(source, expectation, destination),
    }
}

pub(super) fn finish_checked_upload<R: Read>(input: CheckedUploadReader<'_, R>) -> io::Result<()> {
    input.finish().map(|_| ())
}

fn copy_raw_upload_to_raw_staging<W: Write>(
    source: impl Read,
    expectation: EncodedUploadExpectation<'_>,
    destination: &mut W,
) -> io::Result<DecodedValidation> {
    let mut input = CheckedUploadReader::new(
        source,
        expectation.expected_file_hash,
        expectation.expected_file_size.get(),
    );
    let mut output = HashingWriter::new(destination, expectation.max_nar_size);
    io::copy(&mut input, &mut output)?;
    let _complete = input.finish()?;
    let decoded = output.finish();
    validate_raw_upload_identity(decoded, expectation)
}

fn decode_xz_upload_to_raw_staging<W: Write>(
    source: impl Read,
    expectation: EncodedUploadExpectation<'_>,
    destination: &mut W,
) -> io::Result<DecodedValidation> {
    let input = CheckedUploadReader::new(
        source,
        expectation.expected_file_hash,
        expectation.expected_file_size.get(),
    );
    let source_error = Rc::new(RefCell::new(None));
    let mut decoder = XzReader::new(
        CompressedSourceReader::new(input, Rc::clone(&source_error)),
        false,
    );
    let decoded =
        copy_decoded_bytes_to_raw_staging(&mut decoder, destination, expectation.max_nar_size)
            .map_err(|error| take_source_error(&source_error, compressed_read_error(error)))?;
    finish_encoded_upload_after_decoding(decoder.into_inner().into_inner(), &source_error)?;
    Ok(decoded)
}

fn decode_zstd_upload_to_raw_staging<W: Write>(
    source: impl Read,
    expectation: EncodedUploadExpectation<'_>,
    destination: &mut W,
) -> io::Result<DecodedValidation> {
    let input = CheckedUploadReader::new(
        source,
        expectation.expected_file_hash,
        expectation.expected_file_size.get(),
    );
    let source_error = Rc::new(RefCell::new(None));
    let mut decoder =
        StructuredZstdDecoder::new(CompressedSourceReader::new(input, Rc::clone(&source_error)))
            .map_err(|error| take_source_error(&source_error, compressed_decoder_error(error)))?;
    let decoded =
        copy_decoded_bytes_to_raw_staging(&mut decoder, destination, expectation.max_nar_size)
            .map_err(|error| take_source_error(&source_error, compressed_read_error(error)))?;
    finish_encoded_upload_after_decoding(decoder.into_inner().into_inner(), &source_error)?;
    Ok(decoded)
}

#[derive(Clone, Copy)]
pub(super) struct EncodedUploadExpectation<'a> {
    pub(super) expected_file_hash: &'a FileHash,
    pub(super) expected_file_size: EncodedSize,
    pub(super) max_nar_size: u64,
}

fn validate_raw_upload_identity(
    decoded: DecodedValidation,
    expectation: EncodedUploadExpectation<'_>,
) -> io::Result<DecodedValidation> {
    if decoded.size.get() == expectation.expected_file_size.get()
        && expectation
            .expected_file_hash
            .matches_nar_hash(decoded.hash)
    {
        return Ok(decoded);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "raw NAR hash or size mismatch",
    ))
}

fn copy_decoded_bytes_to_raw_staging<R: Read, W: Write>(
    decoder: &mut R,
    destination: &mut W,
    max_nar_size: u64,
) -> io::Result<DecodedValidation> {
    let mut output = HashingWriter::new(destination, max_nar_size);
    io::copy(decoder, &mut output)?;
    Ok(output.finish())
}

fn finish_encoded_upload_after_decoding<R: Read>(
    input: CheckedUploadReader<'_, R>,
    source_error: &RefCell<Option<io::Error>>,
) -> io::Result<()> {
    input
        .finish()
        .map(|complete| drop(complete.into_inner()))
        .map_err(|error| take_source_error(source_error, compressed_read_error(error)))
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256Hasher,
}

struct CompressedSourceReader<R> {
    inner: R,
    error: Rc<RefCell<Option<io::Error>>>,
}

impl<R> CompressedSourceReader<R> {
    fn new(inner: R, error: Rc<RefCell<Option<io::Error>>>) -> Self {
        Self { inner, error }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodedValidation {
    pub(super) hash: NarHash,
    pub(super) size: NarSize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IngestionReceipt {
    encoded: EncodedIdentity,
    decoded: NarIdentity,
}

impl IngestionReceipt {
    pub(super) fn from_decoded(
        encoding: NarEncoding,
        encoded_hash: FileHash,
        encoded_size: EncodedSize,
        decoded: DecodedValidation,
    ) -> Self {
        Self {
            encoded: EncodedIdentity::new(
                encoding,
                encoded_hash,
                EncodedSize::new(encoded_size.get()),
            ),
            decoded: NarIdentity::new(decoded.hash, decoded.size),
        }
    }

    pub(super) fn file_name(&self) -> OsString {
        OsString::from(format!(
            "{}{}.validation",
            self.encoded.hash(),
            self.encoded.encoding().suffix()
        ))
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        format!(
            "version={INGESTION_RECEIPT_VERSION}\nencoding={}\nencoded-hash={}\nencoded-size={}\ndecoded-hash={}\ndecoded-size={}\n",
            self.encoded.encoding().compression(),
            self.encoded.hash(),
            self.encoded.size(),
            self.decoded.hash(),
            self.decoded.size(),
        )
        .into_bytes()
    }

    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        if !text.ends_with('\n') {
            return None;
        }
        let mut version: Option<u8> = None;
        let mut encoding = None;
        let mut encoded_hash = None;
        let mut encoded_size = None;
        let mut decoded_hash = None;
        let mut decoded_size = None;
        for line in text.lines() {
            let (name, value) = line.split_once('=')?;
            match name {
                "version" if version.is_none() => version = Some(value.parse().ok()?),
                "encoding" if encoding.is_none() => {
                    encoding = Some(match value {
                        "zstd" => NarEncoding::Zstd,
                        "xz" => NarEncoding::Xz,
                        _ => return None,
                    })
                }
                "encoded-hash" if encoded_hash.is_none() => {
                    encoded_hash = Some(FileHash::parse(value).ok()?)
                }
                "encoded-size" if encoded_size.is_none() => {
                    encoded_size = Some(EncodedSize::new(value.parse().ok()?))
                }
                "decoded-hash" if decoded_hash.is_none() => {
                    decoded_hash = Some(NarHash::parse(value).ok()?)
                }
                "decoded-size" if decoded_size.is_none() => {
                    decoded_size = Some(NarSize::new(value.parse().ok()?))
                }
                _ => return None,
            }
        }
        let encoded = EncodedIdentity::new(encoding?, encoded_hash?, encoded_size?);
        let decoded = NarIdentity::new(decoded_hash?, decoded_size?);
        let evidence = Self { encoded, decoded };
        (version? == INGESTION_RECEIPT_VERSION).then_some(evidence)
    }

    pub(super) fn matches(&self, expectation: CompressedNarExpectation) -> bool {
        self.encoded == expectation.encoded && self.decoded == expectation.decoded
    }

    pub(super) fn decoded_identity(&self) -> NarIdentity {
        self.decoded
    }
}

pub(super) fn ingestion_receipt_file_name(expectation: CompressedNarExpectation) -> OsString {
    OsString::from(format!(
        "{}{}.validation",
        expectation.encoded.hash(),
        expectation.encoded.encoding().suffix()
    ))
}

#[derive(Debug)]
struct CompressedSourceError(io::Error);

impl fmt::Display for CompressedSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for CompressedSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl<R> HashingReader<R> {
    fn new(inner: R, enabled: bool) -> Self {
        Self {
            inner,
            hasher: Sha256Hasher::new_if(enabled),
        }
    }

    fn matches(self, expected: Option<&FileHash>) -> bool {
        expected.is_none_or(|expected| self.hasher.matches(expected))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self
            .inner
            .read(buffer)
            .map_err(|error| io::Error::other(CompressedSourceError(error)))?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

impl<R: Read> Read for CompressedSourceReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer).map_err(|error| {
            *self.error.borrow_mut() = Some(error);
            io::Error::other("compressed source read failed")
        })
    }
}

fn compressed_source_error<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a io::Error> {
    if let Some(source) = error.downcast_ref::<CompressedSourceError>() {
        return Some(&source.0);
    }
    error.source().and_then(compressed_source_error)
}

fn compressed_read_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        io::Error::new(io::ErrorKind::InvalidData, error)
    } else if let Some(source) = compressed_source_error(&error) {
        source.raw_os_error().map_or_else(
            || io::Error::new(source.kind(), source.to_string()),
            io::Error::from_raw_os_error,
        )
    } else if error.kind() == io::ErrorKind::Other {
        io::Error::new(io::ErrorKind::InvalidData, error)
    } else {
        error
    }
}

fn compressed_decoder_error<E: std::error::Error + 'static>(error: E) -> io::Error {
    if let Some(source) = compressed_source_error(&error) {
        return source.raw_os_error().map_or_else(
            || io::Error::new(source.kind(), source.to_string()),
            io::Error::from_raw_os_error,
        );
    }
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid zstd NAR: {error}"),
    )
}

fn take_source_error(source_error: &RefCell<Option<io::Error>>, fallback: io::Error) -> io::Error {
    source_error.borrow_mut().take().unwrap_or(fallback)
}

fn validate_decoded<R: Read>(
    reader: &mut R,
    expected_nar_hash: Option<&NarHash>,
    max_bytes: u64,
) -> io::Result<DecodedValidation> {
    let mut hasher = Sha256Hasher::new();
    let mut bytes_read = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(compressed_read_error)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        if bytes_read > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed NAR exceeds configured size limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let actual_nar_hash = NarHash::from_digest(hasher.finish());
    if expected_nar_hash.is_some_and(|expected_id| actual_nar_hash != *expected_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed NAR hash mismatch",
        ));
    }
    Ok(DecodedValidation {
        hash: actual_nar_hash,
        size: NarSize::new(bytes_read),
    })
}

pub(super) fn validate_xz(
    file: &File,
    expected_nar_hash: Option<&NarHash>,
    expected_file_hash: Option<&FileHash>,
    max_bytes: u64,
) -> io::Result<DecodedValidation> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = XzReader::new(
        HashingReader::new(file, expected_file_hash.is_some()),
        false,
    );
    let decoded = validate_decoded(&mut reader, expected_nar_hash, max_bytes)?;
    let mut actual_file_hash = reader.into_inner();
    if actual_file_hash.inner.stream_position()? != actual_file_hash.inner.metadata()?.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after XZ NAR",
        ));
    }
    if !actual_file_hash.matches(expected_file_hash) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed NAR hash mismatch",
        ));
    }
    Ok(decoded)
}

pub(super) fn validate_zstd(
    file: &File,
    expected_nar_hash: Option<&NarHash>,
    expected_file_hash: Option<&FileHash>,
    max_bytes: u64,
) -> io::Result<DecodedValidation> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader =
        StructuredZstdDecoder::new(HashingReader::new(file, expected_file_hash.is_some()))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid zstd NAR: {error}"),
                )
            })?;
    let decoded = validate_decoded(&mut reader, expected_nar_hash, max_bytes)?;
    let mut actual_file_hash = reader.into_inner();
    if actual_file_hash.inner.stream_position()? != actual_file_hash.inner.metadata()?.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after zstd NAR",
        ));
    }
    if !actual_file_hash.matches(expected_file_hash) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed NAR hash mismatch",
        ));
    }
    Ok(decoded)
}

pub(super) fn file_matches<H: Sha256Digest>(
    file: &File,
    expected_hash: &H,
    expected_size: u64,
) -> io::Result<bool> {
    if file.metadata()?.len() != expected_size {
        return Ok(false);
    }
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.matches(expected_hash))
}

pub(super) struct VerifiedCompressedNar<'file> {
    file: &'file File,
    expectation: CompressedNarExpectation,
}

pub(super) fn verify_encoded_compressed_file<'file>(
    file: &'file File,
    expectation: CompressedNarExpectation,
) -> io::Result<Option<VerifiedCompressedNar<'file>>> {
    if !file_matches(
        file,
        &expectation.encoded.hash(),
        expectation.encoded.size().get(),
    )? {
        return Ok(None);
    }
    Ok(Some(VerifiedCompressedNar { file, expectation }))
}

pub(super) fn verify_decoded_compressed_file(
    verified: VerifiedCompressedNar<'_>,
) -> io::Result<Option<DecodedValidation>> {
    let decoded = decode_compressed_payload_for_nar_identity(&verified)?;
    Ok(decoded.and_then(|decoded| {
        decoded_nar_with_expected_size(decoded, verified.expectation.decoded.size())
    }))
}

fn decode_compressed_payload_for_nar_identity(
    verified: &VerifiedCompressedNar<'_>,
) -> io::Result<Option<DecodedValidation>> {
    match validate_compressed_payload_for_nar_identity(verified) {
        Ok(decoded) => Ok(Some(decoded)),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_compressed_payload_for_nar_identity(
    verified: &VerifiedCompressedNar<'_>,
) -> io::Result<DecodedValidation> {
    match verified.expectation.encoded.encoding() {
        NarEncoding::Zstd => {
            validate_zstd_payload_against_nar_identity(verified.file, verified.expectation.decoded)
        }
        NarEncoding::Xz => {
            validate_xz_payload_against_nar_identity(verified.file, verified.expectation.decoded)
        }
        NarEncoding::Raw => unreachable!("raw uploads do not use compressed verification"),
    }
}

fn decoded_nar_with_expected_size(
    decoded: DecodedValidation,
    expected_size: NarSize,
) -> Option<DecodedValidation> {
    (decoded.size == expected_size).then_some(decoded)
}

fn validate_xz_payload_against_nar_identity(
    file: &File,
    identity: NarIdentity,
) -> io::Result<DecodedValidation> {
    validate_xz(file, Some(&identity.hash()), None, identity.size().get())
}

fn validate_zstd_payload_against_nar_identity(
    file: &File,
    identity: NarIdentity,
) -> io::Result<DecodedValidation> {
    validate_zstd(file, Some(&identity.hash()), None, identity.size().get())
}

pub(super) fn validate_compressed_nar(
    file: &File,
    expectation: CompressedNarExpectation,
) -> io::Result<Option<DecodedValidation>> {
    let Some(verified) = verify_encoded_compressed_file(file, expectation)? else {
        return Ok(None);
    };
    verify_decoded_compressed_file(verified)
}

pub(super) fn compressed_nar_matches(
    file: &File,
    expectation: CompressedNarExpectation,
) -> io::Result<bool> {
    Ok(validate_compressed_nar(file, expectation)?.is_some())
}

pub(crate) fn nar_file_matches(file: &File, expectation: NarExpectation) -> io::Result<bool> {
    match expectation {
        NarExpectation::Raw(identity) => raw_nar_file_matches(file, identity),
        NarExpectation::Compressed(expectation) => compressed_nar_matches(file, expectation),
    }
}

fn raw_nar_file_matches(file: &File, identity: NarIdentity) -> io::Result<bool> {
    file_matches(file, &identity.hash(), identity.size().get())
}

pub(crate) fn nar_file_size_matches(file: &File, expected_size: u64) -> io::Result<bool> {
    // Serving trusts the full validation performed before publication. The
    // service-owned cache tree and process lease keep published files stable
    // while this cheap availability check runs.
    Ok(file.metadata()?.len() == expected_size)
}
