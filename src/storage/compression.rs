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

use crate::narinfo::{CompressedNarExpectation, NarEncoding, ValidatedPayload};
use crate::object::{
    CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarFileName, NarHash, NarIdentity,
    NarSize,
};

use super::{
    fs::filesystem_space,
    publication::{StagingReservation, StorageError},
};

const INGESTION_RECEIPT_VERSION: u8 = 1;
const RAW_STAGING_GROWTH_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct CheckedUploadReader<'a, R> {
    inner: R,
    expected_hash: &'a FileHash,
    expected_length: u64,
    bytes_read: u64,
    hasher: Sha256,
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
            hasher: Sha256::new(),
            upload_end_validated: false,
        }
    }

    fn validate_observed_upload_hash_and_length(&self) -> io::Result<()> {
        let actual_hash = FileHash::from_digest(self.hasher.clone().finalize().into());
        if self.bytes_read != self.expected_length || actual_hash != *self.expected_hash {
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
        if next_size <= self.reservation.reserved_bytes() {
            return Ok(());
        }
        let required_bytes = next_size
            .div_ceil(RAW_STAGING_GROWTH_BYTES)
            .saturating_mul(RAW_STAGING_GROWTH_BYTES);
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
    hasher: Sha256,
    bytes_written: u64,
    max_bytes: u64,
}

impl<'a, W: Write + ?Sized> HashingWriter<'a, W> {
    fn new(inner: &'a mut W, max_bytes: u64) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
            max_bytes,
        }
    }

    fn finish(self) -> DecodedValidation {
        DecodedValidation {
            hash: NarHash::from_digest(self.hasher.finalize().into()),
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

#[derive(Debug)]
pub(super) enum ReceivedNar {
    Raw(NarIdentity),
    Compressed(IngestionReceipt),
}

impl ReceivedNar {
    pub(super) fn identity(&self) -> NarIdentity {
        match self {
            Self::Raw(identity) => *identity,
            Self::Compressed(receipt) => receipt.decoded_identity(),
        }
    }
}

pub(super) fn receive_uploaded_nar<W: Write>(
    source: impl Read,
    name: NarFileName,
    length: u64,
    max_nar_size: u64,
    destination: &mut W,
) -> io::Result<ReceivedNar> {
    let file_hash = name.file_hash();
    let expectation = EncodedUploadExpectation {
        expected_file_hash: &file_hash,
        expected_file_size: length.into(),
        max_nar_size,
    };
    let codec = match name.encoding() {
        NarEncoding::Raw => {
            let decoded = copy_raw_upload_to_raw_staging(source, expectation, destination)?;
            return Ok(ReceivedNar::Raw(NarIdentity::new(
                decoded.hash,
                decoded.size,
            )));
        }
        NarEncoding::Xz => CompressionCodec::Xz,
        NarEncoding::Zstd => CompressionCodec::Zstd,
    };
    let decoded = match codec {
        CompressionCodec::Xz => decode_xz_upload_to_raw_staging(source, expectation, destination)?,
        CompressionCodec::Zstd => {
            decode_zstd_upload_to_raw_staging(source, expectation, destination)?
        }
    };
    Ok(ReceivedNar::Compressed(IngestionReceipt::from_decoded(
        EncodedIdentity::new(codec, file_hash, length.into()),
        decoded,
    )))
}

fn copy_raw_upload_to_raw_staging<W: Write>(
    mut source: impl Read,
    expectation: EncodedUploadExpectation<'_>,
    destination: &mut W,
) -> io::Result<DecodedValidation> {
    let max_bytes = expectation
        .max_nar_size
        .min(expectation.expected_file_size.get());
    let mut output = HashingWriter::new(destination, max_bytes);
    io::copy(&mut source, &mut output)?;
    validate_raw_upload_identity(output.finish(), expectation)
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
        UploadCompressedSourceReader::new(input, Rc::clone(&source_error)),
        false,
    );
    let decoded =
        copy_decoded_bytes_to_raw_staging(&mut decoder, destination, expectation.max_nar_size)
            .map_err(|error| {
                take_upload_source_error(&source_error, compressed_read_error(error))
            })?;
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
    let mut decoder = StructuredZstdDecoder::new(UploadCompressedSourceReader::new(
        input,
        Rc::clone(&source_error),
    ))
    .map_err(|error| take_upload_source_error(&source_error, compressed_decoder_error(error)))?;
    let decoded =
        copy_decoded_bytes_to_raw_staging(&mut decoder, destination, expectation.max_nar_size)
            .map_err(|error| {
                take_upload_source_error(&source_error, compressed_read_error(error))
            })?;
    finish_encoded_upload_after_decoding(decoder.into_inner().into_inner(), &source_error)?;
    Ok(decoded)
}

#[derive(Clone, Copy)]
struct EncodedUploadExpectation<'a> {
    expected_file_hash: &'a FileHash,
    expected_file_size: EncodedSize,
    max_nar_size: u64,
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
        .map_err(|error| take_upload_source_error(source_error, compressed_read_error(error)))
}

struct StoredCompressedSourceReader<R> {
    inner: R,
}

impl<R> StoredCompressedSourceReader<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

struct UploadCompressedSourceReader<R> {
    inner: R,
    source_error: Rc<RefCell<Option<io::Error>>>,
}

impl<R> UploadCompressedSourceReader<R> {
    fn new(inner: R, source_error: Rc<RefCell<Option<io::Error>>>) -> Self {
        Self {
            inner,
            source_error,
        }
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
    fn from_decoded(encoded: EncodedIdentity, decoded: DecodedValidation) -> Self {
        Self {
            encoded,
            decoded: NarIdentity::new(decoded.hash, decoded.size),
        }
    }

    pub(super) fn file_name(&self) -> OsString {
        OsString::from(format!(
            "{}{}.validation",
            self.encoded.hash(),
            self.encoded.codec().suffix()
        ))
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        format!(
            "version={INGESTION_RECEIPT_VERSION}\nencoding={}\nencoded-hash={}\nencoded-size={}\ndecoded-hash={}\ndecoded-size={}\n",
            self.encoded.codec().compression(),
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
                        "zstd" => CompressionCodec::Zstd,
                        "xz" => CompressionCodec::Xz,
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
        expectation.encoded.codec().suffix()
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

impl<R: Read> Read for StoredCompressedSourceReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner
            .read(buffer)
            .map_err(|error| io::Error::other(CompressedSourceError(error)))
    }
}

impl<R: Read> Read for UploadCompressedSourceReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer).map_err(|error| {
            *self.source_error.borrow_mut() = Some(error);
            io::Error::other("compressed upload source read failed")
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

fn take_upload_source_error(
    source_error: &RefCell<Option<io::Error>>,
    fallback: io::Error,
) -> io::Error {
    source_error.borrow_mut().take().unwrap_or(fallback)
}

fn measure_decoded_nar<R: Read>(reader: &mut R, max_bytes: u64) -> io::Result<DecodedValidation> {
    let mut hasher = Sha256::new();
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
    Ok(DecodedValidation {
        hash: NarHash::from_digest(hasher.finalize().into()),
        size: NarSize::new(bytes_read),
    })
}

fn sha256_file(file: &File) -> io::Result<[u8; 32]> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn encoded_file_matches(file: &File, identity: EncodedIdentity) -> io::Result<bool> {
    if file.metadata()?.len() != identity.size().get() {
        return Ok(false);
    }
    Ok(FileHash::from_digest(sha256_file(file)?) == identity.hash())
}

pub(super) struct VerifiedCompressedNar<'file> {
    file: &'file File,
    expectation: CompressedNarExpectation,
}

pub(super) fn verify_encoded_compressed_file<'file>(
    file: &'file File,
    expectation: CompressedNarExpectation,
) -> io::Result<Option<VerifiedCompressedNar<'file>>> {
    if !encoded_file_matches(file, expectation.encoded)? {
        return Ok(None);
    }
    Ok(Some(VerifiedCompressedNar { file, expectation }))
}

pub(super) fn verify_decoded_compressed_file(
    verified: VerifiedCompressedNar<'_>,
) -> io::Result<Option<DecodedValidation>> {
    match decode_verified_compressed_payload(&verified) {
        Ok(decoded) => Ok(decoded_nar_matches_expected_identity(
            decoded,
            verified.expectation.decoded,
        )),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(None),
        Err(error) => Err(error),
    }
}

fn decode_verified_compressed_payload(
    verified: &VerifiedCompressedNar<'_>,
) -> io::Result<DecodedValidation> {
    match verified.expectation.encoded.codec() {
        CompressionCodec::Zstd => decode_verified_zstd_payload(verified),
        CompressionCodec::Xz => decode_verified_xz_payload(verified),
    }
}

fn decoded_nar_matches_expected_identity(
    decoded: DecodedValidation,
    expected: NarIdentity,
) -> Option<DecodedValidation> {
    (decoded.hash == expected.hash() && decoded.size == expected.size()).then_some(decoded)
}

fn decode_verified_xz_payload(
    verified: &VerifiedCompressedNar<'_>,
) -> io::Result<DecodedValidation> {
    let input = rewound_compressed_file(verified.file)?;
    let mut decoder = XzReader::new(StoredCompressedSourceReader::new(input), false);
    let decoded = measure_decoded_nar(&mut decoder, verified.expectation.decoded.size().get())?;
    ensure_decoder_consumed_complete_compressed_file(
        &mut decoder.into_inner().into_inner(),
        CompressionCodec::Xz,
    )?;
    Ok(decoded)
}

fn decode_verified_zstd_payload(
    verified: &VerifiedCompressedNar<'_>,
) -> io::Result<DecodedValidation> {
    let input = rewound_compressed_file(verified.file)?;
    let mut decoder = StructuredZstdDecoder::new(StoredCompressedSourceReader::new(input))
        .map_err(compressed_decoder_error)?;
    let decoded = measure_decoded_nar(&mut decoder, verified.expectation.decoded.size().get())?;
    ensure_decoder_consumed_complete_compressed_file(
        &mut decoder.into_inner().into_inner(),
        CompressionCodec::Zstd,
    )?;
    Ok(decoded)
}

fn rewound_compressed_file(file: &File) -> io::Result<File> {
    let mut input = file.try_clone()?;
    input.seek(SeekFrom::Start(0))?;
    Ok(input)
}

fn ensure_decoder_consumed_complete_compressed_file(
    file: &mut File,
    codec: CompressionCodec,
) -> io::Result<()> {
    if file.stream_position()? == file.metadata()?.len() {
        return Ok(());
    }
    let message = match codec {
        CompressionCodec::Xz => "trailing bytes after XZ NAR",
        CompressionCodec::Zstd => "trailing bytes after zstd NAR",
    };
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
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

pub(crate) fn nar_file_matches(file: &File, payload: ValidatedPayload) -> io::Result<bool> {
    match payload {
        ValidatedPayload::Raw(identity) => raw_nar_file_matches(file, identity),
        ValidatedPayload::Compressed(expectation) => compressed_nar_matches(file, expectation),
    }
}

fn raw_nar_file_matches(file: &File, identity: NarIdentity) -> io::Result<bool> {
    if file.metadata()?.len() != identity.size().get() {
        return Ok(false);
    }
    Ok(NarHash::from_digest(sha256_file(file)?) == identity.hash())
}

pub(crate) fn nar_file_size_matches(file: &File, expected_size: u64) -> io::Result<bool> {
    // Serving trusts the full validation performed before publication. The
    // service-owned cache tree and process lease keep published files stable
    // while this cheap availability check runs.
    Ok(file.metadata()?.len() == expected_size)
}
