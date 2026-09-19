use std::{
    cell::RefCell,
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

use lzma_rust2::XzReader;
use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use structured_zstd::decoding::StreamingDecoder as StructuredZstdDecoder;
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};

use crate::object::{
    CompressedNarIdentity, CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarFileName,
    NarHash, NarIdentity, NarRepresentation, NarSize, WireEncoding,
};

use super::{
    publication::{StagingReservation, StorageError},
    receipt::CompressedNarReceipt,
    typestate::Validated,
};
const RAW_STAGING_GROWTH_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct CheckedUploadReader<R> {
    inner: R,
    expected_hash: FileHash,
    expected_length: u64,
    bytes_read: u64,
    hasher: Sha256,
    phase: UploadReadPhase,
}

enum UploadReadPhase {
    Reading,
    EndValidated,
}

impl<R> CheckedUploadReader<R> {
    pub(super) fn new(inner: R, expected_hash: FileHash, expected_length: u64) -> Self {
        Self {
            inner,
            expected_hash,
            expected_length,
            bytes_read: 0,
            hasher: Sha256::new(),
            phase: UploadReadPhase::Reading,
        }
    }

    fn validate_observed_upload_hash_and_length(&self) -> io::Result<()> {
        let actual_hash = FileHash::from_digest(self.hasher.clone().finalize().into());
        if self.bytes_read != self.expected_length || actual_hash != self.expected_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR hash or size mismatch",
            ));
        }
        Ok(())
    }

    pub(super) fn finish(self) -> io::Result<Validated<R>>
    where
        R: Read,
    {
        let mut receiving = self;
        receiving.ensure_upload_end_was_consumed()?;
        Ok(Validated::new(receiving.inner))
    }

    fn ensure_upload_end_was_consumed(&mut self) -> io::Result<()>
    where
        R: Read,
    {
        match self.phase {
            UploadReadPhase::EndValidated => Ok(()),
            UploadReadPhase::Reading => {
                let mut buffer = [0; 64 * 1024];
                if self.inner.read(&mut buffer)? != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encoded upload has trailing bytes",
                    ));
                }
                self.record_validated_upload_end()
            }
        }
    }

    fn record_validated_upload_end(&mut self) -> io::Result<()> {
        self.validate_observed_upload_hash_and_length()?;
        self.phase = UploadReadPhase::EndValidated;
        Ok(())
    }
}

impl<R: Read> Read for CheckedUploadReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.phase {
            UploadReadPhase::EndValidated => Ok(0),
            UploadReadPhase::Reading => {
                let read = self.inner.read(buffer)?;
                if read == 0 {
                    self.record_validated_upload_end()?;
                    return Ok(0);
                }

                self.bytes_read = self.bytes_read.checked_add(read as u64).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "NAR is too large")
                })?;
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
    }
}

pub(super) struct CapacityCheckedStagingWriter<'a> {
    file: &'a mut File,
    reservation: &'a mut StagingReservation,
    min_free_bytes: u64,
    bytes_written: u64,
}

impl<'a> CapacityCheckedStagingWriter<'a> {
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
        let additional_required = next_size.saturating_sub(self.bytes_written);
        if additional_required <= self.reservation.reserved_bytes() {
            return Ok(());
        }
        reserve_preferred_or_exact_staging_growth(
            self.reservation,
            self.file,
            self.min_free_bytes,
            additional_required,
        )
        .map_err(storage_capacity_error)
    }
}

fn reserve_preferred_or_exact_staging_growth(
    reservation: &mut StagingReservation,
    directory: &File,
    min_free_bytes: u64,
    additional_required: u64,
) -> Result<(), StorageError> {
    let preferred_bytes = additional_required
        .div_ceil(RAW_STAGING_GROWTH_BYTES)
        .saturating_mul(RAW_STAGING_GROWTH_BYTES);
    reservation
        .grow_to(directory, min_free_bytes, preferred_bytes)
        .or_else(|_| reservation.grow_to(directory, min_free_bytes, additional_required))
}

impl Write for CapacityCheckedStagingWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_size = self
            .bytes_written
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        self.reserve_before_write(next_size)?;
        let written = self.file.write(buffer)?;
        self.bytes_written += written as u64;
        self.reservation.record_materialized_bytes(written as u64);
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

struct EncodedOutputHasher<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    hasher: Sha256,
    bytes_written: u64,
}

impl<'a, W: Write + ?Sized> EncodedOutputHasher<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    fn finish(self, codec: CompressionCodec) -> EncodedIdentity {
        EncodedIdentity::new(
            codec,
            FileHash::from_digest(self.hasher.finalize().into()),
            EncodedSize::new(self.bytes_written),
        )
    }
}

impl<W: Write + ?Sized> Write for EncodedOutputHasher<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(written as u64)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "encoded NAR is too large")
            })?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) fn encode_raw_nar(
    mut source: impl Read,
    codec: CompressionCodec,
    destination: &mut impl Write,
) -> io::Result<EncodedIdentity> {
    let mut output = EncodedOutputHasher::new(destination);
    match codec {
        CompressionCodec::Zstd => {
            let mut encoder = StreamingEncoder::new(&mut output, CompressionLevel::Fastest);
            io::copy(&mut source, &mut encoder)?;
            encoder.finish()?;
        }
        CompressionCodec::Xz => {
            let mut encoder =
                XzWriter::new(&mut output, XzOptions::with_preset(1)).map_err(io::Error::other)?;
            io::copy(&mut source, &mut encoder)?;
            encoder.finish().map_err(io::Error::other)?;
        }
    }
    Ok(output.finish(codec))
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

    fn finish(self) -> NarIdentity {
        NarIdentity::new(
            NarHash::from_digest(self.hasher.finalize().into()),
            NarSize::new(self.bytes_written),
        )
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
    let expectation = UploadExpectation {
        name,
        size: length.into(),
        max_nar_size,
    };
    let codec = match name.encoding() {
        WireEncoding::Raw => {
            let decoded = copy_raw_upload_to_raw_staging(source, expectation, destination)?;
            return Ok(ReceivedNar::Raw(decoded));
        }
        WireEncoding::Compressed(codec) => codec,
    };
    let decoded = match codec {
        CompressionCodec::Xz => decode_xz_upload_to_raw_staging(source, expectation, destination)?,
        CompressionCodec::Zstd => {
            decode_zstd_upload_to_raw_staging(source, expectation, destination)?
        }
    };
    Ok(ReceivedNar::Compressed(IngestionReceipt::new(
        expectation.compressed_identity(codec),
        decoded,
    )))
}

fn copy_raw_upload_to_raw_staging<W: Write>(
    mut source: impl Read,
    expectation: UploadExpectation,
    destination: &mut W,
) -> io::Result<NarIdentity> {
    let max_bytes = expectation.max_nar_size.min(expectation.size.get());
    let mut output = HashingWriter::new(destination, max_bytes);
    io::copy(&mut source, &mut output)?;
    validate_raw_upload_identity(output.finish(), expectation)
}

fn decode_xz_upload_to_raw_staging<W: Write>(
    source: impl Read,
    expectation: UploadExpectation,
    destination: &mut W,
) -> io::Result<NarIdentity> {
    let input =
        CheckedUploadReader::new(source, expectation.name.file_hash(), expectation.size.get());
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
    expectation: UploadExpectation,
    destination: &mut W,
) -> io::Result<NarIdentity> {
    let input =
        CheckedUploadReader::new(source, expectation.name.file_hash(), expectation.size.get());
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
struct UploadExpectation {
    name: NarFileName,
    size: EncodedSize,
    max_nar_size: u64,
}

impl UploadExpectation {
    const fn compressed_identity(self, codec: CompressionCodec) -> EncodedIdentity {
        EncodedIdentity::new(codec, self.name.file_hash(), self.size)
    }
}

fn validate_raw_upload_identity(
    decoded: NarIdentity,
    expectation: UploadExpectation,
) -> io::Result<NarIdentity> {
    if decoded.size().get() == expectation.size.get()
        && expectation
            .name
            .file_hash()
            .matches_nar_hash(decoded.hash())
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
) -> io::Result<NarIdentity> {
    let mut output = HashingWriter::new(destination, max_nar_size);
    io::copy(decoder, &mut output)?;
    Ok(output.finish())
}

fn finish_encoded_upload_after_decoding<R: Read>(
    input: CheckedUploadReader<R>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IngestionReceiptPurpose {}

pub(super) type IngestionReceipt = CompressedNarReceipt<IngestionReceiptPurpose>;

impl CompressedNarReceipt<IngestionReceiptPurpose> {
    pub(super) fn file_name(&self) -> OsString {
        Self::file_name_for(self.identity())
    }

    pub(super) fn file_name_for(expectation: CompressedNarIdentity) -> OsString {
        OsString::from(format!(
            "{}{}.validation",
            expectation.encoded().hash(),
            expectation.encoded().codec().suffix()
        ))
    }

    pub(super) fn matches(&self, expectation: CompressedNarIdentity) -> bool {
        self.identity() == expectation
    }

    pub(super) fn decoded_identity(&self) -> NarIdentity {
        self.decoded()
    }
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

fn measure_decoded_nar<R: Read>(reader: &mut R, max_bytes: u64) -> io::Result<NarIdentity> {
    let mut sink = io::sink();
    let mut measured = HashingWriter::new(&mut sink, max_bytes);
    io::copy(reader, &mut measured).map_err(compressed_read_error)?;
    Ok(measured.finish())
}

fn sha256_file(file: &File) -> io::Result<NarHash> {
    let mut file = file.try_clone()?;
    let position = file.stream_position()?;
    file.seek(SeekFrom::Start(0))?;
    let mut sink = io::sink();
    let mut measured = HashingWriter::new(&mut sink, u64::MAX);
    let copy_result = io::copy(&mut file, &mut measured);
    let hash = measured.finish().hash();
    let restore_result = file.seek(SeekFrom::Start(position));
    copy_result?;
    restore_result?;
    Ok(hash)
}

pub(super) fn encoded_file_matches(file: &File, identity: EncodedIdentity) -> io::Result<bool> {
    if file.metadata()?.len() != identity.size().get() {
        return Ok(false);
    }
    Ok(identity.hash().matches_nar_hash(sha256_file(file)?))
}

pub(super) struct VerifiedCompressedNar<'file> {
    file: &'file File,
    expectation: CompressedNarIdentity,
}

pub(super) fn verify_encoded_compressed_file<'file>(
    file: &'file File,
    expectation: CompressedNarIdentity,
) -> io::Result<Option<VerifiedCompressedNar<'file>>> {
    if !encoded_file_matches(file, expectation.encoded())? {
        return Ok(None);
    }
    Ok(Some(VerifiedCompressedNar { file, expectation }))
}

pub(super) fn verify_decoded_compressed_file(
    verified: VerifiedCompressedNar<'_>,
) -> io::Result<Option<NarIdentity>> {
    match decode_verified_compressed_payload(&verified) {
        Ok(decoded) => Ok((decoded == verified.expectation.decoded()).then_some(decoded)),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(None),
        Err(error) => Err(error),
    }
}

fn decode_verified_compressed_payload(
    verified: &VerifiedCompressedNar<'_>,
) -> io::Result<NarIdentity> {
    match verified.expectation.encoded().codec() {
        CompressionCodec::Zstd => decode_verified_zstd_payload(verified),
        CompressionCodec::Xz => decode_verified_xz_payload(verified),
    }
}

fn decode_verified_xz_payload(verified: &VerifiedCompressedNar<'_>) -> io::Result<NarIdentity> {
    let input = rewound_compressed_file(verified.file)?;
    let mut decoder = XzReader::new(StoredCompressedSourceReader::new(input), false);
    let decoded = measure_decoded_nar(&mut decoder, verified.expectation.decoded().size().get())?;
    ensure_decoder_consumed_complete_compressed_file(
        &mut decoder.into_inner().into_inner(),
        CompressionCodec::Xz,
    )?;
    Ok(decoded)
}

fn decode_verified_zstd_payload(verified: &VerifiedCompressedNar<'_>) -> io::Result<NarIdentity> {
    let input = rewound_compressed_file(verified.file)?;
    let mut decoder = StructuredZstdDecoder::new(StoredCompressedSourceReader::new(input))
        .map_err(compressed_decoder_error)?;
    let decoded = measure_decoded_nar(&mut decoder, verified.expectation.decoded().size().get())?;
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
    expectation: CompressedNarIdentity,
) -> io::Result<Option<NarIdentity>> {
    let Some(verified) = verify_encoded_compressed_file(file, expectation)? else {
        return Ok(None);
    };
    verify_decoded_compressed_file(verified)
}

pub(crate) fn nar_file_matches(file: &File, payload: NarRepresentation) -> io::Result<bool> {
    match payload {
        NarRepresentation::Raw(identity) => raw_nar_file_matches(file, identity),
        NarRepresentation::Compressed(expectation) => {
            Ok(validate_compressed_nar(file, expectation)?.is_some())
        }
    }
}

fn raw_nar_file_matches(file: &File, identity: NarIdentity) -> io::Result<bool> {
    if file.metadata()?.len() != identity.size().get() {
        return Ok(false);
    }
    Ok(sha256_file(file)? == identity.hash())
}

pub(crate) fn nar_file_size_matches(file: &File, expected_size: u64) -> io::Result<bool> {
    // Serving trusts the full validation performed before publication. The
    // service-owned cache tree and process lease keep published files stable
    // while this cheap availability check runs.
    Ok(file.metadata()?.len() == expected_size)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use super::{
        EncodedIdentity, EncodedSize, FileHash, IngestionReceipt, NarHash, NarIdentity, NarSize,
        StagingReservation, encode_raw_nar, reserve_preferred_or_exact_staging_growth,
    };
    use crate::object::CompressionCodec;
    use crate::storage::fs::filesystem_space;

    struct EnospcWriter;

    impl Write for EnospcWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encoding_propagates_physical_enospc() {
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let source = io::Cursor::new(b"raw NAR bytes");
            let error = encode_raw_nar(source, codec, &mut EnospcWriter)
                .expect_err("physical output exhaustion should fail encoding");
            assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        }
    }

    #[test]
    fn ingestion_receipt_round_trips_through_compact_binary_serialization() {
        let encoded_hash = FileHash::from_digest([0; 32]);
        let decoded_hash = NarHash::from_digest([1; 32]);
        let decoded_identity = NarIdentity::new(decoded_hash, NarSize::new(17));
        let receipt = IngestionReceipt::new(
            EncodedIdentity::new(CompressionCodec::Zstd, encoded_hash, EncodedSize::new(23)),
            decoded_identity,
        );
        let bytes = receipt.bytes();
        assert_eq!(
            IngestionReceipt::parse(&bytes)
                .expect("typed ingestion receipt should be readable")
                .decoded_identity(),
            decoded_identity
        );
        assert!(IngestionReceipt::parse(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn staging_growth_falls_back_to_the_exact_immediate_requirement() {
        let directory = tempfile::tempdir().expect("staging growth directory");
        let file = File::open(directory.path()).expect("open staging growth directory");
        let available = filesystem_space(&file)
            .expect("measure staging growth directory")
            .available_bytes;
        let exact_capacity = 2 * 1024 * 1024;
        if available < exact_capacity {
            return;
        }
        let min_free_bytes = available - exact_capacity;
        let mut reservation = StagingReservation::empty(Arc::new(Mutex::new(Default::default())));

        reserve_preferred_or_exact_staging_growth(
            &mut reservation,
            &file,
            min_free_bytes,
            512 * 1024,
        )
        .expect("the exact output requirement should fit when the preferred chunk does not");

        assert_eq!(reservation.reserved_bytes(), 512 * 1024);
    }
}
