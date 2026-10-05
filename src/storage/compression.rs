use std::{
    cell::RefCell,
    ffi::OsString,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

use lzma_rust2::XzReader as LzmaRustXzReader;
use sha2::{Digest, Sha256};
use structured_zstd::decoding::{
    FrameDecoder, StreamingDecoder as StructuredZstdDecoder, read_frame_header_info,
};
use xz4rust::{XzDecoder, XzNextBlockResult};

use crate::object::{
    CompressedNarIdentity, CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarFileName,
    NarHash, NarIdentity, NarRepresentation, NarSize, WireEncoding,
};

use super::{
    publication::{
        DecodedSizeLimitExceeded, DecoderMemoryLimit, DecoderMemoryLimitExceeded,
        StagingReservation, StorageError,
    },
    receipt::CompressedNarReceipt,
    typestate::Validated,
};
const RAW_STAGING_GROWTH_BYTES: u64 = 64 * 1024 * 1024;
const ZSTD_FRAME_HEADER_MAX_BYTES: usize = 18;
const ZSTD_BLOCK_BUFFER_BYTES: u64 = 128 * 1024;
const ZSTD_FIXED_WORKSPACE_ALLOWANCE_BYTES: u64 = 1024 * 1024;

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
        reserve_preferred_or_exact_staging_growth(additional_required, |required| {
            self.reservation
                .grow_to(self.file, self.min_free_bytes, required)
        })
        .map_err(storage_capacity_error)
    }
}

fn reserve_preferred_or_exact_staging_growth(
    additional_required: u64,
    mut reserve: impl FnMut(u64) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let preferred_bytes = additional_required
        .div_ceil(RAW_STAGING_GROWTH_BYTES)
        .saturating_mul(RAW_STAGING_GROWTH_BYTES);
    reserve(preferred_bytes).or_else(|_| reserve(additional_required))
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
            io::Error::from_raw_os_error(rustix::io::Errno::NOSPC.raw_os_error())
        }
        StorageError::Io(error) => error,
        error => io::Error::other(error),
    }
}

struct HashingWriter<'a, W: Write + ?Sized> {
    inner: digest_io::HashWriter<Sha256, &'a mut W>,
    bytes_written: u64,
    max_bytes: u64,
}

impl<'a, W: Write + ?Sized> HashingWriter<'a, W> {
    fn new(inner: &'a mut W, max_bytes: u64) -> Self {
        Self {
            inner: digest_io::HashWriter::new(inner),
            bytes_written: 0,
            max_bytes,
        }
    }

    fn finish(self) -> NarIdentity {
        NarIdentity::new(
            NarHash::from_digest(self.inner.finalize().into()),
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
                DecodedSizeLimitExceeded,
            ));
        }
        let written = self.inner.write(buffer)?;
        self.bytes_written += written as u64;
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
    decoder_memory_limit: DecoderMemoryLimit,
    destination: &mut W,
) -> io::Result<ReceivedNar> {
    let expectation = UploadExpectation {
        name,
        size: length.into(),
        max_nar_size,
        decoder_memory_limit,
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
    let mut decoder = BoundedXzReader::new(
        UploadCompressedSourceReader::new(input, Rc::clone(&source_error)),
        expectation.decoder_memory_limit.get(),
    )
    .map_err(|error| take_upload_source_error(&source_error, error))?;
    let decoded = copy_decoded_upload_to_raw_staging(
        &mut decoder,
        destination,
        expectation.max_nar_size,
        &source_error,
    )?;
    let (input, has_trailing_bytes) = decoder.into_parts();
    if has_trailing_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after XZ NAR",
        ));
    }
    finish_encoded_upload_after_decoding(input.into_inner(), &source_error)?;
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
    let upload_source = UploadCompressedSourceReader::new(input, Rc::clone(&source_error));
    let prefixed_source =
        preflight_zstd_window(upload_source, expectation.decoder_memory_limit.get())
            .map_err(|error| take_upload_source_error(&source_error, error))?;
    let mut decoder = StructuredZstdDecoder::new(prefixed_source).map_err(|error| {
        take_upload_source_error(&source_error, compressed_decoder_error(error))
    })?;
    let decoded = copy_decoded_upload_to_raw_staging(
        &mut decoder,
        destination,
        expectation.max_nar_size,
        &source_error,
    )?;
    finish_zstd_upload_after_decoding(decoder.into_inner(), &source_error)?;
    Ok(decoded)
}

const XZ_INPUT_BUFFER_BYTES: usize = 8 * 1024;
const XZ_COPY_BUFFER_BYTES: u64 = 8 * 1024;
const XZ_FIXED_WORKSPACE_ALLOWANCE_BYTES: u64 = 64 * 1024;

struct BoundedXzReader<R> {
    source: R,
    decoder: Box<XzDecoder<'static>>,
    input: [u8; XZ_INPUT_BUFFER_BYTES],
    input_start: usize,
    input_end: usize,
    end_of_stream: bool,
}

impl<R> BoundedXzReader<R> {
    fn new(source: R, memory_limit_bytes: u64) -> io::Result<Self> {
        let fixed_workspace =
            xz_decoder_memory_requirement(0).ok_or_else(decoder_memory_limit_error)?;
        let dictionary_limit = memory_limit_bytes
            .checked_sub(fixed_workspace)
            .filter(|limit| *limit >= xz4rust::DICT_SIZE_MIN as u64)
            .ok_or_else(decoder_memory_limit_error)?
            .min(xz4rust::DICT_SIZE_MAX as u64) as usize;

        Ok(Self {
            source,
            decoder: XzDecoder::in_heap_with_alloc_dict_size(
                xz4rust::DICT_SIZE_MIN,
                dictionary_limit,
            ),
            input: [0; XZ_INPUT_BUFFER_BYTES],
            input_start: 0,
            input_end: 0,
            end_of_stream: false,
        })
    }

    fn into_parts(self) -> (R, bool) {
        (self.source, self.input_start != self.input_end)
    }
}

pub(super) fn xz_decoder_memory_requirement(dictionary_bytes: u64) -> Option<u64> {
    (std::mem::size_of::<XzDecoder<'static>>() as u64)
        .checked_add(XZ_INPUT_BUFFER_BYTES as u64)?
        .checked_add(XZ_COPY_BUFFER_BYTES)?
        .checked_add(XZ_FIXED_WORKSPACE_ALLOWANCE_BYTES)?
        .checked_add(dictionary_bytes)
}

impl<R: Read> Read for BoundedXzReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.end_of_stream {
            return Ok(0);
        }

        loop {
            if self.input_start == self.input_end {
                self.input_end = self.source.read(&mut self.input)?;
                self.input_start = 0;
                if self.input_end == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
            }

            let result = self
                .decoder
                .decode(&self.input[self.input_start..self.input_end], output)
                .map_err(xz_decoder_error)?;
            let consumed = result.input_consumed();
            let produced = result.output_produced();
            self.input_start += consumed;

            match result {
                XzNextBlockResult::NeedMoreData(_, _) if consumed == 0 && produced == 0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "XZ decoder made no progress",
                    ));
                }
                XzNextBlockResult::NeedMoreData(_, _) if produced == 0 => continue,
                XzNextBlockResult::NeedMoreData(_, _) => return Ok(produced),
                XzNextBlockResult::EndOfStream(_, _) => {
                    self.end_of_stream = true;
                    return Ok(produced);
                }
            }
        }
    }
}

fn xz_decoder_error(error: xz4rust::XzError) -> io::Error {
    match error {
        xz4rust::XzError::DictionaryOverflow => decoder_memory_limit_error(),
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn decoder_memory_limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, DecoderMemoryLimitExceeded)
}

fn zstd_decoder_memory_requirement(window_bytes: u64) -> Option<u64> {
    window_bytes
        .checked_add(ZSTD_BLOCK_BUFFER_BYTES)?
        .checked_add(ZSTD_FIXED_WORKSPACE_ALLOWANCE_BYTES)?
        .checked_add(std::mem::size_of::<FrameDecoder>() as u64)
}

fn preflight_zstd_window<R: Read>(
    mut source: R,
    max_decoder_memory_bytes: u64,
) -> io::Result<io::Chain<Cursor<Vec<u8>>, R>> {
    let mut header_bytes = [0; ZSTD_FRAME_HEADER_MAX_BYTES];
    let mut header_length = 0;
    while header_length < header_bytes.len() {
        match source.read(&mut header_bytes[header_length..]) {
            Ok(0) => break,
            Ok(read) => header_length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    let header_prefix = &header_bytes[..header_length];
    let header = read_frame_header_info(header_prefix, false)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let required_memory = zstd_decoder_memory_requirement(header.window_size);
    if !required_memory.is_some_and(|required| required <= max_decoder_memory_bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            DecoderMemoryLimitExceeded,
        ));
    }

    Ok(Cursor::new(header_prefix.to_vec()).chain(source))
}

fn finish_zstd_upload_after_decoding<R: Read>(
    input: io::Chain<Cursor<Vec<u8>>, UploadCompressedSourceReader<CheckedUploadReader<R>>>,
    source_error: &RefCell<Option<io::Error>>,
) -> io::Result<()> {
    let (prefix, source) = input.into_inner();
    if prefix.position() != prefix.get_ref().len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zstd frame has trailing bytes",
        ));
    }
    finish_encoded_upload_after_decoding(source.into_inner(), source_error)
}

#[derive(Clone, Copy)]
struct UploadExpectation {
    name: NarFileName,
    size: EncodedSize,
    max_nar_size: u64,
    decoder_memory_limit: DecoderMemoryLimit,
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

fn copy_decoded_upload_to_raw_staging<R: Read, W: Write>(
    decoder: &mut R,
    destination: &mut W,
    max_nar_size: u64,
    source_error: &RefCell<Option<io::Error>>,
) -> io::Result<NarIdentity> {
    let mut normalized_decoder = NormalizeCompressedReadErrors(decoder);
    copy_decoded_bytes_to_raw_staging(&mut normalized_decoder, destination, max_nar_size)
        .map_err(|error| take_upload_source_error(source_error, error))
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

struct NormalizeCompressedReadErrors<R>(R);

impl<R: Read> Read for NormalizeCompressedReadErrors<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer).map_err(|error| {
            if error.kind() == io::ErrorKind::OutOfMemory {
                io::Error::new(io::ErrorKind::InvalidData, DecoderMemoryLimitExceeded)
            } else {
                compressed_read_error(error)
            }
        })
    }
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

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct CompressedSourceError(#[source] io::Error);

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
    } else if error.kind() == io::ErrorKind::Other || error.kind() == io::ErrorKind::Unsupported {
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
    let mut decoder = LzmaRustXzReader::new(StoredCompressedSourceReader::new(input), false);
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

pub(super) fn compressed_file_identity(
    file: &File,
    encoded: EncodedIdentity,
) -> io::Result<Option<NarIdentity>> {
    if !encoded_file_matches(file, encoded)? {
        return Ok(None);
    }
    let expectation = CompressedNarIdentity::new(
        encoded,
        NarIdentity::new(encoded.hash().as_nar_hash(), NarSize::new(u64::MAX)),
    );
    let verified = VerifiedCompressedNar { file, expectation };
    match decode_verified_compressed_payload(&verified) {
        Ok(decoded) => Ok(Some(decoded)),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(None),
        Err(error) => Err(error),
    }
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
    use std::io::{self, Write};

    use super::{
        EncodedIdentity, EncodedSize, FileHash, IngestionReceipt, NarHash, NarIdentity, NarSize,
        reserve_preferred_or_exact_staging_growth,
    };
    use crate::object::CompressionCodec;
    use crate::storage::{StorageCapacity, publication::StagingBudget};

    struct EnospcWriter;

    impl Write for EnospcWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(
                rustix::io::Errno::NOSPC.raw_os_error(),
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encoding_propagates_physical_enospc() {
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let mut source = io::Cursor::new(b"raw NAR bytes");
            let error = crate::nar_compression::encode_and_measure_nar(
                codec,
                &mut EnospcWriter,
                |output| io::copy(&mut source, output).map(|_| ()),
            )
            .expect_err("physical output exhaustion should fail encoding");
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::NOSPC.raw_os_error())
            );
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
        let space = StorageCapacity {
            total_bytes: 2 * 1024 * 1024,
            available_bytes: 2 * 1024 * 1024,
            total_inodes: 1,
            available_inodes: 1,
            read_only: false,
        };
        let mut budget = StagingBudget::default();
        let mut attempts = Vec::new();
        reserve_preferred_or_exact_staging_growth(512 * 1024, |required| {
            attempts.push(required);
            budget.reserve(space, 0, required)
        })
        .expect("the exact output requirement should fit when the preferred chunk does not");
        assert_eq!(attempts, [64 * 1024 * 1024, 512 * 1024]);
        assert_eq!(budget.outstanding_bytes(), 512 * 1024);
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_compressed_source_preserves_io_layer() {
        use std::error::Error as _;
        let error = CompressedSourceError(io::Error::other("read failure"));
        assert_eq!(error.to_string(), "read failure");
        let source = error.source().unwrap();
        assert!(source.is::<io::Error>());
        assert_eq!(source.to_string(), "read failure");
        assert!(source.source().is_none());
    }
}
#[cfg(test)]
mod hashing_tests {
    use super::*;

    #[test]
    fn decoded_size_limit_checks_the_entire_attempt_before_a_partial_write() {
        struct PartialWriter(Vec<u8>);
        impl Write for PartialWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let accepted = bytes.len().min(1);
                self.0.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut destination = PartialWriter(Vec::new());
        let mut measured = HashingWriter::new(&mut destination, 4);
        let error = measured.write(b"abcde").unwrap_err();
        assert!(error.get_ref().unwrap().is::<DecodedSizeLimitExceeded>());
        assert_eq!(measured.write(b"abcd").unwrap(), 1);
        assert_eq!(measured.write(b"bcd").unwrap(), 1);
        let identity = measured.finish();
        assert_eq!(destination.0, b"ab");
        assert_eq!(identity.size().get(), 2);
        assert_eq!(
            identity.hash(),
            NarHash::from_digest(Sha256::digest(b"ab").into())
        );
    }

    #[test]
    fn decoded_counter_overflow_rejects_the_write_without_output() {
        let mut destination = Vec::new();
        let mut measured = HashingWriter::new(&mut destination, u64::MAX);
        measured.bytes_written = u64::MAX;
        assert_eq!(
            measured.write(b"x").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(measured);
        assert!(destination.is_empty());
    }
}
