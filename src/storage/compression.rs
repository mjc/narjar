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

use crate::narinfo::{CompressedEncoding, CompressedNarExpectation, NarEncoding, NarExpectation};
use crate::object::{FileHash, NarHash};

use super::ids::nix32_sha256_matches;

const INGESTION_RECEIPT_VERSION: u8 = 1;

pub(super) struct CheckedUploadReader<'a, R> {
    inner: R,
    expected_hash: &'a FileHash,
    expected_length: u64,
    bytes_read: u64,
    hasher: Sha256,
    done: bool,
}

impl<'a, R> CheckedUploadReader<'a, R> {
    pub(super) fn new(inner: R, expected_hash: &'a FileHash, expected_length: u64) -> Self {
        Self {
            inner,
            expected_hash,
            expected_length,
            bytes_read: 0,
            hasher: Sha256::new(),
            done: false,
        }
    }

    pub(super) fn finish(&mut self) -> io::Result<()>
    where
        R: Read,
    {
        if self.done {
            return Ok(());
        }

        let mut buffer = [0; 64 * 1024];
        let read = self.inner.read(&mut buffer)?;
        if read != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded upload has trailing bytes",
            ));
        }
        if self.bytes_read != self.expected_length
            || !self
                .expected_hash
                .matches_digest(&self.hasher.clone().finalize())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NAR hash or size mismatch",
            ));
        }
        self.done = true;
        Ok(())
    }
}

impl<R: Read> Read for CheckedUploadReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }

        let read = self.inner.read(buffer)?;
        if read == 0 {
            let digest = self.hasher.clone().finalize();
            if self.bytes_read != self.expected_length
                || !self.expected_hash.matches_digest(&digest)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NAR hash or size mismatch",
                ));
            }
            self.done = true;
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

struct HashingWriter<'a> {
    inner: &'a mut File,
    hasher: Sha256,
    bytes_written: u64,
    max_bytes: u64,
}

impl<'a> HashingWriter<'a> {
    fn new(inner: &'a mut File, max_bytes: u64) -> Self {
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
            size: self.bytes_written,
        }
    }
}

impl Write for HashingWriter<'_> {
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

pub(super) fn normalize_upload(
    source: impl Read,
    encoding: NarEncoding,
    expected_file_hash: &FileHash,
    expected_file_size: u64,
    destination: &mut File,
    max_nar_size: u64,
) -> io::Result<DecodedValidation> {
    let input = CheckedUploadReader::new(source, expected_file_hash, expected_file_size);
    match encoding {
        NarEncoding::None => {
            let mut input = input;
            let mut output = HashingWriter::new(destination, max_nar_size);
            io::copy(&mut input, &mut output)?;
            input.finish()?;
            let decoded = output.finish();
            if decoded.size != expected_file_size
                || decoded.hash.to_string() != expected_file_hash.to_string()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raw NAR hash or size mismatch",
                ));
            }
            Ok(decoded)
        }
        NarEncoding::Xz => {
            let source_error = Rc::new(RefCell::new(None));
            let mut decoder = XzReader::new(
                CompressedSourceReader::new(input, Rc::clone(&source_error)),
                false,
            );
            let mut output = HashingWriter::new(destination, max_nar_size);
            io::copy(&mut decoder, &mut output)
                .map_err(|error| take_source_error(&source_error, compressed_read_error(error)))?;
            let mut input = decoder.into_inner().inner;
            input
                .finish()
                .map_err(|error| take_source_error(&source_error, compressed_read_error(error)))?;
            Ok(output.finish())
        }
        NarEncoding::Zstd => {
            let source_error = Rc::new(RefCell::new(None));
            let mut decoder = StructuredZstdDecoder::new(CompressedSourceReader::new(
                input,
                Rc::clone(&source_error),
            ))
            .map_err(|error| take_source_error(&source_error, compressed_decoder_error(error)))?;
            let mut output = HashingWriter::new(destination, max_nar_size);
            io::copy(&mut decoder, &mut output)
                .map_err(|error| take_source_error(&source_error, compressed_read_error(error)))?;
            let mut input = decoder.into_inner().inner;
            input
                .finish()
                .map_err(|error| take_source_error(&source_error, compressed_read_error(error)))?;
            Ok(output.finish())
        }
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Option<Sha256>,
}

struct CompressedSourceReader<R> {
    inner: R,
    error: Rc<RefCell<Option<io::Error>>>,
}

impl<R> CompressedSourceReader<R> {
    fn new(inner: R, error: Rc<RefCell<Option<io::Error>>>) -> Self {
        Self { inner, error }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodedValidation {
    pub(super) hash: NarHash,
    pub(super) size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IngestionReceipt {
    encoding: NarEncoding,
    encoded_hash: FileHash,
    encoded_size: u64,
    decoded_hash: NarHash,
    decoded_size: u64,
}

impl IngestionReceipt {
    pub(super) fn from_decoded(
        encoding: NarEncoding,
        encoded_hash: FileHash,
        encoded_size: u64,
        decoded: DecodedValidation,
    ) -> Self {
        Self {
            encoding,
            encoded_hash,
            encoded_size,
            decoded_hash: decoded.hash,
            decoded_size: decoded.size,
        }
    }

    pub(super) fn file_name(&self) -> OsString {
        OsString::from(format!(
            "{}{}.validation",
            self.encoded_hash,
            self.encoding.suffix()
        ))
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        format!(
            "version={INGESTION_RECEIPT_VERSION}\nencoding={}\nencoded-hash={}\nencoded-size={}\ndecoded-hash={}\ndecoded-size={}\n",
            self.encoding.compression(),
            self.encoded_hash,
            self.encoded_size,
            self.decoded_hash,
            self.decoded_size,
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
                    encoded_size = Some(value.parse().ok()?)
                }
                "decoded-hash" if decoded_hash.is_none() => {
                    decoded_hash = Some(NarHash::parse(value).ok()?)
                }
                "decoded-size" if decoded_size.is_none() => {
                    decoded_size = Some(value.parse().ok()?)
                }
                _ => return None,
            }
        }
        let evidence = Self {
            encoding: encoding?,
            encoded_hash: encoded_hash?,
            encoded_size: encoded_size?,
            decoded_hash: decoded_hash?,
            decoded_size: decoded_size?,
        };
        (version? == INGESTION_RECEIPT_VERSION).then_some(evidence)
    }

    pub(super) fn matches(&self, expectation: CompressedNarExpectation<'_>) -> bool {
        self.encoding == nar_encoding(expectation.encoding)
            && self.encoded_hash == *expectation.encoded_hash
            && self.encoded_size == expectation.encoded_size
            && self.decoded_hash == *expectation.decoded_hash
            && self.decoded_size == expectation.decoded_size
    }

    pub(super) fn decoded_hash(&self) -> NarHash {
        self.decoded_hash
    }
}

pub(super) fn nar_encoding(encoding: CompressedEncoding) -> NarEncoding {
    match encoding {
        CompressedEncoding::Zstd => NarEncoding::Zstd,
        CompressedEncoding::Xz => NarEncoding::Xz,
    }
}

pub(super) fn ingestion_receipt_file_name(expectation: CompressedNarExpectation<'_>) -> OsString {
    OsString::from(format!(
        "{}{}.validation",
        expectation.encoded_hash,
        nar_encoding(expectation.encoding).suffix()
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
            hasher: enabled.then(Sha256::new),
        }
    }

    fn matches(self, expected: Option<&str>) -> bool {
        match (self.hasher, expected) {
            (None, None) => true,
            (Some(hasher), Some(expected)) => nix32_sha256_matches(&hasher.finalize(), expected),
            _ => false,
        }
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self
            .inner
            .read(buffer)
            .map_err(|error| io::Error::other(CompressedSourceError(error)))?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(&buffer[..read]);
        }
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
    let actual_nar_hash = NarHash::from_digest(hasher.finalize().into());
    if expected_nar_hash.is_some_and(|expected_id| actual_nar_hash != *expected_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed NAR hash mismatch",
        ));
    }
    Ok(DecodedValidation {
        hash: actual_nar_hash,
        size: bytes_read,
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
    let expected_file_hash = expected_file_hash.map(ToString::to_string);
    if !actual_file_hash.matches(expected_file_hash.as_deref()) {
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
    let expected_file_hash = expected_file_hash.map(ToString::to_string);
    if !actual_file_hash.matches(expected_file_hash.as_deref()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed NAR hash mismatch",
        ));
    }
    Ok(decoded)
}

pub(super) fn file_matches(
    file: &File,
    expected_hash: &str,
    expected_size: u64,
) -> io::Result<bool> {
    if file.metadata()?.len() != expected_size {
        return Ok(false);
    }
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
    Ok(nix32_sha256_matches(&hasher.finalize(), expected_hash))
}

pub(super) struct VerifiedCompressedNar<'file, 'metadata> {
    file: &'file File,
    expectation: CompressedNarExpectation<'metadata>,
}

pub(super) fn verify_encoded_compressed_file<'file, 'metadata>(
    file: &'file File,
    expectation: CompressedNarExpectation<'metadata>,
) -> io::Result<Option<VerifiedCompressedNar<'file, 'metadata>>> {
    if !file_matches(
        file,
        &expectation.encoded_hash.to_string(),
        expectation.encoded_size,
    )? {
        return Ok(None);
    }
    Ok(Some(VerifiedCompressedNar { file, expectation }))
}

pub(super) fn verify_decoded_compressed_file(
    verified: VerifiedCompressedNar<'_, '_>,
) -> io::Result<Option<DecodedValidation>> {
    let validation = match verified.expectation.encoding {
        CompressedEncoding::Zstd => validate_zstd(
            verified.file,
            Some(verified.expectation.decoded_hash),
            None,
            verified.expectation.decoded_size,
        ),
        CompressedEncoding::Xz => validate_xz(
            verified.file,
            Some(verified.expectation.decoded_hash),
            None,
            verified.expectation.decoded_size,
        ),
    };
    match validation {
        Ok(decoded) if decoded.size == verified.expectation.decoded_size => Ok(Some(decoded)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn validate_compressed_nar(
    file: &File,
    expectation: CompressedNarExpectation<'_>,
) -> io::Result<Option<DecodedValidation>> {
    let Some(verified) = verify_encoded_compressed_file(file, expectation)? else {
        return Ok(None);
    };
    verify_decoded_compressed_file(verified)
}

pub(super) fn compressed_nar_matches(
    file: &File,
    expectation: CompressedNarExpectation<'_>,
) -> io::Result<bool> {
    Ok(validate_compressed_nar(file, expectation)?.is_some())
}

pub(crate) fn nar_file_matches(file: &File, expectation: NarExpectation<'_>) -> io::Result<bool> {
    match expectation {
        NarExpectation::Raw { nar_hash, nar_size } => {
            let expected_hash = nar_hash.to_string();
            file_matches(file, &expected_hash, nar_size)
        }
        NarExpectation::Compressed(expectation) => compressed_nar_matches(file, expectation),
    }
}

pub(crate) fn nar_file_size_matches(file: &File, expected_size: u64) -> io::Result<bool> {
    // Serving trusts the full validation performed before publication. The
    // service-owned cache tree and process lease keep published files stable
    // while this cheap availability check runs.
    Ok(file.metadata()?.len() == expected_size)
}
