use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
};

use data_encoding::BASE64;
use ed25519_dalek::{Signature, VerifyingKey};

pub use crate::object::WireEncoding as NarEncoding;
use crate::object::{
    CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarFileName, NarHash, NarIdentity,
    NarSize,
};
use crate::storage::{Directory, StoreHash, StoredNar, open_regular_at};

const MAX_TRUST_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_NARINFO_BYTES: u64 = 1024 * 1024;

pub(crate) fn read_narinfo_file(file: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_NARINFO_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Default)]
pub struct TrustedPublicKeys(BTreeMap<String, VerifyingKey>);

impl TrustedPublicKeys {
    pub fn load(directory: &Directory) -> Result<Self, TrustError> {
        let mut file = match open_regular_at(directory.file(), OsStr::new("trusted-public-keys")) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o133 != 0 {
            return Err(TrustError::InvalidTrustFile);
        }

        let mut contents = String::new();
        (&mut file)
            .take(MAX_TRUST_FILE_BYTES + 1)
            .read_to_string(&mut contents)?;
        if contents.len() as u64 > MAX_TRUST_FILE_BYTES {
            return Err(TrustError::InvalidTrustFile);
        }

        let mut keys = BTreeMap::new();
        for entry in contents.split_ascii_whitespace() {
            let (name, encoded) = entry
                .split_once(':')
                .filter(|(name, encoded)| valid_name(name) && !encoded.is_empty())
                .ok_or(TrustError::InvalidTrustFile)?;
            if keys.contains_key(name) {
                return Err(TrustError::InvalidTrustFile);
            }

            let bytes: [u8; 32] = BASE64
                .decode(encoded.as_bytes())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(TrustError::InvalidTrustFile)?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| TrustError::InvalidTrustFile)?;
            if key.is_weak() {
                return Err(TrustError::InvalidTrustFile);
            }
            keys.insert(name.to_owned(), key);
        }
        Ok(Self(keys))
    }
    pub(crate) fn inspect(
        &self,
        route: &StoreHash,
        bytes: Vec<u8>,
    ) -> Result<ValidatedNarInfo, PublishedNarInfoError> {
        let mut narinfo =
            ParsedNarInfo::parse(route, bytes).map_err(|_| PublishedNarInfoError::Malformed)?;
        if !self.verifies(narinfo.fingerprint.as_bytes(), &narinfo.signatures) {
            return Err(PublishedNarInfoError::UntrustedSignature);
        }
        narinfo.fingerprint = String::new();
        narinfo.signatures = Vec::new();
        Ok(ValidatedNarInfo(narinfo))
    }

    pub fn validate(
        &self,
        route: &StoreHash,
        bytes: Vec<u8>,
    ) -> Result<ValidatedNarInfo, NarInfoError> {
        self.inspect(route, bytes).map_err(|_| NarInfoError)
    }

    fn verifies(&self, fingerprint: &[u8], signatures: &[NamedSignature]) -> bool {
        signatures.iter().any(|signature| {
            self.0
                .get(signature.name.as_str())
                .is_some_and(|key| key.verify_strict(fingerprint, &signature.signature).is_ok())
        })
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[derive(Debug)]
struct NamedSignature {
    name: String,
    signature: Signature,
}

impl NamedSignature {
    fn parse(value: &str) -> Result<Self, NarInfoError> {
        let (name, encoded) = value
            .split_once(':')
            .filter(|(name, encoded)| valid_name(name) && !encoded.is_empty())
            .ok_or(NarInfoError)?;
        let bytes = BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| NarInfoError)?;
        let signature = Signature::from_slice(&bytes).map_err(|_| NarInfoError)?;
        Ok(Self {
            name: name.to_owned(),
            signature,
        })
    }
}

#[derive(Debug)]
struct ParsedNarInfo {
    store: StoreHash,
    store_path: String,
    references: String,
    payload: ValidatedPayload,
    fingerprint: String,
    signatures: Vec<NamedSignature>,
    text: String,
}

impl ParsedNarInfo {
    fn parse(route: &StoreHash, bytes: Vec<u8>) -> Result<Self, NarInfoError> {
        if bytes.len() as u64 > MAX_NARINFO_BYTES {
            return Err(NarInfoError);
        }
        let text = String::from_utf8(bytes).map_err(|_| NarInfoError)?;
        if !text.ends_with('\n') || text.contains('\r') {
            return Err(NarInfoError);
        }

        let mut fields = Vec::with_capacity(11);
        let mut signature_values = Vec::new();
        for line in text.strip_suffix('\n').ok_or(NarInfoError)?.split('\n') {
            let (name, value) = line.split_once(": ").ok_or(NarInfoError)?;
            match name {
                "Sig" => signature_values.push(value),
                "StorePath" | "URL" | "Compression" | "FileHash" | "FileSize" | "NarHash"
                | "NarSize" | "References" | "Deriver" | "CA" => {
                    if fields.iter().any(|(field, _)| *field == name) {
                        return Err(NarInfoError);
                    }
                    fields.push((name, value));
                }
                _ => return Err(NarInfoError),
            }
        }

        let field = |name: &str| {
            fields
                .iter()
                .find_map(|(field, value)| (*field == name).then_some(*value))
        };
        let required = |name| field(name).ok_or(NarInfoError);
        let store_path = required("StorePath")?;
        let store_basename = store_path.strip_prefix("/nix/store/").ok_or(NarInfoError)?;
        let (store_hash, _) = validate_store_basename(store_basename)?;
        if store_hash != route.as_str() {
            return Err(NarInfoError);
        }

        let url = required("URL")?;
        let url_value = url.strip_prefix("nar/").ok_or(NarInfoError)?;
        let payload = NarFileName::parse(url_value).map_err(|_| NarInfoError)?;
        if required("Compression")? != payload.encoding().compression() {
            return Err(NarInfoError);
        }

        let declared_file_hash = required("FileHash")?
            .strip_prefix("sha256:")
            .ok_or(NarInfoError)?;
        let file_hash = FileHash::parse(declared_file_hash).map_err(|_| NarInfoError)?;
        let nar_hash = required("NarHash")?
            .strip_prefix("sha256:")
            .and_then(|value| NarHash::parse(value).ok())
            .ok_or(NarInfoError)?;
        let file_size = EncodedSize::new(
            required("FileSize")?
                .parse::<u64>()
                .map_err(|_| NarInfoError)?,
        );
        let nar_size = NarSize::new(
            required("NarSize")?
                .parse::<u64>()
                .map_err(|_| NarInfoError)?,
        );

        if field("Deriver").is_some_and(|deriver| {
            deriver != "unknown-deriver" && validate_store_basename(deriver).is_err()
        }) {
            return Err(NarInfoError);
        }
        if let Some(ca) = field("CA") {
            parse_content_address(ca)?;
        }

        let references = parse_references(required("References")?)?;
        let identity = NarIdentity::new(nar_hash, nar_size);
        let payload = ValidatedPayload::from_narinfo(payload, file_hash, file_size, identity)?;
        let fingerprint = build_fingerprint(
            store_path,
            &identity.hash(),
            identity.size().get(),
            &references,
        );
        let signatures = signature_values
            .into_iter()
            .map(NamedSignature::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if signatures.is_empty() {
            return Err(NarInfoError);
        }

        Ok(Self {
            store: route.clone(),
            store_path: store_path.to_owned(),
            references,
            payload,
            fingerprint,
            signatures,
            text,
        })
    }
}

#[derive(Debug)]
pub struct ValidatedNarInfo(ParsedNarInfo);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompressedNarExpectation {
    pub(crate) encoded: EncodedIdentity,
    pub(crate) decoded: NarIdentity,
}

impl CompressedNarExpectation {
    pub(crate) const fn new(
        codec: CompressionCodec,
        encoded_hash: FileHash,
        encoded_size: EncodedSize,
        decoded: NarIdentity,
    ) -> Self {
        Self {
            encoded: EncodedIdentity::new(codec, encoded_hash, encoded_size),
            decoded,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidatedPayload {
    Raw(NarIdentity),
    Compressed(CompressedNarExpectation),
}

impl ValidatedPayload {
    fn from_narinfo(
        file_name: NarFileName,
        file_hash: FileHash,
        file_size: EncodedSize,
        identity: NarIdentity,
    ) -> Result<Self, NarInfoError> {
        if file_name.file_hash() != file_hash || identity.size().get() == 0 {
            return Err(NarInfoError);
        }

        match file_name.encoding() {
            NarEncoding::Raw if !file_hash.matches_nar_hash(identity.hash()) => Err(NarInfoError),
            NarEncoding::Raw if file_size.get() != identity.size().get() => Err(NarInfoError),
            NarEncoding::Raw => Ok(Self::Raw(identity)),
            NarEncoding::Zstd => Ok(Self::Compressed(CompressedNarExpectation::new(
                CompressionCodec::Zstd,
                file_hash,
                file_size,
                identity,
            ))),
            NarEncoding::Xz => Ok(Self::Compressed(CompressedNarExpectation::new(
                CompressionCodec::Xz,
                file_hash,
                file_size,
                identity,
            ))),
        }
    }

    pub(crate) const fn decoded_identity(self) -> NarIdentity {
        match self {
            Self::Raw(identity) => identity,
            Self::Compressed(expectation) => expectation.decoded,
        }
    }

    pub(crate) const fn encoded_size(self) -> EncodedSize {
        match self {
            Self::Raw(identity) => EncodedSize::new(identity.size().get()),
            Self::Compressed(expectation) => expectation.encoded.size(),
        }
    }

    pub(crate) const fn payload_name(self) -> NarFileName {
        match self {
            Self::Raw(identity) => NarFileName::raw(identity.hash()),
            Self::Compressed(expectation) => NarFileName::new(
                expectation.encoded.hash(),
                expectation.encoded.codec().wire_encoding(),
            ),
        }
    }
}

impl ValidatedNarInfo {
    pub(crate) fn store_path(&self) -> &str {
        &self.0.store_path
    }

    pub(crate) fn references(&self) -> &str {
        &self.0.references
    }

    pub(crate) const fn payload_name(&self) -> NarFileName {
        self.0.payload.payload_name()
    }

    pub(crate) const fn file_size(&self) -> EncodedSize {
        self.0.payload.encoded_size()
    }

    pub(crate) fn payload(&self) -> ValidatedPayload {
        self.0.payload
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0.text.into_bytes()
    }

    pub(crate) fn bind_raw(self, stored: StoredNar<'_>) -> Result<BoundNarInfo<'_>, NarInfoError> {
        if self.0.payload.decoded_identity() != stored.identity() {
            return Err(NarInfoError);
        }
        Ok(BoundNarInfo {
            metadata: self.0,
            stored,
        })
    }
}

/// Signed claims bound to an opened canonical payload. Only this state can
/// project metadata for raw serving; it retains the file until publication.
pub(crate) struct BoundNarInfo<'storage> {
    metadata: ParsedNarInfo,
    stored: StoredNar<'storage>,
}

impl BoundNarInfo<'_> {
    pub(crate) fn stored(&self) -> &StoredNar<'_> {
        &self.stored
    }

    pub(crate) fn store(&self) -> &StoreHash {
        &self.metadata.store
    }

    pub(crate) fn raw_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = BoundedNarInfoWriter::with_capacity(self.metadata.text.len());
        self.metadata
            .text
            .lines()
            .try_for_each(|line| self.write_raw_field(line, &mut output))?;
        Ok(output.into_bytes())
    }

    fn write_raw_field(&self, line: &str, output: &mut impl Write) -> io::Result<()> {
        let identity = self.stored.identity();
        match line.split_once(": ") {
            Some(("URL", _)) => writeln!(output, "URL: nar/{}", NarFileName::raw(identity.hash())),
            Some(("Compression", _)) => writeln!(output, "Compression: none"),
            Some(("FileHash", _)) => writeln!(output, "FileHash: sha256:{}", identity.hash()),
            Some(("FileSize", _)) => writeln!(output, "FileSize: {}", identity.size()),
            _ => writeln!(output, "{line}"),
        }
    }
}

struct BoundedNarInfoWriter {
    bytes: Vec<u8>,
}

impl BoundedNarInfoWriter {
    fn with_capacity(input_length: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(input_length.min(MAX_NARINFO_BYTES as usize)),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedNarInfoWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let new_length =
            self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "narinfo is too large")
            })?;
        if new_length as u64 > MAX_NARINFO_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projected narinfo exceeds configured size limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_references(value: &str) -> Result<String, NarInfoError> {
    if value.is_empty() {
        return Ok(String::new());
    }

    let mut references = value.split(' ').collect::<Vec<_>>();
    for reference in &references {
        if reference.is_empty() {
            return Err(NarInfoError);
        }
        validate_store_basename(reference)?;
    }
    references.sort_unstable();
    references.dedup();
    Ok(references.join(" "))
}

fn build_fingerprint(
    store_path: &str,
    nar_hash: &NarHash,
    nar_size: u64,
    references: &str,
) -> String {
    let mut fingerprint = format!("1;{store_path};sha256:{nar_hash};{nar_size};");
    for (index, reference) in references.split_ascii_whitespace().enumerate() {
        if index != 0 {
            fingerprint.push(',');
        }
        fingerprint.push_str("/nix/store/");
        fingerprint.push_str(reference);
    }
    fingerprint
}

fn parse_content_address(value: &str) -> Result<(), NarInfoError> {
    let rest = if let Some(rest) = value.strip_prefix("text:") {
        rest
    } else if let Some(rest) = value.strip_prefix("fixed:") {
        rest.strip_prefix("r:")
            .or_else(|| rest.strip_prefix("git:"))
            .unwrap_or(rest)
    } else {
        return Err(NarInfoError);
    };
    let (algorithm, hash) = rest.split_once(':').ok_or(NarInfoError)?;
    let hash_bytes = match algorithm {
        "md5" => 16,
        "sha1" => 20,
        "blake3" | "sha256" => 32,
        "sha512" => 64,
        _ => return Err(NarInfoError),
    };
    let valid = (hash.len() == hash_bytes * 2 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (hash.len() == (hash_bytes * 8).div_ceil(5)
            && hash
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)))
        || BASE64
            .decode(hash.as_bytes())
            .is_ok_and(|decoded| decoded.len() == hash_bytes);
    valid.then_some(()).ok_or(NarInfoError)
}

fn validate_store_basename(value: &str) -> Result<(&str, &str), NarInfoError> {
    let (hash, name) = value.split_once('-').ok_or(NarInfoError)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
    {
        return Err(NarInfoError);
    }
    StoreHash::validate(hash).map_err(|_| NarInfoError)?;
    Ok((hash, name))
}

#[derive(Clone, Copy, Debug)]
pub struct NarInfoError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublishedNarInfoError {
    Malformed,
    UntrustedSignature,
}

impl fmt::Display for NarInfoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid or untrusted narinfo")
    }
}

impl std::error::Error for NarInfoError {}

#[derive(Debug)]
pub enum TrustError {
    InvalidTrustFile,
    Io(io::Error),
}

impl From<io::Error> for TrustError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTrustFile => formatter.write_str("invalid trusted public key file"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTrustFile => None,
            Self::Io(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_read_errors_are_not_reported_as_malformed_content() {
        let directory = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(directory.path().join("write-only")).unwrap();
        let error = read_narinfo_file(file).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    const STORE_HASH: &str = "00000000000000000000000000000000";
    const NAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";
    const XZ_FILE_HASH: &str = "1111111111111111111111111111111111111111111111111111";

    #[test]
    fn parser_rejects_oversized_narinfo() {
        let route = StoreHash::parse(STORE_HASH).expect("valid store hash");
        let store_name = "a".repeat(MAX_NARINFO_BYTES as usize);
        let signature = BASE64.encode(&[0; 64]);
        let bytes = format!(
            "StorePath: /nix/store/{STORE_HASH}-{store_name}\n\
             URL: nar/{NAR_HASH}.nar\n\
             Compression: none\n\
             FileHash: sha256:{NAR_HASH}\n\
             FileSize: 1\n\
             NarHash: sha256:{NAR_HASH}\n\
             NarSize: 1\n\
             References: \n\
             Sig: test:{signature}\n"
        )
        .into_bytes();

        assert!(bytes.len() as u64 > MAX_NARINFO_BYTES);
        assert!(ParsedNarInfo::parse(&route, bytes).is_err());
    }

    #[test]
    fn projected_narinfo_writer_rejects_output_over_the_read_limit() {
        let mut writer = BoundedNarInfoWriter::with_capacity(MAX_NARINFO_BYTES as usize);
        writer
            .write_all(&vec![b'x'; MAX_NARINFO_BYTES as usize])
            .expect("a boundary-sized projection should fit");

        let error = writer
            .write(b"x")
            .expect_err("the projection must not exceed the read limit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parser_deduplicates_references() {
        let references = parse_references(&format!("{STORE_HASH}-package {STORE_HASH}-package"))
            .expect("duplicate references should be accepted");
        assert_eq!(references, format!("{STORE_HASH}-package"));
    }

    #[test]
    fn parser_keeps_compact_sorted_references() {
        let references = parse_references(&format!(
            "{STORE_HASH}-zulu {STORE_HASH}-alpha {STORE_HASH}-zulu"
        ))
        .expect("valid references");
        assert_eq!(references, format!("{STORE_HASH}-alpha {STORE_HASH}-zulu"));
    }

    #[test]
    fn parser_validates_store_basenames_borrowed() {
        let value = format!("{STORE_HASH}-package");
        let (hash, name) = validate_store_basename(&value).expect("valid store basename");
        assert_eq!(hash, STORE_HASH);
        assert_eq!(name, "package");
    }

    #[test]
    fn fingerprint_formats_references_in_order() {
        let nar_hash = NarHash::parse(NAR_HASH).expect("valid nar hash");
        let references = format!("{STORE_HASH}-alpha {STORE_HASH}-zulu");

        assert_eq!(
            build_fingerprint(
                "/nix/store/00000000000000000000000000000000-package",
                &nar_hash,
                7,
                &references,
            ),
            format!("1;/nix/store/{STORE_HASH}-package;sha256:{NAR_HASH};7;/nix/store/")
                + &format!("{STORE_HASH}-alpha,/nix/store/{STORE_HASH}-zulu")
        );
    }

    #[test]
    fn parser_accepts_xz_narinfo() {
        let route = StoreHash::parse(STORE_HASH).expect("valid store hash");
        let signature = BASE64.encode(&[0; 64]);
        let bytes = format!(
            "StorePath: /nix/store/{STORE_HASH}-package\n\
             URL: nar/{XZ_FILE_HASH}.nar.xz\n\
             Compression: xz\n\
             FileHash: sha256:{XZ_FILE_HASH}\n\
             FileSize: 10\n\
             NarHash: sha256:{NAR_HASH}\n\
             NarSize: 1\n\
             References: \n\
             Sig: test:{signature}\n"
        )
        .into_bytes();

        assert!(ParsedNarInfo::parse(&route, bytes).is_ok());
    }
}
