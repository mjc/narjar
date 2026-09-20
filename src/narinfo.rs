use std::{
    fmt,
    io::{self, Read, Write},
};

use crate::object::{
    EncodedIdentity, EncodedSize, FileHash, NarFileName, NarHash, NarIdentity, NarRepresentation,
    NarSize, WireEncoding,
};
use crate::storage::{StoreHash, VerifiedCanonicalNar};
use data_encoding::BASE64;
use ed25519_dalek::Signature;
use fluent_uri::UriRef;

mod trust;

pub use trust::{TrustError, TrustedPublicKeys};

pub const MAX_NARINFO_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct NixStorePath {
    value: String,
    store: StoreHash,
}

impl NixStorePath {
    fn parse(value: String) -> Result<Self, NarInfoError> {
        let basename = value.strip_prefix("/nix/store/").ok_or(NarInfoError)?;
        let (store, _) = validate_store_basename(basename)?;
        Ok(Self { value, store })
    }

    fn from_basename(value: &str) -> Result<Self, NarInfoError> {
        Self::parse(format!("/nix/store/{value}"))
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn basename(&self) -> &str {
        self.value
            .strip_prefix("/nix/store/")
            .expect("validated store paths retain their prefix")
    }

    fn store(&self) -> &StoreHash {
        &self.store
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Deriver {
    Unknown,
    StorePath(NixStorePath),
}

impl Deriver {
    fn from_store_value(value: String) -> Result<Self, NarInfoError> {
        match value.as_str() {
            "unknown-deriver" => Ok(Self::Unknown),
            _ => NixStorePath::parse(value).map(Self::StorePath),
        }
    }

    fn narinfo_value(&self) -> &str {
        match self {
            Self::Unknown => "unknown-deriver",
            Self::StorePath(path) => path.basename(),
        }
    }

    fn from_narinfo_value(value: &str) -> Result<Self, NarInfoError> {
        match value {
            "unknown-deriver" => Ok(Self::Unknown),
            basename => NixStorePath::from_basename(basename).map(Self::StorePath),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContentAddress(String);

impl ContentAddress {
    fn parse(value: String) -> Result<Self, NarInfoError> {
        parse_content_address(&value)?;
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NarInfoClaims {
    store_path: NixStorePath,
    references: Vec<NixStorePath>,
    identity: NarIdentity,
}

#[derive(Clone, Copy)]
enum ReferencesFieldHandling {
    Required,
    MissingMeansEmpty,
}

impl NarInfoClaims {
    pub fn new(
        store_path: String,
        references: Vec<String>,
        identity: NarIdentity,
    ) -> Result<Self, NarInfoError> {
        let store_path = NixStorePath::parse(store_path)?;
        let mut references = references
            .into_iter()
            .map(NixStorePath::parse)
            .collect::<Result<Vec<_>, _>>()?;
        references.sort_unstable_by(|left, right| left.value.cmp(&right.value));
        references.dedup_by(|left, right| left.value == right.value);
        Ok(Self {
            store_path,
            references,
            identity,
        })
    }

    pub fn store_path(&self) -> &str {
        self.store_path.as_str()
    }

    pub fn store(&self) -> &StoreHash {
        self.store_path.store()
    }

    pub fn reference_paths(&self) -> impl ExactSizeIterator<Item = &str> {
        self.references.iter().map(NixStorePath::as_str)
    }

    pub fn reference_basenames(&self) -> impl ExactSizeIterator<Item = &str> {
        self.references.iter().map(NixStorePath::basename)
    }

    pub fn reference_stores(&self) -> impl ExactSizeIterator<Item = &StoreHash> {
        self.references.iter().map(NixStorePath::store)
    }

    pub fn reference_store_paths(&self) -> impl ExactSizeIterator<Item = (&StoreHash, &str)> {
        self.references
            .iter()
            .map(|reference| (reference.store(), reference.as_str()))
    }

    pub fn references_field(&self) -> String {
        self.reference_basenames().collect::<Vec<_>>().join(" ")
    }

    pub const fn identity(&self) -> NarIdentity {
        self.identity
    }

    pub fn fingerprint(&self) -> String {
        build_fingerprint(
            self.store_path(),
            &self.identity.hash(),
            self.identity.size().get(),
            self.reference_basenames(),
        )
    }

    /// Parse and validate the logical claims and transport fields in an
    /// external narinfo before using its existence as a cache result.
    pub fn parse_external_narinfo(route: &StoreHash, bytes: Vec<u8>) -> Result<Self, NarInfoError> {
        let text = parse_narinfo_text(bytes)?;
        let document = NarInfoDocument::parse_external(&text)?;
        document.validate_external_transport()?;
        let claims = Self::from_external_document(route, &document)?;
        document.publication_payload(claims.identity())?;
        Ok(claims)
    }

    fn from_document(
        route: &StoreHash,
        document: &NarInfoDocument<'_>,
    ) -> Result<Self, NarInfoError> {
        Self::from_document_with_references(route, document, ReferencesFieldHandling::Required)
    }

    fn from_external_document(
        route: &StoreHash,
        document: &NarInfoDocument<'_>,
    ) -> Result<Self, NarInfoError> {
        Self::from_document_with_references(
            route,
            document,
            ReferencesFieldHandling::MissingMeansEmpty,
        )
    }

    fn from_document_with_references(
        route: &StoreHash,
        document: &NarInfoDocument<'_>,
        references_handling: ReferencesFieldHandling,
    ) -> Result<Self, NarInfoError> {
        let store_path =
            NixStorePath::parse(document.required(NarInfoField::StorePath)?.to_owned())?;
        if store_path.store() != route {
            return Err(NarInfoError);
        }

        let nar_hash = document
            .required(NarInfoField::NarHash)?
            .strip_prefix("sha256:")
            .and_then(|value| NarHash::parse(value).ok())
            .ok_or(NarInfoError)?;
        let nar_size = document
            .required(NarInfoField::NarSize)?
            .parse::<u64>()
            .ok()
            .filter(|size| *size != 0)
            .map(NarSize::new)
            .ok_or(NarInfoError)?;

        let references = match references_handling {
            ReferencesFieldHandling::Required => {
                parse_references(document.required(NarInfoField::References)?)?
            }
            ReferencesFieldHandling::MissingMeansEmpty => document
                .field(NarInfoField::References)
                .map(parse_references)
                .transpose()?
                .unwrap_or_default(),
        };

        Ok(Self {
            store_path,
            references,
            identity: NarIdentity::new(nar_hash, nar_size),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NarInfoMetadata {
    claims: NarInfoClaims,
    deriver: Option<Deriver>,
    content_address: Option<ContentAddress>,
    signatures: Vec<String>,
}

impl NarInfoMetadata {
    pub fn from_store_metadata(
        store_path: String,
        content_address: Option<String>,
        deriver: Option<String>,
        identity: NarIdentity,
        references: Vec<String>,
        signatures: Vec<String>,
    ) -> Result<Self, NarInfoError> {
        Ok(Self {
            claims: NarInfoClaims::new(store_path, references, identity)?,
            deriver: deriver.map(Deriver::from_store_value).transpose()?,
            content_address: content_address.map(ContentAddress::parse).transpose()?,
            signatures,
        })
    }

    pub fn claims(&self) -> &NarInfoClaims {
        &self.claims
    }

    pub fn signatures(&self) -> &[String] {
        &self.signatures
    }

    pub fn add_signature(&mut self, signature: String) {
        self.signatures.push(signature);
    }

    pub fn serialize(&self, representation: NarRepresentation) -> Result<Vec<u8>, NarInfoError> {
        if representation.identity() != self.claims.identity() {
            return Err(NarInfoError);
        }
        let mut output = Vec::new();
        self.write(representation, &mut output)
            .map_err(|_| NarInfoError)?;
        Ok(output)
    }

    fn from_document(
        route: &StoreHash,
        document: &NarInfoDocument<'_>,
    ) -> Result<Self, NarInfoError> {
        Ok(Self {
            claims: NarInfoClaims::from_document(route, document)?,
            deriver: document
                .field(NarInfoField::Deriver)
                .map(Deriver::from_narinfo_value)
                .transpose()?,
            content_address: document
                .field(NarInfoField::ContentAddress)
                .map(str::to_owned)
                .map(ContentAddress::parse)
                .transpose()?,
            signatures: document
                .signature_values
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        })
    }

    fn write(&self, representation: NarRepresentation, output: &mut impl Write) -> io::Result<()> {
        let file_name = representation.file_name();
        let file_size = representation.encoded_size();
        writeln!(
            output,
            "StorePath: {}\nURL: nar/{file_name}\nCompression: {}\nFileHash: sha256:{}\nFileSize: {file_size}\nNarHash: sha256:{}\nNarSize: {}\nReferences: {}",
            self.claims.store_path(),
            file_name.encoding().compression(),
            file_name.file_hash(),
            self.claims.identity().hash(),
            self.claims.identity().size(),
            self.claims.references_field(),
        )?;
        self.signatures
            .iter()
            .try_for_each(|signature| writeln!(output, "Sig: {signature}"))?;
        if let Some(deriver) = &self.deriver {
            writeln!(output, "Deriver: {}", deriver.narinfo_value())?;
        }
        if let Some(content_address) = &self.content_address {
            writeln!(output, "CA: {}", content_address.as_str())?;
        }
        Ok(())
    }
}

pub(crate) fn read_narinfo_file(file: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_NARINFO_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NarInfoField {
    StorePath,
    Url,
    Compression,
    FileHash,
    FileSize,
    NarHash,
    NarSize,
    References,
    Deriver,
    System,
    ContentAddress,
}

impl NarInfoField {
    const COUNT: usize = Self::ContentAddress as usize + 1;
}

enum NarInfoLineField {
    Unique(NarInfoField),
    Signature,
}

#[derive(Clone, Copy)]
enum UnknownFieldHandling {
    Reject,
    Ignore,
}

impl NarInfoLineField {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "StorePath" => Some(Self::Unique(NarInfoField::StorePath)),
            "URL" => Some(Self::Unique(NarInfoField::Url)),
            "Compression" => Some(Self::Unique(NarInfoField::Compression)),
            "FileHash" => Some(Self::Unique(NarInfoField::FileHash)),
            "FileSize" => Some(Self::Unique(NarInfoField::FileSize)),
            "NarHash" => Some(Self::Unique(NarInfoField::NarHash)),
            "NarSize" => Some(Self::Unique(NarInfoField::NarSize)),
            "References" => Some(Self::Unique(NarInfoField::References)),
            "Deriver" => Some(Self::Unique(NarInfoField::Deriver)),
            "System" => Some(Self::Unique(NarInfoField::System)),
            "CA" => Some(Self::Unique(NarInfoField::ContentAddress)),
            "Sig" => Some(Self::Signature),
            _ => None,
        }
    }
}

struct NarInfoDocument<'text> {
    fields: [Option<&'text str>; NarInfoField::COUNT],
    signature_values: Vec<&'text str>,
}

impl<'text> NarInfoDocument<'text> {
    fn parse(text: &'text str) -> Result<Self, NarInfoError> {
        Self::parse_with_unknown_fields(text, UnknownFieldHandling::Reject)
    }

    fn parse_external(text: &'text str) -> Result<Self, NarInfoError> {
        Self::parse_with_unknown_fields(text, UnknownFieldHandling::Ignore)
    }

    fn parse_with_unknown_fields(
        text: &'text str,
        unknown_fields: UnknownFieldHandling,
    ) -> Result<Self, NarInfoError> {
        text.strip_suffix('\n')
            .ok_or(NarInfoError)?
            .split('\n')
            .try_fold(
                Self {
                    fields: [None; NarInfoField::COUNT],
                    signature_values: Vec::new(),
                },
                |document, line| document.record_line(line, unknown_fields),
            )
    }

    fn record_line(
        mut self,
        line: &'text str,
        unknown_fields: UnknownFieldHandling,
    ) -> Result<Self, NarInfoError> {
        let (name, value) = line.split_once(": ").ok_or(NarInfoError)?;
        let Some(field) = NarInfoLineField::parse(name) else {
            return match unknown_fields {
                UnknownFieldHandling::Reject => Err(NarInfoError),
                UnknownFieldHandling::Ignore => Ok(self),
            };
        };
        self.record_field(field, value)?;
        Ok(self)
    }

    fn record_field(
        &mut self,
        field: NarInfoLineField,
        value: &'text str,
    ) -> Result<(), NarInfoError> {
        match field {
            NarInfoLineField::Signature => {
                self.signature_values.push(value);
                Ok(())
            }
            NarInfoLineField::Unique(field) => set_once(&mut self.fields[field as usize], value),
        }
    }

    fn field(&self, field: NarInfoField) -> Option<&'text str> {
        self.fields[field as usize]
    }

    fn required(&self, field: NarInfoField) -> Result<&'text str, NarInfoError> {
        self.field(field).ok_or(NarInfoError)
    }

    fn named_signatures(&self) -> Result<Vec<NamedSignature>, NarInfoError> {
        if self.signature_values.is_empty() {
            return Err(NarInfoError);
        }
        self.signature_values
            .iter()
            .copied()
            .map(NamedSignature::parse)
            .collect()
    }

    fn publication_payload(
        &self,
        identity: NarIdentity,
    ) -> Result<NarRepresentation, NarInfoError> {
        if self.field(NarInfoField::System).is_some() {
            return Err(NarInfoError);
        }
        let file_name = self
            .required(NarInfoField::Url)?
            .strip_prefix("nar/")
            .ok_or(NarInfoError)
            .and_then(|value| NarFileName::parse(value).map_err(|_| NarInfoError))?;
        if self.required(NarInfoField::Compression)? != file_name.encoding().compression() {
            return Err(NarInfoError);
        }
        let file_hash = self
            .required(NarInfoField::FileHash)?
            .strip_prefix("sha256:")
            .ok_or(NarInfoError)
            .and_then(|value| FileHash::parse(value).map_err(|_| NarInfoError))?;
        let file_size = self
            .required(NarInfoField::FileSize)?
            .parse::<u64>()
            .map(EncodedSize::new)
            .map_err(|_| NarInfoError)?;
        NarRepresentation::from_narinfo(file_name, file_hash, file_size, identity)
    }

    fn validate_external_transport(&self) -> Result<(), NarInfoError> {
        let url = self.required(NarInfoField::Url)?;
        if url.is_empty() {
            return Err(NarInfoError);
        }
        let uri = UriRef::parse(url).map_err(|_| NarInfoError)?;
        if uri.has_fragment()
            || uri
                .scheme()
                .is_some_and(|scheme| !["http", "https"].contains(&scheme.as_str()))
            || uri.scheme().is_some_and(|_| {
                uri.authority()
                    .is_none_or(|authority| authority.host().is_empty())
            })
        {
            return Err(NarInfoError);
        }
        self.required(NarInfoField::Compression)?
            .parse::<WireEncoding>()
            .map_err(|_| NarInfoError)?;
        match (
            self.field(NarInfoField::FileHash),
            self.field(NarInfoField::FileSize),
        ) {
            (None, None) => Ok(()),
            (Some(hash), Some(size)) => {
                hash.strip_prefix("sha256:")
                    .ok_or(NarInfoError)
                    .and_then(|value| FileHash::parse(value).map_err(|_| NarInfoError))?;
                size.parse::<u64>()
                    .ok()
                    .filter(|size| *size != 0)
                    .ok_or(NarInfoError)?;
                Ok(())
            }
            _ => Err(NarInfoError),
        }
    }
}

fn set_once<'text>(
    destination: &mut Option<&'text str>,
    value: &'text str,
) -> Result<(), NarInfoError> {
    match destination {
        None => {
            *destination = Some(value);
            Ok(())
        }
        Some(_) => Err(NarInfoError),
    }
}

fn parse_narinfo_text(bytes: Vec<u8>) -> Result<String, NarInfoError> {
    if bytes.len() as u64 > MAX_NARINFO_BYTES {
        return Err(NarInfoError);
    }
    let text = String::from_utf8(bytes).map_err(|_| NarInfoError)?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(NarInfoError);
    }
    Ok(text)
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
struct PublicationNarInfo {
    metadata: NarInfoMetadata,
    payload: NarRepresentation,
}

struct UnverifiedPublicationNarInfo {
    publication: PublicationNarInfo,
    signatures: Vec<NamedSignature>,
}

impl UnverifiedPublicationNarInfo {
    fn parse(route: &StoreHash, bytes: Vec<u8>) -> Result<Self, NarInfoError> {
        let text = parse_narinfo_text(bytes)?;
        let document = NarInfoDocument::parse(&text)?;
        let metadata = NarInfoMetadata::from_document(route, &document)?;
        let payload = document.publication_payload(metadata.claims().identity())?;
        let signatures = document.named_signatures()?;

        Ok(Self {
            publication: PublicationNarInfo { metadata, payload },
            signatures,
        })
    }

    fn verify_with(
        self,
        trusted_keys: &TrustedPublicKeys,
    ) -> Result<ValidatedNarInfo, PublishedNarInfoError> {
        if !trusted_keys.verifies(
            self.publication.metadata.claims().fingerprint().as_bytes(),
            &self.signatures,
        ) {
            return Err(PublishedNarInfoError::UntrustedSignature);
        }
        Ok(ValidatedNarInfo(self.publication))
    }
}

#[derive(Debug)]
pub struct ValidatedNarInfo(PublicationNarInfo);

/// Logical NAR claims proven by a configured trusted signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedNarInfoClaims(NarInfoClaims);

impl TrustedNarInfoClaims {
    pub fn claims(&self) -> &NarInfoClaims {
        &self.0
    }
}

impl NarRepresentation {
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
            WireEncoding::Raw => Self::validate_raw_payload(file_hash, file_size, identity),
            WireEncoding::Compressed(codec) => Ok(Self::compressed(
                EncodedIdentity::new(codec, file_hash, file_size),
                identity,
            )),
        }
    }

    fn validate_raw_payload(
        file_hash: FileHash,
        file_size: EncodedSize,
        identity: NarIdentity,
    ) -> Result<Self, NarInfoError> {
        (file_hash.matches_nar_hash(identity.hash()) && file_size.get() == identity.size().get())
            .then_some(Self::Raw(identity))
            .ok_or(NarInfoError)
    }
}

impl ValidatedNarInfo {
    pub fn claims(&self) -> &NarInfoClaims {
        self.0.metadata.claims()
    }

    pub(crate) const fn payload(&self) -> NarRepresentation {
        self.0.payload
    }
    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, NarInfoError> {
        self.0.metadata.serialize(self.0.payload)
    }

    pub(crate) fn bind_to_stored_nar(
        self,
        stored: VerifiedCanonicalNar<'_>,
        output: NarRepresentation,
    ) -> Result<BoundNarInfo<'_>, NarInfoError> {
        if self.0.payload.identity() != stored.identity() {
            return Err(NarInfoError);
        }
        Ok(BoundNarInfo {
            narinfo: self.0,
            stored,
            output,
        })
    }
}

/// Signed claims bound to an opened canonical payload and selected output.
/// Only this state can project metadata for serving; it retains the raw file
/// until publication.
pub(crate) struct BoundNarInfo<'storage> {
    narinfo: PublicationNarInfo,
    stored: VerifiedCanonicalNar<'storage>,
    output: NarRepresentation,
}

impl BoundNarInfo<'_> {
    pub(crate) fn stored(&self) -> &VerifiedCanonicalNar<'_> {
        &self.stored
    }

    pub(crate) fn store(&self) -> &StoreHash {
        self.narinfo.metadata.claims().store()
    }

    pub(crate) fn output_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = BoundedNarInfoWriter::new();
        self.narinfo.metadata.write(self.output, &mut output)?;
        Ok(output.into_bytes())
    }
}

struct BoundedNarInfoWriter {
    bytes: Vec<u8>,
}

impl BoundedNarInfoWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
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

fn parse_references(value: &str) -> Result<Vec<NixStorePath>, NarInfoError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut references = value
        .split(' ')
        .map(NixStorePath::from_basename)
        .collect::<Result<Vec<_>, _>>()?;
    references.sort_unstable_by(|left, right| left.value.cmp(&right.value));
    references.dedup_by(|left, right| left.value == right.value);
    Ok(references)
}

fn build_fingerprint(
    store_path: &str,
    nar_hash: &NarHash,
    nar_size: u64,
    references: impl IntoIterator<Item = impl AsRef<str>>,
) -> String {
    let mut fingerprint = format!("1;{store_path};sha256:{nar_hash};{nar_size};");
    for (index, reference) in references.into_iter().enumerate() {
        if index != 0 {
            fingerprint.push(',');
        }
        fingerprint.push_str("/nix/store/");
        fingerprint.push_str(reference.as_ref());
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

fn validate_store_basename(value: &str) -> Result<(StoreHash, &str), NarInfoError> {
    let (hash, name) = value.split_once('-').ok_or(NarInfoError)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
    {
        return Err(NarInfoError);
    }
    Ok((StoreHash::parse(hash).map_err(|_| NarInfoError)?, name))
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

    fn local_metadata(identity: NarIdentity) -> NarInfoMetadata {
        NarInfoMetadata::from_store_metadata(
            format!("/nix/store/{STORE_HASH}-package"),
            None,
            None,
            identity,
            Vec::new(),
            Vec::new(),
        )
        .expect("test store metadata should be valid")
    }

    #[test]
    fn local_metadata_rejects_unvalidated_protocol_fields_at_construction() {
        let identity = NarIdentity::new(
            NarHash::parse(NAR_HASH).expect("test NAR hash should parse"),
            NarSize::new(1),
        );
        let store_path = format!("/nix/store/{STORE_HASH}-package");

        assert!(
            NarInfoMetadata::from_store_metadata(
                store_path.clone(),
                Some("fixed:sha256:not-a-hash".to_owned()),
                None,
                identity,
                Vec::new(),
                Vec::new(),
            )
            .is_err(),
            "an invalid content address must not survive inside typed metadata"
        );
        assert!(
            NarInfoMetadata::from_store_metadata(
                store_path,
                None,
                Some("not-a-store-path".to_owned()),
                identity,
                Vec::new(),
                Vec::new(),
            )
            .is_err(),
            "an invalid deriver must not survive inside typed metadata"
        );
    }

    #[test]
    fn narinfo_serialization_requires_the_selected_representation_to_describe_its_claims() {
        let claimed = NarIdentity::new(
            NarHash::parse(NAR_HASH).expect("test NAR hash should parse"),
            NarSize::new(1),
        );
        let different_size = NarIdentity::new(claimed.hash(), NarSize::new(2));

        assert!(
            local_metadata(claimed)
                .serialize(NarRepresentation::Raw(different_size))
                .is_err(),
            "metadata must not advertise a representation of another logical NAR"
        );
    }

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
        assert!(UnverifiedPublicationNarInfo::parse(&route, bytes).is_err());
    }

    #[test]
    fn projected_narinfo_writer_rejects_output_over_the_read_limit() {
        let mut writer = BoundedNarInfoWriter::new();
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
        assert_eq!(
            references
                .iter()
                .map(NixStorePath::basename)
                .collect::<Vec<_>>(),
            [format!("{STORE_HASH}-package")]
        );
    }

    #[test]
    fn parser_keeps_compact_sorted_references() {
        let references = parse_references(&format!(
            "{STORE_HASH}-zulu {STORE_HASH}-alpha {STORE_HASH}-zulu"
        ))
        .expect("valid references");
        assert_eq!(
            references
                .iter()
                .map(NixStorePath::basename)
                .collect::<Vec<_>>(),
            [format!("{STORE_HASH}-alpha"), format!("{STORE_HASH}-zulu")]
        );
    }

    #[test]
    fn external_parser_ignores_unknown_fields_but_rejects_duplicate_known_fields() {
        let text = "StorePath: /nix/store/example\nX-Cache-Extension: stable\n";
        assert!(NarInfoDocument::parse(text).is_err());
        assert!(NarInfoDocument::parse_external(text).is_ok());

        let duplicate = "StorePath: /nix/store/first\nStorePath: /nix/store/second\n";
        assert!(NarInfoDocument::parse_external(duplicate).is_err());
    }

    #[test]
    fn external_transport_requires_an_authority_for_absolute_http_urls() {
        let without_authority =
            NarInfoDocument::parse_external("URL: https:path\nCompression: none\n")
                .expect("the URI syntax is valid");
        assert!(without_authority.validate_external_transport().is_err());

        let with_authority =
            NarInfoDocument::parse_external("URL: https://cache.example/path\nCompression: none\n")
                .expect("the URI syntax is valid");
        assert!(with_authority.validate_external_transport().is_ok());
    }

    #[test]
    fn external_claims_treat_missing_references_as_empty() {
        let route = StoreHash::parse(STORE_HASH).expect("valid store hash");
        let text = format!(
            "StorePath: /nix/store/{STORE_HASH}-package\nNarHash: sha256:{NAR_HASH}\nNarSize: 1\n"
        );
        let document = NarInfoDocument::parse_external(&text).expect("valid external metadata");

        assert!(NarInfoClaims::from_document(&route, &document).is_err());
        let claims = NarInfoClaims::from_external_document(&route, &document)
            .expect("missing references should mean an empty set");
        assert_eq!(claims.reference_paths().len(), 0);
    }

    #[test]
    fn parser_validates_store_basenames_borrowed() {
        let value = format!("{STORE_HASH}-package");
        let (hash, name) = validate_store_basename(&value).expect("valid store basename");
        assert_eq!(hash.as_str(), STORE_HASH);
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
                references.split_ascii_whitespace(),
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

        assert!(UnverifiedPublicationNarInfo::parse(&route, bytes).is_ok());
    }
}
