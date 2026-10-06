//! Typed identities and representation descriptors used by the NAR API.
//!
//! Logical NAR hashes and encoded-file hashes have distinct marker types, as do
//! their byte counts. This prevents accidentally comparing or substituting
//! identities for different byte streams.

#[cfg(feature = "application")]
use std::ffi::OsString;
use std::{fmt, marker::PhantomData, str::FromStr, sync::OnceLock};

use data_encoding::{BitOrder, Encoding, Specification};
use serde::{Deserialize, Serialize};

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const NIX32_SHA256_LEN: usize = 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// A string is not a canonical Nix base-32 SHA-256 identifier.
#[error("invalid Nix base-32 object identifier")]
pub struct InvalidObjectId;

/// Purpose tag for values describing the decoded NAR byte stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LogicalNar {}

/// Purpose tag for values describing an encoded payload file.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EncodedFile {}

/// A SHA-256 digest whose purpose remains part of its compile-time type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
/// A SHA-256 digest tagged with the kind of bytes it identifies.
///
/// Its textual form is canonical Nix base-32, not hexadecimal or standard
/// RFC 4648 base-32. Construct from digest bytes or parse that textual form.
pub struct Sha256Digest<Purpose>([u8; 32], #[serde(skip)] PhantomData<fn() -> Purpose>);

/// SHA-256 identity of the decoded NAR byte stream.
pub type NarHash = Sha256Digest<LogicalNar>;

/// SHA-256 identity of an encoded payload file.
pub type FileHash = Sha256Digest<EncodedFile>;

impl<Purpose> Sha256Digest<Purpose> {
    /// Parses a canonical 52-character Nix base-32 SHA-256 digest.
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        decode_sha256(value).map(Self::from_digest)
    }

    /// Creates a typed digest from its 32 raw SHA-256 bytes.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest, PhantomData)
    }

    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl<Purpose> fmt::Display for Sha256Digest<Purpose> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = encode_nix32(&self.0);
        formatter.write_str(std::str::from_utf8(&encoded).expect("Nix base32 encoding is ASCII"))
    }
}

impl Sha256Digest<EncodedFile> {
    #[cfg(feature = "application")]
    pub(crate) fn matches_nar_hash(self, hash: NarHash) -> bool {
        self.bytes() == hash.bytes()
    }

    /// Re-tags a digest after establishing that raw file bytes match a NAR hash.
    pub const fn from_nar_hash(hash: NarHash) -> Self {
        Self::from_digest(hash.bytes())
    }

    /// Re-tags this digest as a NAR hash without decoding or verifying bytes.
    ///
    /// Use this only when the hashed file bytes are the uncompressed NAR
    /// itself. For an XZ- or Zstandard-compressed file, this returns the hash
    /// of the compressed bytes, not the decoded NAR hash.
    pub const fn as_nar_hash(self) -> NarHash {
        NarHash::from_digest(self.bytes())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
/// Identity of one compressed NAR representation.
pub struct EncodedIdentity {
    codec: CompressionCodec,
    content: ContentIdentity<EncodedFile>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
/// A compressed representation bound to its decoded logical NAR.
pub struct CompressedNarIdentity {
    encoded: EncodedIdentity,
    decoded: NarIdentity,
}

impl CompressedNarIdentity {
    /// Binds compressed-file identity to the decoded logical NAR identity.
    pub const fn new(encoded: EncodedIdentity, decoded: NarIdentity) -> Self {
        Self { encoded, decoded }
    }

    /// Returns the compressed file's codec, hash, and encoded size.
    pub const fn encoded(self) -> EncodedIdentity {
        self.encoded
    }

    /// Returns the decoded NAR's logical hash and size.
    pub const fn decoded(self) -> NarIdentity {
        self.decoded
    }
}

impl EncodedIdentity {
    /// Describes one compressed representation and its measured file identity.
    pub const fn new(codec: CompressionCodec, hash: FileHash, size: EncodedSize) -> Self {
        Self {
            codec,
            content: ContentIdentity::new(hash, size),
        }
    }

    /// Returns the compression codec used for this file.
    pub const fn codec(self) -> CompressionCodec {
        self.codec
    }

    /// Returns the SHA-256 hash of the encoded file bytes.
    pub const fn hash(self) -> FileHash {
        self.content.hash()
    }

    /// Returns the encoded file length in bytes.
    pub const fn size(self) -> EncodedSize {
        self.content.size()
    }

    /// Returns the immutable cache filename for this compressed file.
    pub const fn file_name(self) -> NarFileName {
        NarFileName::new(self.hash(), WireEncoding::Compressed(self.codec))
    }
}

/// A byte count whose represented content remains part of its compile-time type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
/// A byte count tagged with the kind of content it measures.
pub struct ByteCount<Purpose>(u64, #[serde(skip)] PhantomData<fn() -> Purpose>);

impl<Purpose> ByteCount<Purpose> {
    /// Creates a count of bytes for the selected content purpose.
    pub const fn new(value: u64) -> Self {
        Self(value, PhantomData)
    }

    /// Returns the byte count as an unsigned integer.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<Purpose> From<u64> for ByteCount<Purpose> {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl<Purpose> fmt::Display for ByteCount<Purpose> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Size of the decoded NAR byte stream.
pub type NarSize = ByteCount<LogicalNar>;

/// Size of an encoded payload file.
pub type EncodedSize = ByteCount<EncodedFile>;

/// A hash and byte count that necessarily describe the same kind of content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(bound(serialize = "", deserialize = ""))]
/// A hash and size that identify the same kind of content.
pub struct ContentIdentity<Purpose> {
    hash: Sha256Digest<Purpose>,
    size: ByteCount<Purpose>,
}

impl<Purpose> ContentIdentity<Purpose> {
    /// Combines a purpose-tagged digest and byte count.
    pub const fn new(hash: Sha256Digest<Purpose>, size: ByteCount<Purpose>) -> Self {
        Self { hash, size }
    }

    /// Returns the digest of this content.
    pub const fn hash(self) -> Sha256Digest<Purpose> {
        self.hash
    }

    /// Returns the byte count of this content.
    pub const fn size(self) -> ByteCount<Purpose> {
        self.size
    }
}

/// Hash and size of the decoded NAR byte stream.
pub type NarIdentity = ContentIdentity<LogicalNar>;

/// The immutable filename and wire representation of a NAR payload.
///
/// A raw filename still begins as a `FileHash` at the HTTP boundary. Its
/// equality with the logical `NarHash` is established while validating the
/// upload or narinfo, rather than assumed from its suffix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NarFileName {
    file_hash: FileHash,
    encoding: WireEncoding,
}

impl NarFileName {
    /// Creates a payload filename identity from its hash and wire encoding.
    pub const fn new(file_hash: FileHash, encoding: WireEncoding) -> Self {
        Self {
            file_hash,
            encoding,
        }
    }

    /// Parses a canonical Nix base-32 hash followed by `.nar`, `.nar.xz`, or
    /// `.nar.zst`.
    pub fn parse(name: &str) -> Result<Self, InvalidObjectId> {
        [
            WireEncoding::Compressed(CompressionCodec::Zstd),
            WireEncoding::Compressed(CompressionCodec::Xz),
            WireEncoding::Raw,
        ]
        .into_iter()
        .find_map(|encoding| {
            name.strip_suffix(encoding.suffix())
                .map(|hash| FileHash::parse(hash).map(|file_hash| Self::new(file_hash, encoding)))
        })
        .ok_or(InvalidObjectId)?
    }

    /// Constructs the raw `.nar` filename for a logical NAR hash.
    pub const fn raw(hash: NarHash) -> Self {
        Self::new(FileHash::from_nar_hash(hash), WireEncoding::Raw)
    }

    /// Returns the encoded-file hash used in this pathname.
    pub const fn file_hash(self) -> FileHash {
        self.file_hash
    }

    /// Returns the raw, XZ, or Zstandard encoding selected by this pathname.
    pub const fn encoding(self) -> WireEncoding {
        self.encoding
    }

    #[cfg(feature = "application")]
    pub(crate) const fn raw_hash(self) -> Option<NarHash> {
        match self.encoding {
            WireEncoding::Raw => Some(self.file_hash.as_nar_hash()),
            WireEncoding::Compressed(_) => None,
        }
    }

    #[cfg(feature = "application")]
    pub(crate) fn os_string(self) -> OsString {
        OsString::from(self.to_string())
    }
}

impl fmt::Display for NarFileName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}{}", self.file_hash, self.encoding.suffix())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// Encoding named by a payload filename or narinfo transport fields.
pub enum WireEncoding {
    /// Uncompressed NAR bytes.
    Raw,
    /// Compressed NAR bytes using the selected codec.
    Compressed(CompressionCodec),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// A compression name is not one of the supported wire encodings.
#[error("expected one of: none, zstd, xz")]
pub struct InvalidWireEncoding;

impl FromStr for WireEncoding {
    type Err = InvalidWireEncoding;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "none" => Ok(Self::Raw),
            "zstd" => Ok(Self::Compressed(CompressionCodec::Zstd)),
            "xz" => Ok(Self::Compressed(CompressionCodec::Xz)),
            _ => Err(InvalidWireEncoding),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
/// A supported NAR compression codec.
pub enum CompressionCodec {
    /// Zstandard compression.
    Zstd,
    /// XZ/LZMA2 compression.
    Xz,
}

impl CompressionCodec {
    /// Returns the NAR payload filename suffix for this codec.
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Zstd => ".nar.zst",
            Self::Xz => ".nar.xz",
        }
    }
}

impl From<CompressionCodec> for WireEncoding {
    fn from(codec: CompressionCodec) -> Self {
        Self::Compressed(codec)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// The exact payload representation described by a narinfo document.
pub enum NarRepresentation {
    /// An uncompressed payload with its logical NAR identity.
    Raw(NarIdentity),
    /// A compressed file identity bound to the logical NAR it decodes to.
    Compressed(CompressedNarIdentity),
}

impl NarRepresentation {
    /// Creates a compressed representation from its encoded and decoded facts.
    pub const fn compressed(encoded: EncodedIdentity, decoded: NarIdentity) -> Self {
        Self::Compressed(CompressedNarIdentity::new(encoded, decoded))
    }

    /// Returns the decoded logical NAR identity.
    pub const fn identity(self) -> NarIdentity {
        match self {
            Self::Raw(identity) => identity,
            Self::Compressed(identity) => identity.decoded(),
        }
    }

    /// Returns the immutable filename for the exact payload representation.
    pub const fn file_name(self) -> NarFileName {
        match self {
            Self::Raw(identity) => NarFileName::raw(identity.hash()),
            Self::Compressed(identity) => identity.encoded().file_name(),
        }
    }

    /// Returns the exact byte length of the served or uploaded representation.
    pub const fn encoded_size(self) -> EncodedSize {
        match self {
            Self::Raw(identity) => EncodedSize::new(identity.size().get()),
            Self::Compressed(identity) => identity.encoded().size(),
        }
    }
}

impl WireEncoding {
    /// Returns the Nix narinfo `Compression` field value.
    pub const fn compression(self) -> &'static str {
        match self {
            Self::Raw => "none",
            Self::Compressed(CompressionCodec::Zstd) => "zstd",
            Self::Compressed(CompressionCodec::Xz) => "xz",
        }
    }

    /// Returns the payload filename suffix for this wire encoding.
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Raw => ".nar",
            Self::Compressed(codec) => codec.suffix(),
        }
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], InvalidObjectId> {
    if value.len() != NIX32_SHA256_LEN {
        return Err(InvalidObjectId);
    }

    let mut encoded = [0; NIX32_SHA256_LEN];
    encoded.copy_from_slice(value.as_bytes());
    encoded.reverse();

    let mut digest = [0; 32];
    let decoded_length = nix32_encoding()
        .decode_mut(&encoded, &mut digest)
        .map_err(|_| InvalidObjectId)?;
    if decoded_length != digest.len() {
        return Err(InvalidObjectId);
    }
    Ok(digest)
}

fn encode_nix32(digest: &[u8; 32]) -> [u8; NIX32_SHA256_LEN] {
    let mut output = [0; NIX32_SHA256_LEN];
    nix32_encoding().encode_mut(digest, &mut output);
    output.reverse();
    output
}

fn nix32_encoding() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut specification = Specification::new();
        specification.symbols.push_str(NIX32);
        specification.bit_order = BitOrder::LeastSignificantFirst;
        specification
            .encoding()
            .expect("Nix base32 specification is valid")
    })
}

#[cfg(test)]
mod tests {
    use super::{FileHash, NarHash};

    const SHA256_NIX32_WIDTH: usize = 52;

    #[test]
    fn sha256_nix32_round_trips_zero_and_high_bit_boundary_hashes() {
        let zero_hash = "0".repeat(SHA256_NIX32_WIDTH);
        assert_digest_round_trip(&zero_hash, [0; 32]);

        let highest_canonical_leading_symbol = format!("1{}", "0".repeat(51));
        let decoded = super::decode_sha256(&highest_canonical_leading_symbol)
            .expect("the highest canonical first symbol has no unused high bits");
        assert_digest_round_trip(&highest_canonical_leading_symbol, decoded);
    }

    #[test]
    fn sha256_nix32_rejects_unused_high_bits_and_wrong_widths() {
        let noncanonical_high_bits = format!("2{}", "0".repeat(51));
        assert!(NarHash::parse(&noncanonical_high_bits).is_err());

        let zero_hash = "0".repeat(SHA256_NIX32_WIDTH);
        assert!(NarHash::parse(&zero_hash[..SHA256_NIX32_WIDTH - 1]).is_err());
        assert!(NarHash::parse(&format!("{zero_hash}0")).is_err());
    }

    #[test]
    fn sha256_nix32_rejects_symbols_outside_the_nix_alphabet() {
        let invalid_symbol = format!("e{}", "0".repeat(51));
        assert!(FileHash::parse(&invalid_symbol).is_err());
    }

    fn assert_digest_round_trip(encoded: &str, expected: [u8; 32]) {
        let nar_hash = NarHash::parse(encoded).expect("canonical NAR hash");
        let file_hash = FileHash::parse(encoded).expect("canonical file hash");

        assert_eq!(nar_hash.bytes(), expected);
        assert_eq!(file_hash.bytes(), expected);
        assert_eq!(nar_hash.to_string(), encoded);
        assert_eq!(file_hash.to_string(), encoded);
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (&InvalidObjectId, "invalid Nix base-32 object identifier"),
            (&InvalidWireEncoding, "expected one of: none, zstd, xz"),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }
}
