use std::{fmt, sync::OnceLock};

use data_encoding::{BitOrder, Encoding, Specification};

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const NIX32_SHA256_LEN: usize = 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidObjectId;

impl fmt::Display for InvalidObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Nix base-32 object identifier")
    }
}

impl std::error::Error for InvalidObjectId {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NarHash([u8; 32]);

impl NarHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        decode_sha256(value).map(Self)
    }

    pub(crate) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl fmt::Display for NarHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&encode_nix32(&self.0))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileHash([u8; 32]);

impl FileHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        decode_sha256(value).map(Self)
    }

    pub(crate) fn matches_digest(self, digest: &[u8]) -> bool {
        self.0.as_slice() == digest
    }

    pub(crate) fn matches_nar_hash(self, hash: NarHash) -> bool {
        self.0 == hash.0
    }
}

impl fmt::Display for FileHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&encode_nix32(&self.0))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NarSize(u64);

impl NarSize {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for NarSize {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for NarSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EncodedSize(u64);

impl EncodedSize {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for EncodedSize {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for EncodedSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NarIdentity {
    pub(crate) hash: NarHash,
    pub(crate) size: NarSize,
}

impl NarIdentity {
    pub(crate) const fn new(hash: NarHash, size: NarSize) -> Self {
        Self { hash, size }
    }

    pub(crate) const fn hash(self) -> NarHash {
        self.hash
    }

    pub(crate) const fn size(self) -> NarSize {
        self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WireEncoding {
    Raw,
    Zstd,
    Xz,
}

impl WireEncoding {
    pub(crate) const fn compression(self) -> &'static str {
        match self {
            Self::Raw => "none",
            Self::Zstd => "zstd",
            Self::Xz => "xz",
        }
    }

    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            Self::Raw => ".nar",
            Self::Zstd => ".nar.zst",
            Self::Xz => ".nar.xz",
        }
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], InvalidObjectId> {
    if value.len() != NIX32_SHA256_LEN {
        return Err(InvalidObjectId);
    }
    let mut encoded = value.as_bytes().to_vec();
    encoded.reverse();
    nix32_encoding()
        .decode(&encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(InvalidObjectId)
}

fn encode_nix32(bytes: &[u8]) -> String {
    let encoding = nix32_encoding();
    let mut output = vec![0; encoding.encode_len(bytes.len())];
    encoding.encode_mut(bytes, &mut output);
    output.reverse();
    String::from_utf8(output).expect("Nix base32 encoding is ASCII")
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
