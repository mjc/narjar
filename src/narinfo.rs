use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};

use data_encoding::BASE64;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::storage::{NarObjectId, StoreHash};

const MAX_TRUST_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct TrustedPublicKey {
    name: String,
    key: VerifyingKey,
}

#[derive(Debug, Default)]
pub struct TrustedPublicKeys(Vec<TrustedPublicKey>);

impl TrustedPublicKeys {
    pub fn load(path: &Path) -> Result<Self, TrustError> {
        let mut file = match File::open(path) {
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

        let mut names = BTreeSet::new();
        let mut keys = Vec::new();
        for entry in contents.split_ascii_whitespace() {
            let (name, encoded) = entry
                .split_once(':')
                .filter(|(name, encoded)| valid_name(name) && !encoded.is_empty())
                .ok_or(TrustError::InvalidTrustFile)?;
            if !names.insert(name.to_owned()) {
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
            keys.push(TrustedPublicKey {
                name: name.to_owned(),
                key,
            });
        }
        Ok(Self(keys))
    }

    fn verifies(&self, fingerprint: &[u8], signatures: &[NamedSignature]) -> bool {
        signatures.iter().any(|signature| {
            self.0.iter().any(|trusted| {
                trusted.name == signature.name
                    && trusted
                        .key
                        .verify_strict(fingerprint, &signature.signature)
                        .is_ok()
            })
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
pub struct ParsedNarInfo {
    nar: NarObjectId,
    nar_size: u64,
    fingerprint: String,
    signatures: Vec<NamedSignature>,
}

impl ParsedNarInfo {
    pub fn parse(route: &StoreHash, bytes: &[u8]) -> Result<Self, NarInfoError> {
        let text = std::str::from_utf8(bytes).map_err(|_| NarInfoError)?;
        if !text.ends_with('\n') || text.contains('\r') {
            return Err(NarInfoError);
        }

        let mut fields = BTreeMap::new();
        let mut signature_values = Vec::new();
        for line in text.strip_suffix('\n').ok_or(NarInfoError)?.split('\n') {
            let (name, value) = line.split_once(": ").ok_or(NarInfoError)?;
            match name {
                "Sig" => signature_values.push(value),
                "StorePath" | "URL" | "Compression" | "FileHash" | "FileSize" | "NarHash"
                | "NarSize" | "References" | "Deriver" | "CA" => {
                    if fields.insert(name, value).is_some() {
                        return Err(NarInfoError);
                    }
                }
                _ => return Err(NarInfoError),
            }
        }

        let required = |name| fields.get(name).copied().ok_or(NarInfoError);
        let store_path = required("StorePath")?;
        let store_basename = store_path.strip_prefix("/nix/store/").ok_or(NarInfoError)?;
        let (store_hash, _) = parse_store_basename(store_basename)?;
        if &store_hash != route {
            return Err(NarInfoError);
        }

        let url = required("URL")?;
        let url_hash = url
            .strip_prefix("nar/")
            .and_then(|value| value.strip_suffix(".nar"))
            .ok_or(NarInfoError)?;
        let nar = NarObjectId::parse(url_hash).map_err(|_| NarInfoError)?;
        if required("Compression")? != "none"
            || required("FileHash")? != format!("sha256:{url_hash}")
            || required("NarHash")? != format!("sha256:{url_hash}")
        {
            return Err(NarInfoError);
        }

        let file_size = required("FileSize")?
            .parse::<u64>()
            .map_err(|_| NarInfoError)?;
        let nar_size = required("NarSize")?
            .parse::<u64>()
            .map_err(|_| NarInfoError)?;
        if nar_size == 0 || file_size != nar_size {
            return Err(NarInfoError);
        }

        for optional in ["Deriver", "CA"] {
            if fields
                .get(optional)
                .is_some_and(|value| value.is_empty() || !value.is_ascii())
            {
                return Err(NarInfoError);
            }
        }

        let references = parse_references(required("References")?)?;
        let fingerprint = format!(
            "1;{store_path};sha256:{url_hash};{nar_size};{}",
            references.into_iter().collect::<Vec<_>>().join(",")
        );
        let signatures = signature_values
            .into_iter()
            .map(NamedSignature::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if signatures.is_empty() {
            return Err(NarInfoError);
        }

        Ok(Self {
            nar,
            nar_size,
            fingerprint,
            signatures,
        })
    }

    pub fn verify(self, trusted: &TrustedPublicKeys) -> Result<ValidatedNarInfo, NarInfoError> {
        if !trusted.verifies(self.fingerprint.as_bytes(), &self.signatures) {
            return Err(NarInfoError);
        }
        Ok(ValidatedNarInfo(self))
    }

    pub fn nar(&self) -> &NarObjectId {
        &self.nar
    }

    pub const fn nar_size(&self) -> u64 {
        self.nar_size
    }
}

#[derive(Debug)]
pub struct ValidatedNarInfo(ParsedNarInfo);

impl ValidatedNarInfo {
    pub fn nar(&self) -> &NarObjectId {
        self.0.nar()
    }

    pub const fn nar_size(&self) -> u64 {
        self.0.nar_size()
    }
}

fn parse_references(value: &str) -> Result<BTreeSet<String>, NarInfoError> {
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }

    let mut references = BTreeSet::new();
    for reference in value.split(' ') {
        if reference.is_empty() {
            return Err(NarInfoError);
        }
        parse_store_basename(reference)?;
        if !references.insert(format!("/nix/store/{reference}")) {
            return Err(NarInfoError);
        }
    }
    Ok(references)
}

fn parse_store_basename(value: &str) -> Result<(StoreHash, &str), NarInfoError> {
    let (hash, name) = value.split_once('-').ok_or(NarInfoError)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
    {
        return Err(NarInfoError);
    }
    let hash = StoreHash::parse(hash).map_err(|_| NarInfoError)?;
    Ok((hash, name))
}

#[derive(Clone, Copy, Debug)]
pub struct NarInfoError;

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
