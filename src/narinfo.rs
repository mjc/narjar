use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};

use data_encoding::BASE64;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::storage::{
    NarObjectId, StoreHash, entry_is_regular_at, open_directory, open_regular, open_regular_at,
    read_dir_names,
};

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
    pub fn load(path: &Path) -> Result<Self, TrustError> {
        let mut file = match open_regular(path) {
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
        let narinfo =
            ParsedNarInfo::parse(route, bytes).map_err(|_| PublishedNarInfoError::Malformed)?;
        if !self.verifies(narinfo.fingerprint.as_bytes(), &narinfo.signatures) {
            return Err(PublishedNarInfoError::UntrustedSignature);
        }
        Ok(ValidatedNarInfo(narinfo))
    }

    pub(crate) fn validate(
        &self,
        route: &StoreHash,
        bytes: Vec<u8>,
    ) -> Result<ValidatedNarInfo, NarInfoError> {
        self.inspect(route, bytes).map_err(|_| NarInfoError)
    }

    pub fn validate_published(&self, root: &Path) -> Result<(), TrustError> {
        let root_directory = open_directory(root)?;
        for name in read_dir_names(&root_directory)? {
            let Some(route) = name.to_str().and_then(|name| name.strip_suffix(".narinfo")) else {
                continue;
            };
            let Ok(route) = StoreHash::parse(route) else {
                continue;
            };
            if !entry_is_regular_at(&root_directory, &name)? {
                return Err(TrustError::UntrustedPublishedNarInfo);
            }

            let bytes = read_narinfo_file(open_regular_at(&root_directory, &name)?)?;
            if self.validate(&route, bytes).is_err() {
                return Err(TrustError::UntrustedPublishedNarInfo);
            }
        }
        Ok(())
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
    store_path: String,
    references: BTreeSet<String>,
    nar: NarObjectId,
    nar_size: u64,
    fingerprint: String,
    signatures: Vec<NamedSignature>,
    bytes: Vec<u8>,
}

impl ParsedNarInfo {
    fn parse(route: &StoreHash, bytes: Vec<u8>) -> Result<Self, NarInfoError> {
        if bytes.len() as u64 > MAX_NARINFO_BYTES {
            return Err(NarInfoError);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| NarInfoError)?;
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

        if fields.get("Deriver").is_some_and(|deriver| {
            *deriver != "unknown-deriver" && parse_store_basename(deriver).is_err()
        }) {
            return Err(NarInfoError);
        }
        if let Some(ca) = fields.get("CA") {
            parse_content_address(ca)?;
        }

        let references = parse_references(required("References")?)?;
        let fingerprint = format!(
            "1;{store_path};sha256:{url_hash};{nar_size};{}",
            references
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",")
        );
        let signatures = signature_values
            .into_iter()
            .map(NamedSignature::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if signatures.is_empty() {
            return Err(NarInfoError);
        }

        Ok(Self {
            store_path: store_path.to_owned(),
            references,
            nar,
            nar_size,
            fingerprint,
            signatures,
            bytes,
        })
    }
}

#[derive(Debug)]
pub struct ValidatedNarInfo(ParsedNarInfo);

impl ValidatedNarInfo {
    pub(crate) fn store_path(&self) -> &str {
        &self.0.store_path
    }

    pub(crate) fn references(&self) -> &BTreeSet<String> {
        &self.0.references
    }

    pub(crate) fn nar(&self) -> &NarObjectId {
        &self.0.nar
    }

    pub(crate) const fn nar_size(&self) -> u64 {
        self.0.nar_size
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0.bytes
    }

    pub(crate) fn into_parts(self) -> (NarObjectId, u64, Vec<u8>) {
        let parsed = self.0;
        (parsed.nar, parsed.nar_size, parsed.bytes)
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
        references.insert(format!("/nix/store/{reference}"));
    }
    Ok(references)
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
    UntrustedPublishedNarInfo,
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
            Self::UntrustedPublishedNarInfo => {
                formatter.write_str("published narinfo is not trusted")
            }
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTrustFile => None,
            Self::UntrustedPublishedNarInfo => None,
            Self::Io(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_HASH: &str = "00000000000000000000000000000000";
    const NAR_HASH: &str = "0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl";

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
    fn parser_deduplicates_references() {
        let references = parse_references(&format!("{STORE_HASH}-package {STORE_HASH}-package"))
            .expect("duplicate references should be accepted");
        assert_eq!(references.len(), 1);
    }
}
