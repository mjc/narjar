use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    io::{self, Read},
    os::unix::fs::MetadataExt,
};

use data_encoding::BASE64;
use ed25519_dalek::VerifyingKey;

use crate::storage::{Directory, StoreHash, open_regular_at};

use super::{
    NamedSignature, NarInfoClaims, NarInfoDocument, NarInfoError, PublishedNarInfoError,
    TrustedNarInfoClaims, UnverifiedPublicationNarInfo, ValidatedNarInfo, parse_narinfo_text,
    valid_name,
};

const MAX_TRUST_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default)]
pub struct TrustedPublicKeys(BTreeMap<String, VerifyingKey>);

impl TrustedPublicKeys {
    pub fn parse(contents: &str) -> Result<Self, TrustError> {
        if contents.len() as u64 > MAX_TRUST_FILE_BYTES {
            return Err(TrustError::InvalidTrustFile);
        }

        contents
            .split_ascii_whitespace()
            .try_fold(BTreeMap::new(), |mut keys, entry| {
                let (name, encoded) = entry
                    .split_once(':')
                    .filter(|(name, encoded)| valid_name(name) && !encoded.is_empty())
                    .ok_or(TrustError::InvalidTrustFile)?;
                let bytes: [u8; 32] = BASE64
                    .decode(encoded.as_bytes())
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(TrustError::InvalidTrustFile)?;
                let key =
                    VerifyingKey::from_bytes(&bytes).map_err(|_| TrustError::InvalidTrustFile)?;
                if key.is_weak() || keys.insert(name.to_owned(), key).is_some() {
                    return Err(TrustError::InvalidTrustFile);
                }
                Ok(keys)
            })
            .map(Self)
    }

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
        Self::parse(&contents)
    }

    pub(crate) fn inspect(
        &self,
        route: &StoreHash,
        bytes: Vec<u8>,
    ) -> Result<ValidatedNarInfo, PublishedNarInfoError> {
        let narinfo = UnverifiedPublicationNarInfo::parse(route, bytes)
            .map_err(|_| PublishedNarInfoError::Malformed)?;
        narinfo.verify_with(self)
    }

    pub fn validate(
        &self,
        route: &StoreHash,
        bytes: Vec<u8>,
    ) -> Result<ValidatedNarInfo, NarInfoError> {
        self.inspect(route, bytes).map_err(|_| NarInfoError)
    }

    pub fn verify_external_narinfo(
        &self,
        route: &StoreHash,
        bytes: Vec<u8>,
    ) -> Result<TrustedNarInfoClaims, NarInfoError> {
        let text = parse_narinfo_text(bytes)?;
        let document = NarInfoDocument::parse_external(&text)?;
        document.validate_external_transport()?;
        let claims = NarInfoClaims::from_document(route, &document)?;
        let signatures = document.named_signatures()?;
        self.verifies(claims.fingerprint().as_bytes(), &signatures)
            .then_some(TrustedNarInfoClaims(claims))
            .ok_or(NarInfoError)
    }

    pub(super) fn verifies(&self, fingerprint: &[u8], signatures: &[NamedSignature]) -> bool {
        signatures.iter().any(|signature| {
            self.0
                .get(signature.name.as_str())
                .is_some_and(|key| key.verify_strict(fingerprint, &signature.signature).is_ok())
        })
    }
}

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
