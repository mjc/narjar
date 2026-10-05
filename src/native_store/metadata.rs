use std::{num::NonZeroU64, path::Path};

use narjar::{
    __private::narinfo::{NarInfoMetadata, TrustedPublicKeys},
    object::{NarHash, NarIdentity, NarRepresentation, NarSize},
};
use sqlite::{ConnectionThreadSafe, State};

use super::open_supported_metadata_database;
use crate::narinfo_signing::NixSigningKey;

pub(crate) struct NativeMetadataSnapshot {
    database: ConnectionThreadSafe,
}

impl NativeMetadataSnapshot {
    pub(crate) fn open(state_dir: &Path) -> Result<Self, NativeMetadataError> {
        let database = open_supported_metadata_database(state_dir)
            .map_err(|error| NativeMetadataError::Database(error.to_string()))?;
        Ok(Self { database })
    }

    pub(crate) fn validated_claims_for(
        &self,
        path: &str,
    ) -> Result<ValidatedNativeClaims, NativeMetadataError> {
        let row = read_path_row(&self.database, path)?;
        let references = read_references(&self.database, row.id)?;
        let identity = row.nar_identity()?;
        let metadata = NarInfoMetadata::from_store_metadata(
            path.to_owned(),
            row.content_address,
            row.deriver,
            identity,
            references,
            row.signatures,
        )
        .map_err(|error| NativeMetadataError::InvalidMetadata(error.to_string()))?;
        Ok(ValidatedNativeClaims { metadata })
    }
}

pub(crate) struct ValidatedNativeClaims {
    metadata: NarInfoMetadata,
}

impl ValidatedNativeClaims {
    pub(crate) fn claims(&self) -> &narjar::__private::narinfo::NarInfoClaims {
        self.metadata.claims()
    }

    pub(crate) fn into_narinfo_metadata(self) -> NarInfoMetadata {
        self.metadata
    }

    pub(crate) fn sign_for_trusted_cache(
        mut self,
        trusted_keys: &TrustedPublicKeys,
        signing_key: Option<&NixSigningKey>,
    ) -> Result<SignedNativeNarInfo, MissingTrustedSignature> {
        let fingerprint = self.metadata.claims().fingerprint();
        let reusable_signature = self
            .metadata
            .signatures()
            .iter()
            .find(|signature| trusted_keys.verifies_signature(fingerprint.as_bytes(), signature))
            .cloned();
        let signature = reusable_signature
            .or_else(|| {
                compatible_signature_from_signing_key(signing_key, trusted_keys, &fingerprint)
            })
            .ok_or(MissingTrustedSignature)?;
        self.metadata.replace_signatures(vec![signature]);
        Ok(SignedNativeNarInfo {
            metadata: self.metadata,
        })
    }
}

fn compatible_signature_from_signing_key(
    signing_key: Option<&NixSigningKey>,
    trusted_keys: &TrustedPublicKeys,
    fingerprint: &str,
) -> Option<String> {
    let signing_key = signing_key?;
    let signature = signing_key.sign_fingerprint(fingerprint);
    match trusted_keys.verifies_signature(fingerprint.as_bytes(), &signature) {
        true => Some(signature),
        false => None,
    }
}

pub(crate) struct SignedNativeNarInfo {
    metadata: NarInfoMetadata,
}

impl SignedNativeNarInfo {
    pub(crate) fn serialize_raw(self) -> Result<Vec<u8>, narjar::__private::narinfo::NarInfoError> {
        self.metadata
            .serialize(NarRepresentation::Raw(self.metadata.claims().identity()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("no trusted signature is available for native store metadata")]
pub(crate) struct MissingTrustedSignature;

struct NativePathRow {
    id: i64,
    hash: String,
    nar_size: i64,
    deriver: Option<String>,
    signatures: Vec<String>,
    content_address: Option<String>,
}

impl NativePathRow {
    fn nar_identity(&self) -> Result<NarIdentity, NativeMetadataError> {
        let size = u64::try_from(self.nar_size)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                NativeMetadataError::InvalidMetadata("NAR size is not positive".into())
            })?;
        Ok(NarIdentity::new(
            parse_nix_base16_nar_hash(&self.hash)?,
            NarSize::new(size.get()),
        ))
    }
}

fn read_path_row(
    database: &ConnectionThreadSafe,
    path: &str,
) -> Result<NativePathRow, NativeMetadataError> {
    let mut statement = database
        .prepare(
            "SELECT id, hash, narSize, deriver, sigs, ca \
             FROM ValidPaths WHERE path = ?",
        )
        .map_err(database_error("preparing Nix path lookup"))?;
    statement
        .bind((1, path))
        .map_err(database_error("binding Nix path lookup"))?;
    match statement
        .next()
        .map_err(database_error("reading Nix path lookup"))?
    {
        State::Row => read_native_path_row(&mut statement),
        State::Done => Err(NativeMetadataError::MissingStorePath(path.to_owned())),
    }
}

fn read_native_path_row(
    statement: &mut sqlite::Statement<'_>,
) -> Result<NativePathRow, NativeMetadataError> {
    let id = statement
        .read::<i64, _>("id")
        .map_err(database_error("reading Nix path id"))?;
    let hash = statement
        .read::<String, _>("hash")
        .map_err(database_error("reading Nix path hash"))?;
    let nar_size = statement
        .read::<i64, _>("narSize")
        .map_err(database_error("reading Nix path size"))?;
    let deriver = statement
        .read::<Option<String>, _>("deriver")
        .map_err(database_error("reading Nix path deriver"))?;
    let signatures = statement
        .read::<Option<String>, _>("sigs")
        .map_err(database_error("reading Nix path signatures"))?
        .map(|value| value.split_ascii_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let content_address = statement
        .read::<Option<String>, _>("ca")
        .map_err(database_error("reading Nix path content address"))?;
    Ok(NativePathRow {
        id,
        hash,
        nar_size,
        deriver,
        signatures,
        content_address,
    })
}

fn read_references(
    database: &ConnectionThreadSafe,
    id: i64,
) -> Result<Vec<String>, NativeMetadataError> {
    let mut statement = database
        .prepare(
            "SELECT reference.path FROM Refs \
             LEFT JOIN ValidPaths AS reference ON reference.id = Refs.reference \
             WHERE Refs.referrer = ? ORDER BY reference.path",
        )
        .map_err(database_error("preparing Nix references lookup"))?;
    statement
        .bind((1, id))
        .map_err(database_error("binding Nix references lookup"))?;
    std::iter::from_fn(|| read_next_reference(&mut statement)).collect::<Result<Vec<_>, _>>()
}

fn read_next_reference(
    statement: &mut sqlite::Statement<'_>,
) -> Option<Result<String, NativeMetadataError>> {
    match statement.next() {
        Ok(State::Row) => Some(match statement.read::<Option<String>, _>(0) {
            Ok(Some(path)) => Ok(path),
            Ok(None) => Err(NativeMetadataError::InvalidMetadata(
                "Nix store reference points to a missing path".to_owned(),
            )),
            Err(error) => Err(database_error("reading Nix reference")(error)),
        }),
        Ok(State::Done) => None,
        Err(error) => Some(Err(NativeMetadataError::Database(format!(
            "reading Nix references: {error}"
        )))),
    }
}

fn parse_nix_base16_nar_hash(value: &str) -> Result<NarHash, NativeMetadataError> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        NativeMetadataError::InvalidMetadata(format!("unsupported Nix path hash: {value}"))
    })?;
    if hex.len() != 64 {
        return Err(NativeMetadataError::InvalidMetadata(
            "Nix SHA-256 digest must contain 32 bytes".into(),
        ));
    }
    let mut digest = [0; 32];
    data_encoding::HEXLOWER_PERMISSIVE
        .decode_mut(hex.as_bytes(), &mut digest)
        .map_err(|_| {
            NativeMetadataError::InvalidMetadata(
                "Nix SHA-256 digest contains non-hexadecimal bytes".into(),
            )
        })?;
    Ok(NarHash::from_digest(digest))
}

fn database_error(context: &'static str) -> impl FnOnce(sqlite::Error) -> NativeMetadataError {
    move |error| NativeMetadataError::Database(format!("{context}: {error}"))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeMetadataError {
    #[error("{0}")]
    Database(String),
    #[error("{0}")]
    InvalidMetadata(String),
    #[error("store path is not valid: {0}")]
    MissingStorePath(String),
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64;
    use ed25519_dalek::{Signer, SigningKey};
    use narjar::{
        __private::narinfo::{NarInfoMetadata, TrustedPublicKeys},
        object::{NarHash, NarIdentity, NarSize},
    };
    use std::io::Write;
    use tempfile::NamedTempFile;

    use super::{MissingTrustedSignature, ValidatedNativeClaims, parse_nix_base16_nar_hash};

    const STORE_PATH: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package";
    const NAR_HASH: &str = "01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai";

    fn fixture_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn fixture_trust_store(signing_key: &SigningKey) -> TrustedPublicKeys {
        TrustedPublicKeys::parse(&format!(
            "narjar-test:{}",
            BASE64.encode(signing_key.verifying_key().as_bytes())
        ))
        .expect("fixture trusted key should parse")
    }

    fn fixture_signer(signing_key: &SigningKey) -> crate::narinfo_signing::NixSigningKey {
        let mut key_file = NamedTempFile::new().expect("signing key fixture should be created");
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(signing_key.as_bytes());
        bytes[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        writeln!(key_file, "narjar-test:{}", BASE64.encode(&bytes))
            .expect("signing key fixture should be written");
        crate::narinfo_signing::NixSigningKey::read(key_file.path())
            .expect("fixture signing key should parse")
    }

    fn fixture_metadata(signing_key: &SigningKey) -> ValidatedNativeClaims {
        let identity = NarIdentity::new(
            NarHash::parse(NAR_HASH).expect("fixture NAR hash should parse"),
            NarSize::new(289_656),
        );
        let unsigned = NarInfoMetadata::from_store_metadata(
            STORE_PATH.to_owned(),
            None,
            None,
            identity,
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture metadata should parse");
        let fingerprint = unsigned.claims().fingerprint();
        let signature = format!(
            "narjar-test:{}",
            BASE64.encode(&signing_key.sign(fingerprint.as_bytes()).to_bytes())
        );
        ValidatedNativeClaims {
            metadata: NarInfoMetadata::from_store_metadata(
                STORE_PATH.to_owned(),
                None,
                None,
                identity,
                Vec::new(),
                vec![signature],
            )
            .expect("signed fixture metadata should parse"),
        }
    }

    #[test]
    fn converts_nix_store_hash_to_binary_identity() {
        assert_eq!(
            parse_nix_base16_nar_hash(
                "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
            .expect("valid base16 SHA-256"),
            NarHash::from_digest([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ])
        );
    }

    #[test]
    fn rejects_non_hex_bytes_without_slicing_utf8() {
        let value = format!("sha256:0é{}", "0".repeat(61));
        assert!(parse_nix_base16_nar_hash(&value).is_err());
    }

    #[test]
    fn rejects_non_sha256_and_wrong_length_nix_hash_fields() {
        assert!(parse_nix_base16_nar_hash(&format!("sha512:{}", "0".repeat(64))).is_err());
        assert!(parse_nix_base16_nar_hash("sha256:00").is_err());
    }

    #[test]
    fn reuses_a_trusted_recorded_signature_and_projects_raw_transport_fields() {
        let signing_key = fixture_signing_key();
        let trusted_keys = fixture_trust_store(&signing_key);
        let bytes = fixture_metadata(&signing_key)
            .sign_for_trusted_cache(&trusted_keys, None)
            .expect("trusted recorded signature should be reusable")
            .serialize_raw()
            .expect("raw narinfo projection should serialize");
        let text = std::str::from_utf8(&bytes).expect("narinfo should be UTF-8");

        assert!(text.contains(&format!("URL: nar/{NAR_HASH}.nar\n")));
        assert!(text.contains(&format!("FileHash: sha256:{NAR_HASH}\n")));
        assert!(text.contains("Compression: none\n"));
        assert!(text.contains("FileSize: 289656\n"));
        trusted_keys
            .validate(
                &narjar::__private::storage::StoreHash::parse("0123456789abcdfghijklmnpqrsvwxyz")
                    .expect("fixture route hash should parse"),
                bytes,
            )
            .expect("projected narinfo signature should verify");
    }

    #[test]
    fn replaces_untrusted_recorded_signatures_only_with_a_trusted_signer() {
        let signing_key = fixture_signing_key();
        let trusted_keys = fixture_trust_store(&signing_key);
        let mut metadata = fixture_metadata(&signing_key);
        metadata
            .metadata
            .replace_signatures(vec!["invalid:signature".to_owned()]);

        let signed = metadata
            .sign_for_trusted_cache(&trusted_keys, Some(&fixture_signer(&signing_key)))
            .expect("compatible configured signer should replace untrusted signatures");
        assert_eq!(signed.metadata.signatures().len(), 1);
        assert!(trusted_keys.verifies_signature(
            signed.metadata.claims().fingerprint().as_bytes(),
            &signed.metadata.signatures()[0],
        ));
        let bytes = signed
            .serialize_raw()
            .expect("configured signer projection should serialize");
        trusted_keys
            .validate(
                &narjar::__private::storage::StoreHash::parse("0123456789abcdfghijklmnpqrsvwxyz")
                    .expect("fixture route hash should parse"),
                bytes,
            )
            .expect("configured signer output should pass narinfo trust validation");
    }

    #[test]
    fn has_no_positive_result_without_a_trusted_recorded_or_configured_signature() {
        let signing_key = fixture_signing_key();
        let other_key = SigningKey::from_bytes(&[8; 32]);
        let trusted_keys = fixture_trust_store(&other_key);
        let mut unsigned_metadata = fixture_metadata(&signing_key);
        unsigned_metadata.metadata.replace_signatures(Vec::new());
        let no_signature = unsigned_metadata
            .sign_for_trusted_cache(&trusted_keys, None)
            .err();
        let incompatible_signer = fixture_metadata(&signing_key)
            .sign_for_trusted_cache(&trusted_keys, Some(&fixture_signer(&signing_key)))
            .err();

        assert_eq!(no_signature, Some(MissingTrustedSignature));
        assert_eq!(incompatible_signer, Some(MissingTrustedSignature));
    }

    #[test]
    fn rejects_a_trusted_key_signature_for_a_different_fingerprint() {
        let signing_key = fixture_signing_key();
        let trusted_keys = fixture_trust_store(&signing_key);
        let mut metadata = fixture_metadata(&signing_key);
        let wrong_signature = format!(
            "narjar-test:{}",
            BASE64.encode(
                &signing_key
                    .sign(b"different Nix narinfo fingerprint")
                    .to_bytes()
            )
        );
        metadata.metadata.replace_signatures(vec![wrong_signature]);

        assert_eq!(
            metadata.sign_for_trusted_cache(&trusted_keys, None).err(),
            Some(MissingTrustedSignature)
        );
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &MissingTrustedSignature,
                "no trusted signature is available for native store metadata",
            ),
            (
                &NativeMetadataError::Database("query detail".into()),
                "query detail",
            ),
            (
                &NativeMetadataError::InvalidMetadata("metadata detail".into()),
                "metadata detail",
            ),
            (
                &NativeMetadataError::MissingStorePath("/nix/store/path".into()),
                "store path is not valid: /nix/store/path",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }
}
