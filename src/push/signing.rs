use std::path::Path;

use super::{NarInfoMetadata, PushError};
use crate::narinfo_signing::NixSigningKey;

pub(super) fn sign_metadata(
    key_path: &Path,
    metadata: &mut [NarInfoMetadata],
) -> Result<(), PushError> {
    let key = NixSigningKey::read(key_path).map_err(PushError::new)?;
    metadata.iter_mut().try_for_each(|info| {
        let fingerprint = info.claims().fingerprint();
        info.add_signature(key.sign_fingerprint(&fingerprint));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Verifier;
    use narjar::object::{NarHash, NarIdentity, NarSize};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn reads_the_native_nix_secret_key_format() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let mut key = NamedTempFile::new().expect("create signing key fixture");
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&[7; 32]);
        bytes[32..].copy_from_slice(signing.verifying_key().as_bytes());
        writeln!(key, "narjar-test:{}", BASE64.encode(&bytes)).expect("write signing key fixture");
        let parsed = NixSigningKey::read(key.path()).expect("read signing key fixture");
        let encoded = parsed.sign_fingerprint("message");
        let (name, encoded_signature) = encoded.split_once(':').expect("named signature");
        assert_eq!(name, "narjar-test");
        let signature = ed25519_dalek::Signature::from_slice(
            &BASE64
                .decode(encoded_signature.as_bytes())
                .expect("signature base64"),
        )
        .expect("signature bytes");
        signing
            .verifying_key()
            .verify(b"message", &signature)
            .expect("signature should verify");
    }

    #[test]
    fn signs_the_logical_nar_fingerprint() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let mut key = NamedTempFile::new().expect("create signing key fixture");
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&[7; 32]);
        bytes[32..].copy_from_slice(signing.verifying_key().as_bytes());
        writeln!(key, "narjar-test:{}", BASE64.encode(&bytes)).expect("write signing key fixture");

        let mut metadata = [NarInfoMetadata::from_store_metadata(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package".to_owned(),
            None,
            None,
            NarIdentity::new(
                NarHash::parse("01nvfd133isi40l4id6if932mbwc7mxgwxd8x625xqhjdz6mpzai")
                    .expect("test NAR hash should parse"),
                NarSize::new(289_656),
            ),
            vec![
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency".to_owned(),
                "/nix/store/11111111111111111111111111111111-dependency".to_owned(),
            ],
            Vec::new(),
        )
        .expect("valid fixture metadata")];
        sign_metadata(key.path(), &mut metadata).expect("sign metadata");

        let (name, encoded) = metadata[0].signatures()[0]
            .split_once(':')
            .expect("named signature");
        assert_eq!(name, "narjar-test");
        let signature = ed25519_dalek::Signature::from_slice(
            &BASE64.decode(encoded.as_bytes()).expect("signature base64"),
        )
        .expect("signature bytes");
        signing
            .verifying_key()
            .verify(metadata[0].claims().fingerprint().as_bytes(), &signature)
            .expect("signature should verify");
    }
}
