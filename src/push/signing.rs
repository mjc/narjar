use std::{fs, path::Path};

use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};

use narjar::narinfo::NarInfoMetadata;

pub(super) fn sign_metadata(
    key_path: &Path,
    metadata: &mut [NarInfoMetadata],
) -> Result<(), String> {
    let key = SecretKey::read(key_path)?;
    metadata.iter_mut().try_for_each(|info| {
        let fingerprint = info.claims().fingerprint();
        let signature = key.sign(fingerprint.as_bytes());
        info.add_signature(format!(
            "{}:{}",
            key.name,
            BASE64.encode(&signature.to_bytes())
        ));
        Ok(())
    })
}

struct SecretKey {
    name: String,
    signing: SigningKey,
}

impl SecretKey {
    fn read(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|error| format!("reading signing key {}: {error}", path.display()))?;
        let mut values = contents.split_ascii_whitespace();
        let value = values
            .next()
            .ok_or_else(|| format!("signing key {} is empty", path.display()))?;
        if values.next().is_some() {
            return Err(format!(
                "signing key {} contains multiple keys",
                path.display()
            ));
        }
        let (name, encoded) = value
            .split_once(':')
            .filter(|(name, encoded)| valid_key_name(name) && !encoded.is_empty())
            .ok_or_else(|| format!("invalid signing key {}", path.display()))?;
        let bytes = BASE64
            .decode(encoded.as_bytes())
            .map_err(|error| format!("invalid signing key {}: {error}", path.display()))?;
        let secret: [u8; 64] = bytes
            .try_into()
            .map_err(|_| format!("signing key {} must contain 64 bytes", path.display()))?;
        let seed = secret[..32]
            .try_into()
            .expect("a 64-byte secret key has a 32-byte seed");
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().as_bytes() != &secret[32..] {
            return Err(format!(
                "signing key {} has an invalid public half",
                path.display()
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            signing,
        })
    }

    fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.signing.sign(message)
    }
}

fn valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use narjar::narinfo::NarInfoMetadata;
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
        let parsed = SecretKey::read(key.path()).expect("read signing key fixture");
        assert_eq!(parsed.name, "narjar-test");
        assert_eq!(parsed.sign(b"message"), signing.sign(b"message"));
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
        .expect("test metadata should be valid")];
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
