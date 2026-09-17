use std::{fs, path::Path};

use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};

use super::{PathInfo, narinfo::fingerprint_for};

pub(super) fn sign_metadata(key_path: &Path, metadata: &mut [PathInfo]) -> Result<(), String> {
    let key = SecretKey::read(key_path)?;
    metadata.iter_mut().try_for_each(|info| {
        let fingerprint = fingerprint_for(info)?;
        let signature = key.sign(fingerprint.as_bytes());
        info.signatures.push(format!(
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

        let mut metadata = [PathInfo {
            path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package".to_owned(),
            ca: None,
            deriver: None,
            nar_hash: "sha256-Uf1bzW8S4l6E6ah1/no9jK8qRnLRtEgoIFHHMUJz2wY=".to_owned(),
            nar_size: 289_656,
            references: vec![
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dependency".to_owned(),
                "/nix/store/11111111111111111111111111111111-dependency".to_owned(),
            ],
            signatures: Vec::new(),
        }];
        sign_metadata(key.path(), &mut metadata).expect("sign metadata");

        let (name, encoded) = metadata[0].signatures[0]
            .split_once(':')
            .expect("named signature");
        assert_eq!(name, "narjar-test");
        let signature = ed25519_dalek::Signature::from_slice(
            &BASE64.decode(encoded.as_bytes()).expect("signature base64"),
        )
        .expect("signature bytes");
        signing
            .verifying_key()
            .verify(
                fingerprint_for(&metadata[0]).unwrap().as_bytes(),
                &signature,
            )
            .expect("signature should verify");
    }
}
