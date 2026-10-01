use std::{fs, path::Path};

use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};

pub(crate) struct NixSigningKey {
    name: String,
    signing_key: SigningKey,
}

impl NixSigningKey {
    pub(crate) fn read(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|error| format!("reading signing key {}: {error}", path.display()))?;
        let mut fields = contents.split_ascii_whitespace();
        let key = fields
            .next()
            .ok_or_else(|| format!("signing key {} is empty", path.display()))?;
        if fields.next().is_some() {
            return Err(format!(
                "signing key {} contains multiple keys",
                path.display()
            ));
        }
        let (name, encoded_secret) = key
            .split_once(':')
            .filter(|(name, secret)| {
                narjar::__private::narinfo::valid_name(name) && !secret.is_empty()
            })
            .ok_or_else(|| format!("invalid signing key {}", path.display()))?;
        let secret: [u8; 64] = BASE64
            .decode(encoded_secret.as_bytes())
            .map_err(|error| format!("invalid signing key {}: {error}", path.display()))?
            .try_into()
            .map_err(|_| format!("signing key {} must contain 64 bytes", path.display()))?;
        let seed = secret[..32]
            .try_into()
            .expect("a Nix secret key has a 32-byte Ed25519 seed");
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().as_bytes() != &secret[32..] {
            return Err(format!(
                "signing key {} has an invalid public half",
                path.display()
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            signing_key,
        })
    }

    pub(crate) fn sign_fingerprint(&self, fingerprint: &str) -> String {
        let signature = self.signing_key.sign(fingerprint.as_bytes());
        format!("{}:{}", self.name, BASE64.encode(&signature.to_bytes()))
    }
}
