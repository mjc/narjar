#[cfg(test)]
use data_encoding::{BitOrder, Encoding, Specification};

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const MAX_STORE_NAME_BYTES: usize = 211;

pub use crate::object::InvalidObjectId;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreHash([u8; 32]);

impl StoreHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        match valid_nix32(value, 32) {
            true => value
                .as_bytes()
                .try_into()
                .map(Self)
                .map_err(|_| InvalidObjectId),
            false => Err(InvalidObjectId),
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("validated store hashes are ASCII")
    }
}

/// Validates a complete Nix store basename and returns its hash and name.
pub fn validate_store_basename(value: &str) -> Result<(StoreHash, &str), InvalidObjectId> {
    let (hash, name) = value.split_once('-').ok_or(InvalidObjectId)?;
    if name.is_empty()
        || name.len() > MAX_STORE_NAME_BYTES
        || name == "."
        || name == ".."
        || name.starts_with(".-")
        || name.starts_with("..-")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
    {
        return Err(InvalidObjectId);
    }
    Ok((StoreHash::parse(hash)?, name))
}

fn valid_nix32(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|byte| NIX32.as_bytes().contains(&byte))
}

#[cfg(test)]
fn nix32_encoding() -> &'static Encoding {
    static ENCODING: std::sync::OnceLock<Encoding> = std::sync::OnceLock::new();
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
pub(crate) fn nix32_sha256(digest: &[u8]) -> String {
    let encoding = nix32_encoding();
    let mut encoded = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(digest, &mut encoded);
    encoded.reverse();
    String::from_utf8(encoded).expect("Nix base32 encoding is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";

    #[test]
    fn validates_nix_store_name_boundaries() {
        [".", "..", ".-hidden", "..-parent", &"n".repeat(212)]
            .into_iter()
            .for_each(|name| {
                assert!(
                    validate_store_basename(&format!("{HASH}-{name}")).is_err(),
                    "Nix store name {name:?} should be rejected"
                );
            });

        ["..x", ".x", &"n".repeat(211)]
            .into_iter()
            .for_each(|name| {
                assert!(
                    validate_store_basename(&format!("{HASH}-{name}")).is_ok(),
                    "Nix store name {name:?} should be accepted"
                );
            });
    }
}
