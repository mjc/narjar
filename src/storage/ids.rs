#[cfg(test)]
use data_encoding::{BitOrder, Encoding, Specification};

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";

pub use crate::object::InvalidObjectId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreHash(pub(super) String);

impl StoreHash {
    pub fn parse(value: &str) -> Result<Self, InvalidObjectId> {
        parse_nix32(value, 32).map(Self)
    }

    pub(crate) fn validate(value: &str) -> Result<(), InvalidObjectId> {
        valid_nix32(value, 32).then_some(()).ok_or(InvalidObjectId)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn parse_nix32(value: &str, expected_len: usize) -> Result<String, InvalidObjectId> {
    valid_nix32(value, expected_len)
        .then(|| value.to_owned())
        .ok_or(InvalidObjectId)
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
