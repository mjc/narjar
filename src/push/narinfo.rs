use std::sync::OnceLock;

use data_encoding::{BASE64, BitOrder, Encoding, Specification};

use super::{Compression, PathInfo};

pub(super) fn nix32_encoding() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut specification = Specification::new();
        specification
            .symbols
            .push_str("0123456789abcdfghijklmnpqrsvwxyz");
        specification.bit_order = BitOrder::LeastSignificantFirst;
        specification
            .encoding()
            .expect("Nix base32 specification is valid")
    })
}

pub(super) fn nix32_sha256_from_sri(value: &str) -> Result<String, String> {
    let (algorithm, encoded) = value
        .split_once('-')
        .ok_or_else(|| format!("unsupported Nix hash: {value}"))?;
    if algorithm != "sha256" {
        return Err(format!("unsupported Nix hash algorithm: {algorithm}"));
    }
    let digest = BASE64
        .decode(encoded.as_bytes())
        .map_err(|error| format!("invalid Nix hash {value}: {error}"))?;
    if digest.len() != 32 {
        return Err(format!(
            "invalid SHA-256 length in Nix hash: {}",
            digest.len()
        ));
    }
    let encoding = nix32_encoding();
    let mut output = vec![0; encoding.encode_len(digest.len())];
    encoding.encode_mut(&digest, &mut output);
    output.reverse();
    String::from_utf8(output).map_err(|error| format!("invalid Nix base32 output: {error}"))
}

pub(super) fn serialize_narinfo(
    info: &PathInfo,
    file_hash: &str,
    file_size: u64,
    compression: Compression,
) -> Result<Vec<u8>, String> {
    info.path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| format!("invalid store path: {}", info.path))?;
    let nar_hash = nix32_sha256_from_sri(&info.nar_hash)?;
    let mut references = info
        .references
        .iter()
        .map(|reference| {
            reference
                .strip_prefix("/nix/store/")
                .ok_or_else(|| format!("invalid reference path: {reference}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    references.sort_unstable();
    references.dedup();

    let mut output = format!(
        "StorePath: {}\nURL: nar/{}{}\nCompression: {}\nFileHash: sha256:{}\nFileSize: {}\nNarHash: sha256:{}\nNarSize: {}\nReferences: {}\n",
        info.path,
        file_hash,
        compression.suffix(),
        compression.query_value(),
        file_hash,
        file_size,
        nar_hash,
        info.nar_size,
        references.join(" "),
    );
    for signature in &info.signatures {
        output.push_str("Sig: ");
        output.push_str(signature);
        output.push('\n');
    }
    if let Some(deriver) = &info.deriver {
        if deriver == "unknown-deriver" {
            output.push_str("Deriver: unknown-deriver\n");
        } else {
            let deriver = deriver
                .strip_prefix("/nix/store/")
                .ok_or_else(|| format!("invalid deriver path: {deriver}"))?;
            output.push_str("Deriver: ");
            output.push_str(deriver);
            output.push('\n');
        }
    }
    if let Some(ca) = &info.ca {
        output.push_str("CA: ");
        output.push_str(ca);
        output.push('\n');
    }
    Ok(output.into_bytes())
}
