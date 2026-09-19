use super::{Compression, PathInfo};
use crate::object::{EncodedSize, FileHash};

pub(super) fn serialize_narinfo(
    info: &PathInfo,
    file_hash: FileHash,
    file_size: EncodedSize,
    compression: Compression,
) -> Result<Vec<u8>, String> {
    info.path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| format!("invalid store path: {}", info.path))?;
    let references = normalized_reference_basenames(info)?;

    let mut output = format!(
        "StorePath: {}\nURL: nar/{}{}\nCompression: {}\nFileHash: sha256:{}\nFileSize: {}\nNarHash: sha256:{}\nNarSize: {}\nReferences: {}\n",
        info.path,
        file_hash,
        compression.suffix(),
        compression.query_value(),
        file_hash,
        file_size,
        info.nar.hash(),
        info.nar.size(),
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

pub(super) fn fingerprint_for(info: &PathInfo) -> Result<String, String> {
    let references = normalized_reference_basenames(info)?
        .into_iter()
        .map(|reference| format!("/nix/store/{reference}"))
        .collect::<Vec<_>>();
    Ok(format!(
        "1;{};sha256:{};{};{}",
        info.path,
        info.nar.hash(),
        info.nar.size(),
        references.join(",")
    ))
}

pub(super) fn normalized_references(info: &PathInfo) -> Result<String, String> {
    Ok(normalized_reference_basenames(info)?.join(" "))
}

fn normalized_reference_basenames(info: &PathInfo) -> Result<Vec<&str>, String> {
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
    Ok(references)
}
