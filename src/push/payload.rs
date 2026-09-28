use std::io::{self, Write};
use std::path::Path;

use narjar::nar_compression::{encode_and_measure_nar, encode_nar};

use super::nar_stream::{local_store_path, write_nar};
use super::{NarInfoMetadata, PushError};
use narjar::object::{
    CompressedNarIdentity, CompressionCodec, EncodedIdentity, NarHash, NarIdentity, NarSize,
    WireEncoding,
};

pub(super) fn measure_encoded_nar(
    info: &NarInfoMetadata,
    codec: CompressionCodec,
) -> Result<EncodedIdentity, PushError> {
    let path = local_store_path(info.claims().store_path())?;
    encode_and_measure_nar(codec, &mut io::sink(), |output| {
        write_verified_raw_nar(&path, info.claims().identity(), output)
    })
    .map_err(|error| {
        format!(
            "measuring {} NAR: {error}",
            WireEncoding::from(codec).compression()
        )
        .into()
    })
}

pub(super) fn write_encoded_nar(
    path: &Path,
    representation: CompressedNarIdentity,
    mut output: impl Write,
) -> Result<(), PushError> {
    let codec = representation.encoded().codec();
    encode_nar(codec, &mut output, |output| {
        write_verified_raw_nar(path, representation.decoded(), output)
    })
    .map_err(|error| {
        format!(
            "encoding {} NAR: {error}",
            WireEncoding::from(codec).compression()
        )
        .into()
    })
}

fn write_verified_raw_nar(
    path: &Path,
    expected: NarIdentity,
    output: &mut dyn Write,
) -> io::Result<()> {
    let summary = write_nar(path, output).map_err(io::Error::other)?;
    let actual = NarIdentity::new(
        NarHash::from_digest(summary.raw_sha256),
        NarSize::new(summary.raw_size),
    );
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "NAR identity mismatch for {}: expected {}/{}; got {}/{}",
                path.display(),
                expected.hash(),
                expected.size(),
                actual.hash(),
                actual.size(),
            ),
        ));
    }
    Ok(())
}
