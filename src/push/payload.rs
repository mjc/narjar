use std::io::{self, Write};
use std::path::Path;

use narjar::nar_compression::{encode_and_measure_nar, encode_nar};

use super::nar_stream::{local_store_path, verify_nar_summary, write_nar};
use super::{NarInfoMetadata, PushError};
use narjar::object::{CompressionCodec, EncodedIdentity, WireEncoding};

pub(super) fn measure_encoded_nar(
    info: &NarInfoMetadata,
    codec: CompressionCodec,
) -> Result<EncodedIdentity, PushError> {
    let path = local_store_path(info.claims().store_path())?;
    encode_and_measure_nar(codec, &mut io::sink(), |output| {
        write_verified_raw_nar(&path, info, output)
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
    info: &NarInfoMetadata,
    codec: CompressionCodec,
    mut output: impl Write,
) -> Result<(), PushError> {
    encode_nar(codec, &mut output, |output| {
        write_verified_raw_nar(path, info, output)
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
    info: &NarInfoMetadata,
    output: &mut dyn Write,
) -> io::Result<()> {
    let summary = write_nar(path, output).map_err(io::Error::other)?;
    verify_nar_summary(info, &summary).map_err(io::Error::other)
}
