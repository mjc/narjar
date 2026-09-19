use serde::{Deserialize, Serialize};

use crate::object::CompressedNarIdentity;

const RECEIPT_VERSION: u8 = 1;

#[derive(Deserialize, Serialize)]
struct CompressedNarReceipt {
    version: u8,
    identity: CompressedNarIdentity,
}

pub(super) fn serialize_compressed_nar_identity(identity: CompressedNarIdentity) -> Vec<u8> {
    postcard::to_allocvec(&CompressedNarReceipt {
        version: RECEIPT_VERSION,
        identity,
    })
    .expect("compressed NAR receipt serialization cannot fail")
}

pub(super) fn deserialize_compressed_nar_identity(bytes: &[u8]) -> Option<CompressedNarIdentity> {
    let receipt = postcard::from_bytes::<CompressedNarReceipt>(bytes).ok()?;
    (receipt.version == RECEIPT_VERSION).then_some(receipt.identity)
}
