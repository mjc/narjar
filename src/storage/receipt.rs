use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::object::{CompressedNarIdentity, EncodedIdentity, NarIdentity};

const RECEIPT_VERSION: u8 = 1;

#[derive(Deserialize, Serialize)]
struct SerializedCompressedNarReceipt {
    version: u8,
    identity: CompressedNarIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompressedNarReceipt<Purpose> {
    identity: CompressedNarIdentity,
    purpose: PhantomData<Purpose>,
}

impl<Purpose> CompressedNarReceipt<Purpose> {
    pub(super) const fn new(encoded: EncodedIdentity, decoded: NarIdentity) -> Self {
        Self {
            identity: CompressedNarIdentity::new(encoded, decoded),
            purpose: PhantomData,
        }
    }

    pub(super) const fn identity(&self) -> CompressedNarIdentity {
        self.identity
    }

    pub(super) const fn encoded(&self) -> EncodedIdentity {
        self.identity.encoded()
    }

    pub(super) const fn decoded(&self) -> NarIdentity {
        self.identity.decoded()
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&SerializedCompressedNarReceipt {
            version: RECEIPT_VERSION,
            identity: self.identity,
        })
        .expect("compressed NAR receipt serialization cannot fail")
    }

    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let receipt = postcard::from_bytes::<SerializedCompressedNarReceipt>(bytes).ok()?;
        (receipt.version == RECEIPT_VERSION).then_some(Self {
            identity: receipt.identity,
            purpose: PhantomData,
        })
    }
}
