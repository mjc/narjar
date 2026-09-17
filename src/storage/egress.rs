use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Cursor, Read, Write},
    path::PathBuf,
};

#[cfg(test)]
use std::sync::atomic::Ordering;

use crate::narinfo::ValidatedPayload;
use crate::object::{
    CompressionCodec, EncodedIdentity, EncodedSize, NarFileName, NarHash, NarIdentity, WireEncoding,
};

use super::compression::{
    CapacityCheckedStagingWriter, encode_raw_nar, encoded_file_matches, nar_file_size_matches,
};
use super::fs::{open_optional_at, open_regular_at, read_dir_names, unlink_at};
use super::publication::{
    NarUploadPolicy, PublishOutcome, PublishTarget, StorageError, TemporaryFile,
};
use super::recovery::PublicationState;
use super::state::Storage;

const EGRESS_RECEIPT_VERSION: u8 = 1;
pub(super) const EGRESS_RECEIPT_DIRECTORY: &str = ".narjar-egress";
pub(super) const MAX_EGRESS_RECEIPT_BYTES: u64 = 256;

pub(crate) struct StoredNar<'storage> {
    storage: &'storage Storage,
    pub(super) file: File,
    identity: NarIdentity,
}

impl StoredNar<'_> {
    pub(crate) fn identity(&self) -> NarIdentity {
        self.identity
    }

    pub(super) fn storage(&self) -> &Storage {
        self.storage
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct EgressSlot {
    raw: NarIdentity,
    codec: CompressionCodec,
}

impl EgressSlot {
    pub(super) const fn new(raw: NarIdentity, codec: CompressionCodec) -> Self {
        Self { raw, codec }
    }

    pub(super) const fn raw(self) -> NarIdentity {
        self.raw
    }

    pub(super) const fn codec(self) -> CompressionCodec {
        self.codec
    }

    pub(super) fn receipt_name(self) -> OsString {
        OsString::from(format!(
            "{}{}.receipt",
            self.raw.hash(),
            self.codec.suffix()
        ))
    }

    pub(super) fn lock_key(self) -> PathBuf {
        PathBuf::from(EGRESS_RECEIPT_DIRECTORY).join(self.receipt_name())
    }
}

pub(super) enum EgressRepresentation {
    Raw(NarIdentity),
    Compressed(EncodedIdentity),
}

impl EgressRepresentation {
    pub(super) fn file_name(&self) -> NarFileName {
        match self {
            Self::Raw(identity) => NarFileName::raw(identity.hash()),
            Self::Compressed(output) => output.file_name(),
        }
    }

    pub(super) fn size(&self) -> EncodedSize {
        match self {
            Self::Raw(identity) => identity.size().get().into(),
            Self::Compressed(output) => output.size(),
        }
    }
}

enum ExistingDerivative {
    Missing,
    Corrupt,
    Usable(EncodedIdentity),
}

enum DerivativeDecision {
    Reuse(EncodedIdentity),
    Materialize(DerivativeCommit),
}

enum DerivativeCommit {
    ServerGenerated,
    Reproduce(EncodedIdentity),
}

struct StagedDerivativeFile<'storage> {
    storage: &'storage Storage,
    file: Option<TemporaryFile>,
}

impl Drop for StagedDerivativeFile<'_> {
    fn drop(&mut self) {
        if let Some(file) = &self.file {
            let _ = self.storage.remove_temp(file);
        }
    }
}

struct StagedDerivative<'storage> {
    file: StagedDerivativeFile<'storage>,
    transaction: super::recovery::PublicationTransaction,
}

struct ReadyDerivative<'storage> {
    file: StagedDerivativeFile<'storage>,
    transaction: super::recovery::PublicationTransaction,
    output: EncodedIdentity,
}

impl<'storage> StagedDerivative<'storage> {
    fn begin(storage: &'storage Storage) -> Result<Self, StorageError> {
        let temp_name = storage.next_temp_name_with_prefix("nar");
        let temporary_path = PathBuf::from("nar/.tmp").join(&temp_name);
        let transaction = storage.recovery.begin(&temporary_path)?;
        let file = storage.create_nar_temp_named(temp_name)?;
        Ok(Self {
            file: StagedDerivativeFile {
                storage,
                file: Some(file),
            },
            transaction,
        })
    }

    fn encode(
        self,
        raw: &StoredNar<'_>,
        slot: EgressSlot,
        policy: NarUploadPolicy,
        commit: &DerivativeCommit,
    ) -> Result<ReadyDerivative<'storage>, StorageError> {
        let Self {
            mut file,
            mut transaction,
        } = self;
        let storage = file.storage;
        transaction.transition(PublicationState::Streaming)?;
        let temporary = file.file.as_mut().expect("staged derivative file exists");
        let mut reservation = storage.empty_staging_reservation(policy.min_free_bytes())?;
        let mut destination = CapacityCheckedStagingWriter::new(
            &mut temporary.file,
            &mut reservation,
            policy.min_free_bytes(),
        );
        #[cfg(test)]
        storage.egress_generations.fetch_add(1, Ordering::Relaxed);
        let output = encode_raw_nar(&raw.file, slot.codec(), &mut destination)?;
        let output = EncodedIdentity::new(slot.codec(), output.hash, output.size);
        if let DerivativeCommit::Reproduce(expected) = commit
            && output != *expected
        {
            return Err(StorageError::NarMismatch);
        }
        destination.flush()?;
        temporary.file.sync_all()?;
        transaction.transition(PublicationState::Validated)?;
        Ok(ReadyDerivative {
            file,
            transaction,
            output,
        })
    }
}

impl ReadyDerivative<'_> {
    fn commit(mut self, commit: DerivativeCommit) -> Result<EncodedIdentity, StorageError> {
        let temporary = self.file.file.take().expect("ready derivative file exists");
        let target = match commit {
            DerivativeCommit::ServerGenerated | DerivativeCommit::Reproduce(_) => {
                PublishTarget::RepairEgressNar(self.output)
            }
        };
        self.file
            .storage
            .commit_temporary(target, &temporary, self.transaction, |_| Ok(()))?;
        Ok(self.output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EgressReceipt {
    slot: EgressSlot,
    output: EncodedIdentity,
}

impl EgressReceipt {
    pub(super) fn new(slot: EgressSlot, output: EncodedIdentity) -> Self {
        debug_assert_eq!(slot.codec(), output.codec());
        Self { slot, output }
    }

    pub(super) fn file_name(&self) -> OsString {
        self.slot.receipt_name()
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        format!(
            "version={EGRESS_RECEIPT_VERSION}\nraw-hash={}\nraw-size={}\nencoding={}\nencoded-hash={}\nencoded-size={}\n",
            self.slot.raw().hash(),
            self.slot.raw().size(),
            self.slot.codec().compression(),
            self.output.hash(),
            self.output.size(),
        )
        .into_bytes()
    }

    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        if !text.ends_with('\n') {
            return None;
        }
        let mut version: Option<u8> = None;
        let mut raw_hash = None;
        let mut raw_size = None;
        let mut codec = None;
        let mut encoded_hash = None;
        let mut encoded_size = None;
        for line in text.lines() {
            let (name, value) = line.split_once('=')?;
            match name {
                "version" if version.is_none() => version = Some(value.parse().ok()?),
                "raw-hash" if raw_hash.is_none() => raw_hash = Some(NarHash::parse(value).ok()?),
                "raw-size" if raw_size.is_none() => {
                    raw_size = Some(value.parse::<u64>().ok()?.into())
                }
                "encoding" if codec.is_none() => {
                    codec = Some(match value {
                        "zstd" => CompressionCodec::Zstd,
                        "xz" => CompressionCodec::Xz,
                        _ => return None,
                    })
                }
                "encoded-hash" if encoded_hash.is_none() => {
                    encoded_hash = Some(crate::object::FileHash::parse(value).ok()?)
                }
                "encoded-size" if encoded_size.is_none() => {
                    encoded_size = Some(value.parse::<u64>().ok()?.into())
                }
                _ => return None,
            }
        }
        if version? != EGRESS_RECEIPT_VERSION {
            return None;
        }
        let codec = codec?;
        Some(Self::new(
            EgressSlot::new(NarIdentity::new(raw_hash?, raw_size?), codec),
            EncodedIdentity::new(codec, encoded_hash?, encoded_size?),
        ))
    }

    pub(super) fn matches(&self, slot: EgressSlot) -> bool {
        self.slot == slot && self.output.codec() == slot.codec()
    }

    pub(super) const fn output(&self) -> EncodedIdentity {
        self.output
    }

    pub(super) const fn slot(&self) -> EgressSlot {
        self.slot
    }
}

impl Storage {
    pub(super) fn open_verified_canonical_nar(
        &self,
        payload: ValidatedPayload,
    ) -> Result<StoredNar<'_>, StorageError> {
        let identity = match payload {
            ValidatedPayload::Raw(identity) => identity,
            ValidatedPayload::Compressed(expectation) => self
                .read_ingestion_receipt(expectation)?
                .ok_or(StorageError::NarMismatch)?
                .decoded_identity(),
        };
        let file = self
            .open_nar(identity.hash())?
            .ok_or(StorageError::MissingNar)?;
        if !nar_file_size_matches(&file, identity.size().get())? {
            return Err(StorageError::NarMismatch);
        }
        Ok(StoredNar {
            storage: self,
            file,
            identity,
        })
    }

    pub(super) fn select_egress(
        &self,
        raw: &StoredNar<'_>,
        encoding: WireEncoding,
        policy: NarUploadPolicy,
    ) -> Result<EgressRepresentation, StorageError> {
        match encoding {
            WireEncoding::Raw => Ok(EgressRepresentation::Raw(raw.identity())),
            WireEncoding::Zstd => self.select_compressed(
                raw,
                EgressSlot::new(raw.identity(), CompressionCodec::Zstd),
                policy,
            ),
            WireEncoding::Xz => self.select_compressed(
                raw,
                EgressSlot::new(raw.identity(), CompressionCodec::Xz),
                policy,
            ),
        }
    }

    fn select_compressed(
        &self,
        raw: &StoredNar<'_>,
        slot: EgressSlot,
        policy: NarUploadPolicy,
    ) -> Result<EgressRepresentation, StorageError> {
        let lock = self.destination_lock(slot.lock_key());
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let decision = match self.read_egress_receipt(slot)? {
            Some(receipt) => match self.inspect_egress_derivative(receipt.output())? {
                ExistingDerivative::Usable(output) => DerivativeDecision::Reuse(output),
                ExistingDerivative::Missing => {
                    DerivativeDecision::Materialize(DerivativeCommit::Reproduce(receipt.output()))
                }
                ExistingDerivative::Corrupt => {
                    DerivativeDecision::Materialize(DerivativeCommit::Reproduce(receipt.output()))
                }
            },
            None => DerivativeDecision::Materialize(DerivativeCommit::ServerGenerated),
        };
        let output = match decision {
            DerivativeDecision::Reuse(output) => {
                return Ok(EgressRepresentation::Compressed(output));
            }
            DerivativeDecision::Materialize(commit) => {
                self.materialize_compressed_nar(raw, slot, policy, commit)?
            }
        };
        self.publish_egress_receipt(EgressReceipt::new(slot, output))?;
        Ok(EgressRepresentation::Compressed(output))
    }

    fn materialize_compressed_nar(
        &self,
        raw: &StoredNar<'_>,
        slot: EgressSlot,
        policy: NarUploadPolicy,
        commit: DerivativeCommit,
    ) -> Result<EncodedIdentity, StorageError> {
        let staged = StagedDerivative::begin(self)?;
        let ready = staged.encode(raw, slot, policy, &commit)?;
        ready.commit(commit)
    }

    fn inspect_egress_derivative(
        &self,
        output: EncodedIdentity,
    ) -> Result<ExistingDerivative, StorageError> {
        let nar = self.nar_directory()?;
        let Some(file) = open_optional_at(&nar, &output.file_name().os_string())? else {
            return Ok(ExistingDerivative::Missing);
        };
        if !encoded_file_matches(&file, output)? {
            return Ok(ExistingDerivative::Corrupt);
        }
        Ok(ExistingDerivative::Usable(output))
    }

    fn publish_egress_receipt(
        &self,
        receipt: EgressReceipt,
    ) -> Result<PublishOutcome, StorageError> {
        self.publish(
            PublishTarget::EgressReceipt(&receipt),
            Cursor::new(receipt.bytes()),
        )
    }

    fn read_egress_receipt(&self, slot: EgressSlot) -> Result<Option<EgressReceipt>, StorageError> {
        let directory = self.egress_receipt_directory()?;
        let name = slot.receipt_name();
        let Some(bytes) = read_bounded_regular_file(&directory, &name, MAX_EGRESS_RECEIPT_BYTES)?
        else {
            return Ok(None);
        };
        Ok(EgressReceipt::parse(&bytes).filter(|receipt| receipt.matches(slot)))
    }

    pub(super) fn remove_orphan_egress_receipts(&self) -> Result<(), StorageError> {
        let directory = self.egress_receipt_directory()?;
        let removed =
            read_dir_names(&directory)?
                .into_iter()
                .try_fold(false, |removed, name| {
                    self.remove_orphan_egress_receipt(&directory, &name)
                        .map(|was_removed| removed || was_removed)
                })?;
        if removed {
            directory.sync_all()?;
        }
        Ok(())
    }

    fn remove_orphan_egress_receipt(
        &self,
        directory: &File,
        name: &OsStr,
    ) -> Result<bool, StorageError> {
        let Some(bytes) = read_bounded_regular_file(directory, name, MAX_EGRESS_RECEIPT_BYTES)?
        else {
            unlink_at(directory, name)?;
            return Ok(true);
        };
        let Some(receipt) =
            EgressReceipt::parse(&bytes).filter(|receipt| receipt.file_name().as_os_str() == name)
        else {
            unlink_at(directory, name)?;
            return Ok(true);
        };
        let raw_is_usable = self.canonical_raw_has_expected_size(receipt.slot().raw())?;
        if raw_is_usable {
            return Ok(false);
        }
        unlink_at(directory, name)?;
        Ok(true)
    }

    fn canonical_raw_has_expected_size(&self, identity: NarIdentity) -> Result<bool, StorageError> {
        let Some(file) = self.open_nar(identity.hash())? else {
            return Ok(false);
        };
        Ok(nar_file_size_matches(&file, identity.size().get())?)
    }

    pub(super) fn egress_receipt_directory(&self) -> Result<File, StorageError> {
        let root = self.root_directory()?;
        Ok(super::fs::open_directory_at(
            &root,
            OsStr::new(EGRESS_RECEIPT_DIRECTORY),
        )?)
    }

    #[cfg(test)]
    pub(super) fn compressed_representation_for_test(
        &self,
        identity: NarIdentity,
        codec: CompressionCodec,
        min_free_bytes: u64,
    ) -> Result<(NarFileName, EncodedSize), StorageError> {
        let raw = self.open_verified_canonical_nar(ValidatedPayload::Raw(identity))?;
        self.select_compressed(
            &raw,
            EgressSlot::new(identity, codec),
            NarUploadPolicy::new(u64::MAX, min_free_bytes),
        )
        .map(|output| (output.file_name(), output.size()))
    }

    #[cfg(test)]
    pub(super) fn materialize_compressed_nar_for_test(
        &self,
        raw: &File,
        identity: NarIdentity,
        codec: CompressionCodec,
        min_free_bytes: u64,
    ) -> Result<(), StorageError> {
        let stored = StoredNar {
            storage: self,
            file: raw.try_clone()?,
            identity,
        };
        self.materialize_compressed_nar(
            &stored,
            EgressSlot::new(identity, codec),
            NarUploadPolicy::new(u64::MAX, min_free_bytes),
            DerivativeCommit::ServerGenerated,
        )
        .map(|_| ())
    }

    #[cfg(test)]
    pub(super) fn egress_generations(&self) -> u64 {
        self.egress_generations.load(Ordering::Relaxed)
    }
}

fn read_bounded_regular_file(
    directory: &File,
    name: &OsStr,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, StorageError> {
    let file = match open_regular_at(directory, name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Ok(None);
    }
    Ok(Some(bytes))
}
