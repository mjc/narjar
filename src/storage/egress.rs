use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

#[cfg(test)]
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::narinfo::ValidatedPayload;
use crate::object::{
    CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarHash, NarIdentity,
    NarRepresentation, NarSize, WireEncoding,
};

#[cfg(test)]
use crate::object::NarFileName;

use super::chunk_store::{ChunkStore, ChunkedNarReader, MAX_CHUNK_MANIFEST_BYTES};
use super::compression::{
    CapacityCheckedStagingWriter, encode_raw_nar, encoded_file_matches, nar_file_size_matches,
};
use super::fs::{
    BoundedRegularFile, open_optional_at, read_bounded_regular_file, read_dir_names, unlink_at,
};
use super::publication::{
    NarUploadPolicy, PublishOutcome, PublishTarget, StorageError, TemporaryFile,
};
use super::recovery::PublicationState;
use super::state::{Storage, StorageBackend};
use super::{CleanupAction, EGRESS_RECEIPT_DIRECTORY};

const EGRESS_RECEIPT_VERSION: u8 = 1;
pub(super) const MAX_EGRESS_RECEIPT_BYTES: u64 = 256;

pub(crate) struct StoredNar<'storage> {
    storage: &'storage Storage,
    source: StoredNarSource<'storage>,
    identity: NarIdentity,
}

enum StoredNarSource<'storage> {
    Flat(File),
    Chunked(&'storage ChunkStore),
}

pub(crate) enum NarReadBody<'storage> {
    File(File),
    Chunked(Box<ChunkedNarReader<'storage>>),
}

impl Read for NarReadBody<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            Self::Chunked(reader) => reader.read(buffer),
        }
    }
}

impl<'storage> StoredNar<'storage> {
    pub(crate) fn identity(&self) -> NarIdentity {
        self.identity
    }

    pub(super) fn storage(&self) -> &Storage {
        self.storage
    }

    fn reader(&self) -> Result<NarReadBody<'storage>, StorageError> {
        match &self.source {
            StoredNarSource::Flat(file) => {
                let mut file = file.try_clone()?;
                file.seek(SeekFrom::Start(0))?;
                Ok(NarReadBody::File(file))
            }
            StoredNarSource::Chunked(store) => {
                // Derivative generation must verify every immutable chunk
                // before encoding the declared canonical NAR.
                let reader = store
                    .open_verified_reader(
                        self.identity.hash(),
                        0..self.identity.size().get(),
                        MAX_CHUNK_MANIFEST_BYTES,
                    )
                    .map_err(|error| StorageError::Io(io::Error::other(error)))?;
                Ok(NarReadBody::Chunked(Box::new(reader)))
            }
        }
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

struct VerifiedDerivative(EncodedIdentity);

impl VerifiedDerivative {
    fn identity(&self) -> EncodedIdentity {
        self.0
    }
}

enum ExistingDerivative {
    Missing,
    Corrupt,
    Usable(VerifiedDerivative),
}

#[derive(Debug)]
pub(super) enum CanonicalRawStatus {
    Missing,
    WrongSize,
    Present,
}

enum DerivativeWork {
    Reuse(VerifiedDerivative),
    Generate(GenerationContract),
}

enum GenerationContract {
    AnyOutput,
    ExactOutput(EncodedIdentity),
}

impl GenerationContract {
    fn verify_generated_output(self, output: EncodedIdentity) -> Result<(), StorageError> {
        match self {
            Self::AnyOutput => Ok(()),
            Self::ExactOutput(expected) if expected == output => Ok(()),
            Self::ExactOutput(_) => Err(StorageError::NarMismatch),
        }
    }
}

struct TemporaryDerivative<'storage> {
    storage: &'storage Storage,
    temporary: Option<TemporaryFile>,
}

impl TemporaryDerivative<'_> {
    fn writer(&mut self) -> &mut File {
        &mut self
            .temporary
            .as_mut()
            .expect("staged derivative owns its temporary file")
            .file
    }

    fn take_temporary(&mut self) -> TemporaryFile {
        self.temporary
            .take()
            .expect("staged derivative owns its temporary file")
    }
}

impl Drop for TemporaryDerivative<'_> {
    fn drop(&mut self) {
        if let Some(temporary) = &self.temporary {
            let _ = self.storage.remove_temp(temporary);
        }
    }
}

struct StagedDerivative<'storage> {
    temporary: TemporaryDerivative<'storage>,
    transaction: super::recovery::PublicationTransaction,
}

struct StreamingDerivative<'storage> {
    temporary: TemporaryDerivative<'storage>,
    transaction: super::recovery::PublicationTransaction,
}

struct ReadyDerivative<'storage> {
    temporary: TemporaryDerivative<'storage>,
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
            temporary: TemporaryDerivative {
                storage,
                temporary: Some(file),
            },
            transaction,
        })
    }

    fn start_streaming(mut self) -> Result<StreamingDerivative<'storage>, StorageError> {
        self.transaction.transition(PublicationState::Streaming)?;
        Ok(StreamingDerivative {
            temporary: self.temporary,
            transaction: self.transaction,
        })
    }
}

impl<'storage> StreamingDerivative<'storage> {
    fn encode_canonical_raw_nar(
        self,
        raw: &StoredNar<'_>,
        slot: EgressSlot,
        policy: NarUploadPolicy,
        contract: GenerationContract,
    ) -> Result<ReadyDerivative<'storage>, StorageError> {
        let Self {
            mut temporary,
            mut transaction,
        } = self;
        let storage = temporary.storage;
        let mut reservation = storage.empty_staging_reservation(policy.min_free_bytes())?;
        #[cfg(test)]
        storage.egress_generations.fetch_add(1, Ordering::Relaxed);
        let output = encode_canonical_raw_nar_into_capacity_checked_staging_file(
            raw,
            slot.codec(),
            temporary.writer(),
            &mut reservation,
            policy.min_free_bytes(),
        )?;
        contract.verify_generated_output(output)?;
        temporary.writer().sync_all()?;
        transaction.transition(PublicationState::Validated)?;
        Ok(ReadyDerivative {
            temporary,
            transaction,
            output,
        })
    }
}

fn encode_canonical_raw_nar_into_capacity_checked_staging_file(
    raw: &StoredNar<'_>,
    codec: CompressionCodec,
    temporary: &mut File,
    reservation: &mut super::publication::StagingReservation,
    min_free_bytes: u64,
) -> Result<EncodedIdentity, StorageError> {
    let mut destination = CapacityCheckedStagingWriter::new(temporary, reservation, min_free_bytes);
    let source = raw.reader()?;
    let output = encode_raw_nar(source, codec, &mut destination)?;
    destination.flush()?;
    Ok(EncodedIdentity::new(codec, output.hash, output.size))
}

impl ReadyDerivative<'_> {
    fn commit(mut self) -> Result<EncodedIdentity, StorageError> {
        let temporary = self.temporary.take_temporary();
        let target = PublishTarget::RepairEgressNar(self.output);
        let destination = target.destination();
        self.temporary.storage.commit_temporary(
            destination,
            &temporary,
            self.transaction,
            |_| Ok(()),
        )?;
        Ok(self.output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EgressReceipt {
    slot: EgressSlot,
    encoded_hash: FileHash,
    encoded_size: EncodedSize,
}

#[derive(Deserialize, Serialize)]
struct EgressReceiptRecord {
    version: u8,
    raw_hash: NarHash,
    raw_size: NarSize,
    encoding: CompressionCodec,
    encoded_hash: crate::object::FileHash,
    encoded_size: EncodedSize,
}

impl EgressReceiptRecord {
    fn from_receipt(receipt: &EgressReceipt) -> Self {
        Self {
            version: EGRESS_RECEIPT_VERSION,
            raw_hash: receipt.slot.raw().hash(),
            raw_size: receipt.slot.raw().size(),
            encoding: receipt.slot.codec(),
            encoded_hash: receipt.encoded_hash,
            encoded_size: receipt.encoded_size,
        }
    }

    fn into_receipt(self) -> Option<EgressReceipt> {
        (self.version == EGRESS_RECEIPT_VERSION).then_some(())?;
        let raw = NarIdentity::new(self.raw_hash, self.raw_size);
        Some(EgressReceipt::new(
            EgressSlot::new(raw, self.encoding),
            self.encoded_hash,
            self.encoded_size,
        ))
    }
}

impl EgressReceipt {
    pub(super) fn new(slot: EgressSlot, encoded_hash: FileHash, encoded_size: EncodedSize) -> Self {
        Self {
            slot,
            encoded_hash,
            encoded_size,
        }
    }

    pub(super) fn file_name(&self) -> OsString {
        self.slot.receipt_name()
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&EgressReceiptRecord::from_receipt(self))
            .expect("egress receipt serialization cannot fail")
    }

    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes::<EgressReceiptRecord>(bytes)
            .ok()
            .and_then(EgressReceiptRecord::into_receipt)
    }

    pub(super) fn matches(&self, slot: EgressSlot) -> bool {
        self.slot == slot
    }

    pub(super) const fn output(&self) -> EncodedIdentity {
        EncodedIdentity::new(self.slot.codec(), self.encoded_hash, self.encoded_size)
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
        let source = match self.backend {
            StorageBackend::Flat => {
                let file = self
                    .open_nar(identity.hash())?
                    .ok_or(StorageError::MissingNar)?;
                if !nar_file_size_matches(&file, identity.size().get())? {
                    return Err(StorageError::NarMismatch);
                }
                StoredNarSource::Flat(file)
            }
            StorageBackend::Chunked => {
                let Some(manifest) = self
                    .chunk_store
                    .validate_manifest(identity.hash())
                    .map_err(super::operations::storage_error_for_chunk_store)?
                else {
                    return Err(StorageError::MissingNar);
                };
                if manifest.identity() != identity {
                    return Err(StorageError::NarMismatch);
                }
                StoredNarSource::Chunked(&self.chunk_store)
            }
        };
        Ok(StoredNar {
            storage: self,
            source,
            identity,
        })
    }

    pub(super) fn select_egress(
        &self,
        raw: &StoredNar<'_>,
        encoding: WireEncoding,
        policy: NarUploadPolicy,
    ) -> Result<NarRepresentation, StorageError> {
        match encoding {
            WireEncoding::Raw => Ok(NarRepresentation::Raw(raw.identity())),
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
    ) -> Result<NarRepresentation, StorageError> {
        let lock = self.destination_lock(slot.lock_key());
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let decision = self.resolve_derivative_work(slot)?;
        let output = match decision {
            DerivativeWork::Reuse(output) => output.identity(),
            DerivativeWork::Generate(contract) => {
                self.materialize_compressed_nar(raw, slot, policy, contract)?
            }
        };
        self.publish_egress_receipt(EgressReceipt::new(slot, output.hash(), output.size()))?;
        Ok(NarRepresentation::Compressed(output))
    }

    fn resolve_derivative_work(&self, slot: EgressSlot) -> Result<DerivativeWork, StorageError> {
        self.read_egress_receipt(slot)?.map_or(
            Ok(DerivativeWork::Generate(GenerationContract::AnyOutput)),
            |receipt| self.work_for_receipt(receipt),
        )
    }

    fn work_for_receipt(&self, receipt: EgressReceipt) -> Result<DerivativeWork, StorageError> {
        match self.inspect_egress_derivative(receipt.output())? {
            ExistingDerivative::Usable(output) => Ok(DerivativeWork::Reuse(output)),
            ExistingDerivative::Missing | ExistingDerivative::Corrupt => Ok(
                DerivativeWork::Generate(GenerationContract::ExactOutput(receipt.output())),
            ),
        }
    }

    fn materialize_compressed_nar(
        &self,
        raw: &StoredNar<'_>,
        slot: EgressSlot,
        policy: NarUploadPolicy,
        contract: GenerationContract,
    ) -> Result<EncodedIdentity, StorageError> {
        StagedDerivative::begin(self)?
            .start_streaming()?
            .encode_canonical_raw_nar(raw, slot, policy, contract)?
            .commit()
    }

    fn inspect_egress_derivative(
        &self,
        output: EncodedIdentity,
    ) -> Result<ExistingDerivative, StorageError> {
        let nar = self.nar_directory()?;
        open_optional_at(&nar, &output.file_name().os_string())?.map_or(
            Ok(ExistingDerivative::Missing),
            |file| {
                Ok(
                    encoded_file_matches(&file, output).map(|matches| match matches {
                        true => ExistingDerivative::Usable(VerifiedDerivative(output)),
                        false => ExistingDerivative::Corrupt,
                    })?,
                )
            },
        )
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
        match read_bounded_regular_file(&directory, &name, MAX_EGRESS_RECEIPT_BYTES)?
            .parse(|bytes| EgressReceipt::parse(bytes).filter(|receipt| receipt.matches(slot)))
        {
            BoundedRegularFile::Valid(receipt) => Ok(Some(receipt)),
            BoundedRegularFile::Missing | BoundedRegularFile::Invalid => Ok(None),
        }
    }

    pub(super) fn remove_orphan_egress_receipts(&self) -> Result<(), StorageError> {
        let directory = self.egress_receipt_directory()?;
        let action = read_dir_names(&directory)?.into_iter().try_fold(
            CleanupAction::Keep,
            |action, name| {
                self.remove_orphan_egress_receipt(&directory, &name)
                    .map(|entry_action| action.combine(entry_action))
            },
        )?;
        if action == CleanupAction::Remove {
            directory.sync_all()?;
        }
        Ok(())
    }

    fn remove_orphan_egress_receipt(
        &self,
        directory: &File,
        name: &OsStr,
    ) -> Result<CleanupAction, StorageError> {
        match read_bounded_regular_file(directory, name, MAX_EGRESS_RECEIPT_BYTES)?
            .parse(|bytes| Self::parse_named_egress_receipt(bytes, name))
        {
            BoundedRegularFile::Missing => Ok(CleanupAction::Keep),
            BoundedRegularFile::Invalid => {
                unlink_at(directory, name)?;
                Ok(CleanupAction::Remove)
            }
            BoundedRegularFile::Valid(receipt) => {
                self.retain_or_remove_egress_receipt(directory, name, receipt)
            }
        }
    }

    fn parse_named_egress_receipt(bytes: &[u8], name: &OsStr) -> Option<EgressReceipt> {
        EgressReceipt::parse(bytes).filter(|receipt| receipt.file_name().as_os_str() == name)
    }

    fn retain_or_remove_egress_receipt(
        &self,
        directory: &File,
        name: &OsStr,
        receipt: EgressReceipt,
    ) -> Result<CleanupAction, StorageError> {
        match self.canonical_raw_status(receipt.slot().raw())? {
            CanonicalRawStatus::Present => Ok(CleanupAction::Keep),
            CanonicalRawStatus::Missing | CanonicalRawStatus::WrongSize => {
                self.remove_egress_receipt(directory, name)
            }
        }
    }

    fn remove_egress_receipt(
        &self,
        directory: &File,
        name: &OsStr,
    ) -> Result<CleanupAction, StorageError> {
        unlink_at(directory, name)?;
        Ok(CleanupAction::Remove)
    }

    pub(super) fn canonical_raw_status(
        &self,
        identity: NarIdentity,
    ) -> Result<CanonicalRawStatus, StorageError> {
        if self.backend == StorageBackend::Chunked {
            return Ok(
                match self
                    .chunk_store
                    .validate_manifest(identity.hash())
                    .map_err(super::operations::storage_error_for_chunk_store)?
                {
                    None => CanonicalRawStatus::Missing,
                    Some(manifest) if manifest.identity() == identity => {
                        CanonicalRawStatus::Present
                    }
                    Some(_) => CanonicalRawStatus::WrongSize,
                },
            );
        }
        self.open_nar(identity.hash())?
            .map_or(Ok(CanonicalRawStatus::Missing), |file| {
                Ok(nar_file_size_matches(&file, identity.size().get()).map(
                    |matches| match matches {
                        true => CanonicalRawStatus::Present,
                        false => CanonicalRawStatus::WrongSize,
                    },
                )?)
            })
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
        .map(|output| (output.file_name(), output.encoded_size()))
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
            source: StoredNarSource::Flat(raw.try_clone()?),
            identity,
        };
        self.materialize_compressed_nar(
            &stored,
            EgressSlot::new(identity, codec),
            NarUploadPolicy::new(u64::MAX, min_free_bytes),
            GenerationContract::AnyOutput,
        )
        .map(|_| ())
    }

    #[cfg(test)]
    pub(super) fn egress_generations(&self) -> u64 {
        self.egress_generations.load(Ordering::Relaxed)
    }
}
