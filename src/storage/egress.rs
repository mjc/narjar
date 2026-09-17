use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Cursor, Read, Write},
    path::PathBuf,
};

#[cfg(test)]
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

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
use super::receipt::parse_legacy_fields;
use super::recovery::PublicationState;
use super::state::Storage;

const LEGACY_EGRESS_RECEIPT_VERSION: u8 = 1;
const EGRESS_RECEIPT_VERSION: u8 = 2;
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

enum BoundedFile {
    Missing,
    Invalid,
    Present(Vec<u8>),
}

#[derive(Debug)]
pub(super) enum CanonicalRawStatus {
    Missing,
    WrongSize,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupAction {
    Keep,
    Remove,
}

impl CleanupAction {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Remove, _) | (_, Self::Remove) => Self::Remove,
            (Self::Keep, Self::Keep) => Self::Keep,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EgressReceiptRecord {
    version: u8,
    #[serde(rename = "raw-hash")]
    raw_hash: String,
    #[serde(rename = "raw-size")]
    raw_size: u64,
    encoding: CompressionCodec,
    #[serde(rename = "encoded-hash")]
    encoded_hash: String,
    #[serde(rename = "encoded-size")]
    encoded_size: u64,
}

impl EgressReceiptRecord {
    fn from_receipt(receipt: &EgressReceipt) -> Self {
        Self {
            version: EGRESS_RECEIPT_VERSION,
            raw_hash: receipt.slot.raw().hash().to_string(),
            raw_size: receipt.slot.raw().size().get(),
            encoding: receipt.slot.codec(),
            encoded_hash: receipt.output.hash().to_string(),
            encoded_size: receipt.output.size().get(),
        }
    }

    fn into_receipt(self) -> Option<EgressReceipt> {
        (self.version == EGRESS_RECEIPT_VERSION).then_some(())?;
        let raw = NarIdentity::new(NarHash::parse(&self.raw_hash).ok()?, self.raw_size.into());
        Some(EgressReceipt::new(
            EgressSlot::new(raw, self.encoding),
            EncodedIdentity::new(
                self.encoding,
                crate::object::FileHash::parse(&self.encoded_hash).ok()?,
                self.encoded_size.into(),
            ),
        ))
    }
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
    fn verify(self, output: EncodedIdentity) -> Result<EncodedIdentity, StorageError> {
        match self {
            Self::AnyOutput => Ok(output),
            Self::ExactOutput(expected) if expected == output => Ok(output),
            Self::ExactOutput(_) => Err(StorageError::NarMismatch),
        }
    }
}

struct StagedDerivativeFile<'storage> {
    storage: &'storage Storage,
    file: Option<TemporaryFile>,
}

impl StagedDerivativeFile<'_> {
    fn file_mut(&mut self) -> &mut File {
        &mut self
            .file
            .as_mut()
            .expect("staged derivative owns its temporary file")
            .file
    }

    fn take_file(&mut self) -> TemporaryFile {
        self.file
            .take()
            .expect("staged derivative owns its temporary file")
    }
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
        contract: GenerationContract,
    ) -> Result<ReadyDerivative<'storage>, StorageError> {
        let Self {
            mut file,
            mut transaction,
        } = self;
        let storage = file.storage;
        transaction.transition(PublicationState::Streaming)?;
        let mut reservation = storage.empty_staging_reservation(policy.min_free_bytes())?;
        #[cfg(test)]
        storage.egress_generations.fetch_add(1, Ordering::Relaxed);
        let output = {
            let mut destination = CapacityCheckedStagingWriter::new(
                file.file_mut(),
                &mut reservation,
                policy.min_free_bytes(),
            );
            let output = encode_raw_nar(&raw.file, slot.codec(), &mut destination)?;
            destination.flush()?;
            output
        };
        let output = EncodedIdentity::new(slot.codec(), output.hash, output.size);
        let output = contract.verify(output)?;
        file.file_mut().sync_all()?;
        transaction.transition(PublicationState::Validated)?;
        Ok(ReadyDerivative {
            file,
            transaction,
            output,
        })
    }
}

impl ReadyDerivative<'_> {
    fn commit(mut self) -> Result<EncodedIdentity, StorageError> {
        let temporary = self.file.take_file();
        let target = PublishTarget::RepairEgressNar(self.output);
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
        serde_json::to_vec(&EgressReceiptRecord::from_receipt(self))
            .expect("egress receipt serialization cannot fail")
    }

    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice::<EgressReceiptRecord>(bytes)
            .ok()
            .and_then(EgressReceiptRecord::into_receipt)
            .or_else(|| parse_legacy_egress_receipt(bytes))
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

fn parse_legacy_egress_receipt(bytes: &[u8]) -> Option<EgressReceipt> {
    let fields = parse_legacy_fields(bytes, 6)?;
    let version = fields.get("version")?.parse::<u8>().ok()?;
    (version == LEGACY_EGRESS_RECEIPT_VERSION).then_some(())?;
    let codec = fields.get("encoding")?.parse().ok()?;
    Some(EgressReceipt::new(
        EgressSlot::new(
            NarIdentity::new(
                NarHash::parse(fields.get("raw-hash")?).ok()?,
                fields.get("raw-size")?.parse::<u64>().ok()?.into(),
            ),
            codec,
        ),
        EncodedIdentity::new(
            codec,
            crate::object::FileHash::parse(fields.get("encoded-hash")?).ok()?,
            fields.get("encoded-size")?.parse::<u64>().ok()?.into(),
        ),
    ))
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
        let decision = self.resolve_derivative_work(slot)?;
        let output = match decision {
            DerivativeWork::Reuse(output) => output.identity(),
            DerivativeWork::Generate(contract) => {
                self.materialize_compressed_nar(raw, slot, policy, contract)?
            }
        };
        self.publish_egress_receipt(EgressReceipt::new(slot, output))?;
        Ok(EgressRepresentation::Compressed(output))
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
        let staged = StagedDerivative::begin(self)?;
        let ready = staged.encode(raw, slot, policy, contract)?;
        ready.commit()
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
        match read_bounded_regular_file(&directory, &name, MAX_EGRESS_RECEIPT_BYTES)? {
            BoundedFile::Missing | BoundedFile::Invalid => Ok(None),
            BoundedFile::Present(bytes) => {
                Ok(EgressReceipt::parse(&bytes).filter(|receipt| receipt.matches(slot)))
            }
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
        match read_bounded_regular_file(directory, name, MAX_EGRESS_RECEIPT_BYTES)? {
            BoundedFile::Missing => Ok(CleanupAction::Keep),
            BoundedFile::Invalid => {
                unlink_at(directory, name)?;
                Ok(CleanupAction::Remove)
            }
            BoundedFile::Present(bytes) => Self::parse_named_egress_receipt(&bytes, name)
                .map_or_else(
                    || self.remove_egress_receipt(directory, name),
                    |receipt| self.retain_or_remove_egress_receipt(directory, name, receipt),
                ),
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
            GenerationContract::AnyOutput,
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
) -> Result<BoundedFile, StorageError> {
    let file = match open_regular_at(directory, name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BoundedFile::Missing),
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(BoundedFile::Invalid);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Ok(BoundedFile::Invalid);
    }
    Ok(BoundedFile::Present(bytes))
}
