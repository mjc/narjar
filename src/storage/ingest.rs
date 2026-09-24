//! Own the upload resources through receiving, verification, and durable publication.

use std::io::Read;

use crate::object::{NarFileName, NarIdentity};

use super::{
    PublishOutcome, StagingReservation, Storage, StorageError,
    compression::{CapacityCheckedStagingWriter, ReceivedNar, receive_uploaded_nar},
    publication::{NarUploadPolicy, PublishTarget, TemporaryFile},
    recovery::{PublicationState, PublicationTransaction},
    typestate::{Streaming, Validated},
};

pub(super) struct UploadRequest {
    name: NarFileName,
    length: u64,
    policy: NarUploadPolicy,
}

/// The state and the resource it describes move together. Only streaming uploads
/// expose a writer; only validated uploads expose publication.
pub(super) struct Staged<'storage, State> {
    temporary: UploadTemporary<'storage>,
    transaction: PublicationTransaction,
    reservation: StagingReservation,
    state: State,
}

struct UploadTemporary<'storage> {
    storage: &'storage Storage,
    file: TemporaryFile,
}

impl Drop for UploadTemporary<'_> {
    fn drop(&mut self) {
        let _ = self.storage.remove_temp(&self.file);
    }
}

impl UploadTemporary<'_> {
    fn commit(
        self,
        identity: NarIdentity,
        transaction: PublicationTransaction,
    ) -> Result<PublishOutcome, StorageError> {
        let target = PublishTarget::Nar(NarFileName::raw(identity.hash()));
        let destination = target.destination();
        self.storage
            .commit_temporary(destination, &self.file, transaction, |_| Ok(()))
    }
}

impl Storage {
    pub(super) fn begin_upload(
        &self,
        name: NarFileName,
        length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
    ) -> Result<Staged<'_, Streaming<UploadRequest>>, StorageError> {
        if length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }
        let target = PublishTarget::Nar(name);
        let destination = target.destination();
        let temp_name = self.next_temp_name(&target);
        let temporary_path = self.temporary_path(&target, temp_name.clone());
        let transaction = self.recovery.begin(
            &temporary_path.relative_path(),
            &destination.relative_path(),
        )?;
        let temporary = UploadTemporary {
            storage: self,
            file: self.create_temp_named(&target, temp_name)?,
        };
        Ok(Staged {
            temporary,
            transaction,
            reservation,
            state: Streaming::new(UploadRequest {
                name,
                length,
                policy,
            }),
        })
    }
}

impl<'storage> Staged<'storage, Streaming<UploadRequest>> {
    pub(super) fn receive(
        mut self,
        source: impl Read,
    ) -> Result<Staged<'storage, Validated<ReceivedNar>>, StorageError> {
        self.transaction.transition(PublicationState::Streaming)?;
        let received = self.write_and_verify_uploaded_nar(source)?;
        self.temporary.file.file.sync_all()?;
        self.transaction.transition(PublicationState::Validated)?;
        self.temporary
            .storage
            .activity
            .record_upload_validated_logical_bytes(received.identity().size().get());
        Ok(Staged {
            temporary: self.temporary,
            transaction: self.transaction,
            reservation: self.reservation,
            state: Validated::new(received),
        })
    }

    fn write_and_verify_uploaded_nar(
        &mut self,
        source: impl Read,
    ) -> Result<ReceivedNar, StorageError> {
        let mut destination = CapacityCheckedStagingWriter::new(
            &mut self.temporary.file.file,
            &mut self.reservation,
            self.state.value().policy.min_free_bytes,
        );
        Ok(receive_uploaded_nar(
            source,
            self.state.value().name,
            self.state.value().length,
            self.state.value().policy.max_bytes,
            &mut destination,
        )?)
    }
}

impl Staged<'_, Validated<ReceivedNar>> {
    pub(super) fn commit(self) -> Result<PublishOutcome, StorageError> {
        self.commit_with_receipt_checkpoint(|_| Ok(()))
    }

    #[cfg(test)]
    pub(super) fn commit_fault(
        self,
        fault: super::publication::PublishBoundary,
    ) -> Result<PublishOutcome, StorageError> {
        self.commit_with_receipt_checkpoint(|boundary| {
            super::publication::injected_fault(boundary, fault)
        })
    }

    fn commit_with_receipt_checkpoint(
        self,
        mut checkpoint: impl FnMut(super::publication::PublishBoundary) -> Result<(), StorageError>,
    ) -> Result<PublishOutcome, StorageError> {
        let Staged {
            temporary,
            transaction,
            reservation,
            state,
        } = self;
        let received = state.into_inner();
        let storage = temporary.storage;
        let identity = received.identity();
        let outcome = temporary.commit(identity, transaction)?;
        storage
            .activity
            .record_upload_publication(outcome, identity.size().get());
        checkpoint(super::publication::PublishBoundary::AfterNarPublication)?;
        match received {
            ReceivedNar::Raw(_) => {}
            ReceivedNar::Compressed(receipt) => {
                storage.publish_ingestion_receipt(receipt)?;
            }
        }
        // Keep the disk reservation until both payload and receipt are durable.
        drop(reservation);
        Ok(outcome)
    }
}
