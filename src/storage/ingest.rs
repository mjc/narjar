//! Own the upload resources through receiving, verification, and durable publication.

use std::{
    io::{self, Read},
    os::unix::fs::PermissionsExt,
};

use crate::object::NarFileName;

use super::{
    PublishOutcome, StagingReservation, Storage, StorageError,
    collection::{ActivityLease, ProtectedObject},
    compression::{CapacityCheckedStagingWriter, ReceivedNar, receive_uploaded_nar},
    publication::{NarUploadPolicy, OwnedPublication, PublishTarget, TemporaryFile},
    recovery::PublicationState,
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
    publication: OwnedPublication<'storage>,
    reservation: StagingReservation,
    state: State,
    activity: ActivityLease<'storage>,
}

impl Storage {
    pub(super) fn begin_upload(
        &self,
        name: NarFileName,
        length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
    ) -> Result<Staged<'_, Streaming<UploadRequest>>, StorageError> {
        self.begin_upload_with_temp_setup(name, length, policy, reservation, |temporary| {
            temporary
                .file
                .set_permissions(std::fs::Permissions::from_mode(0o600))
        })
    }

    pub(super) fn begin_upload_with_temp_setup(
        &self,
        name: NarFileName,
        length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
        setup: impl FnOnce(&TemporaryFile) -> io::Result<()>,
    ) -> Result<Staged<'_, Streaming<UploadRequest>>, StorageError> {
        let activity = self.collection.mutation()?;
        let target = PublishTarget::Nar(name);
        let destination = target.destination();
        destination.validate_path()?;
        let temp_name = self.next_temp_name(&target);
        let temporary_path = self.temporary_path(&target, temp_name.clone());
        let transaction = self.recovery.begin(&temporary_path.relative_path())?;
        let temporary = match self.create_temp_named_owned(&target, temp_name) {
            Ok(temporary) => temporary,
            Err(error) => {
                transaction.cancel();
                return Err(error);
            }
        };
        let publication = OwnedPublication::new(temporary, transaction);
        setup(publication.temporary().file())?;
        Ok(Staged {
            publication,
            reservation,
            activity,
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
        self.publication
            .transaction_mut()
            .transition(PublicationState::Streaming)?;
        let received = self.write_and_verify_uploaded_nar(source)?;
        self.publication.temporary().file().file.sync_all()?;
        self.publication
            .transaction_mut()
            .transition(PublicationState::Validated)?;
        self.publication
            .temporary()
            .storage()
            .activity
            .record_upload_validated_logical_bytes(received.identity().size().get());
        Ok(Staged {
            publication: self.publication,
            reservation: self.reservation,
            activity: self.activity,
            state: Validated::new(received),
        })
    }

    fn write_and_verify_uploaded_nar(
        &mut self,
        source: impl Read,
    ) -> Result<ReceivedNar, StorageError> {
        let mut destination = CapacityCheckedStagingWriter::new(
            self.publication.temporary_mut().file_mut(),
            &mut self.reservation,
            self.state.value().policy.min_free_bytes,
        );
        Ok(receive_uploaded_nar(
            source,
            self.state.value().name,
            self.state.value().length,
            self.state.value().policy.max_decoded_bytes,
            self.state.value().policy.decoder_memory_limit,
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
            publication,
            reservation,
            state,
            activity,
        } = self;
        let received = state.into_inner();
        let storage = publication.temporary().storage();
        let identity = received.identity();
        let (temporary, transaction) = publication.into_parts();
        let temporary_file = temporary.into_file();
        let target = PublishTarget::Nar(NarFileName::raw(identity.hash()));
        let outcome = storage.commit_temporary(
            target.destination(),
            &temporary_file,
            transaction,
            &mut checkpoint,
        )?;
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
        activity.protect(ProtectedObject::CanonicalNar(identity.hash()))?;
        drop(reservation);
        Ok(outcome)
    }
}
