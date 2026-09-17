//! Own the upload resources through receiving, verification, and durable publication.

use std::io::Read;

use crate::object::{NarFileName, NarIdentity};

use super::{
    PublishOutcome, StagingReservation, Storage, StorageError,
    compression::{RawStagingWriter, ReceivedNar, receive_uploaded_nar},
    publication::{NarUploadPolicy, PublishTarget, TemporaryFile},
    recovery::{PublicationState, PublicationTransaction},
};

pub(super) struct Receiving {
    name: NarFileName,
    length: u64,
    policy: NarUploadPolicy,
}

pub(super) struct Complete {
    received: ReceivedNar,
}

/// The state and the resource it describes move together. Only `Receiving`
/// exposes a writer; only `Complete` exposes publication.
pub(super) struct Staged<'storage, State> {
    temporary: UploadTemporary<'storage>,
    transaction: PublicationTransaction,
    reservation: StagingReservation,
    state: State,
}

struct UploadTemporary<'storage> {
    storage: &'storage Storage,
    file: TemporaryFile,
    cleanup_on_drop: bool,
}

impl Drop for UploadTemporary<'_> {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = self.storage.remove_temp(&self.file);
        }
    }
}

impl UploadTemporary<'_> {
    fn commit(
        mut self,
        identity: NarIdentity,
        transaction: PublicationTransaction,
    ) -> Result<PublishOutcome, StorageError> {
        let result = self.storage.commit_temporary(
            PublishTarget::Nar(NarFileName::raw(identity.hash())),
            &self.file,
            transaction,
            |_| Ok(()),
        );
        // The commit protocol performs fallible cleanup on both success and
        // failure. Drop still handles abandonment and unwinding before return.
        self.cleanup_on_drop = false;
        result
    }
}

impl Storage {
    pub(super) fn begin_upload(
        &self,
        name: NarFileName,
        length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
    ) -> Result<Staged<'_, Receiving>, StorageError> {
        if length > policy.max_bytes {
            return Err(StorageError::UploadTooLarge);
        }
        let target = PublishTarget::Nar(name);
        let temp_name = self.next_temp_name(&target);
        let transaction = self
            .recovery
            .begin(&self.temporary_path(&target, &temp_name))?;
        let temporary = UploadTemporary {
            storage: self,
            file: self.create_temp_named(&target, temp_name)?,
            cleanup_on_drop: true,
        };
        Ok(Staged {
            temporary,
            transaction,
            reservation,
            state: Receiving {
                name,
                length,
                policy,
            },
        })
    }
}

impl<'storage> Staged<'storage, Receiving> {
    pub(super) fn receive(
        mut self,
        source: impl Read,
    ) -> Result<Staged<'storage, Complete>, StorageError> {
        self.transaction.transition(PublicationState::Streaming)?;
        let received = self.write_and_verify_uploaded_nar(source)?;
        self.temporary.file.file.sync_all()?;
        self.transaction.transition(PublicationState::Validated)?;
        Ok(Staged {
            temporary: self.temporary,
            transaction: self.transaction,
            reservation: self.reservation,
            state: Complete { received },
        })
    }

    fn write_and_verify_uploaded_nar(
        &mut self,
        source: impl Read,
    ) -> Result<ReceivedNar, StorageError> {
        let mut destination = RawStagingWriter::new(
            &mut self.temporary.file.file,
            &mut self.reservation,
            self.state.policy.min_free_bytes,
        );
        Ok(receive_uploaded_nar(
            source,
            self.state.name,
            self.state.length,
            self.state.policy.max_bytes,
            &mut destination,
        )?)
    }
}

impl Staged<'_, Complete> {
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
            state: Complete { received },
        } = self;
        let storage = temporary.storage;
        let outcome = temporary.commit(received.identity(), transaction)?;
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
