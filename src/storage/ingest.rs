//! Own the upload resources through receiving, verification, and durable publication.

use std::io::{self, Read};

use crate::cache::object::{EncodedIdentity, NarFileName, NarIdentity};

use super::{
    PublishOutcome, StagingReservation, Storage, StorageError,
    collection::{ActivityLease, ProtectedObject},
    compression::{
        CapacityCheckedStagingWriter, EncodedStagingWriter, ReceivedNar, receive_uploaded_nar,
        receive_uploaded_nar_while_capturing,
    },
    operations::ChunkedNarUpload,
    publication::{
        NarUploadPolicy, OwnedPublication, PublishTarget, StagingInodeReservation, TemporaryFile,
    },
    recovery::PublicationState,
    typestate::{Streaming, Validated},
};
pub(super) struct UploadRequest {
    name: NarFileName,
    length: u64,
    policy: NarUploadPolicy,
}

pub(crate) enum ReadThroughStaging {
    Canonical {
        expected: NarIdentity,
        reservation: StagingReservation,
    },
    Retained {
        expected: NarIdentity,
        canonical: StagingReservation,
        encoded: StagingReservation,
        encoded_identity: EncodedIdentity,
        inodes: StagingInodeReservation,
    },
}

pub(super) enum DecodedNarIdentityRequirement {
    NotProvidedByTheCaller,
    Signed(NarIdentity),
}

impl DecodedNarIdentityRequirement {
    pub(super) fn verify(self, actual: NarIdentity) -> Result<(), StorageError> {
        match self {
            Self::NotProvidedByTheCaller => Ok(()),
            Self::Signed(expected) => match expected == actual {
                true => Ok(()),
                false => Err(StorageError::NarMismatch),
            },
        }
    }
}

struct RetainedReadThroughUpload {
    name: NarFileName,
    expected_length: u64,
    expected_identity: NarIdentity,
    policy: NarUploadPolicy,
    canonical_reservation: StagingReservation,
    encoded_identity: EncodedIdentity,
    encoded_reservation: StagingReservation,
    inode_reservation: StagingInodeReservation,
}

/// The state and the resource it describes move together. Only streaming uploads
/// expose a writer; only validated uploads expose publication.
pub(super) struct Staged<'storage, State> {
    publication: OwnedPublication<'storage>,
    reservation: StagingReservation,
    state: State,
    activity: ActivityLease<'storage>,
}

pub(super) struct ReceivedUpload<'storage> {
    nar: ReceivedNar,
    retained: Option<ValidatedRetainedEncoding<'storage>>,
    inode_reservation: Option<StagingInodeReservation>,
    repair_canonical: bool,
}

pub(super) struct RetainedEncoding<'storage, State> {
    publication: OwnedPublication<'storage>,
    reservation: StagingReservation,
    state: State,
}

type ValidatedRetainedEncoding<'storage> = RetainedEncoding<'storage, Validated<EncodedIdentity>>;

impl<'storage> RetainedEncoding<'storage, Streaming<EncodedIdentity>> {
    pub(super) fn begin(
        storage: &'storage Storage,
        identity: EncodedIdentity,
        reservation: StagingReservation,
    ) -> Result<Self, StorageError> {
        let target = PublishTarget::Nar(identity.file_name());
        let publication = storage.begin_journaled_temporary(&target, || Ok(()))?;
        Ok(Self {
            publication,
            reservation,
            state: Streaming::new(identity),
        })
    }

    fn start_receiving(&mut self) -> Result<(), StorageError> {
        self.publication
            .transaction_mut()
            .transition(PublicationState::Streaming)
    }

    fn capacity_checked_writer(&mut self, min_free_bytes: u64) -> EncodedStagingWriter<'_> {
        let writer = CapacityCheckedStagingWriter::new(
            self.publication.temporary_mut().file_mut(),
            &mut self.reservation,
            min_free_bytes,
        );
        EncodedStagingWriter::new(writer, self.state.value().codec())
    }

    fn validate(
        mut self,
        actual: EncodedIdentity,
    ) -> Result<ValidatedRetainedEncoding<'storage>, StorageError> {
        if *self.state.value() != actual {
            return Err(StorageError::NarMismatch);
        }
        self.publication.temporary().file().file.sync_all()?;
        self.publication
            .transaction_mut()
            .transition(PublicationState::Validated)?;
        Ok(RetainedEncoding {
            publication: self.publication,
            reservation: self.reservation,
            state: Validated::new(actual),
        })
    }
}

impl RetainedEncoding<'_, Validated<EncodedIdentity>> {
    fn commit(self) -> Result<EncodedIdentity, StorageError> {
        let identity = self.state.into_inner();
        let storage = self.publication.temporary().storage();
        let (temporary, transaction) = self.publication.into_parts();
        let temporary_file = temporary.into_file();
        storage.commit_temporary(
            PublishTarget::RepairEgressNar(identity).destination(),
            &temporary_file,
            transaction,
            &mut |_| Ok(()),
        )?;
        drop(self.reservation);
        Ok(identity)
    }
}

impl Storage {
    pub(crate) fn reserve_read_through_staging(
        &self,
        expected_identity: NarIdentity,
        encoded_size: u64,
        min_free_bytes: u64,
        retained: Option<EncodedIdentity>,
    ) -> Result<ReadThroughStaging, StorageError> {
        let canonical = self.reserve_staging(expected_identity.size().get(), min_free_bytes)?;
        match retained {
            Some(identity) if identity.size().get() == encoded_size => {
                let encoded = self.reserve_staging(encoded_size, min_free_bytes)?;
                let directory = self.nar_temp_directory()?;
                let (created_entries, journal_draft_peak) = match &self.payloads {
                    super::state::PayloadStorage::Flat => (4, 1),
                    super::state::PayloadStorage::Chunked(_) => (3, 1),
                };
                let inodes = StagingInodeReservation::reserve(
                    &self.staging_budget,
                    &directory,
                    created_entries + journal_draft_peak,
                )?;
                Ok(ReadThroughStaging::Retained {
                    expected: expected_identity,
                    canonical,
                    encoded,
                    encoded_identity: identity,
                    inodes,
                })
            }
            Some(_) => Err(StorageError::NarMismatch),
            None => Ok(ReadThroughStaging::Canonical {
                expected: expected_identity,
                reservation: canonical,
            }),
        }
    }

    pub(crate) fn publish_read_through_nar(
        &self,
        name: NarFileName,
        source: impl Read,
        expected_length: u64,
        policy: NarUploadPolicy,
        staging: ReadThroughStaging,
    ) -> Result<PublishOutcome, StorageError> {
        match staging {
            ReadThroughStaging::Canonical {
                expected,
                reservation,
            } => match &self.payloads {
                super::state::PayloadStorage::Flat => self
                    .begin_upload(name, expected_length, policy, reservation)?
                    .receive_read_through(source, expected)?
                    .commit(),
                super::state::PayloadStorage::Chunked(store) => self
                    .publish_chunked_nar_with_staging(ChunkedNarUpload {
                        store,
                        name,
                        source,
                        expected_length,
                        policy,
                        reservation,
                        identity_requirement: DecodedNarIdentityRequirement::Signed(expected),
                    }),
            },
            ReadThroughStaging::Retained {
                expected,
                canonical,
                encoded,
                encoded_identity,
                inodes,
            } => match &self.payloads {
                super::state::PayloadStorage::Flat => self
                    .begin_upload(name, expected_length, policy, canonical)?
                    .receive_retaining_encoded(
                        source,
                        expected,
                        encoded_identity,
                        encoded,
                        inodes,
                        policy.min_free_bytes,
                    )?
                    .commit(),
                super::state::PayloadStorage::Chunked(chunk_store) => self
                    .publish_chunked_nar_retaining_encoded(
                        chunk_store,
                        source,
                        RetainedReadThroughUpload {
                            name,
                            expected_length,
                            expected_identity: expected,
                            policy,
                            canonical_reservation: canonical,
                            encoded_identity,
                            encoded_reservation: encoded,
                            inode_reservation: inodes,
                        },
                    ),
            },
        }
    }

    pub(super) fn begin_upload(
        &self,
        name: NarFileName,
        length: u64,
        policy: NarUploadPolicy,
        reservation: StagingReservation,
    ) -> Result<Staged<'_, Streaming<UploadRequest>>, StorageError> {
        self.begin_upload_with_temp_setup(name, length, policy, reservation, |_| Ok(()))
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
        let publication = self.begin_journaled_temporary(&target, || Ok(()))?;
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

    fn publish_chunked_nar_retaining_encoded(
        &self,
        store: &super::chunk_store::ChunkStore,
        source: impl Read,
        upload: RetainedReadThroughUpload,
    ) -> Result<PublishOutcome, StorageError> {
        let RetainedReadThroughUpload {
            name,
            expected_length,
            expected_identity,
            policy,
            canonical_reservation,
            encoded_identity,
            encoded_reservation,
            mut inode_reservation,
        } = upload;
        let activity = self.collection.mutation()?;
        let mut destination = store
            .begin_ingest_with_reservation(
                super::chunked::ChunkProfile::MinCdcHash4V2,
                canonical_reservation,
                policy.min_free_bytes,
            )
            .map_err(super::operations::storage_error_for_chunk_store)?;
        let mut retained = RetainedEncoding::begin(self, encoded_identity, encoded_reservation)?;
        inode_reservation.record_created_staging_entries(3);
        retained.start_receiving()?;
        let mut encoded_writer = retained.capacity_checked_writer(policy.min_free_bytes);
        let received = receive_uploaded_nar_while_capturing(
            source,
            &mut encoded_writer,
            name,
            expected_length,
            policy.max_decoded_bytes,
            policy.decoder_memory_limit,
            &mut destination,
        )?;
        if received.identity() != expected_identity {
            return Err(StorageError::NarMismatch);
        }
        let captured_identity = encoded_writer.finish();
        let retained = retained.validate(captured_identity)?;
        let identity = received.identity();
        let completed = destination
            .finish(identity)
            .map_err(super::operations::storage_error_for_chunk_store)?;
        let outcome = completed.outcome();
        self.activity
            .record_upload_validated_logical_bytes(identity.size().get());
        self.activity
            .record_upload_publication(outcome, identity.size().get());
        completed.release_reservation();
        let output = retained.commit()?;
        self.publish_retained_egress_receipt(identity, output)?;
        self.publish_ingestion_receipt_for_received_nar(received)?;
        activity.protect(ProtectedObject::CanonicalNar(identity.hash()))?;
        Ok(outcome)
    }
}

impl<'storage> Staged<'storage, Streaming<UploadRequest>> {
    pub(super) fn receive(
        mut self,
        source: impl Read,
    ) -> Result<Staged<'storage, Validated<ReceivedUpload<'storage>>>, StorageError> {
        self.publication
            .transaction_mut()
            .transition(PublicationState::Streaming)?;
        let received = self.write_and_verify_uploaded_nar(source)?;
        self.finish_receiving(ReceivedUpload {
            nar: received,
            retained: None,
            inode_reservation: None,
            repair_canonical: false,
        })
    }

    pub(super) fn receive_read_through(
        mut self,
        source: impl Read,
        expected_identity: NarIdentity,
    ) -> Result<Staged<'storage, Validated<ReceivedUpload<'storage>>>, StorageError> {
        self.publication
            .transaction_mut()
            .transition(PublicationState::Streaming)?;
        let received = self.write_and_verify_uploaded_nar(source)?;
        if received.identity() != expected_identity {
            return Err(StorageError::NarMismatch);
        }
        self.finish_receiving(ReceivedUpload {
            nar: received,
            retained: None,
            inode_reservation: None,
            repair_canonical: true,
        })
    }

    pub(super) fn receive_retaining_encoded(
        mut self,
        source: impl Read,
        expected_identity: NarIdentity,
        encoded_identity: EncodedIdentity,
        encoded_reservation: StagingReservation,
        mut inode_reservation: StagingInodeReservation,
        min_free_bytes: u64,
    ) -> Result<Staged<'storage, Validated<ReceivedUpload<'storage>>>, StorageError> {
        self.publication
            .transaction_mut()
            .transition(PublicationState::Streaming)?;
        let storage = self.publication.temporary().storage();
        let mut retained = RetainedEncoding::begin(storage, encoded_identity, encoded_reservation)?;
        inode_reservation.record_created_staging_entries(4);
        retained.start_receiving()?;
        let mut encoded_writer = retained.capacity_checked_writer(min_free_bytes);
        let received =
            self.write_and_verify_uploaded_nar_while_capturing(source, &mut encoded_writer)?;
        if received.identity() != expected_identity {
            return Err(StorageError::NarMismatch);
        }
        let captured_identity = encoded_writer.finish();
        let retained = retained.validate(captured_identity)?;
        self.finish_receiving(ReceivedUpload {
            nar: received,
            retained: Some(retained),
            inode_reservation: Some(inode_reservation),
            repair_canonical: true,
        })
    }

    fn finish_receiving(
        mut self,
        received: ReceivedUpload<'storage>,
    ) -> Result<Staged<'storage, Validated<ReceivedUpload<'storage>>>, StorageError> {
        self.publication.temporary().file().file.sync_all()?;
        self.publication
            .transaction_mut()
            .transition(PublicationState::Validated)?;
        self.publication
            .temporary()
            .storage()
            .activity
            .record_upload_validated_logical_bytes(received.nar.identity().size().get());
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

    fn write_and_verify_uploaded_nar_while_capturing(
        &mut self,
        source: impl Read,
        captured: &mut EncodedStagingWriter<'_>,
    ) -> Result<ReceivedNar, StorageError> {
        let request = self.state.value();
        let mut destination = CapacityCheckedStagingWriter::new(
            self.publication.temporary_mut().file_mut(),
            &mut self.reservation,
            request.policy.min_free_bytes,
        );
        Ok(receive_uploaded_nar_while_capturing(
            source,
            captured,
            request.name,
            request.length,
            request.policy.max_decoded_bytes,
            request.policy.decoder_memory_limit,
            &mut destination,
        )?)
    }
}

impl Staged<'_, Validated<ReceivedUpload<'_>>> {
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
        let ReceivedUpload {
            nar: received,
            retained,
            inode_reservation,
            repair_canonical,
        } = state.into_inner();
        let storage = publication.temporary().storage();
        let identity = received.identity();
        let (temporary, transaction) = publication.into_parts();
        let temporary_file = temporary.into_file();
        let target = match repair_canonical {
            true => PublishTarget::RepairCanonicalNar(identity),
            false => PublishTarget::Nar(NarFileName::raw(identity.hash())),
        };
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
        if let Some(retained) = retained {
            let output = retained.commit()?;
            storage.publish_retained_egress_receipt(identity, output)?;
        }
        match received {
            ReceivedNar::Raw(_) => {}
            ReceivedNar::Compressed(receipt) => {
                storage.publish_ingestion_receipt(receipt)?;
            }
        }
        // Keep the disk reservation until both payload and receipt are durable.
        activity.protect(ProtectedObject::CanonicalNar(identity.hash()))?;
        drop(reservation);
        drop(inode_reservation);
        Ok(outcome)
    }
}
