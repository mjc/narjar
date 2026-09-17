use std::{
    env, fs,
    io::{self, Cursor, Read, Write},
    num::NonZeroUsize,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, SystemTime},
};

use super::compression::{
    CheckedUploadReader, DecodedValidation, nar_file_size_matches, receive_uploaded_nar,
    verify_decoded_compressed_file, verify_encoded_compressed_file,
};
use super::fs::{FilesystemSpace, remove_temp, reserve_staging_bytes_for_test, sync_dir};
use super::ids::nix32_sha256;
use super::publication::{Layout, PublishBoundary, PublishTarget};
use super::{
    CapacityErrorKind, Directory, PublishOutcome, ReconcileClass, Storage, StorageError, StoreHash,
    capacity_error_kind,
};
use crate::narinfo::{CompressedNarExpectation, NarEncoding};
use crate::object::{
    CompressionCodec, EncodedSize, FileHash, NarFileName, NarHash, NarIdentity, NarSize,
};
use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use structured_zstd::encoding::{CompressionLevel, compress};

const NAR_ID: &str = "0000000000000000000000000000000000000000000000000000";
const STORE_HASH: &str = "00000000000000000000000000000000";

fn initialize_storage(path: &Path) -> Result<Storage, StorageError> {
    Storage::initialize(&Directory::open(path)?)
}

fn compressed_bytes(encoding: NarEncoding, raw: &[u8]) -> Vec<u8> {
    match encoding {
        NarEncoding::Xz => {
            let mut compressed = Vec::new();
            let mut writer = XzWriter::new(&mut compressed, XzOptions::with_preset(1)).unwrap();
            writer.write_all(raw).unwrap();
            writer.finish().unwrap();
            compressed
        }
        NarEncoding::Zstd => {
            let mut compressed = Vec::new();
            compress(Cursor::new(raw), &mut compressed, CompressionLevel::Fastest);
            compressed
        }
        NarEncoding::Raw => panic!("test helper only compresses XZ and Zstd"),
    }
}

fn begin_raw_upload<'storage>(
    storage: &'storage Storage,
    bytes: &[u8],
) -> super::ingest::Staged<'storage, super::ingest::Receiving> {
    let name = NarFileName::new(
        FileHash::from_digest(Sha256::digest(bytes).into()),
        NarEncoding::Raw,
    );
    let length = bytes.len() as u64;
    let reservation = storage.reserve_staging(length, 0).unwrap();
    storage
        .begin_upload(
            name,
            length,
            super::NarUploadPolicy::new(length, 0),
            reservation,
        )
        .unwrap()
}

fn assert_upload_resources_released(storage: &Storage) {
    assert_eq!(
        storage.temporary_objects(),
        0,
        "temporary accounting must be released"
    );
    assert_eq!(
        storage.staging_budget.lock().unwrap().outstanding_bytes(),
        0,
        "the upload must release its disk reservation"
    );
    assert_eq!(
        fs::read_dir(storage.layout().nar_temp_dir())
            .unwrap()
            .count(),
        0,
        "dropping an upload must unlink its temporary file"
    );
}

#[test]
fn abandoning_a_receiving_upload_releases_its_file_and_reservation() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let receiving = begin_raw_upload(&storage, b"raw NAR");
    assert_eq!(storage.temporary_objects(), 1);
    assert_eq!(
        storage.staging_budget.lock().unwrap().outstanding_bytes(),
        7
    );
    drop(receiving);
    assert_upload_resources_released(&storage);
}

#[test]
fn completing_an_upload_does_not_publish_it_and_abandonment_still_cleans_up() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let bytes = b"raw NAR";
    let complete = begin_raw_upload(&storage, bytes)
        .receive(bytes.as_slice())
        .unwrap();
    let hash = NarHash::from_digest(Sha256::digest(bytes).into());
    assert!(
        storage.open_nar(hash).unwrap().is_none(),
        "receive must not publish"
    );
    assert_eq!(
        storage.temporary_objects(),
        1,
        "the complete state still owns staging"
    );
    assert_eq!(
        storage.staging_budget.lock().unwrap().outstanding_bytes(),
        0,
        "materialized raw bytes must no longer occupy outstanding reservation capacity"
    );
    drop(complete);
    assert_upload_resources_released(&storage);
    assert!(storage.open_nar(hash).unwrap().is_none());
}

#[test]
fn a_completed_upload_commits_its_own_bytes_and_releases_resources() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let bytes = b"raw NAR";
    let complete = begin_raw_upload(&storage, bytes)
        .receive(FailsIfReadAfterEof::new(bytes))
        .unwrap();
    assert_eq!(complete.commit().unwrap(), PublishOutcome::Created);
    assert_upload_resources_released(&storage);
    let hash = NarHash::from_digest(Sha256::digest(bytes).into());
    assert_eq!(fs::read(storage.layout().nar_path(hash)).unwrap(), bytes);
}

#[test]
fn source_errors_and_unwinding_release_upload_resources() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let failed = begin_raw_upload(&storage, b"raw NAR").receive(BrokenReader::new(libc::EIO));
    assert!(
        matches!(failed, Err(StorageError::Io(error)) if error.raw_os_error() == Some(libc::EIO))
    );
    assert_upload_resources_released(&storage);

    struct PanickingReader;
    impl Read for PanickingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("injected upload reader panic");
        }
    }
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = begin_raw_upload(&storage, b"raw NAR").receive(PanickingReader);
    }));
    assert!(unwound.is_err());
    assert_upload_resources_released(&storage);
}

#[test]
fn a_commit_destination_open_failure_still_cleans_the_owned_staging_file() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let complete = begin_raw_upload(&storage, b"raw NAR")
        .receive(&b"raw NAR"[..])
        .unwrap();
    let moved = directory.path().join("moved-nar");
    fs::rename(storage.layout().nar_dir(), &moved).unwrap();
    symlink(&moved, storage.layout().nar_dir()).unwrap();
    assert!(
        complete.commit().is_err(),
        "publication must reject the replaced directory"
    );
    assert_upload_resources_released(&storage);
    assert_eq!(
        fs::read_dir(&moved).unwrap().count(),
        1,
        "only the empty .tmp directory remains"
    );
}

#[test]
fn upload_reader_checks_encoded_hash_and_length() {
    let bytes = b"encoded NAR bytes";
    let expected =
        FileHash::parse(&nix32_sha256(&Sha256::digest(bytes))).expect("file hash is valid");
    let mut reader = CheckedUploadReader::new(Cursor::new(bytes), &expected, bytes.len() as u64);
    let mut received = [0; 17];
    reader
        .read_exact(&mut received)
        .expect("matching upload should be readable");
    assert_eq!(&received, bytes);
    reader
        .finish()
        .expect("matching upload should complete successfully");

    let wrong_hash = FileHash::parse(NAR_ID).expect("file hash is valid");
    let mut reader = CheckedUploadReader::new(Cursor::new(bytes), &wrong_hash, bytes.len() as u64);
    reader
        .read_exact(&mut [0; 17])
        .expect("reading the upload body should succeed before completion");
    let error = match reader.finish() {
        Ok(_) => panic!("wrong encoded hash should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn upload_reader_finish_does_not_read_after_validating_eof() {
    let bytes = b"encoded NAR bytes";
    let expected =
        FileHash::parse(&nix32_sha256(&Sha256::digest(bytes))).expect("file hash is valid");
    let mut reader = CheckedUploadReader::new(
        FailsIfReadAfterEof::new(bytes),
        &expected,
        bytes.len() as u64,
    );
    let mut received = Vec::new();
    reader
        .read_to_end(&mut received)
        .expect("matching upload should be readable");
    assert_eq!(received, bytes);
    reader
        .finish()
        .expect("finish should reuse the validated EOF");
}

struct FailsIfReadAfterEof {
    bytes: &'static [u8],
    delivered: bool,
    eof_reported: bool,
}

impl FailsIfReadAfterEof {
    fn new(bytes: &'static [u8]) -> Self {
        Self {
            bytes,
            delivered: false,
            eof_reported: false,
        }
    }
}

impl Read for FailsIfReadAfterEof {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.delivered {
            buffer[..self.bytes.len()].copy_from_slice(self.bytes);
            self.delivered = true;
            return Ok(self.bytes.len());
        }
        if !self.eof_reported {
            self.eof_reported = true;
            return Ok(0);
        }
        Err(io::Error::other("read after EOF"))
    }
}

#[test]
fn normalized_compressed_source_errors_remain_io_errors() {
    for encoding in [NarEncoding::Xz, NarEncoding::Zstd] {
        let directory = TestDir::new();
        let destination = directory.path().join("raw.nar");
        let mut destination = fs::File::create(destination).expect("create raw staging file");
        let error = receive_uploaded_nar(
            BrokenReader::new(libc::EIO),
            NarFileName::new(
                FileHash::parse(NAR_ID).expect("file hash is valid"),
                encoding,
            ),
            3,
            u64::MAX,
            &mut destination,
        )
        .expect_err("source failure must not become invalid content");
        assert_eq!(error.raw_os_error(), Some(libc::EIO), "{encoding:?}");
    }
}

#[test]
fn xz_uploads_are_normalized_to_the_raw_nar() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ writer");
    writer.write_all(raw).expect("compress NAR");
    writer.finish().expect("finish XZ stream");
    let encoded = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed)))
        .expect("compressed hash is a valid file hash");
    let raw =
        NarHash::parse(&nix32_sha256(&Sha256::digest(raw))).expect("raw hash is a valid NAR hash");

    let outcome = storage
        .publish_nar(
            NarFileName::new(encoded, NarEncoding::Xz),
            Cursor::new(&compressed),
            compressed.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        )
        .expect("publish XZ NAR");
    assert_eq!(outcome, PublishOutcome::Created);
    assert_eq!(
        fs::read(storage.layout().nar_path(raw)).expect("read stored raw NAR"),
        b"nar bytes"
    );
    assert!(!directory.path().join(format!("{encoded}.nar.xz")).exists());
}

#[test]
fn encoded_verification_precedes_xz_nar_identity_verification() {
    let directory = TestDir::new();
    let path = directory.path().join("nar.xz");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ writer");
    writer.write_all(raw).expect("compress NAR");
    writer.finish().expect("finish XZ stream");
    fs::write(&path, &compressed).expect("write XZ NAR");
    let file = fs::File::open(path).expect("open XZ NAR");
    let nar_hash = NarHash::parse(&nix32_sha256(&Sha256::digest(raw))).expect("NAR hash is valid");
    let file_hash =
        FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed))).expect("file hash is valid");

    let expectation = CompressedNarExpectation::new(
        CompressionCodec::Xz,
        file_hash,
        EncodedSize::new(compressed.len() as u64),
        NarIdentity::new(nar_hash, NarSize::new(raw.len() as u64)),
    );
    let verified = verify_encoded_compressed_file(&file, expectation)
        .expect("verify encoded XZ NAR")
        .expect("encoded XZ NAR matches");

    assert_eq!(
        verify_decoded_compressed_file(verified)
            .expect("verify decoded XZ NAR")
            .expect("decoded XZ NAR matches"),
        DecodedValidation {
            hash: nar_hash,
            size: NarSize::new(raw.len() as u64),
        }
    );
}

#[test]
fn compressed_matching_still_checks_both_hashes_and_sizes() {
    let raw = b"nar bytes";
    let mut xz = Vec::new();
    let mut writer = XzWriter::new(&mut xz, XzOptions::with_preset(1)).unwrap();
    writer.write_all(raw).unwrap();
    writer.finish().unwrap();
    let mut zstd = Vec::new();
    compress(Cursor::new(raw), &mut zstd, CompressionLevel::Fastest);
    let nar_hash = NarHash::parse(&nix32_sha256(&Sha256::digest(raw))).unwrap();
    let wrong_file_hash = FileHash::parse(&"0".repeat(52)).unwrap();
    let wrong_nar_hash = NarHash::parse(&"0".repeat(52)).unwrap();

    for (encoding, compressed) in [(NarEncoding::Xz, xz), (NarEncoding::Zstd, zstd)] {
        let directory = TestDir::new();
        let path = directory.path().join("compressed-nar");
        fs::write(&path, &compressed).unwrap();
        let file_hash = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed))).unwrap();
        let file_size = EncodedSize::new(compressed.len() as u64);
        let nar_size = NarSize::new(raw.len() as u64);
        let matches = |encoded_hash: &FileHash,
                       decoded_hash: &NarHash,
                       encoded_size: EncodedSize,
                       decoded_size: NarSize| {
            let expectation = CompressedNarExpectation::new(
                match encoding {
                    NarEncoding::Xz => CompressionCodec::Xz,
                    NarEncoding::Zstd => CompressionCodec::Zstd,
                    NarEncoding::Raw => unreachable!("test only supplies compressed encodings"),
                },
                *encoded_hash,
                encoded_size,
                NarIdentity::new(*decoded_hash, decoded_size),
            );
            let file = fs::File::open(&path).unwrap();
            let Some(verified) = verify_encoded_compressed_file(&file, expectation).unwrap() else {
                return false;
            };
            verify_decoded_compressed_file(verified).unwrap().is_some()
        };
        assert!(matches(&file_hash, &nar_hash, file_size, nar_size));
        assert!(!matches(&wrong_file_hash, &nar_hash, file_size, nar_size));
        assert!(!matches(&file_hash, &wrong_nar_hash, file_size, nar_size));
        assert!(!matches(
            &file_hash,
            &nar_hash,
            EncodedSize::new(file_size.get() + 1),
            nar_size
        ));
        assert!(!matches(
            &file_hash,
            &nar_hash,
            file_size,
            NarSize::new(nar_size.get() + 1)
        ));
    }
}

#[test]
fn zstd_uploads_are_normalized_to_the_raw_nar() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    compress(Cursor::new(raw), &mut compressed, CompressionLevel::Fastest);
    let encoded = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed)))
        .expect("compressed hash is a valid file hash");
    let raw_hash =
        NarHash::parse(&nix32_sha256(&Sha256::digest(raw))).expect("raw hash is a valid NAR hash");

    let outcome = storage
        .publish_nar(
            NarFileName::new(encoded, NarEncoding::Zstd),
            Cursor::new(&compressed),
            compressed.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        )
        .expect("publish zstd NAR");
    assert_eq!(outcome, PublishOutcome::Created);
    assert_eq!(
        fs::read(storage.layout().nar_path(raw_hash)).expect("read stored raw NAR"),
        b"nar bytes"
    );
    assert!(!directory.path().join(format!("{encoded}.nar.zst")).exists());
}

#[test]
fn a_restart_after_raw_commit_retries_receipt_publication() {
    for encoding in [NarEncoding::Xz, NarEncoding::Zstd] {
        let directory = TestDir::new();
        let raw = b"nar bytes";
        let compressed = compressed_bytes(encoding, raw);
        let encoded = FileHash::from_digest(Sha256::digest(&compressed).into());
        let storage = initialize_storage(directory.path()).expect("initialize storage");
        let reservation = storage
            .reserve_staging(compressed.len() as u64, 0)
            .expect("reserve compressed upload");
        let complete = storage
            .begin_upload(
                NarFileName::new(encoded, encoding),
                compressed.len() as u64,
                super::NarUploadPolicy::new(1024, 0),
                reservation,
            )
            .expect("begin compressed upload")
            .receive(Cursor::new(&compressed))
            .expect("receive compressed upload");

        assert!(
            complete
                .commit_fault(PublishBoundary::AfterNarPublication)
                .is_err(),
            "receipt boundary should simulate lost acknowledgement"
        );
        let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
        assert_eq!(
            fs::read(storage.layout().nar_path(raw_hash)).unwrap(),
            raw,
            "the canonical raw object is durable before receipt publication"
        );
        assert_eq!(
            fs::read_dir(storage.layout().ingestion_receipt_dir())
                .unwrap()
                .count(),
            0,
            "the failed receipt publication must not leave partial evidence"
        );
        drop(storage);

        let restarted = initialize_storage(directory.path()).expect("restart storage");
        let outcome = restarted
            .publish_nar(
                NarFileName::new(encoded, encoding),
                Cursor::new(&compressed),
                compressed.len() as u64,
                super::NarUploadPolicy::new(1024, 0),
            )
            .expect("retry compressed upload");
        assert_eq!(outcome, PublishOutcome::Identical);
        assert_eq!(
            fs::read_dir(restarted.layout().ingestion_receipt_dir())
                .unwrap()
                .count(),
            1,
            "the retry must publish exactly one durable receipt"
        );
    }
}

#[test]
fn recovery_removes_receipts_without_a_usable_raw_object() {
    for encoding in [NarEncoding::Xz, NarEncoding::Zstd] {
        let directory = TestDir::new();
        let raw = b"nar bytes";
        let compressed = compressed_bytes(encoding, raw);
        let encoded = FileHash::from_digest(Sha256::digest(&compressed).into());
        let storage = initialize_storage(directory.path()).expect("initialize storage");
        storage
            .publish_nar(
                NarFileName::new(encoded, encoding),
                Cursor::new(&compressed),
                compressed.len() as u64,
                super::NarUploadPolicy::new(1024, 0),
            )
            .expect("publish compressed upload");
        storage
            .finish_recovery()
            .expect("retain a receipt with a usable raw object");
        let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
        fs::remove_file(storage.layout().nar_path(raw_hash)).expect("remove raw object");
        drop(storage);

        let restarted = initialize_storage(directory.path()).expect("restart storage");
        assert_eq!(
            fs::read_dir(restarted.layout().ingestion_receipt_dir())
                .unwrap()
                .count(),
            1,
            "restart must see the stale receipt before recovery"
        );
        restarted
            .finish_recovery()
            .expect("clean the receipt for the missing raw object");
        assert_eq!(
            fs::read_dir(restarted.layout().ingestion_receipt_dir())
                .unwrap()
                .count(),
            0,
            "recovery must remove unusable receipt evidence"
        );
    }
}

#[test]
fn compressed_uploads_converge_on_one_raw_object() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    compress(Cursor::new(raw), &mut compressed, CompressionLevel::Fastest);
    let mut xz = Vec::new();
    let mut writer = XzWriter::new(&mut xz, XzOptions::with_preset(1)).unwrap();
    writer.write_all(raw).unwrap();
    writer.finish().unwrap();
    let xz_id = FileHash::parse(&nix32_sha256(&Sha256::digest(&xz))).unwrap();
    let zstd_id = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed))).unwrap();
    let raw_hash = NarHash::parse(&nix32_sha256(&Sha256::digest(raw))).unwrap();

    let xz_result = storage
        .publish_nar(
            NarFileName::new(xz_id, NarEncoding::Xz),
            Cursor::new(&xz),
            xz.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        )
        .expect("publish XZ NAR");
    let zstd_result = storage
        .publish_nar(
            NarFileName::new(zstd_id, NarEncoding::Zstd),
            Cursor::new(&compressed),
            compressed.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        )
        .expect("publish Zstd NAR");

    assert_eq!(xz_result, PublishOutcome::Created);
    assert_eq!(zstd_result, PublishOutcome::Identical);
    assert_eq!(fs::read(storage.layout().nar_path(raw_hash)).unwrap(), raw);
    assert!(
        !storage
            .layout()
            .nar_path_encoded(NarFileName::new(xz_id, NarEncoding::Xz))
            .exists()
    );
    assert!(
        !storage
            .layout()
            .nar_path_encoded(NarFileName::new(zstd_id, NarEncoding::Zstd))
            .exists()
    );
}

#[test]
fn compressed_egress_respects_the_staging_capacity_reserve() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let raw = (0_u32..2_000_000)
        .map(|index| index.wrapping_mul(37) as u8)
        .collect::<Vec<_>>();
    let raw_hash = NarHash::from_digest(Sha256::digest(&raw).into());
    storage
        .publish_nar_unchecked(&raw_hash, Cursor::new(&raw))
        .expect("raw NAR should be stored");
    let raw_file = storage
        .open_nar(raw_hash)
        .expect("raw NAR should open")
        .expect("raw NAR should exist");
    let min_free_bytes = u64::MAX;
    let result = storage.materialize_compressed_nar_for_test(
        &raw_file,
        NarIdentity::new(raw_hash, (raw.len() as u64).into()),
        CompressionCodec::Zstd,
        min_free_bytes,
    );

    assert!(
        matches!(result, Err(StorageError::InsufficientSpace))
            || matches!(
                result,
                Err(StorageError::Io(error))
                    if error.raw_os_error() == Some(libc::ENOSPC)
            ),
        "egress must respect the configured free-space reserve"
    );
    assert_eq!(storage.temporary_objects(), 0);
    assert_eq!(
        fs::read_dir(storage.layout().nar_temp_dir())
            .unwrap()
            .count(),
        0,
        "failed egress must remove its temporary payload"
    );
}

#[test]
fn repeated_compressed_egress_reuses_its_durable_derivative() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let raw = b"raw NAR for durable egress reuse";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    storage
        .publish_nar_unchecked(&raw_hash, Cursor::new(raw))
        .expect("raw NAR should be stored");

    let first = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
        .expect("first derivative should be created");
    assert_eq!(storage.egress_generations(), 1);
    let second = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, u64::MAX)
        .expect("second publication should reuse the derivative");

    assert_eq!(second, first);
    assert_eq!(storage.egress_generations(), 1);
    assert_eq!(
        fs::read_dir(storage.layout().egress_receipt_dir())
            .expect("egress receipt directory should be readable")
            .count(),
        1
    );
    assert!(storage.layout().nar_path_encoded(first.0).is_file());
}

#[test]
fn restarting_storage_reuses_a_durable_compressed_derivative() {
    let directory = TestDir::new();
    let raw = b"raw NAR for restart reuse";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    let (first, initial_generations) = {
        let storage = initialize_storage(directory.path()).expect("storage should initialize");
        storage
            .publish_nar_unchecked(&raw_hash, Cursor::new(raw))
            .expect("raw NAR should be stored");
        let output = storage
            .compressed_representation_for_test(identity, CompressionCodec::Xz, 0)
            .expect("first derivative should be created");
        (output, storage.egress_generations())
    };
    assert_eq!(initial_generations, 1);

    let restarted = initialize_storage(directory.path()).expect("storage should restart");
    let second = restarted
        .compressed_representation_for_test(identity, CompressionCodec::Xz, u64::MAX)
        .expect("restart should reuse the derivative");

    assert_eq!(second, first);
    assert_eq!(restarted.egress_generations(), 0);
}

#[test]
fn missing_compressed_derivative_is_rebuilt_from_its_receipt() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let raw = b"raw NAR with a removable derivative";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    storage
        .publish_nar_unchecked(&raw_hash, Cursor::new(raw))
        .expect("raw NAR should be stored");

    let first = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
        .expect("first derivative should be created");
    fs::remove_file(storage.layout().nar_path_encoded(first.0))
        .expect("derivative should be removable for the recovery test");

    let rebuilt = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
        .expect("missing derivative should be rebuilt");

    assert_eq!(rebuilt, first);
    assert!(storage.layout().nar_path_encoded(rebuilt.0).is_file());
}

#[test]
fn missing_compressed_derivative_must_reproduce_its_receipt_identity() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let raw = b"raw NAR with a binding receipt";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    storage
        .publish_nar_unchecked(&raw_hash, Cursor::new(raw))
        .expect("raw NAR should be stored");

    let output = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
        .expect("derivative should be created");
    fs::remove_file(storage.layout().nar_path_encoded(output.0))
        .expect("derivative should be removable for the binding test");
    let receipt_path = fs::read_dir(storage.layout().egress_receipt_dir())
        .expect("egress receipt directory should be readable")
        .next()
        .expect("egress receipt should exist")
        .expect("egress receipt should be readable")
        .path();
    let receipt = String::from_utf8(fs::read(&receipt_path).expect("receipt should be readable"))
        .expect("receipt should be UTF-8");
    let rewritten = receipt
        .lines()
        .map(|line| {
            line.strip_prefix("encoded-hash=").map_or_else(
                || line.to_owned(),
                |value| format!("encoded-hash={}", "0".repeat(value.len())),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(receipt_path, rewritten).expect("test should rewrite the receipt identity");

    assert!(matches!(
        storage.compressed_representation_for_test(identity, CompressionCodec::Zstd, 0),
        Err(StorageError::NarMismatch)
    ));
}

#[test]
fn same_size_corrupt_compressed_derivative_is_repaired() {
    assert_egress_derivative_is_repaired(|bytes| bytes[0] ^= 1, false);
}

#[test]
fn truncated_compressed_derivative_is_repaired() {
    assert_egress_derivative_is_repaired(|bytes| bytes.truncate(bytes.len() / 2), false);
}

#[test]
fn server_generated_derivative_is_repaired_without_a_receipt() {
    assert_egress_derivative_is_repaired(|bytes| bytes[0] ^= 1, true);
}

fn assert_egress_derivative_is_repaired(
    corrupt_derivative: impl FnOnce(&mut Vec<u8>),
    remove_receipt: bool,
) {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let raw = b"raw NAR with a corrupt derivative";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    storage
        .publish_nar_unchecked(&raw_hash, Cursor::new(raw))
        .expect("raw NAR should be stored");

    let output = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
        .expect("derivative should be created");
    let output_path = storage.layout().nar_path_encoded(output.0);
    let original = fs::read(&output_path).expect("derivative should be readable");
    let mut corrupt = fs::read(&output_path).expect("derivative should be readable");
    corrupt_derivative(&mut corrupt);
    fs::write(&output_path, &corrupt).expect("test should corrupt the derivative");
    storage
        .finish_recovery()
        .expect("recovery should retain repair evidence for an existing raw NAR");
    assert_eq!(
        fs::read_dir(storage.layout().egress_receipt_dir())
            .expect("egress receipt directory should be readable")
            .count(),
        1,
        "recovery must retain the receipt while its raw source exists"
    );
    if remove_receipt {
        let receipt = fs::read_dir(storage.layout().egress_receipt_dir())
            .expect("egress receipt directory should be readable")
            .next()
            .expect("egress receipt should exist")
            .expect("egress receipt should be readable")
            .path();
        fs::remove_file(receipt).expect("test should remove the egress receipt");
    }

    assert_eq!(
        storage
            .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
            .expect("a server-generated corrupt derivative should be repaired"),
        output
    );
    assert_eq!(
        fs::read(output_path).expect("repaired derivative should be readable"),
        original
    );
    assert_eq!(storage.temporary_objects(), 0);
}

#[test]
fn concurrent_requests_coalesce_compressed_derivative_generation() {
    let directory = TestDir::new();
    let storage =
        Arc::new(initialize_storage(directory.path()).expect("storage should initialize"));
    let raw = b"raw NAR for concurrent egress generation";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    storage
        .publish_nar_unchecked(&raw_hash, Cursor::new(raw))
        .expect("raw NAR should be stored");

    let barrier = Arc::new(std::sync::Barrier::new(4));
    let workers = (0..4)
        .map(|_| {
            let storage = Arc::clone(&storage);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                storage
                    .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
                    .expect("coalesced derivative generation should succeed")
            })
        })
        .collect::<Vec<_>>();
    let outputs = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker should not panic"))
        .collect::<Vec<_>>();

    assert!(outputs.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(storage.egress_generations(), 1);
    assert_eq!(
        fs::read_dir(storage.layout().egress_receipt_dir())
            .expect("egress receipt directory should be readable")
            .count(),
        1
    );
}

#[test]
fn zstd_validation_rejects_bytes_after_the_frame() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    compress(Cursor::new(raw), &mut compressed, CompressionLevel::Fastest);
    let frame_length = compressed.len();
    compressed.extend_from_slice(b"trailing bytes");
    let nar = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed[..frame_length])))
        .expect("compressed frame hash is a valid file hash");

    let result = storage.publish_nar(
        NarFileName::new(nar, NarEncoding::Zstd),
        Cursor::new(&compressed),
        compressed.len() as u64,
        super::NarUploadPolicy::new(1024, 0),
    );

    assert!(result.is_err(), "trailing bytes must not be accepted");
}

#[test]
fn xz_validation_rejects_bytes_after_the_stream() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ writer");
    writer.write_all(raw).expect("compress XZ NAR");
    writer.finish().expect("finish XZ stream");
    let frame_length = compressed.len();
    compressed.extend_from_slice(b"trailing bytes");
    let nar = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed[..frame_length])))
        .expect("compressed frame hash is a valid file hash");

    let result = storage.publish_nar(
        NarFileName::new(nar, NarEncoding::Xz),
        Cursor::new(&compressed),
        compressed.len() as u64,
        super::NarUploadPolicy::new(1024, 0),
    );

    assert!(result.is_err(), "trailing bytes must not be accepted");
}

#[test]
fn compressed_nars_reject_truncated_frames() {
    let raw = b"nar bytes";
    let mut xz = Vec::new();
    let mut xz_writer =
        XzWriter::new(&mut xz, XzOptions::with_preset(1)).expect("create XZ writer");
    xz_writer.write_all(raw).expect("compress XZ NAR");
    xz_writer.finish().expect("finish XZ stream");

    let mut zstd = Vec::new();
    compress(Cursor::new(raw), &mut zstd, CompressionLevel::Fastest);

    for (encoding, mut compressed) in [(NarEncoding::Xz, xz), (NarEncoding::Zstd, zstd)] {
        compressed.pop().expect("compressed frame is not empty");
        let nar = FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed)))
            .expect("compressed hash is a valid file hash");
        let directory = TestDir::new();
        let storage = initialize_storage(directory.path()).expect("initialize storage");

        let result = storage.publish_nar(
            NarFileName::new(nar, encoding),
            Cursor::new(&compressed),
            compressed.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        );

        let StorageError::Io(error) = result.expect_err("truncated frame was accepted") else {
            panic!("truncated {encoding:?} returned a non-I/O storage error");
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "truncated {encoding:?} should be classified as invalid input: {error}"
        );
    }
}

#[test]
fn read_side_nar_check_only_requires_the_declared_file_size() {
    let directory = TestDir::new();
    let path = directory.path().join("opaque-nar");
    fs::write(&path, b"not an XZ stream").expect("write opaque NAR");
    let file = fs::File::open(path).expect("open opaque NAR");

    assert!(
        nar_file_size_matches(&file, b"not an XZ stream".len() as u64).expect("read file metadata")
    );
    assert!(!nar_file_size_matches(&file, 0).expect("read file metadata"));
}

#[test]
fn validated_ids_map_to_exact_layout_paths() {
    let layout = Layout::new(PathBuf::from("/cache"));
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

    assert_eq!(
        layout.nar_path(nar),
        PathBuf::from(format!("/cache/nar/{NAR_ID}.nar"))
    );
    assert_eq!(
        layout.narinfo_path(&store),
        PathBuf::from(format!("/cache/{STORE_HASH}.narinfo"))
    );
    assert_eq!(layout.temp_dir(), PathBuf::from("/cache/.tmp"));
}

#[test]
fn ids_reject_wrong_length_and_non_nix32_bytes() {
    for value in [
        "",
        "0",
        "0000000000000000000000000000000",
        "000000000000000000000000000000000",
        "0000000000000000000000000000000/",
        "0000000000000000000000000000000e",
        "0000000000000000000000000000000A",
    ] {
        assert!(
            StoreHash::parse(value).is_err(),
            "accepted invalid store hash: {value:?}"
        );
    }

    for value in [
        &NAR_ID[..51],
        "00000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000e",
        "../0000000000000000000000000000000000000000000000000",
    ] {
        assert!(
            FileHash::parse(value).is_err(),
            "accepted invalid NAR file hash: {value:?}"
        );
    }
}

#[test]
fn initialization_creates_only_the_fixed_layout() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");

    assert!(directory.path().join("nar").is_dir());
    assert!(directory.path().join("nar/.tmp").is_dir());
    assert!(directory.path().join(".tmp").is_dir());
    assert!(directory.path().join("realisations").is_dir());
    assert!(directory.path().join("realisations/.tmp").is_dir());
    assert_eq!(storage.layout(), &Layout::new(directory.path().to_owned()));
}

#[test]
fn initialization_rejects_a_symlinked_data_directory() {
    let directory = TestDir::new();
    let target = directory.path().join("target");
    let link = directory.path().join("data");
    fs::create_dir(&target).expect("create symlink target");
    symlink(&target, &link).expect("create data directory symlink");

    let error = initialize_storage(&link).expect_err("symlinked data must be rejected");
    assert!(error.to_string().contains("data directory"));
    assert!(!target.join("nar").exists());
    assert!(!target.join(".tmp").exists());
    assert!(!target.join("realisations").exists());
}

#[test]
fn initialization_rejects_a_symlinked_lock() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    drop(storage);

    let target = directory.path().join("lock-target");
    let lock = directory.path().join("lock");
    fs::write(&target, b"external lock").expect("create lock target");
    fs::remove_file(&lock).expect("remove original lock");
    symlink(&target, &lock).expect("create lock symlink");

    let error = initialize_storage(directory.path()).expect_err("symlinked lock must fail");
    assert!(error.to_string().contains("lock"));
}

#[test]
fn initialization_rejects_writable_storage_directories() {
    let directory = TestDir::new();
    let nar = directory.path().join("nar");
    fs::create_dir(&nar).expect("create NAR directory");
    fs::set_permissions(&nar, fs::Permissions::from_mode(0o777))
        .expect("make NAR directory writable");

    let error = initialize_storage(directory.path())
        .expect_err("writable storage directory must be rejected");
    assert!(error.to_string().contains("nar directory"));
}

#[test]
fn temporary_publication_files_are_private() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let temporary = storage
        .create_temp(&PublishTarget::CacheInfo)
        .expect("create temporary publication file");

    assert_eq!(
        temporary
            .file
            .metadata()
            .expect("read temp metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    remove_temp(&temporary).expect("remove temporary publication file");
}

#[test]
fn nar_publication_uses_a_destination_local_temporary_directory() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");

    let temporary = storage
        .create_temp(&PublishTarget::Nar(NarFileName::raw(nar)))
        .expect("create NAR temporary publication file");
    assert_eq!(
        fs::read_dir(storage.layout().temp_dir())
            .expect("read metadata temporary directory")
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(storage.layout().nar_temp_dir())
            .expect("read NAR temporary directory")
            .count(),
        1
    );
    remove_temp(&temporary).expect("remove NAR temporary publication file");
}

#[test]
fn directory_sync_rejects_a_symlinked_directory() {
    let directory = TestDir::new();
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    fs::create_dir(&target).expect("create sync target");
    symlink(&target, &link).expect("create sync directory symlink");

    assert!(sync_dir(&link).is_err());
}

#[test]
fn publication_rejects_a_symlinked_temporary_directory() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let temporary = storage.layout.nar_temp_dir();
    let real_temporary = directory.path().join("nar-tmp-real");
    let target = directory.path().join("external");
    fs::rename(&temporary, &real_temporary).expect("move real temporary directory");
    fs::create_dir(&target).expect("create external directory");
    symlink(&target, &temporary).expect("create temporary directory symlink");

    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    assert!(
        storage
            .publish_nar_unchecked(&nar, Cursor::new(b"must not escape"))
            .is_err()
    );
    assert!(!storage.layout.nar_path(nar).exists());
    assert!(
        fs::read_dir(&target)
            .expect("read external directory")
            .next()
            .is_none()
    );
}

#[test]
fn publication_rejects_a_symlinked_destination_directory() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let nar_dir = storage.layout.nar_dir();
    let real_nar_dir = directory.path().join("nar-real");
    let external = directory.path().join("external");
    let external_nar = external.join(format!("{NAR_ID}.nar"));
    fs::rename(&nar_dir, &real_nar_dir).expect("move real NAR directory");
    fs::create_dir(&external).expect("create external directory");
    fs::write(&external_nar, b"must not be compared").expect("write external NAR");
    symlink(&external, &nar_dir).expect("create NAR directory symlink");

    assert!(
        storage
            .publish_nar_unchecked(&nar, Cursor::new(b"must not be compared"))
            .is_err()
    );
    assert_eq!(
        fs::read(&external_nar).expect("read external NAR"),
        b"must not be compared"
    );
}

#[test]
fn reconciliation_rejects_a_symlinked_nar_directory() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let nar_dir = storage.layout.nar_dir();
    let real_nar_dir = directory.path().join("nar-real");
    let external = directory.path().join("external");
    fs::rename(&nar_dir, &real_nar_dir).expect("move real NAR directory");
    fs::create_dir(&external).expect("create external directory");
    fs::write(
        external.join("0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar"),
        b"external",
    )
    .expect("write external NAR");
    symlink(&external, &nar_dir).expect("create NAR directory symlink");

    assert!(
        storage
            .reconcile(
                NonZeroUsize::new(32).expect("non-zero limit"),
                SystemTime::now()
            )
            .is_err()
    );
}

#[test]
fn delete_rejects_a_symlinked_narinfo() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("storage should initialize");
    let store = StoreHash::parse(STORE_HASH).expect("valid store hash");
    let target = directory.path().join("external-narinfo");
    let link = directory.path().join(format!("{STORE_HASH}.narinfo"));
    fs::write(&target, b"external narinfo").expect("write external narinfo");
    symlink(&target, &link).expect("create narinfo symlink");

    assert!(storage.delete_narinfo(&store).is_err());
    assert!(link.exists());
    assert_eq!(
        fs::read(&target).expect("read external narinfo"),
        b"external narinfo"
    );
}

#[test]
fn recovery_marker_distinguishes_clean_and_interrupted_publication() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");

    assert!(
        !storage
            .recovery_required()
            .expect("inspect clean recovery marker")
    );
    assert!(
        storage
            .publish_nar_fault(
                &nar,
                Cursor::new(b"nar bytes"),
                PublishBoundary::AfterTempCreate
            )
            .is_err()
    );
    assert!(
        storage
            .recovery_required()
            .expect("inspect interrupted recovery marker")
    );
}

#[test]
fn recovery_cleans_incomplete_publication_transactions() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let trusted_keys = directory.path().join("trusted-public-keys");
    let temporary = directory.path().join(".tmp/cache-info-recovery.part");
    let nar_temporary = directory.path().join("nar/.tmp/nar-recovery.part");
    fs::write(&trusted_keys, b"").expect("create trusted key file");
    fs::write(&temporary, b"partial publication").expect("create interrupted temporary file");
    fs::write(&nar_temporary, b"partial NAR publication")
        .expect("create interrupted NAR temporary file");
    storage
        .recovery
        .begin(Path::new(".tmp/cache-info-recovery.part"))
        .expect("record interrupted cache-info publication");
    storage
        .recovery
        .begin(Path::new("nar/.tmp/nar-recovery.part"))
        .expect("record interrupted NAR publication");

    assert!(storage.recovery_required().expect("inspect recovery state"));
    storage
        .finish_recovery()
        .expect("finish interrupted publication recovery");

    assert!(!temporary.exists());
    assert!(!nar_temporary.exists());
    assert!(
        fs::read_dir(directory.path().join(".narjar-transactions"))
            .expect("read transaction directory")
            .next()
            .is_none()
    );
    assert!(!storage.recovery_required().expect("inspect clean state"));
}

#[test]
fn recovery_records_publish_state_before_each_fault_boundary() {
    for (boundary, expected_state) in [
        (PublishBoundary::BeforeTempCreate, "staging"),
        (PublishBoundary::AfterTempCreate, "streaming"),
        (PublishBoundary::AfterStream, "streaming"),
        (PublishBoundary::AfterTempSync, "streaming"),
        (PublishBoundary::BeforeFinalLink, "validated"),
        (PublishBoundary::BeforeParentSync, "linked"),
    ] {
        let directory = TestDir::new();
        let storage = initialize_storage(directory.path()).expect("initialize storage");
        let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");

        assert!(
            storage
                .publish_nar_fault(&nar, Cursor::new(b"nar bytes"), boundary)
                .is_err(),
            "{boundary:?} unexpectedly succeeded"
        );
        let mut records = fs::read_dir(directory.path().join(".narjar-transactions"))
            .expect("read transaction directory");
        let record = records
            .next()
            .expect("faulted publication should retain a transaction")
            .expect("read transaction entry");
        assert!(
            records.next().is_none(),
            "state replacement must not leave an extra transaction record"
        );
        let contents = fs::read(record.path()).expect("read transaction record");
        let contents = String::from_utf8(contents).expect("transaction record is UTF-8");
        assert!(
            contents.starts_with(&format!("state={expected_state}\npath=")),
            "{boundary:?} recorded unexpected state: {contents:?}"
        );
    }
}

#[test]
fn malformed_publication_transaction_blocks_recovery() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let trusted_keys = directory.path().join("trusted-public-keys");
    let record = directory
        .path()
        .join(".narjar-transactions/publish-malformed.txn");
    fs::write(&trusted_keys, b"").expect("create trusted key file");
    fs::write(&record, b"/outside/recovery.part\n").expect("create malformed record");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
        .expect("make malformed record private");

    assert!(storage.recovery_required().expect("inspect recovery state"));
    assert!(storage.finish_recovery().is_err());
    assert!(record.exists(), "failed recovery must retain its evidence");
}

#[test]
fn unknown_publication_transaction_state_blocks_recovery() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let trusted_keys = directory.path().join("trusted-public-keys");
    let temporary = directory.path().join(".tmp/unknown-state.part");
    let record = directory
        .path()
        .join(".narjar-transactions/publish-unknown-state.txn");
    fs::write(&trusted_keys, b"").expect("create trusted key file");
    fs::write(&temporary, b"temporary").expect("create temporary publication");
    fs::write(&record, b"state=unknown\npath=.tmp/unknown-state.part\n")
        .expect("create unknown-state record");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
        .expect("make unknown-state record private");

    assert!(storage.finish_recovery().is_err());
    assert!(record.exists(), "unknown state must retain its evidence");
    assert!(
        temporary.exists(),
        "failed recovery must not remove its temp"
    );
}

#[test]
fn publication_is_immutable_idempotent_and_pair_gated() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

    assert_eq!(
        storage
            .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
            .expect("publish NAR"),
        PublishOutcome::Created
    );
    assert_eq!(
        storage
            .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
            .expect("retry identical NAR"),
        PublishOutcome::Identical
    );
    assert!(matches!(
        storage.publish_nar_unchecked(&nar, Cursor::new(b"different")),
        Err(StorageError::Conflict)
    ));
    assert!(
        storage
            .open_pair(&store, nar)
            .expect("check incomplete pair")
            .is_none(),
        "an orphan NAR must not make a store path visible"
    );

    assert_eq!(
        storage
            .publish_narinfo_unchecked(&store, nar, Cursor::new(b"narinfo bytes"))
            .expect("publish narinfo"),
        PublishOutcome::Created
    );
    assert_eq!(
        storage
            .publish_narinfo_unchecked(&store, nar, Cursor::new(b"narinfo bytes"))
            .expect("retry identical narinfo"),
        PublishOutcome::Identical
    );
    assert!(matches!(
        storage.publish_narinfo_unchecked(&store, nar, Cursor::new(b"different")),
        Err(StorageError::Conflict)
    ));

    let mut pair = storage
        .open_pair(&store, nar)
        .expect("open durable pair")
        .expect("pair should be visible");
    let mut nar_bytes = Vec::new();
    let mut narinfo_bytes = Vec::new();
    pair.nar.read_to_end(&mut nar_bytes).expect("read NAR");
    pair.narinfo
        .read_to_end(&mut narinfo_bytes)
        .expect("read narinfo");
    assert_eq!(nar_bytes, b"nar bytes");
    assert_eq!(narinfo_bytes, b"narinfo bytes");
    assert!(
        fs::read_dir(storage.layout().temp_dir())
            .expect("read temp directory")
            .next()
            .is_none(),
        "completed attempts must not leave temporary files"
    );
}

#[test]
fn failed_publisher_cannot_invalidate_concurrent_identical_success() {
    let directory = TestDir::new();
    let storage = Arc::new(initialize_storage(directory.path()).expect("initialize storage"));
    let (linked_tx, linked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let winner = {
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
            storage.publish_with(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"nar bytes"),
                |boundary| {
                    if boundary == PublishBoundary::BeforeParentSync {
                        linked_tx.send(()).expect("signal linked destination");
                        release_rx.recv().expect("release failing publisher");
                        return Err(io::Error::other("injected parent sync failure").into());
                    }
                    Ok(())
                },
            )
        })
    };

    linked_rx.recv().expect("wait for linked destination");
    let (started_tx, started_rx) = mpsc::channel();
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let contender = {
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
            started_tx.send(()).expect("signal contender start");
            let outcome = storage.publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"));
            outcome_tx.send(outcome).expect("send contender outcome");
        })
    };

    started_rx.recv().expect("wait for contender");
    let early_outcome = outcome_rx.recv_timeout(Duration::from_millis(500)).ok();
    release_tx.send(()).expect("release failing publisher");

    assert!(winner.join().expect("join failing publisher").is_err());
    let outcome = match early_outcome {
        Some(outcome) => outcome,
        None => outcome_rx.recv().expect("wait for contender outcome"),
    };
    contender.join().expect("join contender");
    assert_eq!(
        outcome.expect("concurrent identical publication"),
        PublishOutcome::Created
    );

    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    assert!(storage.layout().nar_path(nar).exists());
}

#[test]
fn each_failed_pre_durable_boundary_leaves_no_final_or_temp() {
    for boundary in [
        PublishBoundary::BeforeTempCreate,
        PublishBoundary::AfterTempCreate,
        PublishBoundary::AfterStream,
        PublishBoundary::AfterTempSync,
        PublishBoundary::BeforeFinalLink,
        PublishBoundary::BeforeParentSync,
    ] {
        let directory = TestDir::new();
        let storage = initialize_storage(directory.path()).expect("initialize storage");
        let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");

        assert!(
            storage
                .publish_nar_fault(&nar, Cursor::new(b"nar bytes"), boundary)
                .is_err(),
            "{boundary:?} unexpectedly succeeded"
        );
        assert!(
            !storage.layout().nar_path(nar).exists(),
            "{boundary:?} left a final NAR"
        );
        assert!(
            fs::read_dir(storage.layout().temp_dir())
                .expect("read temp directory")
                .next()
                .is_none(),
            "{boundary:?} left a temporary file"
        );
        assert_eq!(
            fs::read_dir(directory.path().join(".narjar-transactions"))
                .expect("read publication transaction directory")
                .count(),
            1,
            "{boundary:?} lost its durable recovery record"
        );
        storage
            .finish_recovery()
            .expect("recover failed publication");
        assert_eq!(
            fs::read_dir(directory.path().join(".narjar-transactions"))
                .expect("read recovered transaction directory")
                .count(),
            0,
            "{boundary:?} left its recovery record"
        );
    }
}

#[test]
fn response_loss_after_parent_sync_is_visible_and_idempotent() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let store = StoreHash::parse(STORE_HASH).expect("valid store hash");

    assert!(
        storage
            .publish_nar_fault(
                &nar,
                Cursor::new(b"nar bytes"),
                PublishBoundary::AfterParentSync,
            )
            .is_err()
    );
    assert_eq!(
        fs::read_dir(directory.path().join(".narjar-transactions"))
            .expect("read publication transaction directory")
            .count(),
        0,
        "durable response loss must complete its transaction record"
    );
    assert_eq!(
        storage
            .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
            .expect("retry durable NAR"),
        PublishOutcome::Identical
    );

    assert!(
        storage
            .publish_narinfo_fault(
                &store,
                nar,
                Cursor::new(b"narinfo bytes"),
                PublishBoundary::AfterParentSync,
            )
            .is_err()
    );
    assert!(
        storage
            .open_pair(&store, nar)
            .expect("open durable pair")
            .is_some(),
        "a parent-synced pair must remain visible after response loss"
    );
    assert_eq!(
        storage
            .publish_narinfo_unchecked(&store, nar, Cursor::new(b"narinfo bytes"))
            .expect("retry durable narinfo"),
        PublishOutcome::Identical
    );
}

#[test]
fn stream_resource_failures_leave_no_false_publication_state() {
    for raw_error in [libc::EIO, libc::ENOSPC] {
        let directory = TestDir::new();
        let storage = initialize_storage(directory.path()).expect("initialize storage");
        let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");

        let error = storage
            .publish_nar_unchecked(&nar, BrokenReader::new(raw_error))
            .expect_err("stream failure must reject publication");
        let StorageError::Io(error) = error else {
            panic!("stream failure returned a non-I/O error");
        };
        assert_eq!(error.raw_os_error(), Some(raw_error));
        assert!(!storage.layout().nar_path(nar).exists());
        assert!(
            fs::read_dir(storage.layout().temp_dir())
                .expect("read temp directory")
                .next()
                .is_none()
        );
    }
}

#[test]
fn destination_capacity_rejects_inode_exhaustion() {
    let space = FilesystemSpace {
        total_bytes: u64::MAX,
        available_bytes: u64::MAX,
        total_inodes: u64::MAX,
        available_inodes: 0,
        read_only: false,
    };

    assert!(matches!(
        space.required_capacity(1),
        Err(StorageError::InsufficientInodes)
    ));
}

#[test]
fn read_only_filesystems_are_not_ready() {
    let space = FilesystemSpace {
        total_bytes: u64::MAX,
        available_bytes: u64::MAX,
        total_inodes: u64::MAX,
        available_inodes: u64::MAX,
        read_only: true,
    };

    assert!(matches!(
        space.required_capacity(1),
        Err(StorageError::Io(error)) if error.raw_os_error() == Some(libc::EROFS)
    ));
}

#[test]
fn capacity_errors_have_stable_categories() {
    assert_eq!(
        capacity_error_kind(libc::ENOSPC),
        CapacityErrorKind::NoSpace
    );
    assert_eq!(capacity_error_kind(libc::EDQUOT), CapacityErrorKind::Quota);
    assert_eq!(
        capacity_error_kind(libc::EROFS),
        CapacityErrorKind::ReadOnly
    );
}

#[test]
fn staging_reservations_are_bounded_and_released() {
    let reservations = Arc::new(Mutex::new(Default::default()));
    let space = FilesystemSpace {
        total_bytes: 100,
        available_bytes: 100,
        total_inodes: 2,
        available_inodes: 2,
        read_only: false,
    };
    let min_free_bytes = 10;
    let first = reserve_staging_bytes_for_test(&reservations, min_free_bytes, 90, || Ok(space))
        .expect("first reservation should fit");
    assert!(
        reserve_staging_bytes_for_test(&reservations, min_free_bytes, 1, || Ok(space)).is_err(),
        "reservations must not exceed available bytes after the free-space reserve"
    );

    drop(first);
    reserve_staging_bytes_for_test(&reservations, min_free_bytes, 1, || Ok(space))
        .expect("released staging capacity should be reusable");
}

#[test]
fn staging_admission_rejects_read_only_and_inode_exhausted_filesystems() {
    let read_only = FilesystemSpace {
        total_bytes: 100,
        available_bytes: 100,
        total_inodes: 2,
        available_inodes: 2,
        read_only: true,
    };
    let inode_exhausted = FilesystemSpace {
        total_bytes: 100,
        available_bytes: 100,
        total_inodes: 2,
        available_inodes: 0,
        read_only: false,
    };

    for space in [read_only, inode_exhausted] {
        let reservations = Arc::new(Mutex::new(Default::default()));
        assert!(
            reserve_staging_bytes_for_test(&reservations, 10, 1, || Ok(space)).is_err(),
            "staging admission must retain all filesystem capability checks"
        );
        assert_eq!(
            reservations.lock().unwrap().outstanding_bytes(),
            0,
            "rejected admission must not consume budget"
        );
    }
}

#[test]
fn staging_reservation_growth_is_atomic_and_monotonic() {
    let directory = TestDir::new();
    let directory_file = fs::File::open(directory.path()).unwrap();
    let reservations = Arc::new(Mutex::new(Default::default()));
    let mut reservation = super::publication::StagingReservation::empty(reservations.clone());

    reservation
        .grow_to(&directory_file, 10, 64)
        .expect("first growth should fit");
    assert_eq!(reservation.reserved_bytes(), 64);
    assert_eq!(reservations.lock().unwrap().outstanding_bytes(), 64);

    reservation
        .grow_to(&directory_file, 10, 32)
        .expect("smaller growth should be a no-op");
    assert_eq!(reservation.reserved_bytes(), 64);
    assert_eq!(reservations.lock().unwrap().outstanding_bytes(), 64);

    assert!(reservation.grow_to(&directory_file, u64::MAX, 100).is_err());
    assert_eq!(reservation.reserved_bytes(), 64);
    assert_eq!(reservations.lock().unwrap().outstanding_bytes(), 64);
}

#[test]
fn materialized_staging_bytes_are_not_counted_against_free_space() {
    let directory = TestDir::new();
    let directory_file = fs::File::open(directory.path()).unwrap();
    let reservations = Arc::new(Mutex::new(Default::default()));
    let mut first = super::publication::StagingReservation::empty(reservations.clone());

    first
        .grow_to(&directory_file, 10, 64)
        .expect("the first staging chunk should fit");
    first.record_materialized_bytes(64);
    assert_eq!(reservations.lock().unwrap().outstanding_bytes(), 0);

    let mut second = super::publication::StagingReservation::empty(reservations.clone());
    second
        .grow_to(&directory_file, 10, 64)
        .expect("the next chunk should be checked only against remaining free space");
    assert_eq!(reservations.lock().unwrap().outstanding_bytes(), 64);
}

struct BrokenReader {
    raw_error: i32,
    returned_prefix: bool,
}

impl BrokenReader {
    fn new(raw_error: i32) -> Self {
        Self {
            raw_error,
            returned_prefix: false,
        }
    }
}

impl Read for BrokenReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.returned_prefix {
            return Err(io::Error::from_raw_os_error(self.raw_error));
        }

        self.returned_prefix = true;
        buffer[..3].copy_from_slice(b"nar");
        Ok(3)
    }
}

struct BlockingReader {
    started: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    returned_bytes: bool,
}

impl Read for BlockingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.returned_bytes {
            return Ok(0);
        }

        self.started
            .take()
            .expect("blocking reader only starts once")
            .send(())
            .expect("signal blocked publication");
        self.release.recv().expect("release blocked publication");
        buffer[..3].copy_from_slice(b"nar");
        self.returned_bytes = true;
        Ok(3)
    }
}

#[test]
fn independent_publications_do_not_wait_for_another_body() {
    let directory = TestDir::new();
    let storage = Arc::new(initialize_storage(directory.path()).expect("initialize storage"));
    let first = NarHash::parse(NAR_ID).expect("valid first NAR hash");
    let second = NarHash::parse(&"1".repeat(52)).expect("valid second NAR hash");
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let publisher = {
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            storage.publish_with(
                PublishTarget::Nar(NarFileName::raw(first)),
                BlockingReader {
                    started: Some(started_tx),
                    release: release_rx,
                    returned_bytes: false,
                },
                |_| Ok(()),
            )
        })
    };

    started_rx.recv().expect("wait for first publication body");
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let contender = {
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            let outcome = storage.publish_nar_unchecked(&second, Cursor::new(b"nar"));
            outcome_tx
                .send(outcome)
                .expect("send second publication outcome");
        })
    };

    let early_outcome = outcome_rx.recv_timeout(Duration::from_millis(500)).ok();
    release_tx.send(()).expect("release first publication");
    assert_eq!(
        publisher
            .join()
            .expect("join first publication")
            .expect("publish first NAR"),
        PublishOutcome::Created
    );
    contender.join().expect("join second publication");
    assert!(
        early_outcome.is_some(),
        "second publication waited for the first body to finish"
    );
    assert_eq!(
        early_outcome
            .or_else(|| outcome_rx.recv().ok())
            .expect("second publication outcome")
            .expect("publish second NAR"),
        PublishOutcome::Created
    );
}

#[test]
fn process_lock_is_exclusive_and_released_on_drop() {
    let directory = TestDir::new();
    let first = initialize_storage(directory.path()).expect("acquire first process lock");

    assert!(directory.path().join("lock").is_file());
    assert!(matches!(
        initialize_storage(directory.path()),
        Err(StorageError::Locked)
    ));

    drop(first);
    initialize_storage(directory.path()).expect("reacquire released process lock");
}

#[test]
fn process_lock_release_does_not_depend_on_storage_directory_handles() {
    let directory = TestDir::new();
    let first = initialize_storage(directory.path()).expect("acquire first process lock");
    let lingering_directory_handle = first.root.try_clone().expect("clone directory handle");

    drop(first);
    initialize_storage(directory.path()).expect("reacquire without waiting for directory handles");

    drop(lingering_directory_handle);
}

#[test]
fn process_lock_survives_lockfile_replacement() {
    let directory = TestDir::new();
    let first = initialize_storage(directory.path()).expect("acquire first process lock");
    let lock = directory.path().join("lock");
    fs::remove_file(&lock).expect("remove lock pathname");
    fs::write(&lock, b"replacement").expect("replace lock pathname");

    assert!(matches!(
        initialize_storage(directory.path()),
        Err(StorageError::Locked)
    ));

    drop(first);
    initialize_storage(directory.path()).expect("reacquire after lease release");
}

#[test]
fn process_lock_replacement_blocks_a_child_process() {
    let directory = TestDir::new();
    let first = initialize_storage(directory.path()).expect("acquire first process lock");
    let lock = directory.path().join("lock");
    fs::remove_file(&lock).expect("remove lock pathname");
    fs::write(&lock, b"replacement").expect("replace lock pathname");

    let status = process::Command::new(env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            "storage::tests::process_lock_replacement_probe",
            "--nocapture",
        ])
        .env("NARJAR_LOCK_PROBE_DATA", directory.path())
        .status()
        .expect("run lock probe child");
    assert!(status.success(), "child process should observe the lease");

    drop(first);
    initialize_storage(directory.path()).expect("reacquire after lease release");
}

#[test]
fn process_lock_replacement_probe() {
    let Some(path) = env::var_os("NARJAR_LOCK_PROBE_DATA") else {
        return;
    };
    assert!(matches!(
        initialize_storage(Path::new(&path)),
        Err(StorageError::Locked)
    ));
}

#[test]
fn reconciliation_is_deterministic_bounded_and_reports_manual_changes() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    fs::write(directory.path().join("manual"), b"manual").expect("write manual file");
    fs::write(directory.path().join("nar/not-valid.nar"), b"bad").expect("write malformed NAR");
    fs::write(directory.path().join(".tmp/nar-manual.part"), b"temp")
        .expect("write temporary file");

    let stale_before = SystemTime::now() + Duration::from_secs(1);
    let full = storage
        .reconcile(NonZeroUsize::new(16).expect("nonzero limit"), stale_before)
        .expect("reconcile storage");
    let paths: Vec<_> = full
        .entries()
        .iter()
        .map(|entry| entry.relative_path().to_owned())
        .collect();
    assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(full.entries().iter().any(|entry| {
        entry.relative_path() == Path::new("manual") && entry.class() == ReconcileClass::UnknownFile
    }));
    assert!(full.entries().iter().any(|entry| {
        entry.relative_path() == Path::new("nar/not-valid.nar")
            && entry.class() == ReconcileClass::InvalidFilename
    }));
    assert!(full.entries().iter().any(|entry| {
        entry.relative_path() == Path::new(".tmp/nar-manual.part")
            && entry.class() == ReconcileClass::TempStale
    }));

    let bounded = storage
        .reconcile(NonZeroUsize::new(1).expect("nonzero limit"), stale_before)
        .expect("bounded reconcile");
    assert_eq!(bounded.entries().len(), 1);
    assert!(bounded.truncated());
    assert_eq!(bounded.entries()[0].relative_path(), paths[0]);
}

#[test]
fn cleanup_removes_only_reported_stale_temps() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let stale_path = directory.path().join(".tmp/nar-stale.part");
    fs::write(&stale_path, b"temp").expect("write stale temp");

    let stale_report = storage
        .reconcile(
            NonZeroUsize::new(16).expect("nonzero limit"),
            SystemTime::now() + Duration::from_secs(1),
        )
        .expect("classify stale temp");
    let stale = stale_report
        .entries()
        .iter()
        .find(|entry| entry.relative_path() == Path::new(".tmp/nar-stale.part"))
        .expect("stale temp entry");
    assert_eq!(stale.class(), ReconcileClass::TempStale);
    assert!(
        storage
            .cleanup_stale_temp(stale)
            .expect("cleanup stale temp")
    );
    assert!(!stale_path.exists());

    let young_path = directory.path().join(".tmp/nar-young.part");
    fs::write(&young_path, b"temp").expect("write young temp");
    let young_report = storage
        .reconcile(
            NonZeroUsize::new(16).expect("nonzero limit"),
            SystemTime::now()
                .checked_sub(Duration::from_secs(1))
                .expect("past time"),
        )
        .expect("classify young temp");
    let young = young_report
        .entries()
        .iter()
        .find(|entry| entry.relative_path() == Path::new(".tmp/nar-young.part"))
        .expect("young temp entry");
    assert_eq!(young.class(), ReconcileClass::TempYoung);
    assert!(!storage.cleanup_stale_temp(young).expect("keep young temp"));
    assert!(young_path.exists());

    let validation_path = directory.path().join(".tmp/validation-repair.part");
    fs::write(&validation_path, b"temp").expect("write validation temp");
    let validation_report = storage
        .reconcile(
            NonZeroUsize::new(16).expect("nonzero limit"),
            SystemTime::now()
                .checked_sub(Duration::from_secs(1))
                .expect("past time"),
        )
        .expect("classify validation temp");
    let validation = validation_report
        .entries()
        .iter()
        .find(|entry| entry.relative_path() == Path::new(".tmp/validation-repair.part"))
        .expect("validation temp entry");
    assert_eq!(validation.class(), ReconcileClass::TempYoung);
    assert!(validation_path.exists());

    let egress_path = directory.path().join(".tmp/egress-receipt-stale.part");
    fs::write(&egress_path, b"temp").expect("write egress receipt temp");
    let egress_report = storage
        .reconcile(
            NonZeroUsize::new(16).expect("nonzero limit"),
            SystemTime::now() + Duration::from_secs(1),
        )
        .expect("classify egress receipt temp");
    let egress = egress_report
        .entries()
        .iter()
        .find(|entry| entry.relative_path() == Path::new(".tmp/egress-receipt-stale.part"))
        .expect("egress receipt temp entry");
    assert_eq!(egress.class(), ReconcileClass::TempStale);
    assert!(
        storage
            .cleanup_stale_temp(egress)
            .expect("cleanup egress receipt temp")
    );
    assert!(!egress_path.exists());
}

#[test]
fn cleanup_does_not_remove_a_replaced_stale_temp() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let path = directory.path().join(".tmp/nar-replaced.part");
    fs::write(&path, b"original").expect("write stale temp");

    let report = storage
        .reconcile(
            NonZeroUsize::new(16).expect("nonzero limit"),
            SystemTime::now() + Duration::from_secs(1),
        )
        .expect("classify stale temp");
    let stale = report
        .entries()
        .iter()
        .find(|entry| entry.relative_path() == Path::new(".tmp/nar-replaced.part"))
        .expect("stale temp entry");
    fs::remove_file(&path).expect("remove reported temp");
    fs::write(&path, b"replacement").expect("write replacement temp");

    assert!(
        !storage
            .cleanup_stale_temp(stale)
            .expect("replacement should not be removed")
    );
    assert_eq!(fs::read(&path).expect("read replacement"), b"replacement");
}

#[test]
fn safe_delete_removes_only_narinfo_and_syncs_visibility() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let store = StoreHash::parse(STORE_HASH).expect("valid store hash");
    storage
        .publish_nar_unchecked(&nar, Cursor::new(b"nar bytes"))
        .expect("publish NAR");
    storage
        .publish_narinfo_unchecked(&store, nar, Cursor::new(b"narinfo bytes"))
        .expect("publish narinfo");

    assert!(storage.delete_narinfo(&store).expect("delete narinfo"));
    assert!(
        storage
            .open_pair(&store, nar)
            .expect("open deleted pair")
            .is_none()
    );
    assert!(storage.layout().nar_path(nar).is_file());
    assert!(!storage.delete_narinfo(&store).expect("repeat delete"));
}

struct TestDir(tempfile::TempDir);

impl TestDir {
    fn new() -> Self {
        Self(tempfile::tempdir().expect("create test directory"))
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}
