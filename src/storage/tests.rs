use std::{
    env, fs,
    io::{self, Cursor, Read, Write},
    num::NonZeroUsize,
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, SystemTime},
};

use super::compression::{
    CheckedUploadReader, nar_file_size_matches, receive_uploaded_nar,
    verify_decoded_compressed_file, verify_encoded_compressed_file, xz_decoder_memory_requirement,
};
use super::egress::{EgressReceipt, EgressSlot};
use super::fs::{StorageCapacity, remove_temp, reserve_staging_bytes_for_test, sync_dir};
use super::ids::nix32_sha256;
use super::publication::{DecoderMemoryLimit, Layout, PublishBoundary, PublishTarget};
use super::{
    CapacityErrorKind, Directory, PublishOutcome, ReconcileClass, Storage, StorageBackend,
    StorageError, StoreHash, SupportedStorageBackend, capacity_error_kind,
};
use crate::narinfo::NarInfoClaims;
use crate::object::{
    CompressedNarIdentity, CompressionCodec, EncodedIdentity, EncodedSize, FileHash, NarFileName,
    NarHash, NarIdentity, NarRepresentation, NarSize, WireEncoding,
};
use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use structured_zstd::decoding::{
    StreamingDecoder as StructuredZstdDecoder, read_frame_header_info,
};
use structured_zstd::encoding::{CompressionLevel, compress};

const NAR_ID: &str = "0000000000000000000000000000000000000000000000000000";
const STORE_HASH: &str = "00000000000000000000000000000000";
const ZSTD_FIXED_WORKSPACE_ALLOWANCE_BYTES: u64 = 1024 * 1024;

#[test]
fn egress_receipt_round_trips_through_compact_binary_serialization() {
    let raw_hash = NarHash::parse(NAR_ID).expect("test NAR hash is valid");
    let encoded_hash = FileHash::parse(NAR_ID).expect("test file hash is valid");
    let raw_size = NarSize::new(17);
    let encoded_size = EncodedSize::new(23);
    let slot = EgressSlot::new(NarIdentity::new(raw_hash, raw_size), CompressionCodec::Zstd);
    let egress = EgressReceipt::for_slot(slot, encoded_hash, encoded_size);
    let egress =
        EgressReceipt::parse(&egress.bytes()).expect("typed egress receipt should be readable");
    assert!(egress.matches(slot));
    assert_eq!(
        egress.output(),
        EncodedIdentity::new(CompressionCodec::Zstd, encoded_hash, encoded_size)
    );

    let bytes = egress.bytes();
    assert!(EgressReceipt::parse(&bytes[..bytes.len() - 1]).is_none());
}

fn initialize_storage(path: &Path) -> Result<Storage, StorageError> {
    Storage::initialize(&Directory::open(path)?, SupportedStorageBackend::FLAT)
}

#[test]
fn population_scan_counts_recognized_files_without_retaining_names() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let narinfo = format!(
        "StorePath: /nix/store/{STORE_HASH}-sample\nURL: nar/{NAR_ID}.nar\nCompression: none\nFileHash: sha256:{NAR_ID}\nFileSize: 11\nNarHash: sha256:{NAR_ID}\nNarSize: 11\nReferences: \n"
    );
    let second_store_hash = format!("{}1", &STORE_HASH[..STORE_HASH.len() - 1]);
    let second_narinfo = narinfo
        .replace(STORE_HASH, &second_store_hash)
        .replace("-sample", "-sample-two");
    let third_store_hash = format!("{}2", &STORE_HASH[..STORE_HASH.len() - 1]);
    let fourth_store_hash = format!("{}3", &STORE_HASH[..STORE_HASH.len() - 1]);
    fs::write(
        directory.path().join(format!("{STORE_HASH}.narinfo")),
        &narinfo,
    )
    .unwrap();
    fs::write(
        directory
            .path()
            .join(format!("{second_store_hash}.narinfo")),
        &second_narinfo,
    )
    .unwrap();
    fs::write(
        directory.path().join("malformed.narinfo"),
        b"invalid metadata",
    )
    .unwrap();
    fs::write(
        directory.path().join(format!("{third_store_hash}.narinfo")),
        b"broken narinfo",
    )
    .unwrap();
    symlink(
        directory.path().join(format!("{STORE_HASH}.narinfo")),
        directory
            .path()
            .join(format!("{fourth_store_hash}.narinfo")),
    )
    .unwrap();
    fs::write(
        directory.path().join("nar").join(format!("{NAR_ID}.nar")),
        b"raw payload",
    )
    .unwrap();
    fs::write(
        directory
            .path()
            .join("nar")
            .join(format!("{NAR_ID}.nar.xz")),
        b"xz payload",
    )
    .unwrap();
    fs::write(directory.path().join(".tmp").join("staged"), b"temporary").unwrap();
    fs::write(
        directory.path().join("nar").join("not-a-hash.nar"),
        b"bad payload name",
    )
    .unwrap();

    let population = storage
        .population_counts(&std::sync::atomic::AtomicBool::new(false))
        .unwrap();

    assert_eq!(population.structurally_valid_narinfo_entries, 2);
    assert_eq!(population.malformed_narinfo_filenames, 1);
    assert_eq!(population.malformed_narinfo_contents, 1);
    assert_eq!(population.narinfo_read_errors, 1);
    assert_eq!(population.narinfo_files, 4);
    assert_eq!(
        population.narinfo_bytes,
        narinfo.len() as u64
            + second_narinfo.len() as u64
            + b"invalid metadata".len() as u64
            + b"broken narinfo".len() as u64
    );
    assert_eq!(population.narinfo_claimed_nar_bytes, 22);
    assert_eq!((population.raw_files, population.raw_bytes), (1, 11));
    assert_eq!((population.xz_files, population.xz_bytes), (1, 10));
    assert_eq!(
        (
            population.malformed_nar_files,
            population.malformed_nar_bytes
        ),
        (1, 16)
    );
    assert_eq!(
        (population.temporary_files, population.temporary_bytes),
        (1, 9)
    );
    assert_eq!(
        population.apparent_file_bytes,
        population.narinfo_bytes
            + population.raw_bytes
            + population.xz_bytes
            + population.malformed_nar_bytes
            + population.temporary_bytes
    );
}

#[test]
fn population_scan_can_be_cancelled_without_returning_partial_totals() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let stopping = std::sync::atomic::AtomicBool::new(true);

    let error = storage.population_counts(&stopping).unwrap_err();

    assert!(
        matches!(error, StorageError::Io(ref error) if error.kind() == io::ErrorKind::Interrupted)
    );
}

#[test]
#[cfg(not(target_os = "macos"))]
fn chunked_ingestion_publishes_a_verified_manifest() {
    let directory = TestDir::new();
    let storage = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        StorageBackend::Chunked.try_into().unwrap(),
    )
    .unwrap();
    let raw = vec![b'x'; 100_000];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let name = NarFileName::raw(hash);
    storage
        .publish_nar(
            name,
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(200_000, 0),
        )
        .unwrap();
    let manifest = storage
        .chunk_store()
        .unwrap()
        .validate_manifest(hash)
        .unwrap()
        .unwrap();

    assert_eq!(
        manifest.identity(),
        NarIdentity::new(hash, (raw.len() as u64).into())
    );
    assert!(
        storage
            .chunk_store()
            .unwrap()
            .open_manifest(hash)
            .unwrap()
            .is_some()
    );
    assert!(manifest.chunk_count() > 0);
    let population = storage
        .population_counts(&std::sync::atomic::AtomicBool::new(false))
        .unwrap();
    assert_eq!(population.manifest_files, 1);
    assert_eq!(population.chunked_nars, 1);
    assert_eq!(population.chunked_nar_bytes, raw.len() as u64);
    assert!(population.chunk_files > 0);
    assert!(population.chunk_files <= manifest.chunk_count());
}

#[test]
#[cfg(not(target_os = "macos"))]
fn chunked_backend_routes_the_complete_nar_publication() {
    let directory = TestDir::new();
    let storage = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        StorageBackend::Chunked.try_into().unwrap(),
    )
    .unwrap();
    let raw = vec![b'c'; 100_000];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let name = NarFileName::raw(hash);
    let policy = super::NarUploadPolicy::new(raw.len() as u64, 0);

    assert_eq!(
        storage
            .publish_nar(name, Cursor::new(&raw), raw.len() as u64, policy)
            .unwrap(),
        PublishOutcome::Created
    );
    storage.ensure_nar(&hash).unwrap();

    let opened = storage
        .open_nar_range(name, 12_345..54_321)
        .unwrap()
        .unwrap();
    let mut reconstructed = Vec::new();
    opened
        .body
        .take(54_321 - 12_345)
        .read_to_end(&mut reconstructed)
        .unwrap();
    assert_eq!(reconstructed, raw[12_345..54_321]);

    let (compressed_name, compressed_size) = storage
        .compressed_representation_for_test(
            NarIdentity::new(hash, (raw.len() as u64).into()),
            CompressionCodec::Zstd,
            0,
        )
        .unwrap();
    assert_eq!(
        storage
            .open_nar(compressed_name)
            .unwrap()
            .unwrap()
            .metadata()
            .unwrap()
            .len(),
        compressed_size.get()
    );

    assert_eq!(
        storage
            .publish_nar(name, Cursor::new(&raw), raw.len() as u64, policy)
            .unwrap(),
        PublishOutcome::Identical
    );
}

#[test]
#[cfg(not(target_os = "macos"))]
fn chunked_upload_enforces_encoded_size_before_creating_staging() {
    let directory = TestDir::new();
    let storage = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        StorageBackend::Chunked.try_into().unwrap(),
    )
    .unwrap();
    let raw = b"compressed body larger than encoded upload limit";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let encoding = WireEncoding::Compressed(CompressionCodec::Zstd);
    let compressed = compressed_bytes(encoding, raw);
    let encoded_hash = FileHash::from_digest(Sha256::digest(&compressed).into());
    let name = NarFileName::new(encoded_hash, encoding);
    let policy = super::NarUploadPolicy::with_limits(
        5,
        raw.len() as u64,
        super::NarUploadPolicy::DEFAULT_MAX_DECODER_MEMORY_BYTES,
        0,
    );
    let reservation = storage.reserve_staging(0, 0).unwrap();

    assert!(
        matches!(
            storage.publish_nar_with_staging(
                name,
                Cursor::new(&compressed),
                compressed.len() as u64,
                policy,
                reservation,
            ),
            Err(StorageError::UploadTooLarge)
        ),
        "the chunked path applies encoded-size policy before ingest"
    );
    assert_eq!(
        storage.staging_budget.lock().unwrap().outstanding_bytes(),
        0
    );
    assert!(
        !directory
            .path()
            .join(format!("nar/{raw_hash}.nar"))
            .exists()
    );
}

#[test]
fn nar_upload_activity_counts_only_validated_and_committed_logical_bytes() {
    for backend in [
        StorageBackend::Flat,
        #[cfg(not(target_os = "macos"))]
        StorageBackend::Chunked,
    ] {
        let directory = TestDir::new();
        let storage = Storage::initialize(
            &Directory::open(directory.path()).unwrap(),
            backend.try_into().unwrap(),
        )
        .unwrap();
        let raw = vec![b'u'; 100_000];
        let hash = NarHash::from_digest(Sha256::digest(&raw).into());
        let name = NarFileName::raw(hash);
        let policy = super::NarUploadPolicy::new(raw.len() as u64, 0);

        assert_eq!(
            storage
                .publish_nar(name, Cursor::new(&raw), raw.len() as u64, policy)
                .unwrap(),
            PublishOutcome::Created
        );
        assert_eq!(
            storage
                .publish_nar(name, Cursor::new(&raw), raw.len() as u64, policy)
                .unwrap(),
            PublishOutcome::Identical
        );

        let mut invalid = raw.clone();
        invalid[0] ^= 1;
        assert!(
            storage
                .publish_nar(name, Cursor::new(&invalid), invalid.len() as u64, policy)
                .is_err()
        );

        let activity = storage.activity_snapshot();
        assert_eq!(
            activity.upload_validated_logical_bytes,
            2 * raw.len() as u64
        );
        assert_eq!(activity.upload_created_logical_bytes, raw.len() as u64);
        assert_eq!(activity.upload_identical_logical_bytes, raw.len() as u64);
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn corrupt_chunk_manifest_cannot_be_bound_as_a_canonical_nar() {
    let directory = TestDir::new();
    let storage = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        StorageBackend::Chunked.try_into().unwrap(),
    )
    .unwrap();
    let raw = vec![b'm'; 100_000];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let identity = NarIdentity::new(hash, NarSize::new(raw.len() as u64));
    storage
        .publish_nar(
            NarFileName::raw(hash),
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(raw.len() as u64, 0),
        )
        .unwrap();

    let manifest_path = directory
        .path()
        .join(super::MANIFEST_DIRECTORY)
        .join(format!("{hash}.manifest"));
    let mut manifest = fs::read(&manifest_path).unwrap();
    let checksum = manifest.len() - 1;
    manifest[checksum] ^= 1;
    fs::write(manifest_path, manifest).unwrap();

    let result = storage.open_verified_canonical_nar(NarRepresentation::Raw(identity));
    assert!(matches!(
        result,
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData
    ));
}

#[test]
#[cfg(not(target_os = "macos"))]
fn chunked_serving_rejects_a_corrupt_chunk_before_emitting_bytes() {
    let directory = TestDir::new();
    let storage = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        StorageBackend::Chunked.try_into().unwrap(),
    )
    .unwrap();
    let raw = vec![b's'; 100_000];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let name = NarFileName::raw(hash);
    storage
        .publish_nar(
            name,
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(raw.len() as u64, 0),
        )
        .unwrap();

    let chunks = directory.path().join(super::CHUNK_DIRECTORY);
    let shard = fs::read_dir(&chunks)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    let chunk = fs::read_dir(shard)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_file())
        .unwrap();
    let mut bytes = fs::read(&chunk).unwrap();
    bytes[0] ^= 1;
    fs::write(chunk, bytes).unwrap();

    let mut opened = storage
        .open_nar_range(name, 0..raw.len() as u64)
        .unwrap()
        .unwrap()
        .body;
    let error = io::copy(&mut opened, &mut io::sink()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn flat_canonical_nar_rejects_same_size_corruption() {
    let directory = TestDir::new();
    let storage = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        SupportedStorageBackend::FLAT,
    )
    .unwrap();
    let raw = vec![b'f'; 4096];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let identity = NarIdentity::new(hash, NarSize::new(raw.len() as u64));
    let name = NarFileName::raw(hash);
    storage
        .publish_nar(
            name,
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(raw.len() as u64, 0),
        )
        .unwrap();

    let payload = directory.path().join("nar").join(format!("{hash}.nar"));
    let mut corrupted = fs::read(&payload).unwrap();
    corrupted[0] ^= 1;
    fs::write(payload, corrupted).unwrap();

    assert!(matches!(
        storage.open_verified_canonical_nar(NarRepresentation::Raw(identity)),
        Err(StorageError::NarMismatch)
    ));
    assert!(matches!(
        storage.open_nar_range(name, 0..raw.len() as u64),
        Err(StorageError::NarMismatch)
    ));
}

#[test]
fn evicted_delivery_validation_proof_is_recomputed() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = vec![b'f'; 4096];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let identity = NarIdentity::new(hash, NarSize::new(raw.len() as u64));
    let name = NarFileName::raw(hash);
    storage
        .publish_nar(
            name,
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(raw.len() as u64, 0),
        )
        .expect("raw NAR should be stored");
    let file = storage
        .open_nar(name)
        .expect("stored NAR should open")
        .expect("stored NAR should exist");

    let incorrect_identity = NarIdentity::new(
        NarHash::from_digest([0xa5; 32]),
        NarSize::new(raw.len() as u64),
    );
    storage
        .delivery_validation
        .insert(name, &file, incorrect_identity)
        .expect("seed proof for eviction regression");

    (0..super::state::DELIVERY_VALIDATION_CACHE_CAPACITY).for_each(|index| {
        let mut digest = [0; 32];
        digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
        storage
            .delivery_validation
            .insert(
                NarFileName::raw(NarHash::from_digest(digest)),
                &file,
                identity,
            )
            .expect("additional proof should be cacheable");
    });

    assert_eq!(
        storage
            .validated_delivery_identity(name, &file)
            .expect("evicted proof should be recomputed"),
        identity
    );
}

#[test]
fn flat_canonical_nar_rejects_a_claimed_size_mismatch() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = vec![b's'; 4096];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    storage
        .publish_nar(
            NarFileName::raw(hash),
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(raw.len() as u64, 0),
        )
        .expect("raw NAR should be stored");

    let claimed = NarIdentity::new(hash, NarSize::new(raw.len() as u64 + 1));
    assert!(matches!(
        storage.open_verified_canonical_nar(NarRepresentation::Raw(claimed)),
        Err(StorageError::NarMismatch)
    ));
}

#[test]
fn compressed_delivery_rejects_same_size_corruption() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = vec![b'c'; 4096];
    let hash = NarHash::from_digest(Sha256::digest(&raw).into());
    let identity = NarIdentity::new(hash, NarSize::new(raw.len() as u64));
    storage
        .publish_nar(
            NarFileName::raw(hash),
            Cursor::new(&raw),
            raw.len() as u64,
            super::NarUploadPolicy::new(raw.len() as u64, 0),
        )
        .expect("raw NAR should be stored");
    let (name, encoded_size) = storage
        .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
        .expect("compressed NAR should be generated");
    let payload = storage.layout().nar_path_encoded(name);
    let mut corrupted = fs::read(&payload).expect("compressed payload should exist");
    corrupted[0] ^= 1;
    fs::write(payload, corrupted).expect("same-size corruption should be writable");

    assert!(matches!(
        storage.open_nar_range(name, 0..encoded_size.get()),
        Err(StorageError::NarMismatch)
    ));
}

fn compressed_bytes(encoding: WireEncoding, raw: &[u8]) -> Vec<u8> {
    match encoding {
        WireEncoding::Compressed(CompressionCodec::Xz) => {
            let mut compressed = Vec::new();
            let mut writer = XzWriter::new(&mut compressed, XzOptions::with_preset(1)).unwrap();
            writer.write_all(raw).unwrap();
            writer.finish().unwrap();
            compressed
        }
        WireEncoding::Compressed(CompressionCodec::Zstd) => {
            let mut compressed = Vec::new();
            compress(Cursor::new(raw), &mut compressed, CompressionLevel::Fastest);
            compressed
        }
        WireEncoding::Raw => panic!("test helper only compresses XZ and Zstd"),
    }
}

fn begin_raw_upload<'storage>(
    storage: &'storage Storage,
    bytes: &[u8],
) -> super::ingest::Staged<'storage, super::typestate::Streaming<super::ingest::UploadRequest>> {
    let name = NarFileName::new(
        FileHash::from_digest(Sha256::digest(bytes).into()),
        WireEncoding::Raw,
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

fn transaction_record_count(storage: &Storage) -> usize {
    fs::read_dir(storage.layout().transaction_dir())
        .expect("read transaction directory")
        .count()
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
        storage.open_nar(NarFileName::raw(hash)).unwrap().is_none(),
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
    assert!(storage.open_nar(NarFileName::raw(hash)).unwrap().is_none());
}

#[test]
fn generic_publication_commits_only_after_finishing_its_stream() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let target = super::publication::PublishTarget::Nar(NarFileName::raw(nar));

    let streaming = storage
        .begin_publication(target, |_| Ok(()))
        .expect("begin publication");
    assert!(storage.open_nar(NarFileName::raw(nar)).unwrap().is_none());
    assert_eq!(storage.temporary_objects(), 1);
    let validated = streaming
        .finish_and_sync(Cursor::new(b"nar bytes"))
        .expect("finish publication stream");
    assert!(storage.open_nar(NarFileName::raw(nar)).unwrap().is_none());
    assert_eq!(storage.temporary_objects(), 1);

    assert_eq!(
        validated.commit().expect("commit publication"),
        PublishOutcome::Created
    );
    assert_eq!(storage.temporary_objects(), 0);
    assert_eq!(
        fs::read(storage.layout().nar_path(nar)).unwrap(),
        b"nar bytes"
    );
}

#[test]
fn abandoned_generic_publication_cleans_up_staging() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let target = super::publication::PublishTarget::Nar(NarFileName::raw(nar));

    let streaming = storage.begin_publication(target, |_| Ok(())).unwrap();
    assert!(storage.recovery_required().unwrap());
    drop(streaming);
    assert!(!storage.recovery_required().unwrap());
    assert_eq!(storage.temporary_objects(), 0);

    let target = super::publication::PublishTarget::Nar(NarFileName::raw(nar));
    let validated = storage
        .begin_publication(target, |_| Ok(()))
        .unwrap()
        .finish_and_sync(Cursor::new(b"nar bytes"))
        .unwrap();
    assert_eq!(storage.temporary_objects(), 1);
    assert!(storage.recovery_required().unwrap());
    drop(validated);

    assert_eq!(storage.temporary_objects(), 0);
    assert!(!storage.recovery_required().unwrap());
    assert!(storage.open_nar(NarFileName::raw(nar)).unwrap().is_none());
    assert!(
        fs::read_dir(storage.layout().nar_temp_dir())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn abandoned_generic_publication_retains_recovery_when_temp_cleanup_fails() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let target = PublishTarget::Nar(NarFileName::raw(nar));
    let streaming = storage.begin_publication(target, |_| Ok(())).unwrap();
    let temporary_directory = storage.layout().nar_temp_dir();
    fs::set_permissions(&temporary_directory, fs::Permissions::from_mode(0o500))
        .expect("make temporary directory unavailable for unlink");

    drop(streaming);

    fs::set_permissions(&temporary_directory, fs::Permissions::from_mode(0o700))
        .expect("restore temporary directory permissions");
    assert!(storage.recovery_required().unwrap());
    assert_eq!(fs::read_dir(&temporary_directory).unwrap().count(), 1);

    storage.finish_recovery().unwrap();

    assert!(!storage.recovery_required().unwrap());
    assert_eq!(fs::read_dir(&temporary_directory).unwrap().count(), 0);
}

#[test]
fn failed_generic_publication_stream_cleans_up_staging() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let target = PublishTarget::Nar(NarFileName::raw(nar));

    let result = storage
        .begin_publication(target, |_| Ok(()))
        .unwrap()
        .finish_and_sync(BrokenReader::new(libc::EIO));

    assert!(
        matches!(result, Err(StorageError::Io(error)) if error.raw_os_error() == Some(libc::EIO))
    );
    assert_eq!(storage.temporary_objects(), 0);
    assert!(storage.open_nar(NarFileName::raw(nar)).unwrap().is_none());
    assert!(
        fs::read_dir(storage.layout().nar_temp_dir())
            .unwrap()
            .next()
            .is_none()
    );
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
    assert_eq!(transaction_record_count(&storage), 0);

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
    assert_eq!(transaction_record_count(&storage), 0);
}

#[test]
fn rejected_and_disconnected_uploads_do_not_accumulate_transactions() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let bytes = b"rejected NAR";
    let wrong_hash = FileHash::from_digest(Sha256::digest(b"different NAR").into());

    for _ in 0..8 {
        let reservation = storage.reserve_staging(bytes.len() as u64, 0).unwrap();
        let receiving = storage
            .begin_upload(
                NarFileName::new(wrong_hash, WireEncoding::Raw),
                bytes.len() as u64,
                super::NarUploadPolicy::new(bytes.len() as u64, 0),
                reservation,
            )
            .unwrap();
        let rejected = receiving.receive(bytes.as_slice());
        assert!(matches!(
            rejected,
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert_eq!(transaction_record_count(&storage), 0);

        let receiving = begin_raw_upload(&storage, bytes);
        assert!(
            receiving
                .receive(BrokenReader::new(libc::ECONNRESET))
                .is_err()
        );
        assert_eq!(transaction_record_count(&storage), 0);
    }

    assert_upload_resources_released(&storage);
}

#[test]
fn uncertain_upload_publication_retains_its_recovery_record() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let raw = b"raw NAR";
    let complete = begin_raw_upload(&storage, raw)
        .receive(raw.as_slice())
        .unwrap();

    assert!(
        complete
            .commit_fault(PublishBoundary::BeforeFinalLink)
            .is_err()
    );
    assert_eq!(transaction_record_count(&storage), 1);
    assert!(
        fs::read_dir(storage.layout().nar_temp_dir())
            .unwrap()
            .next()
            .is_none(),
        "a conclusively removable staging file is cleaned even when publication is uncertain"
    );
    assert_upload_resources_released(&storage);

    storage.finish_recovery().unwrap();
    assert_eq!(transaction_record_count(&storage), 0);
}

#[test]
fn upload_setup_failure_cancels_transaction_after_temporary_cleanup() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let bytes = b"raw NAR";
    let name = NarFileName::new(
        FileHash::from_digest(Sha256::digest(bytes).into()),
        WireEncoding::Raw,
    );
    let reservation = storage.reserve_staging(bytes.len() as u64, 0).unwrap();

    let result = storage.begin_upload_with_temp_setup(
        name,
        bytes.len() as u64,
        super::NarUploadPolicy::new(bytes.len() as u64, 0),
        reservation,
        |_| Err(io::Error::other("injected setup failure")),
    );

    assert!(result.is_err());
    assert_eq!(transaction_record_count(&storage), 0);
    assert_upload_resources_released(&storage);
}

#[test]
fn upload_setup_failure_retains_transaction_when_temporary_cleanup_fails() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).unwrap();
    let bytes = b"raw NAR";
    let name = NarFileName::new(
        FileHash::from_digest(Sha256::digest(bytes).into()),
        WireEncoding::Raw,
    );
    let reservation = storage.reserve_staging(bytes.len() as u64, 0).unwrap();
    let temporary_directory = storage.layout().nar_temp_dir();
    let result = storage.begin_upload_with_temp_setup(
        name,
        bytes.len() as u64,
        super::NarUploadPolicy::new(bytes.len() as u64, 0),
        reservation,
        |temporary| {
            let temporary_path = temporary_directory.join(&temporary.name);
            fs::remove_file(&temporary_path)?;
            fs::create_dir(&temporary_path)?;
            fs::write(temporary_path.join("keep-unlink-failing"), b"block unlink")?;
            Err(io::Error::other("injected setup failure"))
        },
    );

    assert!(result.is_err());
    assert_eq!(transaction_record_count(&storage), 1);
    assert_eq!(
        fs::read_dir(&temporary_directory).unwrap().count(),
        1,
        "failed cleanup leaves the replacement path for recovery"
    );

    let temporary_path = fs::read_dir(&temporary_directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(temporary_path.join("keep-unlink-failing")).unwrap();
    fs::remove_dir(&temporary_path).unwrap();
    storage.finish_recovery().unwrap();
    assert_eq!(transaction_record_count(&storage), 0);
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
    let mut reader = CheckedUploadReader::new(Cursor::new(bytes), expected, bytes.len() as u64);
    let mut received = [0; 17];
    reader
        .read_exact(&mut received)
        .expect("matching upload should be readable");
    assert_eq!(&received, bytes);
    reader
        .finish()
        .expect("matching upload should complete successfully");

    let wrong_hash = FileHash::parse(NAR_ID).expect("file hash is valid");
    let mut reader = CheckedUploadReader::new(Cursor::new(bytes), wrong_hash, bytes.len() as u64);
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
        expected,
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
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
        for source_error in [libc::EIO, libc::EOPNOTSUPP] {
            let directory = TestDir::new();
            let destination_path = directory.path().join("raw.nar");
            let mut destination =
                fs::File::create(destination_path).expect("create raw staging file");
            let error = receive_uploaded_nar(
                BrokenReader::new(source_error),
                NarFileName::new(
                    FileHash::parse(NAR_ID).expect("file hash is valid"),
                    encoding,
                ),
                3,
                u64::MAX,
                DecoderMemoryLimit::new(super::NarUploadPolicy::DEFAULT_MAX_DECODER_MEMORY_BYTES),
                &mut destination,
            )
            .expect_err("source failure must not become invalid content");
            assert_eq!(error.raw_os_error(), Some(source_error), "{encoding:?}");
        }
    }
}

struct UnsupportedOutputWriter;

impl Write for UnsupportedOutputWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn compressed_output_writer_errors_remain_io_errors() {
    let raw = b"valid raw NAR bytes";
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
        let compressed = compressed_bytes(encoding, raw);
        let file_hash = FileHash::from_digest(Sha256::digest(&compressed).into());
        let nar_name = NarFileName::new(file_hash, encoding);

        let error = receive_uploaded_nar(
            Cursor::new(&compressed),
            nar_name,
            compressed.len() as u64,
            u64::MAX,
            DecoderMemoryLimit::new(super::NarUploadPolicy::DEFAULT_MAX_DECODER_MEMORY_BYTES),
            &mut UnsupportedOutputWriter,
        )
        .expect_err("output storage failure must not become invalid compressed input");

        assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP), "{encoding:?}");
    }
}

#[test]
fn xz_upload_decoder_rejects_memory_just_below_the_declared_dictionary_requirement() {
    let raw = b"XZ dictionary memory limit fixture";
    let compressed = compressed_bytes(WireEncoding::Compressed(CompressionCodec::Xz), raw);
    let dictionary_bytes = XzOptions::with_preset(1).lzma_options.dict_size as u64;
    let exact_limit = xz_decoder_memory_requirement(dictionary_bytes)
        .expect("fixed XZ workspace plus dictionary size fits u64");

    assert_compressed_upload_memory_limit(
        WireEncoding::Compressed(CompressionCodec::Xz),
        raw,
        &compressed,
        exact_limit - 1024,
        false,
    );
    assert_compressed_upload_memory_limit(
        WireEncoding::Compressed(CompressionCodec::Xz),
        raw,
        &compressed,
        exact_limit,
        true,
    );
    assert_compressed_upload_memory_limit(
        WireEncoding::Compressed(CompressionCodec::Xz),
        raw,
        &compressed,
        exact_limit + 1024,
        true,
    );
}

#[test]
fn xz_index_block_count_is_rejected_before_allocating_records() {
    const EXCESSIVE_XZ_BLOCK_COUNT: u64 = 16_777_216;

    let raw = b"a single XZ block";
    let mut compressed = compressed_bytes(WireEncoding::Compressed(CompressionCodec::Xz), raw);
    let footer_start = compressed.len() - 12;
    let backward_size = u32::from_le_bytes(
        compressed[footer_start + 4..footer_start + 8]
            .try_into()
            .expect("XZ footer contains its backward size"),
    ) as usize;
    let index_start = footer_start - (backward_size + 1) * 4;
    assert_eq!(
        compressed[index_start], 0,
        "XZ index starts with its marker"
    );
    assert_eq!(
        compressed[index_start + 1],
        1,
        "fixture has exactly one block"
    );
    compressed.splice(
        index_start + 1..index_start + 2,
        encode_xz_variable_integer(EXCESSIVE_XZ_BLOCK_COUNT),
    );

    let encoded_hash = FileHash::from_digest(Sha256::digest(&compressed).into());
    let mut decoded = Vec::new();
    let error = receive_uploaded_nar(
        Cursor::new(&compressed),
        NarFileName::new(encoded_hash, WireEncoding::Compressed(CompressionCodec::Xz)),
        compressed.len() as u64,
        u64::MAX,
        DecoderMemoryLimit::new(super::NarUploadPolicy::DEFAULT_MAX_DECODER_MEMORY_BYTES),
        &mut decoded,
    )
    .expect_err("index claiming more blocks than decoded must be rejected");

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

fn encode_xz_variable_integer(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 0x80 {
        bytes.push(value as u8 | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

#[test]
fn zstd_upload_decoder_rejects_windows_above_the_configured_memory_limit() {
    let raw = vec![b'z'; 512 * 1024];
    let encoding = WireEncoding::Compressed(CompressionCodec::Zstd);
    let compressed = compressed_bytes(encoding, &raw);
    let window_bytes = read_frame_header_info(&compressed, false)
        .expect("fixture has a complete zstd frame header")
        .window_size;
    let exact_limit = window_bytes
        + 128 * 1024
        + ZSTD_FIXED_WORKSPACE_ALLOWANCE_BYTES
        + std::mem::size_of::<structured_zstd::decoding::FrameDecoder>() as u64;

    assert_compressed_upload_memory_limit(encoding, &raw, &compressed, exact_limit - 1, false);
    assert_compressed_upload_memory_limit(encoding, &raw, &compressed, exact_limit, true);
    assert_compressed_upload_memory_limit(encoding, &raw, &compressed, exact_limit + 1, true);
}

#[test]
fn zstd_upload_memory_limit_includes_decoder_workspace_beyond_its_window() {
    let mut state = 0x1234_5678_u32;
    let seed = (0..512 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect::<Vec<_>>();
    let raw = seed.repeat(4);
    let encoding = WireEncoding::Compressed(CompressionCodec::Zstd);
    let mut compressed = Vec::new();
    let mut encoder = structured_zstd::encoding::StreamingEncoder::new(
        &mut compressed,
        CompressionLevel::Default,
    );
    encoder.write_all(&raw).expect("encode zstd fixture");
    encoder.finish().expect("finish zstd fixture");
    let header = read_frame_header_info(&compressed, false)
        .expect("fixture has a complete zstd frame header");
    let old_window_only_limit = header.window_size + 128 * 1024;
    let mut decoder = StructuredZstdDecoder::new(Cursor::new(&compressed))
        .expect("fixture starts a valid zstd decoder");
    io::copy(&mut decoder, &mut io::sink()).expect("fixture decodes");

    let actual_workspace_bytes =
        decoder.decoder.workspace_size() as u64 + std::mem::size_of_val(&decoder.decoder) as u64;
    assert!(
        actual_workspace_bytes > old_window_only_limit,
        "fixture workspace {actual_workspace_bytes} must exceed window-only limit \
         {old_window_only_limit} (window {})",
        header.window_size
    );
    let full_workspace_limit = old_window_only_limit
        + ZSTD_FIXED_WORKSPACE_ALLOWANCE_BYTES
        + std::mem::size_of::<structured_zstd::decoding::FrameDecoder>() as u64;
    assert!(
        actual_workspace_bytes <= full_workspace_limit,
        "fixture workspace {actual_workspace_bytes} must fit conservative limit \
         {full_workspace_limit}"
    );
    assert_compressed_upload_memory_limit(
        encoding,
        &raw,
        &compressed,
        old_window_only_limit,
        false,
    );
}

#[test]
fn upload_memory_rejection_publishes_no_nar_and_releases_staging() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let raw = b"compressed upload rejected before decoder allocation";
    let decoded_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let decoder_limit = 1024;

    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
        let compressed = compressed_bytes(encoding, raw);
        let encoded_hash = FileHash::from_digest(Sha256::digest(&compressed).into());
        let policy = super::NarUploadPolicy::with_limits(
            compressed.len() as u64,
            raw.len() as u64,
            decoder_limit,
            0,
        );
        let result = storage.publish_nar(
            NarFileName::new(encoded_hash, encoding),
            Cursor::new(&compressed),
            compressed.len() as u64,
            policy,
        );

        assert!(
            matches!(&result, Err(StorageError::DecoderMemoryLimitExceeded)),
            "{encoding:?} decoder requirement should be a client content error: {result:?}"
        );
        assert!(
            !directory
                .path()
                .join(format!("nar/{decoded_hash}.nar"))
                .exists()
        );
        assert_eq!(
            fs::read_dir(directory.path().join(".tmp"))
                .expect("temporary directory exists")
                .count(),
            0,
            "rejection removes its staging file"
        );
        assert_eq!(
            storage.staging_budget.lock().unwrap().outstanding_bytes(),
            0,
            "rejection releases its staging reservation"
        );
    }
}

fn assert_compressed_upload_memory_limit(
    encoding: WireEncoding,
    raw: &[u8],
    compressed: &[u8],
    memory_limit: u64,
    should_decode: bool,
) {
    let hash = FileHash::from_digest(Sha256::digest(compressed).into());
    let mut decoded = Vec::new();
    let result = receive_uploaded_nar(
        Cursor::new(compressed),
        NarFileName::new(hash, encoding),
        compressed.len() as u64,
        raw.len() as u64,
        DecoderMemoryLimit::new(memory_limit),
        &mut decoded,
    );

    if should_decode {
        result.expect("frame at or below the configured memory limit is accepted");
        assert_eq!(decoded, raw);
    } else {
        let error = result.expect_err("frame above the configured memory limit is rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            decoded.is_empty(),
            "decoder rejected the frame before output"
        );
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
            NarFileName::new(encoded, WireEncoding::Compressed(CompressionCodec::Xz)),
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

    let expectation = CompressedNarIdentity::new(
        EncodedIdentity::new(
            CompressionCodec::Xz,
            file_hash,
            EncodedSize::new(compressed.len() as u64),
        ),
        NarIdentity::new(nar_hash, NarSize::new(raw.len() as u64)),
    );
    let verified = verify_encoded_compressed_file(&file, expectation)
        .expect("verify encoded XZ NAR")
        .expect("encoded XZ NAR matches");

    assert_eq!(
        verify_decoded_compressed_file(verified)
            .expect("verify decoded XZ NAR")
            .expect("decoded XZ NAR matches"),
        NarIdentity::new(nar_hash, NarSize::new(raw.len() as u64))
    );
}

#[test]
fn reserved_xz_stream_flags_are_invalid_content() {
    let directory = TestDir::new();
    let path = directory.path().join("nar.xz");
    let raw = b"nar bytes";
    let mut compressed = Vec::new();
    let mut writer =
        XzWriter::new(&mut compressed, XzOptions::with_preset(1)).expect("create XZ writer");
    writer.write_all(raw).expect("compress NAR");
    writer.finish().expect("finish XZ stream");

    // Keep the stream-header CRC valid while setting a reserved flag bit.
    compressed[6] = 0x04;
    compressed[7] = 0x04;
    compressed[8..12].copy_from_slice(&[0xe2, 0x13, 0xd8, 0x22]);
    fs::write(&path, &compressed).expect("write malformed XZ NAR");
    let file = fs::File::open(path).expect("open malformed XZ NAR");
    let nar_hash = NarHash::parse(&nix32_sha256(&Sha256::digest(raw))).expect("NAR hash is valid");
    let file_hash =
        FileHash::parse(&nix32_sha256(&Sha256::digest(&compressed))).expect("file hash is valid");
    let expectation = CompressedNarIdentity::new(
        EncodedIdentity::new(
            CompressionCodec::Xz,
            file_hash,
            EncodedSize::new(compressed.len() as u64),
        ),
        NarIdentity::new(nar_hash, NarSize::new(raw.len() as u64)),
    );
    let verified = verify_encoded_compressed_file(&file, expectation)
        .expect("read encoded malformed XZ NAR")
        .expect("encoded malformed XZ NAR matches its hash");

    assert!(
        verify_decoded_compressed_file(verified)
            .expect("malformed XZ is classified as invalid content")
            .is_none()
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

    for (encoding, compressed) in [
        (WireEncoding::Compressed(CompressionCodec::Xz), xz),
        (WireEncoding::Compressed(CompressionCodec::Zstd), zstd),
    ] {
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
            let expectation = CompressedNarIdentity::new(
                EncodedIdentity::new(
                    match encoding {
                        WireEncoding::Compressed(codec) => codec,
                        WireEncoding::Raw => {
                            unreachable!("test only supplies compressed encodings")
                        }
                    },
                    *encoded_hash,
                    encoded_size,
                ),
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
            NarFileName::new(encoded, WireEncoding::Compressed(CompressionCodec::Zstd)),
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
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
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
    for encoding in [
        WireEncoding::Compressed(CompressionCodec::Xz),
        WireEncoding::Compressed(CompressionCodec::Zstd),
    ] {
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
#[cfg(not(target_os = "macos"))]
fn chunked_recovery_retains_egress_receipts_for_manifest_backed_raw_objects() {
    let directory = TestDir::new();
    let raw = b"chunked raw NAR for egress recovery";
    let raw_hash = NarHash::from_digest(Sha256::digest(raw).into());
    let identity = NarIdentity::new(raw_hash, (raw.len() as u64).into());
    let output = {
        let storage = Storage::initialize(
            &Directory::open(directory.path()).unwrap(),
            StorageBackend::Chunked.try_into().unwrap(),
        )
        .unwrap();
        storage
            .publish_nar(
                NarFileName::raw(raw_hash),
                Cursor::new(raw),
                raw.len() as u64,
                super::NarUploadPolicy::new(raw.len() as u64, 0),
            )
            .unwrap();
        let output = storage
            .compressed_representation_for_test(identity, CompressionCodec::Zstd, 0)
            .unwrap();
        assert_eq!(storage.egress_generations(), 1);
        output
    };

    let restarted = Storage::initialize(
        &Directory::open(directory.path()).unwrap(),
        StorageBackend::Chunked.try_into().unwrap(),
    )
    .unwrap();
    restarted.finish_recovery().unwrap();
    assert_eq!(
        fs::read_dir(restarted.layout().egress_receipt_dir())
            .unwrap()
            .count(),
        1,
        "manifest-backed canonical raw storage must retain its egress receipt"
    );
    assert_eq!(
        restarted
            .compressed_representation_for_test(identity, CompressionCodec::Zstd, u64::MAX)
            .unwrap(),
        output
    );
    assert_eq!(restarted.egress_generations(), 0);
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
            NarFileName::new(xz_id, WireEncoding::Compressed(CompressionCodec::Xz)),
            Cursor::new(&xz),
            xz.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        )
        .expect("publish XZ NAR");
    let zstd_result = storage
        .publish_nar(
            NarFileName::new(zstd_id, WireEncoding::Compressed(CompressionCodec::Zstd)),
            Cursor::new(&compressed),
            compressed.len() as u64,
            super::NarUploadPolicy::new(1024, 0),
        )
        .expect("publish Zstd NAR");

    assert_eq!(xz_result, PublishOutcome::Created);
    assert_eq!(zstd_result, PublishOutcome::Identical);
    let activity = storage.activity_snapshot();
    assert_eq!(
        activity.upload_validated_logical_bytes,
        2 * raw.len() as u64
    );
    assert_eq!(activity.upload_created_logical_bytes, raw.len() as u64);
    assert_eq!(activity.upload_identical_logical_bytes, raw.len() as u64);
    assert_eq!(fs::read(storage.layout().nar_path(raw_hash)).unwrap(), raw);
    assert!(
        !storage
            .layout()
            .nar_path_encoded(NarFileName::new(
                xz_id,
                WireEncoding::Compressed(CompressionCodec::Xz),
            ))
            .exists()
    );
    assert!(
        !storage
            .layout()
            .nar_path_encoded(NarFileName::new(
                zstd_id,
                WireEncoding::Compressed(CompressionCodec::Zstd),
            ))
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
        .publish(
            PublishTarget::Nar(NarFileName::raw(raw_hash)),
            Cursor::new(&raw),
        )
        .expect("raw NAR should be stored");
    let raw_file = storage
        .open_nar(NarFileName::raw(raw_hash))
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
        matches!(result, Err(StorageError::InsufficientSpace)),
        "egress must reject the configured free-space reserve before writing"
    );
    assert_eq!(storage.temporary_objects(), 0);
    let activity = storage.activity_snapshot();
    assert_eq!(activity.egress_generations_started, 1);
    assert_eq!(activity.egress_generations_failed, 1);
    assert_eq!(activity.egress_generations_succeeded, 0);
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
        .publish(
            PublishTarget::Nar(NarFileName::raw(raw_hash)),
            Cursor::new(raw),
        )
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
    let activity = storage.activity_snapshot();
    assert_eq!(activity.egress_generations_started, 1);
    assert_eq!(activity.egress_generations_succeeded, 1);
    assert_eq!(activity.egress_reuses, 1);
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
            .publish(
                PublishTarget::Nar(NarFileName::raw(raw_hash)),
                Cursor::new(raw),
            )
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
        .publish(
            PublishTarget::Nar(NarFileName::raw(raw_hash)),
            Cursor::new(raw),
        )
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
        .publish(
            PublishTarget::Nar(NarFileName::raw(raw_hash)),
            Cursor::new(raw),
        )
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
    let wrong_output_hash = FileHash::from_digest([0xff; 32]);
    let wrong_receipt = EgressReceipt::for_slot(
        EgressSlot::new(identity, CompressionCodec::Zstd),
        wrong_output_hash,
        output.1,
    );
    fs::write(receipt_path, wrong_receipt.bytes())
        .expect("test should rewrite the receipt identity");

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
        .publish(
            PublishTarget::Nar(NarFileName::raw(raw_hash)),
            Cursor::new(raw),
        )
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
    assert_eq!(storage.activity_snapshot().egress_repairs, 1);
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
        .publish(
            PublishTarget::Nar(NarFileName::raw(raw_hash)),
            Cursor::new(raw),
        )
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
    let activity = storage.activity_snapshot();
    assert_eq!(activity.egress_generations_succeeded, 1);
    assert_eq!(activity.egress_reuses, 3);
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
        NarFileName::new(nar, WireEncoding::Compressed(CompressionCodec::Zstd)),
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
        NarFileName::new(nar, WireEncoding::Compressed(CompressionCodec::Xz)),
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

    for (encoding, mut compressed) in [
        (WireEncoding::Compressed(CompressionCodec::Xz), xz),
        (WireEncoding::Compressed(CompressionCodec::Zstd), zstd),
    ] {
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

    assert_eq!(
        fs::read(directory.path().join(super::LAYOUT_DESCRIPTOR)).unwrap(),
        StorageBackend::Flat.layout_descriptor()
    );
    assert!(directory.path().join("nar").is_dir());
    assert!(directory.path().join("nar/.tmp").is_dir());
    assert!(directory.path().join(".tmp").is_dir());
    assert!(directory.path().join("realisations").is_dir());
    assert!(directory.path().join("realisations/.tmp").is_dir());
    assert_eq!(storage.layout(), &Layout::new(directory.path().to_owned()));
}

#[test]
#[cfg(not(target_os = "macos"))]
fn initialization_rejects_a_different_storage_backend() {
    let directory = TestDir::new();
    let root = Directory::open(directory.path()).unwrap();
    let storage = Storage::initialize(&root, SupportedStorageBackend::FLAT).unwrap();
    drop(storage);

    let error = Storage::initialize(&root, StorageBackend::Chunked.try_into().unwrap())
        .expect_err("a populated root must retain its selected backend");
    assert!(error.to_string().contains("different storage backend"));
}

#[test]
#[cfg(target_os = "macos")]
fn unsupported_backend_cannot_be_prepared_for_storage_initialization() {
    let directory = TestDir::new();
    let error = SupportedStorageBackend::try_from(StorageBackend::Chunked)
        .expect_err("chunked storage is unsupported on macOS");

    assert!(error.to_string().contains("not supported on macOS"));
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
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
            .publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"must not escape"),
            )
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
            .publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"must not be compared"),
            )
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
        .begin(
            Path::new(".tmp/cache-info-recovery.part"),
            Path::new("nix-cache-info"),
        )
        .expect("record interrupted cache-info publication");
    storage
        .recovery
        .begin(
            Path::new("nar/.tmp/nar-recovery.part"),
            Path::new("nar/recovery.nar"),
        )
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
fn recovery_discards_abandoned_transaction_drafts_before_parsing_records() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let temporary = directory.path().join(".tmp/abandoned-draft.part");
    fs::write(&temporary, b"incomplete publication").expect("create publication temp");
    drop(
        storage
            .recovery
            .begin(
                Path::new(".tmp/abandoned-draft.part"),
                Path::new("nix-cache-info"),
            )
            .expect("record interrupted publication"),
    );

    let transaction_directory = directory.path().join(".narjar-transactions");
    let record_name = fs::read_dir(&transaction_directory)
        .expect("read transaction directory")
        .next()
        .expect("transaction record exists")
        .expect("read transaction entry")
        .file_name();
    let abandoned_draft = transaction_directory.join(format!(
        "{}.next-0000000000000001",
        record_name.to_string_lossy()
    ));
    fs::write(&abandoned_draft, b"partial state=")
        .expect("simulate process termination during draft write");
    fs::set_permissions(&abandoned_draft, fs::Permissions::from_mode(0o000))
        .expect("make abandoned draft unreadable");

    storage
        .finish_recovery()
        .expect("abandoned draft is not an authoritative transaction");

    assert!(
        !temporary.exists(),
        "authoritative record recovers its temp"
    );
    assert!(
        !abandoned_draft.exists(),
        "recovery removes the abandoned draft"
    );
    assert!(
        fs::read_dir(&transaction_directory)
            .expect("read recovered transaction directory")
            .next()
            .is_none(),
        "recovery leaves no transaction entries"
    );
}

#[test]
fn recovery_handles_the_initial_record_hard_link_before_draft_unlink() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let temporary = directory.path().join(".tmp/initial-link-window.part");
    fs::write(&temporary, b"interrupted publication").expect("create publication temp");
    drop(
        storage
            .recovery
            .begin(
                Path::new(".tmp/initial-link-window.part"),
                Path::new("nix-cache-info"),
            )
            .expect("record interrupted publication"),
    );

    let transaction_directory = directory.path().join(".narjar-transactions");
    let record_path = fs::read_dir(&transaction_directory)
        .expect("read transaction directory")
        .next()
        .expect("transaction record exists")
        .expect("read transaction entry")
        .path();
    let draft_path = transaction_directory.join(format!(
        "{}.next-0000000000000002",
        record_path
            .file_name()
            .expect("record filename")
            .to_string_lossy()
    ));
    fs::hard_link(&record_path, &draft_path).expect("simulate crash after hard-link install");

    storage
        .finish_recovery()
        .expect("recovery handles the complete linked record and its draft");

    assert!(
        !temporary.exists(),
        "the authoritative record recovers its temp"
    );
    assert!(
        !draft_path.exists(),
        "recovery removes the leftover draft link"
    );
    assert!(
        fs::read_dir(&transaction_directory)
            .expect("read recovered transaction directory")
            .next()
            .is_none(),
        "recovery leaves no transaction entries"
    );
}

#[test]
fn recovery_rejects_invalid_destination_before_creating_a_record() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let invalid_destination = Path::new(std::ffi::OsStr::from_bytes(b"invalid-\xff-name"));

    assert!(
        storage
            .recovery
            .begin(Path::new(".tmp/unrecorded.part"), invalid_destination)
            .is_err(),
        "transaction paths must be validated before record publication"
    );
    assert!(
        fs::read_dir(directory.path().join(".narjar-transactions"))
            .expect("read transaction directory")
            .next()
            .is_none(),
        "a rejected transaction must not leave a partial authoritative record"
    );
}

#[test]
fn recovery_requires_published_transaction_destinations() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    fs::write(
        directory.path().join("nix-cache-info"),
        b"Cache-Control: max-age=1\n",
    )
    .expect("create published destination");

    let mut transaction = storage
        .recovery
        .begin(
            Path::new(".tmp/published-recovery.part"),
            Path::new("nix-cache-info"),
        )
        .expect("record publication");
    transaction
        .transition(super::recovery::PublicationState::Streaming)
        .expect("streaming transition");
    transaction
        .transition(super::recovery::PublicationState::Validated)
        .expect("validation transition");
    transaction
        .transition(super::recovery::PublicationState::Linked)
        .expect("linked transition");
    drop(transaction);

    storage
        .finish_recovery()
        .expect("published destination should make recovery safe");
    assert!(!storage.recovery_required().expect("inspect recovery state"));
}

#[test]
fn recovery_keeps_evidence_when_published_destination_is_missing() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let mut transaction = storage
        .recovery
        .begin(
            Path::new(".tmp/missing-destination.part"),
            Path::new("nix-cache-info"),
        )
        .expect("record publication");
    transaction
        .transition(super::recovery::PublicationState::Streaming)
        .expect("streaming transition");
    transaction
        .transition(super::recovery::PublicationState::Validated)
        .expect("validation transition");
    transaction
        .transition(super::recovery::PublicationState::Published)
        .expect("published transition");
    drop(transaction);

    assert!(matches!(
        storage.finish_recovery(),
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound
    ));
    assert!(
        storage
            .recovery_required()
            .expect("inspect recovery evidence")
    );
}

#[test]
fn legacy_terminal_publication_transactions_remain_recoverable() {
    for state in ["linked", "published"] {
        let directory = TestDir::new();
        let storage = initialize_storage(directory.path()).expect("initialize storage");
        let trusted_keys = directory.path().join("trusted-public-keys");
        let temporary = directory.path().join(format!(".tmp/legacy-{state}.part"));
        let record = directory
            .path()
            .join(format!(".narjar-transactions/publish-legacy-{state}.txn"));
        fs::write(&trusted_keys, b"").expect("create trusted key file");
        fs::write(&temporary, b"legacy temporary publication")
            .expect("create legacy temporary publication");
        fs::write(
            &record,
            format!("state={state}\npath=.tmp/legacy-{state}.part\n"),
        )
        .expect("create legacy transaction record");
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
            .expect("make legacy record private");

        storage
            .finish_recovery()
            .expect("legacy transaction should be recoverable");
        assert!(!temporary.exists());
        assert!(!record.exists());
    }
}

#[test]
fn current_terminal_publication_transactions_still_require_destinations() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let temporary = directory.path().join(".tmp/missing-field.part");
    let record = directory
        .path()
        .join(".narjar-transactions/publish-missing-field.txn");
    fs::write(&temporary, b"temporary publication").expect("create temporary publication");
    fs::write(
        &record,
        b"state=published\npath=.tmp/missing-field.part\ndestination=\n",
    )
    .expect("create incomplete current transaction record");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
        .expect("make incomplete record private");

    assert!(storage.finish_recovery().is_err());
    assert!(temporary.exists());
    assert!(record.exists());
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
fn malformed_publication_transaction_destination_blocks_recovery() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let trusted_keys = directory.path().join("trusted-public-keys");
    let temporary = directory.path().join(".tmp/malformed-destination.part");
    let record = directory
        .path()
        .join(".narjar-transactions/publish-malformed-destination.txn");
    fs::write(&trusted_keys, b"").expect("create trusted key file");
    fs::write(&temporary, b"temporary").expect("create temporary publication");
    fs::write(
        &record,
        b"state=staging\npath=.tmp/malformed-destination.part\ngarbage\n",
    )
    .expect("create malformed destination record");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
        .expect("make malformed record private");

    assert!(storage.finish_recovery().is_err());
    assert!(record.exists(), "failed recovery must retain its evidence");
    assert!(
        temporary.exists(),
        "failed recovery must not remove the temporary publication"
    );
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
            .publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"nar bytes"),
            )
            .expect("publish NAR"),
        PublishOutcome::Created
    );
    assert_eq!(
        storage
            .publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"nar bytes"),
            )
            .expect("retry identical NAR"),
        PublishOutcome::Identical
    );
    assert!(matches!(
        storage.publish(
            PublishTarget::Nar(NarFileName::raw(nar)),
            Cursor::new(b"different"),
        ),
        Err(StorageError::Conflict)
    ));
    assert!(storage.open_narinfo(&store).unwrap().is_none());

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

    let mut nar_file = storage
        .open_nar(NarFileName::raw(nar))
        .expect("open durable NAR")
        .expect("NAR should be visible");
    let mut narinfo_file = storage
        .open_narinfo(&store)
        .expect("open durable narinfo")
        .expect("narinfo should be visible");
    let mut nar_bytes = Vec::new();
    let mut narinfo_bytes = Vec::new();
    nar_file.read_to_end(&mut nar_bytes).expect("read NAR");
    narinfo_file
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
fn narinfo_publication_is_idempotent_for_matching_logical_claims() {
    let directory = TestDir::new();
    let storage = initialize_storage(directory.path()).expect("initialize storage");
    let store = StoreHash::parse(STORE_HASH).expect("valid store hash");
    let nar = NarHash::parse(NAR_ID).expect("valid NAR hash");
    let identity = NarIdentity::new(nar, NarSize::new(11));
    let claims = NarInfoClaims::new(
        format!("/nix/store/{STORE_HASH}-sample"),
        Vec::new(),
        identity,
    )
    .expect("valid narinfo claims");
    let existing = format!(
        "StorePath: /nix/store/{STORE_HASH}-sample\n\
         URL: nar/{NAR_ID}.nar\n\
         Compression: none\n\
         FileHash: sha256:{NAR_ID}\n\
         FileSize: 11\n\
         NarHash: sha256:{NAR_ID}\n\
         NarSize: 11\n\
         References: \n"
    );
    storage
        .publish(
            PublishTarget::NarInfo(&store),
            Cursor::new(existing.as_bytes()),
        )
        .expect("publish existing narinfo");

    let incoming = format!("{existing}Sig: another-key:signature\n").into_bytes();
    assert_eq!(
        storage
            .publish_narinfo_with_claims(&claims, incoming)
            .expect("matching claims should make publication idempotent"),
        PublishOutcome::Identical
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
            let outcome = storage.publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"nar bytes"),
            );
            outcome_tx.send(outcome).expect("send contender outcome");
        })
    };

    started_rx.recv().expect("wait for contender");
    let early_outcome = outcome_rx.recv_timeout(Duration::from_secs(5)).ok();
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
            .publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                Cursor::new(b"nar bytes"),
            )
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
    assert!(storage.open_narinfo(&store).unwrap().is_some());
    assert!(storage.open_nar(NarFileName::raw(nar)).unwrap().is_some());
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
            .publish(
                PublishTarget::Nar(NarFileName::raw(nar)),
                BrokenReader::new(raw_error),
            )
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
    let space = StorageCapacity {
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
    let space = StorageCapacity {
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
    let space = StorageCapacity {
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
    let read_only = StorageCapacity {
        total_bytes: 100,
        available_bytes: 100,
        total_inodes: 2,
        available_inodes: 2,
        read_only: true,
    };
    let inode_exhausted = StorageCapacity {
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
    let (staged_tx, staged_rx) = mpsc::channel();
    let contender = {
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            storage.publish_with(
                PublishTarget::Nar(NarFileName::raw(second)),
                Cursor::new(b"nar"),
                |boundary| match boundary {
                    PublishBoundary::AfterTempCreate => {
                        staged_tx
                            .send(())
                            .expect("signal second publication staged");
                        Ok(())
                    }
                    _ => Ok(()),
                },
            )
        })
    };

    let staged_while_first_body_is_blocked =
        staged_rx.recv_timeout(Duration::from_secs(30)).is_ok();
    release_tx.send(()).expect("release first publication");
    assert_eq!(
        publisher
            .join()
            .expect("join first publication")
            .expect("publish first NAR"),
        PublishOutcome::Created
    );
    assert!(
        staged_while_first_body_is_blocked,
        "second publication could not stage while the first body was blocked"
    );
    assert_eq!(
        contender
            .join()
            .expect("join second publication")
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

    assert_lock_probe_status(directory.path(), "held");

    drop(first);
    assert_lock_probe_status(directory.path(), "available");
}

fn assert_lock_probe_status(path: &Path, expected: &str) {
    let status = process::Command::new(env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            "storage::tests::process_lock_replacement_probe",
            "--nocapture",
        ])
        .env("NARJAR_LOCK_PROBE_DATA", path)
        .env("NARJAR_LOCK_PROBE_EXPECTED", expected)
        .status()
        .expect("run lock probe child");
    assert!(
        status.success(),
        "child process should report the {expected} lease state"
    );
}

#[test]
fn process_lock_replacement_probe() {
    let Some(path) = env::var_os("NARJAR_LOCK_PROBE_DATA") else {
        return;
    };
    match env::var("NARJAR_LOCK_PROBE_EXPECTED").as_deref() {
        Ok("available") => {
            initialize_storage(Path::new(&path))
                .expect("lock should be available after lease release");
        }
        Ok("held") => assert!(matches!(
            initialize_storage(Path::new(&path)),
            Err(StorageError::Locked)
        )),
        other => panic!("unexpected lock probe expectation: {other:?}"),
    }
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
    assert_eq!(
        storage
            .cleanup_stale_temp(stale)
            .expect("cleanup stale temp"),
        super::reconcile::CleanupOutcome::Removed
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
    assert_eq!(
        storage.cleanup_stale_temp(young).expect("keep young temp"),
        super::reconcile::CleanupOutcome::Unchanged
    );
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
    assert_eq!(
        storage
            .cleanup_stale_temp(egress)
            .expect("cleanup egress receipt temp"),
        super::reconcile::CleanupOutcome::Removed
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

    assert_eq!(
        storage
            .cleanup_stale_temp(stale)
            .expect("replacement should not be removed"),
        super::reconcile::CleanupOutcome::Unchanged
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
        .publish(
            PublishTarget::Nar(NarFileName::raw(nar)),
            Cursor::new(b"nar bytes"),
        )
        .expect("publish NAR");
    storage
        .publish_narinfo_unchecked(&store, nar, Cursor::new(b"narinfo bytes"))
        .expect("publish narinfo");

    assert_eq!(
        storage.delete_narinfo(&store).expect("delete narinfo"),
        super::operations::NarInfoDeletion::Deleted
    );
    assert!(storage.open_narinfo(&store).unwrap().is_none());
    assert!(storage.layout().nar_path(nar).is_file());
    assert_eq!(
        storage.delete_narinfo(&store).expect("repeat delete"),
        super::operations::NarInfoDeletion::Absent
    );
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
