//! POSIX permission faults, directory-flock behavior, and renames with open descendants.

use super::*;
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};

#[test]
fn known_publication_destinations_reject_non_unicode_paths() {
    use super::super::location::StorePath;

    let mut destination = PublishTarget::CacheInfo.destination();
    destination.path =
        StorePath::Root(std::ffi::OsStr::from_bytes(b"invalid-\xff-name").to_os_string());
    assert!(destination.validate_path().is_err());
}

#[test]
fn recovery_discards_unreadable_transaction_drafts_before_parsing_records() {
    check_abandoned_transaction_draft_recovery(|path| {
        fs::set_permissions(path, fs::Permissions::from_mode(0o000))
    });
}

#[test]
fn abandoned_generic_publication_retains_recovery_when_temp_cleanup_fails() {
    let (_directory, storage) = flat_storage_fixture();
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
    assert_eq!(directory_entry_count(&temporary_directory), 1);

    storage.finish_recovery().unwrap();

    assert!(!storage.recovery_required().unwrap());
    assert_eq!(directory_entry_count(&temporary_directory), 0);
}

#[test]
fn failed_destination_rollback_retains_recovery_evidence() {
    let (_directory, storage) = flat_storage_fixture();
    let hash = NarHash::parse(NAR_ID).unwrap();
    let nar_directory = storage.layout().nar_dir();
    let result = storage.publish_with(
        PublishTarget::Nar(NarFileName::raw(hash)),
        Cursor::new(b"NAR bytes"),
        |boundary| {
            if boundary == PublishBoundary::BeforeParentSync {
                fs::set_permissions(&nar_directory, fs::Permissions::from_mode(0o500))?;
                return Err(io::Error::other("injected destination sync failure").into());
            }
            Ok(())
        },
    );
    fs::set_permissions(&nar_directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        result,
        Err(StorageError::Io(error)) if error.to_string() == "injected destination sync failure"
    ));
    assert!(storage.layout().nar_path(hash).exists());
    assert_eq!(transaction_record_count(&storage), 1);
    assert!(storage.recovery_required().unwrap());
    storage.finish_recovery().unwrap();
    assert_eq!(transaction_record_count(&storage), 0);
    assert_eq!(storage.temporary_objects(), 0);
}

#[test]
fn a_failed_journal_completion_preserves_the_original_publication_error() {
    let (directory, storage) = flat_storage_fixture();
    let transactions = directory.path().join(".narjar-transactions");
    let hash = NarHash::parse(NAR_ID).unwrap();
    let result = storage.publish_with(
        PublishTarget::Nar(NarFileName::raw(hash)),
        Cursor::new(b"NAR bytes"),
        |boundary| {
            if boundary == PublishBoundary::AfterParentSync {
                fs::set_permissions(&transactions, fs::Permissions::from_mode(0o500))?;
                return Err(
                    io::Error::new(io::ErrorKind::ConnectionAborted, "publication failed").into(),
                );
            }
            Ok(())
        },
    );
    fs::set_permissions(&transactions, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(
        result,
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::ConnectionAborted
    ));
    assert!(storage.layout().nar_path(hash).exists());
    assert_eq!(storage.temporary_objects(), 0);
    assert_eq!(transaction_record_count(&storage), 1);
    assert!(storage.recovery_required().unwrap());
    storage.finish_recovery().unwrap();
    assert_eq!(transaction_record_count(&storage), 0);
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
fn process_lock_survives_lockfile_replacement() {
    let directory = TestDir::new();
    let first = initialize_storage(directory.path()).expect("acquire first process lock");
    let lock = directory.path().join("lock");
    fs::remove_file(&lock).expect("remove lock pathname");
    fs::write(&lock, b"replacement").expect("replace lock pathname");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

    assert_lock_probe_status(directory.path(), "held");

    drop(first);
    assert_lock_probe_status(directory.path(), "available");
    assert_eq!(fs::read(lock).unwrap(), b"replacement");
}

#[test]
fn process_lock_excludes_a_second_process_using_a_directory_alias() {
    let directory = TestDir::new();
    let parent_alias = TestDir::new();
    let alias = parent_alias.path().join("parent");
    symlink(directory.path(), &alias).expect("alias the DATA parent directory");
    let data = directory.path().join("data");
    fs::create_dir(&data).unwrap();
    let first = initialize_storage(&data).unwrap();

    assert_lock_probe_status(&alias.join("data"), "held");
    drop(first);
    assert_lock_probe_status(&alias.join("data"), "available");
}

#[test]
fn initialization_rejects_a_writable_data_root_before_creating_layout_files() {
    let directory = TestDir::new();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        Directory::open(directory.path()),
        Err(error) if error.kind() == io::ErrorKind::InvalidData
    ));
    assert_eq!(directory_entry_count(directory.path()), 0);
}

#[test]
fn creation_rejects_a_lock_whose_permissions_opening_would_reject() {
    let directory = TestDir::new();
    let lock = directory.path().join("lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        initialize_storage(directory.path()).is_err(),
        "creation cannot approve a non-private lock"
    );
    assert_eq!(
        fs::metadata(lock).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn a_commit_destination_open_failure_still_cleans_the_owned_staging_file() {
    let (directory, storage) = flat_storage_fixture();
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
        directory_entry_count(&moved),
        1,
        "only the empty .tmp directory remains"
    );
}

#[test]
fn process_lock_follows_the_opened_directory_after_its_path_is_replaced() {
    let parent = TestDir::new();
    let data = parent.path().join("data");
    let renamed = parent.path().join("renamed");
    fs::create_dir(&data).unwrap();
    let opened = Directory::open(&data).unwrap();
    let first = CacheCreation::prepare(&opened, SupportedStorageBackend::FLAT)
        .unwrap()
        .create_or_complete()
        .unwrap();
    fs::rename(&data, &renamed).unwrap();
    fs::create_dir(&data).unwrap();

    assert!(matches!(
        CacheCreation::prepare(&opened, SupportedStorageBackend::FLAT),
        Err(StorageError::Locked)
    ));
    assert_lock_probe_status(&renamed, "held");
    assert_lock_probe_status(&data, "available");
    drop(first);
    assert_lock_probe_status(&renamed, "available");
    CacheCreation::prepare(&opened, SupportedStorageBackend::FLAT)
        .expect("the original capability can reacquire its own directory");
}
