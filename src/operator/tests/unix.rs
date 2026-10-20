use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn doctor_rejects_private_file_modes_that_startup_rejects() {
    let directory = initialized_doctor_cache();
    for name in ["lock", LAYOUT_DESCRIPTOR]
        .into_iter()
        .chain(CACHE_POLICY_FILES.iter().copied())
    {
        let path = directory.path().join(name);
        for mode in [0o400, 0o644, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let report = inspect_doctor(directory.path(), SupportedStorageBackend::FLAT).unwrap();
            let entry = report
                .paths
                .iter()
                .find(|entry| entry.path == name)
                .unwrap();
            assert!(
                entry.severity.is_failure(),
                "doctor accepted {name} with mode {mode:04o}"
            );
            assert!(report.has_failures());
        }
        crate::cache::test_support::make_private_file(path).unwrap();
    }
    assert!(
        !inspect_doctor(directory.path(), SupportedStorageBackend::FLAT)
            .unwrap()
            .has_failures()
    );
}

#[test]
fn native_doctor_loads_the_same_required_policies_as_startup() {
    let directory = initialized_doctor_cache();
    let settings = NativeStoreSettings::new(
        directory.path().join("missing-store"),
        directory.path().join("native-state"),
        directory.path().join("native-roots"),
        NonZeroU64::new(60).unwrap(),
    );
    for name in CACHE_POLICY_FILES {
        let path = directory.path().join(name);
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            validate_doctor_native_store(directory.path(), &settings),
            Err("cache policy is invalid")
        );
        assert!(!path.exists(), "doctor must not recreate {name}");
        fs::write(&path, original).unwrap();
        crate::cache::test_support::make_private_file(path).unwrap();
    }
    fs::write(
        directory.path().join("auth/write.tokens"),
        b"invalid token record\n",
    )
    .unwrap();
    assert_eq!(
        validate_doctor_native_store(directory.path(), &settings),
        Err("cache policy is invalid")
    );
}

#[test]
fn doctor_source_policy_errors_keep_the_existing_static_details() {
    use narjar::object::CompressionCodec;

    let complete = NativeStoreOptions {
        store_dir: Some(Path::new("/private/store-path")),
        state_dir: Some(Path::new("/private/state-path")),
        roots_dir: Some(Path::new("/private/roots-path")),
        min_lease_seconds: NonZeroU64::new(60),
        signing_key_file: None,
    };
    for (choice, native, encoding, backend, expected_error, detail) in [
        (
            ServeSourceChoice::ReadThrough,
            NativeStoreOptions::default(),
            WireEncoding::Compressed(CompressionCodec::Zstd),
            StorageBackend::Flat,
            SourcePreparationError::EdgeCompressedOutput,
            "read-through source requires raw output",
        ),
        (
            ServeSourceChoice::ReadThrough,
            NativeStoreOptions::default(),
            WireEncoding::Compressed(CompressionCodec::Xz),
            StorageBackend::Flat,
            SourcePreparationError::EdgeCompressedOutput,
            "read-through source requires raw output",
        ),
        (
            ServeSourceChoice::FlatCache,
            complete,
            WireEncoding::Raw,
            StorageBackend::Flat,
            SourcePreparationError::NativeOptionsForCache,
            "native source options require native-store selection",
        ),
        (
            ServeSourceChoice::NativeStore,
            NativeStoreOptions {
                state_dir: None,
                ..complete
            },
            WireEncoding::Raw,
            StorageBackend::Flat,
            SourcePreparationError::MissingNativeOptions,
            "required native source options are missing",
        ),
        (
            ServeSourceChoice::NativeStore,
            complete,
            WireEncoding::Compressed(CompressionCodec::Xz),
            StorageBackend::Flat,
            SourcePreparationError::NativeCompressedOutput,
            "native source requires raw output and flat storage",
        ),
        (
            ServeSourceChoice::NativeStore,
            complete,
            WireEncoding::Compressed(CompressionCodec::Zstd),
            StorageBackend::Flat,
            SourcePreparationError::NativeCompressedOutput,
            "native source requires raw output and flat storage",
        ),
        (
            ServeSourceChoice::NativeStore,
            complete,
            WireEncoding::Raw,
            StorageBackend::Chunked,
            SourcePreparationError::NativeChunkedBackend,
            "native source requires raw output and flat storage",
        ),
    ] {
        let options = Doctor {
            data_dir: PathBuf::from("/unavailable/narjar-cache"),
            json: true,
            serve_source: choice,
            native_store_dir: native.store_dir.map(Path::to_owned),
            native_state_dir: native.state_dir.map(Path::to_owned),
            native_roots_dir: native.roots_dir.map(Path::to_owned),
            native_min_lease_seconds: native.min_lease_seconds,
            native_signing_key_file: None,
            egress_compression: encoding,
            storage_backend: backend,
        };
        let source = options.prepare_source();
        assert_eq!(
            source.as_ref().unwrap_err(),
            &expected_error,
            "doctor must use the same source policy as serve"
        );
        let diagnostic = inspect_doctor_source(&options, source);
        assert_eq!(diagnostic.name, choice.name());
        assert!(matches!(diagnostic.severity, DoctorSeverity::Error));
        assert_eq!(
            diagnostic.detail, detail,
            "policy errors must retain static details instead of inspecting unavailable paths"
        );
    }
}
