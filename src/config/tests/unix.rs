use super::*;

#[test]
fn native_http_rejects_nonstandard_store_roots_before_opening_source_files() {
    let native = NativeStoreOptions {
        store_dir: Some(Path::new("/other/store")),
        ..native_options()
    };
    assert_eq!(
        ServeSource::prepare(
            ServeSourceChoice::NativeStore,
            StorageBackend::Flat,
            WireEncoding::Raw,
            native
        )
        .unwrap_err(),
        SourcePreparationError::NativeStoreDirectory
    );
}

#[test]
fn source_preparation_checks_all_native_options_before_output_policy() {
    let complete = native_options();
    for present in 0..16 {
        let options = NativeStoreOptions {
            store_dir: (present & 1 != 0).then_some(complete.store_dir).flatten(),
            state_dir: (present & 2 != 0).then_some(complete.state_dir).flatten(),
            roots_dir: (present & 4 != 0).then_some(complete.roots_dir).flatten(),
            min_lease_seconds: (present & 8 != 0)
                .then_some(complete.min_lease_seconds)
                .flatten(),
            signing_key_file: None,
        };
        let native = ServeSource::prepare(
            ServeSourceChoice::NativeStore,
            StorageBackend::Flat,
            WireEncoding::Raw,
            options,
        );
        match present {
            15 => {
                let source = native.expect("complete native options should prepare");
                assert!(matches!(source, ServeSource::NativeStore(_)));
                assert_eq!(source.storage_backend(), SupportedStorageBackend::FLAT);
                assert_eq!(source.egress_compression(), WireEncoding::Raw);
            }
            _ => assert_eq!(
                native.unwrap_err(),
                SourcePreparationError::MissingNativeOptions,
                "native preparation requires all four options (present mask: {present:#06b})"
            ),
        }

        let cache = ServeSource::prepare(
            ServeSourceChoice::FlatCache,
            StorageBackend::Flat,
            WireEncoding::Raw,
            options,
        );
        match present {
            0 => assert!(matches!(cache.unwrap(), ServeSource::FlatCache { .. })),
            _ => assert_eq!(
                cache.unwrap_err(),
                SourcePreparationError::NativeOptionsForCache,
                "cache preparation must reject every native option (present mask: {present:#06b})"
            ),
        }
    }

    assert_eq!(
        ServeSource::prepare(
            ServeSourceChoice::NativeStore,
            StorageBackend::Chunked,
            WireEncoding::Compressed(CompressionCodec::Zstd),
            NativeStoreOptions::default(),
        )
        .unwrap_err(),
        SourcePreparationError::MissingNativeOptions,
        "serve reports missing source options before incompatible backend/output choices"
    );
}

#[test]
fn native_output_policy_has_typed_errors_and_static_doctor_details() {
    for backend in [StorageBackend::Flat, StorageBackend::Chunked] {
        for codec in [CompressionCodec::Xz, CompressionCodec::Zstd] {
            let error = ServeSource::prepare(
                ServeSourceChoice::NativeStore,
                backend,
                WireEncoding::Compressed(codec),
                native_options(),
            )
            .unwrap_err();
            assert_eq!(error, SourcePreparationError::NativeCompressedOutput);
            assert_eq!(
                error.doctor_detail(),
                "native source requires raw output and flat storage"
            );
        }
    }
    let error = ServeSource::prepare(
        ServeSourceChoice::NativeStore,
        StorageBackend::Chunked,
        WireEncoding::Raw,
        native_options(),
    )
    .unwrap_err();
    assert_eq!(error, SourcePreparationError::NativeChunkedBackend);
    assert_eq!(
        error.doctor_detail(),
        "native source requires raw output and flat storage"
    );
}

#[test]
fn native_store_rejects_incomplete_configuration() {
    let matches = ServeArgs::augment_args(Command::new("serve"))
        .try_get_matches_from([
            "serve",
            "--data-dir",
            "/cache",
            "--serve-source",
            "native-store",
            "--native-store-dir",
            "/nix/store",
        ])
        .expect("CLI should parse source options before validating completeness");
    let args = ServeArgs::from_arg_matches(&matches).expect("serve arguments should parse");

    assert_eq!(
        ServeConfig::try_from(args).expect_err("incomplete native config should be rejected"),
        "native-store source requires --native-store-dir, --native-state-dir, --native-roots-dir, and --native-min-lease-seconds"
    );
}

#[test]
fn native_store_rejects_compressed_or_chunked_output() {
    use crate::cache::storage::StorageBackend;
    use narjar::object::{CompressionCodec, WireEncoding};

    let matches = ServeArgs::augment_args(Command::new("serve"))
        .try_get_matches_from([
            "serve",
            "--data-dir",
            "/cache",
            "--serve-source",
            "native-store",
            "--native-store-dir",
            "/nix/store",
            "--native-state-dir",
            "/nix/var/nix",
            "--native-roots-dir",
            "/var/lib/narjar-roots",
            "--native-min-lease-seconds",
            "60",
        ])
        .expect("raw flat native-store flags are valid on every supported platform");

    for (encoding, backend, expected_error) in [
        (
            WireEncoding::Compressed(CompressionCodec::Xz),
            StorageBackend::Flat,
            "native-store source requires uncompressed output (--egress-compression none)",
        ),
        (
            WireEncoding::Compressed(CompressionCodec::Zstd),
            StorageBackend::Flat,
            "native-store source requires uncompressed output (--egress-compression none)",
        ),
        (
            WireEncoding::Raw,
            StorageBackend::Chunked,
            "native-store source requires the flat storage backend during initial raw output support",
        ),
    ] {
        let mut args =
            ServeArgs::from_arg_matches(&matches).expect("serve arguments should deserialize");
        args.egress_compression = encoding;
        args.storage_backend = backend;

        assert_eq!(
            ServeConfig::try_from(args)
                .expect_err("unsupported native output must fail configuration"),
            expected_error,
        );
    }
}
