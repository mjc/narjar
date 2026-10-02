use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use clap::Args;
use clap::ValueEnum;
use narjar::{
    __private::storage::{StorageBackend, SupportedStorageBackend},
    object::WireEncoding,
};

use crate::native_store::NativeStoreSettings;

#[derive(Debug)]
pub(crate) struct ServeConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) workers: NonZeroUsize,
    pub(crate) max_in_flight: NonZeroUsize,
    pub(crate) max_nar_bytes: NonZeroU64,
    pub(crate) max_encoded_nar_bytes: NonZeroU64,
    pub(crate) max_decoder_memory_bytes: NonZeroU64,
    pub(crate) min_free_bytes: u64,
    pub(crate) shutdown_grace_seconds: NonZeroU64,
    pub(crate) io_timeout_seconds: NonZeroU64,
    pub(crate) egress_compression: WireEncoding,
    pub(crate) storage_backend: SupportedStorageBackend,
    pub(crate) source: ServeSource,
    pub(crate) stats_inventory_interval_seconds: Option<NonZeroU64>,
    pub(crate) stats_filesystem_sample: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) enum ServeSource {
    FlatCache,
    NativeStore(NativeStoreSettings),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum ServeSourceChoice {
    #[default]
    FlatCache,
    NativeStore,
}

#[derive(Args)]
pub(crate) struct ServeArgs {
    #[arg(long, env = "NARJAR_DATA_DIR", value_parser = non_empty_path)]
    data_dir: PathBuf,
    #[arg(long, env = "NARJAR_LISTEN", default_value = "127.0.0.1:5000")]
    listen: SocketAddr,
    #[arg(long, env = "NARJAR_WORKERS", default_value_t = NonZeroUsize::new(8).unwrap())]
    workers: NonZeroUsize,
    #[arg(long, env = "NARJAR_MAX_IN_FLIGHT", default_value_t = NonZeroUsize::new(64).unwrap())]
    max_in_flight: NonZeroUsize,
    #[arg(long, env = "NARJAR_MAX_NAR_BYTES", default_value_t = NonZeroU64::new(17_179_869_184).unwrap())]
    max_nar_bytes: NonZeroU64,
    #[arg(long, env = "NARJAR_MAX_ENCODED_NAR_BYTES", default_value_t = NonZeroU64::new(17_179_869_184).unwrap())]
    max_encoded_nar_bytes: NonZeroU64,
    #[arg(long, env = "NARJAR_MAX_DECODER_MEMORY_BYTES", default_value_t = NonZeroU64::new(134_217_728).unwrap())]
    max_decoder_memory_bytes: NonZeroU64,
    #[arg(long, env = "NARJAR_MIN_FREE_BYTES", default_value_t = 1_073_741_824)]
    min_free_bytes: u64,
    #[arg(
        long,
        env = "NARJAR_SHUTDOWN_GRACE_SECONDS",
        default_value_t = NonZeroU64::new(30).unwrap()
    )]
    shutdown_grace_seconds: NonZeroU64,
    #[arg(
        long,
        env = "NARJAR_IO_TIMEOUT_SECONDS",
        default_value_t = NonZeroU64::new(30).unwrap()
    )]
    io_timeout_seconds: NonZeroU64,
    #[arg(long, env = "NARJAR_EGRESS_COMPRESSION", default_value = "none")]
    egress_compression: WireEncoding,
    #[arg(long, env = "NARJAR_STORAGE_BACKEND", default_value = "flat")]
    storage_backend: StorageBackend,
    #[arg(
        long = "serve-source",
        env = "NARJAR_SERVE_SOURCE",
        default_value = "flat-cache"
    )]
    source: ServeSourceChoice,
    #[arg(long, env = "NARJAR_NATIVE_STORE_DIR", value_parser = non_empty_path)]
    native_store_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_STATE_DIR", value_parser = non_empty_path)]
    native_state_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_ROOTS_DIR", value_parser = non_empty_path)]
    native_roots_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_MIN_LEASE_SECONDS")]
    native_min_lease_seconds: Option<NonZeroU64>,
    #[arg(
        long,
        env = "NARJAR_STATS_INVENTORY_INTERVAL_SECONDS",
        num_args = 0..=1,
        default_missing_value = "900"
    )]
    stats_inventory_interval_seconds: Option<NonZeroU64>,
    #[arg(long, env = "NARJAR_STATS_FILESYSTEM_SAMPLE", value_parser = non_empty_path)]
    stats_filesystem_sample: Option<PathBuf>,
}

impl TryFrom<ServeArgs> for ServeConfig {
    type Error = String;

    fn try_from(args: ServeArgs) -> Result<Self, Self::Error> {
        let source = serve_source_from_args(&args)?;
        Ok(Self {
            data_dir: args.data_dir,
            listen: args.listen,
            workers: args.workers,
            max_in_flight: args.max_in_flight,
            max_nar_bytes: args.max_nar_bytes,
            max_encoded_nar_bytes: args.max_encoded_nar_bytes,
            max_decoder_memory_bytes: args.max_decoder_memory_bytes,
            min_free_bytes: args.min_free_bytes,
            shutdown_grace_seconds: args.shutdown_grace_seconds,
            io_timeout_seconds: args.io_timeout_seconds,
            egress_compression: args.egress_compression,
            storage_backend: SupportedStorageBackend::try_from(args.storage_backend)
                .map_err(|error| error.to_string())?,
            source,
            stats_inventory_interval_seconds: args.stats_inventory_interval_seconds,
            stats_filesystem_sample: args.stats_filesystem_sample,
        })
    }
}

fn serve_source_from_args(args: &ServeArgs) -> Result<ServeSource, String> {
    let native_store_options = (
        args.native_store_dir.as_deref(),
        args.native_state_dir.as_deref(),
        args.native_roots_dir.as_deref(),
        args.native_min_lease_seconds,
    );
    match (args.source, native_store_options) {
        (ServeSourceChoice::FlatCache, (None, None, None, None)) => Ok(ServeSource::FlatCache),
        (ServeSourceChoice::FlatCache, _) => {
            Err("native-store options require --serve-source native-store".to_owned())
        }
        (
            ServeSourceChoice::NativeStore,
            (Some(store_dir), Some(state_dir), Some(roots_dir), Some(min_lease_seconds)),
        ) => {
            require_raw_flat_native_output(args)?;
            Ok(ServeSource::NativeStore(NativeStoreSettings::new(
                store_dir.to_owned(),
                state_dir.to_owned(),
                roots_dir.to_owned(),
                min_lease_seconds,
            )))
        }
        (ServeSourceChoice::NativeStore, _) => Err(concat!(
            "native-store source requires --native-store-dir, --native-state-dir, ",
            "--native-roots-dir, and --native-min-lease-seconds"
        )
        .to_owned()),
    }
}

fn require_raw_flat_native_output(args: &ServeArgs) -> Result<(), String> {
    match (args.egress_compression, args.storage_backend) {
        (WireEncoding::Raw, StorageBackend::Flat) => Ok(()),
        (WireEncoding::Raw, StorageBackend::Chunked) => Err(
            "native-store source requires the flat storage backend during initial raw output support"
                .to_owned(),
        ),
        (WireEncoding::Compressed(_), _) => Err(
            "native-store source requires uncompressed output (--egress-compression none)"
                .to_owned(),
        ),
    }
}

fn non_empty_path(value: &str) -> Result<PathBuf, String> {
    (!value.is_empty())
        .then(|| PathBuf::from(value))
        .ok_or_else(|| "must not be empty".to_owned())
}

#[cfg(test)]
mod tests {
    use clap::{Args as _, Command, FromArgMatches};
    use std::num::NonZeroU64;

    use super::{ServeArgs, ServeConfig, ServeSource};

    #[test]
    fn inventory_interval_flag_defaults_to_fifteen_minutes_and_remains_optional() {
        let command = ServeArgs::augment_args(Command::new("serve"));
        let default_matches = command
            .clone()
            .try_get_matches_from(["serve", "--data-dir", "/cache"])
            .expect("serve arguments should parse without enabling inventory");
        let default_args = ServeArgs::from_arg_matches(&default_matches)
            .expect("serve arguments should deserialize");
        assert_eq!(default_args.stats_inventory_interval_seconds, None);

        let enabled_matches = command
            .clone()
            .try_get_matches_from([
                "serve",
                "--data-dir",
                "/cache",
                "--stats-inventory-interval-seconds",
            ])
            .expect("bare inventory flag should select the default interval");
        let enabled_args = ServeArgs::from_arg_matches(&enabled_matches)
            .expect("serve arguments should deserialize");
        assert_eq!(
            enabled_args.stats_inventory_interval_seconds,
            NonZeroU64::new(900)
        );

        let custom_matches = command
            .try_get_matches_from([
                "serve",
                "--data-dir",
                "/cache",
                "--stats-inventory-interval-seconds",
                "30",
            ])
            .expect("an explicit inventory interval should override the default");
        let custom_args = ServeArgs::from_arg_matches(&custom_matches)
            .expect("serve arguments should deserialize");
        assert_eq!(
            custom_args.stats_inventory_interval_seconds,
            NonZeroU64::new(30)
        );
    }

    #[test]
    fn encoded_size_and_decoder_memory_limits_are_independently_configurable() {
        let matches = ServeArgs::augment_args(Command::new("serve"))
            .try_get_matches_from([
                "serve",
                "--data-dir",
                "/cache",
                "--max-nar-bytes",
                "100",
                "--max-encoded-nar-bytes",
                "200",
                "--max-decoder-memory-bytes",
                "300",
            ])
            .expect("each upload resource limit has its own option");
        let args =
            ServeArgs::from_arg_matches(&matches).expect("serve arguments should deserialize");

        assert_eq!(args.max_nar_bytes.get(), 100);
        assert_eq!(args.max_encoded_nar_bytes.get(), 200);
        assert_eq!(args.max_decoder_memory_bytes.get(), 300);
    }

    #[test]
    fn serve_defaults_to_the_existing_flat_cache_source() {
        let matches = ServeArgs::augment_args(Command::new("serve"))
            .try_get_matches_from(["serve", "--data-dir", "/cache"])
            .expect("flat-cache arguments should parse");
        let args = ServeArgs::from_arg_matches(&matches).expect("serve arguments should parse");
        let config = ServeConfig::try_from(args).expect("flat-cache config should validate");

        assert!(matches!(config.source, ServeSource::FlatCache));
    }

    #[test]
    fn flat_cache_rejects_native_store_options() {
        let matches = ServeArgs::augment_args(Command::new("serve"))
            .try_get_matches_from([
                "serve",
                "--data-dir",
                "/cache",
                "--native-store-dir",
                "/nix/store",
            ])
            .expect("CLI should parse source options before validating their combination");
        let args = ServeArgs::from_arg_matches(&matches).expect("serve arguments should parse");

        assert_eq!(
            ServeConfig::try_from(args).expect_err("mixed source options should be rejected"),
            "native-store options require --serve-source native-store"
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
        use narjar::__private::storage::StorageBackend;
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
}
