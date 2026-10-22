use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use clap::Args;
use clap::ValueEnum;
use narjar::object::WireEncoding;

use crate::cache::storage::{StorageBackend, SupportedStorageBackend, UnsupportedStorageBackend};
#[cfg(unix)]
use crate::native_store::NativeStoreSettings;
use crate::{http_url::HttpUrl, read_through::EdgeSettings};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeStoreOptions<'a> {
    pub(crate) store_dir: Option<&'a std::path::Path>,
    pub(crate) state_dir: Option<&'a std::path::Path>,
    pub(crate) roots_dir: Option<&'a std::path::Path>,
    pub(crate) min_lease_seconds: Option<NonZeroU64>,
    pub(crate) signing_key_file: Option<&'a std::path::Path>,
}

#[derive(Debug)]
pub(crate) struct ServeConfig {
    pub(crate) hosting: crate::discovery::hosting::HostingConfig,
    pub(crate) track_access: bool,
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
    pub(crate) source: ServeSource,
    pub(crate) stats_inventory_interval_seconds: Option<NonZeroU64>,
    pub(crate) stats_filesystem_sample: Option<PathBuf>,
}

/// Prepared source selection; native-store output is inherently flat/raw.
#[derive(Debug)]
pub(crate) enum ServeSource {
    FlatCache {
        storage_backend: SupportedStorageBackend,
        egress_compression: WireEncoding,
    },
    #[cfg(unix)]
    NativeStore(NativeStoreSettings),
    ReadThrough {
        storage_backend: SupportedStorageBackend,
        settings: EdgeSettings,
    },
}

impl ServeConfig {
    pub(crate) const fn storage_backend(&self) -> SupportedStorageBackend {
        self.source.storage_backend()
    }

    pub(crate) const fn egress_compression(&self) -> WireEncoding {
        self.source.egress_compression()
    }
}

impl ServeSource {
    fn minimum_advertisement_lease(&self) -> Option<u64> {
        match self {
            Self::FlatCache { .. } => None,
            Self::ReadThrough { settings, .. } => Some(settings.lease_seconds.get()),
            #[cfg(unix)]
            Self::NativeStore(settings) => Some(settings.minimum_advertisement_lease()),
        }
    }
    pub(crate) fn prepare_edge_storage(
        storage_backend: StorageBackend,
        egress_compression: WireEncoding,
        native: NativeStoreOptions<'_>,
    ) -> Result<SupportedStorageBackend, SourcePreparationError> {
        let cache = Self::prepare(
            ServeSourceChoice::FlatCache,
            storage_backend,
            egress_compression,
            native,
        )?;
        Ok(cache.storage_backend())
    }

    pub(crate) fn prepare(
        choice: ServeSourceChoice,
        storage_backend: StorageBackend,
        egress_compression: WireEncoding,
        native: NativeStoreOptions<'_>,
    ) -> Result<Self, SourcePreparationError> {
        match (choice, native) {
            #[cfg(windows)]
            (ServeSourceChoice::NativeStore, _) => Err(SourcePreparationError::NativeUnavailable),
            (
                ServeSourceChoice::FlatCache,
                NativeStoreOptions {
                    store_dir: None,
                    state_dir: None,
                    roots_dir: None,
                    min_lease_seconds: None,
                    signing_key_file: None,
                },
            ) => Ok(Self::FlatCache {
                storage_backend: SupportedStorageBackend::try_from(storage_backend)
                    .map_err(SourcePreparationError::UnsupportedBackend)?,
                egress_compression,
            }),
            (ServeSourceChoice::FlatCache, _) => Err(SourcePreparationError::NativeOptionsForCache),
            #[cfg(unix)]
            (
                ServeSourceChoice::NativeStore,
                NativeStoreOptions {
                    store_dir: Some(store_dir),
                    state_dir: Some(state_dir),
                    roots_dir: Some(roots_dir),
                    min_lease_seconds: Some(min_lease_seconds),
                    signing_key_file,
                },
            ) => match (egress_compression, storage_backend) {
                (WireEncoding::Raw, StorageBackend::Flat)
                    if store_dir != std::path::Path::new("/nix/store") =>
                {
                    Err(SourcePreparationError::NativeStoreDirectory)
                }
                (WireEncoding::Raw, StorageBackend::Flat) => Ok(Self::NativeStore(
                    NativeStoreSettings::new(
                        store_dir.to_owned(),
                        state_dir.to_owned(),
                        roots_dir.to_owned(),
                        min_lease_seconds,
                    )
                    .with_signing_key_file(signing_key_file),
                )),
                (WireEncoding::Raw, StorageBackend::Chunked) => {
                    Err(SourcePreparationError::NativeChunkedBackend)
                }
                (WireEncoding::Compressed(_), _) => {
                    Err(SourcePreparationError::NativeCompressedOutput)
                }
            },
            #[cfg(unix)]
            (ServeSourceChoice::NativeStore, _) => {
                Err(SourcePreparationError::MissingNativeOptions)
            }
            (ServeSourceChoice::ReadThrough, _) => Err(SourcePreparationError::MissingEdgeUpstream),
        }
    }

    pub(crate) const fn storage_backend(&self) -> SupportedStorageBackend {
        match self {
            Self::FlatCache {
                storage_backend, ..
            } => *storage_backend,
            Self::ReadThrough {
                storage_backend, ..
            } => *storage_backend,
            #[cfg(unix)]
            Self::NativeStore(_) => SupportedStorageBackend::FLAT,
        }
    }

    pub(crate) const fn egress_compression(&self) -> WireEncoding {
        match self {
            Self::FlatCache {
                egress_compression, ..
            } => *egress_compression,
            #[cfg(unix)]
            Self::NativeStore(_) => WireEncoding::Raw,
            Self::ReadThrough { settings, .. } => settings.egress_compression,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SourcePreparationError {
    #[cfg(windows)]
    #[error(
        "native Nix store serving is not supported on Windows; choose --serve-source flat-cache"
    )]
    NativeUnavailable,
    #[error("read-through source requires --edge-upstream")]
    MissingEdgeUpstream,
    #[error("edge upstream options require --serve-source read-through")]
    EdgeOptionsForOtherSource,
    #[error("read-through source requires at least two HTTP workers and connection admissions")]
    EdgeRequestCapacityTooSmall,
    #[error("native-store HTTP serving requires --native-store-dir /nix/store")]
    NativeStoreDirectory,
    #[error("native-store options require --serve-source native-store")]
    NativeOptionsForCache,
    #[error(
        "native-store source requires --native-store-dir, --native-state-dir, --native-roots-dir, and --native-min-lease-seconds"
    )]
    MissingNativeOptions,
    #[error("native-store source requires uncompressed output (--egress-compression none)")]
    NativeCompressedOutput,
    #[error(
        "native-store source requires the flat storage backend during initial raw output support"
    )]
    NativeChunkedBackend,
    #[error("{0}")]
    UnsupportedBackend(#[source] UnsupportedStorageBackend),
}

impl SourcePreparationError {
    pub(crate) const fn doctor_detail(self) -> &'static str {
        match self {
            #[cfg(windows)]
            Self::NativeUnavailable => "native Nix store serving is unavailable on Windows",
            Self::MissingEdgeUpstream => "required edge upstream is missing",
            Self::EdgeOptionsForOtherSource => "edge options require read-through selection",
            Self::EdgeRequestCapacityTooSmall => {
                "read-through source requires two workers and connection admissions"
            }
            Self::NativeStoreDirectory => {
                "native serving requires the standard /nix/store directory"
            }
            Self::NativeOptionsForCache => "native source options require native-store selection",
            Self::MissingNativeOptions => "required native source options are missing",
            Self::NativeCompressedOutput | Self::NativeChunkedBackend => {
                "native source requires raw output and flat storage"
            }
            Self::UnsupportedBackend(_) => "storage backend is unsupported on this platform",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum ServeSourceChoice {
    #[default]
    FlatCache,
    NativeStore,
    ReadThrough,
}

impl ServeSourceChoice {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::FlatCache => "flat-cache",
            Self::NativeStore => "native-store",
            Self::ReadThrough => "read-through",
        }
    }
}

#[derive(Args)]
pub(crate) struct ServeArgs {
    #[command(flatten)]
    hosting: crate::discovery::hosting::HostingArgs,
    /// Record coalesced read-use hints for last-use GC ordering.
    #[arg(long, env = "NARJAR_TRACK_ACCESS")]
    track_access: bool,
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
    /// Upstream cache URL. Download and verify each NAR before returning its narinfo.
    #[arg(long, env = "NARJAR_EDGE_UPSTREAM")]
    edge_upstream: Option<HttpUrl>,
    /// Seconds GC must retain a NAR after returning its narinfo. Default: 60 days plus one hour.
    #[arg(
        long,
        env = "NARJAR_EDGE_LEASE_SECONDS",
        default_value = "5187600",
        requires = "edge_upstream"
    )]
    edge_lease_seconds: NonZeroU64,
    /// Maximum number of simultaneous downloads from the upstream cache.
    #[arg(
        long,
        env = "NARJAR_EDGE_MAX_FILLS",
        default_value = "4",
        requires = "edge_upstream"
    )]
    edge_max_fills: NonZeroUsize,
    /// Timeout in seconds for connecting, idle network I/O or waiting for another request's download.
    #[arg(
        long,
        env = "NARJAR_EDGE_TIMEOUT_SECONDS",
        default_value = "30",
        requires = "edge_upstream"
    )]
    edge_timeout_seconds: NonZeroU64,
    /// Total upstream download timeout in seconds, including time spent making progress.
    #[arg(
        long,
        env = "NARJAR_EDGE_FILL_TIMEOUT_SECONDS",
        default_value = "3600",
        requires = "edge_upstream"
    )]
    edge_fill_timeout_seconds: NonZeroU64,
    /// Seconds to cache upstream misses and failures, capped at 60.
    #[arg(
        long,
        env = "NARJAR_EDGE_NEGATIVE_TTL_SECONDS",
        default_value = "1",
        requires = "edge_upstream"
    )]
    edge_negative_ttl_seconds: NonZeroU64,
    #[arg(long, env = "NARJAR_NATIVE_STORE_DIR", value_parser = non_empty_path)]
    native_store_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_STATE_DIR", value_parser = non_empty_path)]
    native_state_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_ROOTS_DIR", value_parser = non_empty_path)]
    native_roots_dir: Option<PathBuf>,
    #[arg(long, env = "NARJAR_NATIVE_MIN_LEASE_SECONDS")]
    native_min_lease_seconds: Option<NonZeroU64>,
    /// Nix secret key used to sign native paths without a reusable trusted signature.
    #[arg(long, env = "NARJAR_NATIVE_SIGNING_KEY_FILE", value_parser = non_empty_path)]
    native_signing_key_file: Option<PathBuf>,
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

impl ServeArgs {
    fn native_options(&self) -> NativeStoreOptions<'_> {
        NativeStoreOptions {
            store_dir: self.native_store_dir.as_deref(),
            state_dir: self.native_state_dir.as_deref(),
            roots_dir: self.native_roots_dir.as_deref(),
            min_lease_seconds: self.native_min_lease_seconds,
            signing_key_file: self.native_signing_key_file.as_deref(),
        }
    }

    fn prepare_source(&self) -> Result<ServeSource, SourcePreparationError> {
        match (self.source, self.edge_upstream.as_ref()) {
            (ServeSourceChoice::ReadThrough, Some(upstream)) => self.prepare_edge_source(upstream),
            (ServeSourceChoice::ReadThrough, None) => {
                Err(SourcePreparationError::MissingEdgeUpstream)
            }
            (ServeSourceChoice::FlatCache | ServeSourceChoice::NativeStore, Some(_)) => {
                Err(SourcePreparationError::EdgeOptionsForOtherSource)
            }
            (choice, None) => ServeSource::prepare(
                choice,
                self.storage_backend,
                self.egress_compression,
                self.native_options(),
            ),
        }
    }

    fn prepare_edge_source(
        &self,
        upstream: &HttpUrl,
    ) -> Result<ServeSource, SourcePreparationError> {
        if self.workers.get() < 2 || self.max_in_flight.get() < 2 {
            return Err(SourcePreparationError::EdgeRequestCapacityTooSmall);
        }
        let storage_backend = ServeSource::prepare_edge_storage(
            self.storage_backend,
            self.egress_compression,
            self.native_options(),
        )?;
        Ok(ServeSource::ReadThrough {
            storage_backend,
            settings: EdgeSettings {
                upstream: upstream.clone(),
                egress_compression: self.egress_compression,
                lease_seconds: self.edge_lease_seconds,
                max_fills: self.edge_max_fills,
                request_workers: self.workers,
                max_in_flight: self.max_in_flight,
                timeout: std::time::Duration::from_secs(self.edge_timeout_seconds.get()),
                fill_timeout: std::time::Duration::from_secs(self.edge_fill_timeout_seconds.get()),
                negative_ttl: std::time::Duration::from_secs(self.edge_negative_ttl_seconds.get()),
            },
        })
    }
}

impl TryFrom<ServeArgs> for ServeConfig {
    type Error = String;

    fn try_from(args: ServeArgs) -> Result<Self, Self::Error> {
        let source = args.prepare_source().map_err(|error| error.to_string())?;
        Ok(Self {
            hosting: args.hosting.prepare(source.minimum_advertisement_lease())?,
            track_access: args.track_access,
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
            source,
            stats_inventory_interval_seconds: args.stats_inventory_interval_seconds,
            stats_filesystem_sample: args.stats_filesystem_sample,
        })
    }
}

fn non_empty_path(value: &str) -> Result<PathBuf, String> {
    (!value.is_empty())
        .then(|| PathBuf::from(value))
        .ok_or_else(|| "must not be empty".to_owned())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    mod unix;
    use clap::{Args as _, Command, FromArgMatches};
    use std::num::NonZeroU64;
    use std::path::Path;

    use crate::cache::storage::{StorageBackend, SupportedStorageBackend};
    use narjar::object::{CompressionCodec, WireEncoding};

    use super::{ServeArgs, ServeConfig, ServeSource, ServeSourceChoice, SourcePreparationError};
    use crate::config::NativeStoreOptions;

    #[cfg(unix)]
    fn native_options() -> NativeStoreOptions<'static> {
        NativeStoreOptions {
            store_dir: Some(Path::new("/nix/store")),
            state_dir: Some(Path::new("/nix/var/nix")),
            roots_dir: Some(Path::new("/var/lib/narjar-roots")),
            min_lease_seconds: NonZeroU64::new(60),
            signing_key_file: None,
        }
    }

    #[test]
    fn prepared_cache_retains_the_selected_backend_and_output() {
        for backend in [
            StorageBackend::Flat,
            #[cfg(target_os = "linux")]
            StorageBackend::Chunked,
        ] {
            for encoding in [
                WireEncoding::Raw,
                WireEncoding::Compressed(CompressionCodec::Xz),
                WireEncoding::Compressed(CompressionCodec::Zstd),
            ] {
                let source = ServeSource::prepare(
                    ServeSourceChoice::FlatCache,
                    backend,
                    encoding,
                    NativeStoreOptions::default(),
                )
                .unwrap();
                assert_eq!(source.storage_backend().backend(), backend);
                assert_eq!(source.egress_compression(), encoding);
            }
        }
    }

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

        assert!(matches!(config.source, ServeSource::FlatCache { .. }));
        assert_eq!(config.storage_backend(), SupportedStorageBackend::FLAT);
        assert_eq!(config.egress_compression(), WireEncoding::Raw);
    }

    fn parse_serve_config(extra: &[&str]) -> Result<ServeConfig, String> {
        let matches = ServeArgs::augment_args(Command::new("serve"))
            .try_get_matches_from(
                ["serve", "--data-dir", "/cache"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .expect("serve syntax should parse before source validation");
        ServeConfig::try_from(ServeArgs::from_arg_matches(&matches).unwrap())
    }

    #[test]
    fn explicit_edge_tunings_require_an_upstream_even_when_they_equal_defaults() {
        for (flag, value) in [
            ("--edge-lease-seconds", "5187600"),
            ("--edge-max-fills", "4"),
            ("--edge-timeout-seconds", "30"),
            ("--edge-fill-timeout-seconds", "3600"),
            ("--edge-negative-ttl-seconds", "1"),
        ] {
            let error = ServeArgs::augment_args(Command::new("serve"))
                .try_get_matches_from(["serve", "--data-dir", "/cache", flag, value])
                .expect_err("explicit edge settings must not be silently ignored");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains("--edge-upstream"));
        }
    }

    #[test]
    fn edge_configuration_requires_a_fixed_upstream_and_preserves_safe_defaults() {
        assert_eq!(
            parse_serve_config(&["--serve-source", "read-through"]).unwrap_err(),
            SourcePreparationError::MissingEdgeUpstream.to_string()
        );
        let config = parse_serve_config(&[
            "--serve-source",
            "read-through",
            "--edge-upstream",
            "https://cache.example/base",
        ])
        .unwrap();
        assert_eq!(config.egress_compression(), WireEncoding::Raw);
        let ServeSource::ReadThrough { settings, .. } = config.source else {
            panic!("edge source required")
        };
        assert_eq!(settings.upstream.as_str(), "https://cache.example/base");
        assert_eq!(settings.lease_seconds.get(), 2 * 2_592_000 + 3600);
        assert_eq!(settings.max_fills.get(), 4);
        assert_eq!(settings.request_workers.get(), 8);
        assert_eq!(settings.fill_timeout, std::time::Duration::from_secs(3600));
        assert_eq!(settings.negative_ttl, std::time::Duration::from_secs(1));
    }

    #[test]
    fn edge_source_accepts_compressed_output_and_rejects_options_for_other_sources() {
        assert_eq!(
            parse_serve_config(&["--edge-upstream", "https://cache.example"]).unwrap_err(),
            SourcePreparationError::EdgeOptionsForOtherSource.to_string()
        );
        let config = parse_serve_config(&[
            "--serve-source",
            "read-through",
            "--edge-upstream",
            "https://cache.example",
            "--egress-compression",
            "zstd",
        ])
        .expect("read-through may opt into a compressed served representation");
        assert_eq!(
            config.egress_compression(),
            WireEncoding::Compressed(crate::cache::object::CompressionCodec::Zstd)
        );
        assert_eq!(
            parse_serve_config(&[
                "--serve-source",
                "read-through",
                "--edge-upstream",
                "https://cache.example",
                "--native-store-dir",
                "/nix/store"
            ])
            .unwrap_err(),
            SourcePreparationError::NativeOptionsForCache.to_string()
        );
    }

    #[test]
    fn edge_source_reserves_a_worker_for_non_fill_requests() {
        for limit in ["--workers", "--max-in-flight"] {
            assert_eq!(
                parse_serve_config(&[
                    "--serve-source",
                    "read-through",
                    "--edge-upstream",
                    "https://cache.example",
                    limit,
                    "1"
                ])
                .unwrap_err(),
                SourcePreparationError::EdgeRequestCapacityTooSmall.to_string()
            );
        }
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
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &SourcePreparationError::NativeOptionsForCache,
                "native-store options require --serve-source native-store",
            ),
            (
                &SourcePreparationError::MissingNativeOptions,
                "native-store source requires --native-store-dir, --native-state-dir, --native-roots-dir, and --native-min-lease-seconds",
            ),
            (
                &SourcePreparationError::NativeCompressedOutput,
                "native-store source requires uncompressed output (--egress-compression none)",
            ),
            (
                &SourcePreparationError::NativeChunkedBackend,
                "native-store source requires the flat storage backend during initial raw output support",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_source_preparation_keeps_backend_source_and_doctor_detail() {
        use std::error::Error as _;
        let error = SourcePreparationError::UnsupportedBackend(UnsupportedStorageBackend::MacOS);
        assert_eq!(
            error.to_string(),
            "chunked storage is not supported on macOS; choose flat"
        );
        assert!(error.source().unwrap().is::<UnsupportedStorageBackend>());
        assert!(error.source().unwrap().source().is_none());
        for (error, detail) in [
            (
                SourcePreparationError::NativeOptionsForCache,
                "native source options require native-store selection",
            ),
            (
                SourcePreparationError::MissingNativeOptions,
                "required native source options are missing",
            ),
            (
                SourcePreparationError::NativeCompressedOutput,
                "native source requires raw output and flat storage",
            ),
            (
                SourcePreparationError::NativeChunkedBackend,
                "native source requires raw output and flat storage",
            ),
            (error, "storage backend is unsupported on this platform"),
        ] {
            assert_eq!(error.doctor_detail(), detail);
        }
    }
}
