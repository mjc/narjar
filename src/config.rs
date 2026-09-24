use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use clap::Args;
use narjar::{object::WireEncoding, storage::StorageBackend};

#[derive(Debug)]
pub(crate) struct ServeConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) workers: NonZeroUsize,
    pub(crate) max_in_flight: NonZeroUsize,
    pub(crate) max_nar_bytes: NonZeroU64,
    pub(crate) min_free_bytes: u64,
    pub(crate) shutdown_grace_seconds: NonZeroU64,
    pub(crate) io_timeout_seconds: NonZeroU64,
    pub(crate) egress_compression: WireEncoding,
    pub(crate) storage_backend: StorageBackend,
    pub(crate) stats_inventory_interval_seconds: Option<NonZeroU64>,
    pub(crate) stats_filesystem_sample: Option<PathBuf>,
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
        long,
        env = "NARJAR_STATS_INVENTORY_INTERVAL_SECONDS",
        num_args = 0..=1,
        default_missing_value = "900"
    )]
    stats_inventory_interval_seconds: Option<NonZeroU64>,
    #[arg(long, env = "NARJAR_STATS_FILESYSTEM_SAMPLE", value_parser = non_empty_path)]
    stats_filesystem_sample: Option<PathBuf>,
}

impl From<ServeArgs> for ServeConfig {
    fn from(args: ServeArgs) -> Self {
        Self {
            data_dir: args.data_dir,
            listen: args.listen,
            workers: args.workers,
            max_in_flight: args.max_in_flight,
            max_nar_bytes: args.max_nar_bytes,
            min_free_bytes: args.min_free_bytes,
            shutdown_grace_seconds: args.shutdown_grace_seconds,
            io_timeout_seconds: args.io_timeout_seconds,
            egress_compression: args.egress_compression,
            storage_backend: args.storage_backend,
            stats_inventory_interval_seconds: args.stats_inventory_interval_seconds,
            stats_filesystem_sample: args.stats_filesystem_sample,
        }
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

    use super::ServeArgs;

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
}
