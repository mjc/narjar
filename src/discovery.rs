mod advertisement;
mod browse;
mod configuration;

use clap::{Args, Subcommand};

use crate::error::Error;

/// Find nearby caches or print client configuration with explicitly trusted keys.
#[derive(Args)]
pub(crate) struct Discover {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Browse LAN advertisements without trusting keys or changing configuration.
    Browse(browse::Browse),
    /// Print client configuration; obtain the keys from a trusted operator.
    Config(configuration::Configure),
}

pub(crate) fn run(options: Discover) -> Result<(), Error> {
    match options.action {
        Action::Browse(options) => browse::run(options),
        Action::Config(options) => configuration::run(options),
    }
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(error.to_string().escape_debug().to_string())
}
