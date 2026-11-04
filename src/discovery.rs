mod advertisement;
mod browse;
mod configuration;
pub(crate) mod hosting;
pub(crate) mod page;

use clap::{Args, Subcommand};

use crate::error::Error;

/// Tracker used when discovery has no operator-configured list.
#[allow(dead_code)] // the discovery client is a separate change; this is the tested default
pub(crate) const DEFAULT_PEERIX_TRACKER: &str = "https://narjar.mjc.lol/peerix";

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

#[cfg(test)]
mod tests {
    #[test]
    fn discovery_defaults_to_the_narjar_peerix_tracker() {
        assert_eq!(
            super::DEFAULT_PEERIX_TRACKER,
            "https://narjar.mjc.lol/peerix"
        );
    }
}
