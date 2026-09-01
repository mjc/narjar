use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
};

use crate::error::Error;

struct Input {
    text: String,
    source: &'static str,
}

impl Input {
    fn parse<T: FromStr>(&self, expected: &str) -> Result<T, Error> {
        self.text
            .parse()
            .map_err(|_| Error::usage(format!("{} must be {expected}", self.source)))
    }

    fn nonzero_usize(&self) -> Result<NonZeroUsize, Error> {
        let value = self.parse("a positive integer")?;
        NonZeroUsize::new(value)
            .ok_or_else(|| Error::usage(format!("{} must be greater than zero", self.source)))
    }

    fn nonzero_u64(&self) -> Result<NonZeroU64, Error> {
        let value = self.parse("a positive integer")?;
        NonZeroU64::new(value)
            .ok_or_else(|| Error::usage(format!("{} must be greater than zero", self.source)))
    }
}

#[derive(Debug)]
pub(crate) struct ServeConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) workers: NonZeroUsize,
    pub(crate) max_in_flight: NonZeroUsize,
    pub(crate) max_nar_bytes: NonZeroU64,
    pub(crate) min_free_bytes: u64,
}

impl ServeConfig {
    pub(crate) fn parse(args: impl Iterator<Item = String>) -> Result<Self, Error> {
        Self::parse_with(args, environment)
    }

    fn parse_with(
        mut args: impl Iterator<Item = String>,
        mut environment: impl FnMut(&'static str) -> Result<Option<String>, Error>,
    ) -> Result<Self, Error> {
        let mut flags = BTreeMap::new();

        while let Some(flag) = args.next() {
            if !is_setting(&flag) {
                return Err(Error::usage(format!("unexpected argument: {flag}")));
            }
            if flags.contains_key(&flag) {
                return Err(Error::usage(format!("{flag} may only be specified once")));
            }
            let value = args
                .next()
                .ok_or_else(|| Error::usage(format!("{flag} requires a value")))?;
            flags.insert(flag, value);
        }

        let mut input = |flag: &'static str,
                         environment_name: &'static str,
                         default: Option<&'static str>|
         -> Result<Option<Input>, Error> {
            if let Some(text) = flags.remove(flag) {
                return Ok(Some(Input { text, source: flag }));
            }
            if let Some(text) = environment(environment_name)? {
                return Ok(Some(Input {
                    text,
                    source: environment_name,
                }));
            }
            Ok(default.map(|text| Input {
                text: text.to_owned(),
                source: "compiled default",
            }))
        };

        let data_dir = input("--data-dir", "NARJAR_DATA_DIR", None)?
            .ok_or_else(|| Error::usage("--data-dir is required"))?;
        if data_dir.text.is_empty() {
            return Err(Error::usage(format!(
                "{} must not be empty",
                data_dir.source
            )));
        }

        let listen = input("--listen", "NARJAR_LISTEN", Some("127.0.0.1:5000"))?
            .expect("listen has a compiled default");
        let workers = input("--workers", "NARJAR_WORKERS", Some("8"))?
            .expect("worker count has a compiled default");
        let max_in_flight = input("--max-in-flight", "NARJAR_MAX_IN_FLIGHT", Some("64"))?
            .expect("request limit has a compiled default");
        let max_nar_bytes = input(
            "--max-nar-bytes",
            "NARJAR_MAX_NAR_BYTES",
            Some("17179869184"),
        )?
        .expect("NAR limit has a compiled default");
        let min_free_bytes = input(
            "--min-free-bytes",
            "NARJAR_MIN_FREE_BYTES",
            Some("1073741824"),
        )?
        .expect("free-space reserve has a compiled default");

        Ok(Self {
            data_dir: PathBuf::from(data_dir.text),
            listen: listen.parse("an IP socket address")?,
            workers: workers.nonzero_usize()?,
            max_in_flight: max_in_flight.nonzero_usize()?,
            max_nar_bytes: max_nar_bytes.nonzero_u64()?,
            min_free_bytes: min_free_bytes.parse("a non-negative integer")?,
        })
    }
}

fn is_setting(flag: &str) -> bool {
    matches!(
        flag,
        "--data-dir"
            | "--listen"
            | "--workers"
            | "--max-in-flight"
            | "--max-nar-bytes"
            | "--min-free-bytes"
    )
}

fn environment(name: &'static str) -> Result<Option<String>, Error> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(Error::usage(format!("{name} must contain UTF-8")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], environment: &[(&str, &str)]) -> Result<ServeConfig, Error> {
        ServeConfig::parse_with(args.iter().map(|value| (*value).to_owned()), |name| {
            Ok(environment
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned()))
        })
    }

    #[test]
    fn compiled_defaults_are_bounded() {
        let config = parse(&["--data-dir", "/cache"], &[]).expect("defaults should parse");

        assert_eq!(config.listen, "127.0.0.1:5000".parse().unwrap());
        assert_eq!(config.workers.get(), 8);
        assert_eq!(config.max_in_flight.get(), 64);
        assert_eq!(config.max_nar_bytes.get(), 17_179_869_184);
        assert_eq!(config.min_free_bytes, 1_073_741_824);
    }

    #[test]
    fn every_flag_overrides_its_environment_value() {
        let config = parse(
            &[
                "--data-dir",
                "/flag-cache",
                "--listen",
                "127.0.0.1:5001",
                "--workers",
                "3",
                "--max-in-flight",
                "5",
                "--max-nar-bytes",
                "7",
                "--min-free-bytes",
                "0",
            ],
            &[
                ("NARJAR_DATA_DIR", ""),
                ("NARJAR_LISTEN", "invalid"),
                ("NARJAR_WORKERS", "0"),
                ("NARJAR_MAX_IN_FLIGHT", "0"),
                ("NARJAR_MAX_NAR_BYTES", "0"),
                ("NARJAR_MIN_FREE_BYTES", "invalid"),
            ],
        )
        .expect("flags should hide lower-precedence environment values");

        assert_eq!(config.data_dir, PathBuf::from("/flag-cache"));
        assert_eq!(config.listen, "127.0.0.1:5001".parse().unwrap());
        assert_eq!(config.workers.get(), 3);
        assert_eq!(config.max_in_flight.get(), 5);
        assert_eq!(config.max_nar_bytes.get(), 7);
        assert_eq!(config.min_free_bytes, 0);
    }

    #[test]
    fn positive_worker_counts_round_trip() {
        for workers in 1..=128 {
            let workers = workers.to_string();
            let config = parse(&["--data-dir", "/cache", "--workers", &workers], &[])
                .expect("positive worker count should parse");
            assert_eq!(config.workers.get().to_string(), workers);
        }
    }

    #[test]
    fn malformed_worker_counts_are_rejected() {
        for workers in ["", "-1", "1.0", " 1", "1 "] {
            let error = parse(&["--data-dir", "/cache", "--workers", workers], &[])
                .expect_err("malformed worker count should fail");
            assert_eq!(error.to_string(), "--workers must be a positive integer");
        }
    }
}
