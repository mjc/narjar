use std::{
    env,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use crate::error::Error;

const DEFAULT_LISTEN: &str = "127.0.0.1:5000";
const DEFAULT_WORKERS: &str = "8";
const DEFAULT_MAX_IN_FLIGHT: &str = "64";
const DEFAULT_MAX_NAR_BYTES: &str = "17179869184";
const DEFAULT_MIN_FREE_BYTES: &str = "1073741824";

pub(crate) struct ServeConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) workers: NonZeroUsize,
    pub(crate) max_in_flight: NonZeroUsize,
    pub(crate) max_nar_bytes: NonZeroU64,
    pub(crate) min_free_bytes: u64,
}

impl ServeConfig {
    pub(crate) fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, Error> {
        let mut data_dir = None;
        let mut listen = None;
        let mut workers = None;
        let mut max_in_flight = None;
        let mut max_nar_bytes = None;
        let mut min_free_bytes = None;

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--data-dir" => set(&mut data_dir, &mut args, "--data-dir")?,
                "--listen" => set(&mut listen, &mut args, "--listen")?,
                "--workers" => set(&mut workers, &mut args, "--workers")?,
                "--max-in-flight" => {
                    set(&mut max_in_flight, &mut args, "--max-in-flight")?;
                }
                "--max-nar-bytes" => {
                    set(&mut max_nar_bytes, &mut args, "--max-nar-bytes")?;
                }
                "--min-free-bytes" => {
                    set(&mut min_free_bytes, &mut args, "--min-free-bytes")?;
                }
                _ => return Err(Error::usage(format!("unexpected argument: {argument}"))),
            }
        }

        let (data_dir, data_dir_source) = resolve(data_dir, "--data-dir", "NARJAR_DATA_DIR", None)?
            .ok_or_else(|| Error::usage("--data-dir is required"))?;
        if data_dir.is_empty() {
            return Err(Error::usage(format!("{data_dir_source} must not be empty")));
        }

        let listen = resolve(listen, "--listen", "NARJAR_LISTEN", Some(DEFAULT_LISTEN))?
            .expect("listen has a compiled default");
        let listen = listen
            .0
            .parse()
            .map_err(|_| Error::usage(format!("{} must be an IP socket address", listen.1)))?;

        Ok(Self {
            data_dir: PathBuf::from(data_dir),
            listen,
            workers: positive_usize(
                resolve(
                    workers,
                    "--workers",
                    "NARJAR_WORKERS",
                    Some(DEFAULT_WORKERS),
                )?
                .expect("worker count has a compiled default"),
            )?,
            max_in_flight: positive_usize(
                resolve(
                    max_in_flight,
                    "--max-in-flight",
                    "NARJAR_MAX_IN_FLIGHT",
                    Some(DEFAULT_MAX_IN_FLIGHT),
                )?
                .expect("request limit has a compiled default"),
            )?,
            max_nar_bytes: positive_u64(
                resolve(
                    max_nar_bytes,
                    "--max-nar-bytes",
                    "NARJAR_MAX_NAR_BYTES",
                    Some(DEFAULT_MAX_NAR_BYTES),
                )?
                .expect("NAR limit has a compiled default"),
            )?,
            min_free_bytes: nonnegative_u64(
                resolve(
                    min_free_bytes,
                    "--min-free-bytes",
                    "NARJAR_MIN_FREE_BYTES",
                    Some(DEFAULT_MIN_FREE_BYTES),
                )?
                .expect("free-space reserve has a compiled default"),
            )?,
        })
    }
}

fn set(
    slot: &mut Option<String>,
    args: &mut impl Iterator<Item = String>,
    option: &'static str,
) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::usage(format!("{option} may only be specified once")));
    }
    *slot = Some(
        args.next()
            .ok_or_else(|| Error::usage(format!("{option} requires a value")))?,
    );
    Ok(())
}

fn resolve(
    flag: Option<String>,
    option: &'static str,
    environment: &'static str,
    default: Option<&'static str>,
) -> Result<Option<(String, &'static str)>, Error> {
    if let Some(value) = flag {
        return Ok(Some((value, option)));
    }

    match env::var(environment) {
        Ok(value) => Ok(Some((value, environment))),
        Err(env::VarError::NotPresent) => {
            Ok(default.map(|value| (value.to_owned(), "compiled default")))
        }
        Err(env::VarError::NotUnicode(_)) => {
            Err(Error::usage(format!("{environment} must contain UTF-8")))
        }
    }
}

fn positive_usize((value, source): (String, &'static str)) -> Result<NonZeroUsize, Error> {
    let value = value
        .parse()
        .map_err(|_| Error::usage(format!("{source} must be a positive integer")))?;
    NonZeroUsize::new(value)
        .ok_or_else(|| Error::usage(format!("{source} must be greater than zero")))
}

fn positive_u64((value, source): (String, &'static str)) -> Result<NonZeroU64, Error> {
    let value = value
        .parse()
        .map_err(|_| Error::usage(format!("{source} must be a positive integer")))?;
    NonZeroU64::new(value)
        .ok_or_else(|| Error::usage(format!("{source} must be greater than zero")))
}

fn nonnegative_u64((value, source): (String, &'static str)) -> Result<u64, Error> {
    value
        .parse()
        .map_err(|_| Error::usage(format!("{source} must be a non-negative integer")))
}
