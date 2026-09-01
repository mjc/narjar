use std::{num::NonZeroUsize, path::PathBuf};

use crate::error::Error;

pub(crate) struct ServeConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) listen: String,
    pub(crate) workers: NonZeroUsize,
}

impl ServeConfig {
    pub(crate) fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, Error> {
        let mut data_dir = None;
        let mut listen = "127.0.0.1:5000".to_owned();
        let mut workers = NonZeroUsize::new(8).expect("default worker count is nonzero");

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--data-dir" => {
                    data_dir = Some(PathBuf::from(value(&mut args, "--data-dir")?));
                }
                "--listen" => listen = value(&mut args, "--listen")?,
                "--workers" => {
                    let parsed = value(&mut args, "--workers")?
                        .parse()
                        .map_err(|_| Error::usage("--workers must be a positive integer"))?;
                    workers = NonZeroUsize::new(parsed)
                        .ok_or_else(|| Error::usage("--workers must be greater than zero"))?;
                }
                _ => return Err(Error::usage(format!("unexpected argument: {argument}"))),
            }
        }

        Ok(Self {
            data_dir: data_dir.ok_or_else(|| Error::usage("--data-dir is required"))?,
            listen,
            workers,
        })
    }
}

fn value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, Error> {
    args.next()
        .ok_or_else(|| Error::usage(format!("{option} requires a value")))
}
