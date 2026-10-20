mod args;
pub(crate) use args::Push;

#[cfg(unix)]
mod native;
#[cfg(unix)]
pub(crate) use native::run;

#[cfg(windows)]
pub(crate) fn run(_: Push) -> Result<(), crate::error::Error> {
    Err(crate::error::Error::usage(
        "push requires a local Nix store on Unix; run narjar push on the machine owning that store",
    ))
}
