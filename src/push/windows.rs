#[path = "args.rs"]
mod args;
pub(crate) use args::Push;

pub(crate) fn run(_: Push) -> Result<(), crate::error::Error> {
    Err(crate::error::Error::usage(
        "push requires a local Nix store on Unix; run narjar push on the machine owning that store",
    ))
}
