use clap::Parser;
use std::num::NonZeroU32;

#[derive(Parser)]
pub struct Options {
    /// Run only this exact fixture/operation pair, e.g. tiny-4096/decode.
    #[arg(long)]
    filter: Option<String>,
    /// Operations per sample; omit to calibrate batches automatically.
    #[arg(long)]
    pub iterations: Option<NonZeroU32>,
    #[arg(long, hide = true)]
    bench: bool,
}

impl Options {
    pub fn selects(&self, fixture: &str, operation: &str) -> bool {
        self.filter
            .as_ref()
            .is_none_or(|filter| *filter == format!("{fixture}/{operation}"))
    }
}
