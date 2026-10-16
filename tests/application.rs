// One harness owns the application unit tests and CLI tests. No library exports
// are needed to test the binary's private modules.
include!("../src/main.rs");

#[path = "cli.rs"]
mod cli_tests;
