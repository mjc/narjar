#![no_main]

use std::io;

use libfuzzer_sys::fuzz_target;
use narjar::nar::{Decoder, Event, EventSink, Limits};

struct Sink;

impl EventSink for Sink {
    fn event(&mut self, _event: Event<'_>) -> io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|input: &[u8]| {
    let limits = Limits {
        max_depth: 64,
        max_name_bytes: 64 * 1024,
        max_symlink_target_bytes: 64 * 1024,
        max_entries: 4_096,
        max_file_bytes: 4 * 1024 * 1024,
        max_total_bytes: 8 * 1024 * 1024,
        max_work: 65_536,
    };
    let mut decoder = Decoder::with_limits(input, limits);
    let mut sink = Sink;
    let _ = decoder.decode(&mut sink);
});
