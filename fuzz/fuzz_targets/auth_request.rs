#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| narjar_fuzz::auth_request(input));
