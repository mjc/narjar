#![no_main]

use libfuzzer_sys::fuzz_target;
use narjar::object::CompressionCodec;

fuzz_target!(|input: &[u8]| narjar_fuzz::compressed_upload(input, CompressionCodec::Xz));
