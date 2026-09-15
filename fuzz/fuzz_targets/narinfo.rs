#![no_main]

use libfuzzer_sys::fuzz_target;
use narjar::narinfo::TrustedPublicKeys;
use narjar::storage::StoreHash;

fuzz_target!(|input: &[u8]| {
    let store = StoreHash::parse("0123456789abcdfghijklmnpqrsvwxyz").unwrap();
    let trusted = TrustedPublicKeys::default();
    let _ = trusted.validate(&store, input.to_vec());
});
