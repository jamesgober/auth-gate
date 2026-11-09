//! clientDataJSON parser: never a panic, bounded, and a parsed value keeps
//! its invariants.
#![no_main]

use auth_gate::webauthn::{MAX_CLIENT_DATA, parse_client_data};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(c) = parse_client_data(data) {
        assert!(data.len() <= MAX_CLIENT_DATA);
        assert!(c.challenge.len() <= 256);
        assert!(c.origin.len() <= data.len());
    }
});
