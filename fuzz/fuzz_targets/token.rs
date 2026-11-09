//! Any bytes presented as a session token: never a panic, and nothing but
//! a token this gate issued verifies.
#![no_main]

use std::sync::OnceLock;

use auth_gate::{GateKeys, TokenCheck, TokenKeys, check_token};
use libfuzzer_sys::fuzz_target;

fn keys() -> &'static GateKeys {
    static K: OnceLock<GateKeys> = OnceLock::new();
    K.get_or_init(|| {
        GateKeys::derive(&[7; 32]).unwrap().with_token_keys(
            TokenKeys::new(1, [1; 32])
                .accept(2, [2; 32])
                .retire(3, [3; 32]),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    match check_token(keys(), data) {
        TokenCheck::Valid(_) | TokenCheck::RetiredKey => {
            // Only a correctly signed 67-byte token can get here; random
            // input finding one means the signature check is broken.
            panic!("unsigned input verified");
        }
        TokenCheck::Malformed | TokenCheck::UnknownKey | TokenCheck::BadSignature => {}
    }
});
