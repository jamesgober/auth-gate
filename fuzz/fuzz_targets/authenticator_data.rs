//! Authenticator data parser (with its CBOR walker): never a panic, and
//! every slice it returns lies inside the input.
#![no_main]

use auth_gate::webauthn::{FLAG_AT, MAX_CREDENTIAL_ID, parse_authenticator_data};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(a) = parse_authenticator_data(data) {
        assert_eq!(a.rp_id_hash.len(), 32);
        assert_eq!(a.credential.is_some(), a.flags & FLAG_AT != 0);
        if let Some((id, key)) = a.credential {
            assert!(!id.is_empty() && id.len() <= MAX_CREDENTIAL_ID);
            assert!(!key.is_empty());
            assert!(id.len() + key.len() + 55 <= data.len());
        }
    }
});
