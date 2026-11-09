//! The second-factor step with any challenge text and any code: never a
//! panic, never a sign-in.
#![no_main]

use std::sync::OnceLock;

use auth_gate::{AuthGate, GateKeys, Presented, SignIn};
use libfuzzer_sys::fuzz_target;

fn gate() -> &'static AuthGate {
    static G: OnceLock<AuthGate> = OnceLock::new();
    G.get_or_init(|| {
        AuthGate::builder(GateKeys::derive(&[9; 32]).unwrap())
            .build()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let split = data
        .first()
        .map_or(0, |b| usize::from(*b))
        .min(data.len().saturating_sub(1));
    let rest = data.get(1..).unwrap_or_default();
    let (a, b) = rest.split_at(split.min(rest.len()));
    let challenge = String::from_utf8_lossy(a);
    let code = String::from_utf8_lossy(b);
    let out = gate().second_factor(&challenge, &code, &Presented::new());
    assert!(matches!(out, SignIn::Failed(_)));
});
