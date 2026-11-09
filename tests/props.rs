//! Invariants for any input.

use std::{net::IpAddr, sync::Arc, time::Duration};

use auth_gate::*;
use proptest::prelude::*;

fn gate() -> (AuthGate, String) {
    let gate = AuthGate::builder(GateKeys::derive(&[3; 32]).unwrap())
        .password_policy(PasswordPolicy::insecure_for_tests())
        .signals(Arc::new(NoSignals))
        .build()
        .unwrap();
    gate.create_account("p@x.io", "property password", Standing::Active, &[])
        .unwrap();
    let SignIn::Verified(v) = gate.sign_in("p@x.io", "property password", &Presented::new()) else {
        panic!()
    };
    let token = gate
        .issue(v, Payload::EMPTY, &Presented::new())
        .unwrap()
        .token
        .as_str()
        .to_owned();
    (gate, token)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Changing any one byte of a real token never yields a session.
    #[test]
    fn any_tampering_is_refused(pos in 0usize..TOKEN_TEXT_LEN, byte in any::<u8>()) {
        let (gate, token) = gate();
        let mut t = token.clone().into_bytes();
        prop_assume!(t[pos] != byte);
        t[pos] = byte;
        let p = Presented::new().token(Some(&t));
        prop_assert!(matches!(gate.authenticate(&p), Authentication::Guest(Guest::Invalid(_))));
        let ok = Presented::new().token(Some(token.as_bytes()));
        prop_assert!(matches!(gate.authenticate(&ok), Authentication::Member(_)));
    }

    /// Arbitrary bytes are never a session, and never panic.
    #[test]
    fn random_tokens_are_guests(raw in prop::collection::vec(any::<u8>(), 0..120)) {
        let keys = GateKeys::derive(&[3; 32]).unwrap();
        prop_assert!(!matches!(check_token(&keys, &raw), TokenCheck::Valid(_)));
    }

    /// Timed standings read as active from `until` on, and as themselves
    /// before it.
    #[test]
    fn timed_standings_lift(until in any::<u64>(), now in any::<u64>()) {
        let d = Decision::new("r", Actor::System, UnixTime::EPOCH);
        let until = UnixTime::from_millis(until);
        let now = UnixTime::from_millis(now);
        for s in [
            Standing::Locked { until },
            Standing::Suspended { until, decision: d.clone() },
            Standing::Banned { until, decision: d.clone() },
        ] {
            let active = matches!(s.at(now), Standing::Active);
            prop_assert_eq!(active, now >= until);
        }
        let forever = Standing::BannedPermanent { decision: d };
        prop_assert!(forever.ends_sessions(now));
    }

    /// Identifiers normalize once: normalizing again changes nothing.
    #[test]
    fn identifiers_are_idempotent(raw in "\\PC{0,80}") {
        if let Ok(id) = Identifier::new(&raw) {
            prop_assert_eq!(Identifier::new(id.as_str()).unwrap(), id.clone());
            prop_assert!(id.as_str().len() <= MAX_IDENTIFIER_LEN);
        }
    }

    /// Payloads hold up to 192 bytes, exactly.
    #[test]
    fn payload_bounds(raw in prop::collection::vec(any::<u8>(), 0..300)) {
        match Payload::new(&raw) {
            Ok(p) => prop_assert_eq!(p.as_bytes(), &raw[..]),
            Err(e) => {
                prop_assert!(raw.len() > MAX_PAYLOAD);
                prop_assert_eq!(e, AuthError::PayloadTooLarge);
            }
        }
    }

    /// Reasons are cut to the limit at a character boundary.
    #[test]
    fn reasons_are_bounded(text in "\\PC{0,300}") {
        let r = Reason::new(&text);
        prop_assert!(r.as_str().len() <= MAX_REASON_LEN);
        prop_assert!(text.starts_with(r.as_str()));
    }

    /// Two addresses in the same /24 share a network binding; the browser
    /// binding follows the user agent.
    #[test]
    fn bindings(a in any::<[u8; 4]>(), last in any::<u8>(), ua in prop::collection::vec(any::<u8>(), 0..40)) {
        let (gate, _) = gate();
        let user = gate.identities().lookup(&Identifier::new("p@x.io").unwrap()).unwrap().unwrap();
        let ip1 = IpAddr::from(a);
        let ip2 = IpAddr::from([a[0], a[1], a[2], last]);
        let SignIn::Verified(v) = gate.sign_in("p@x.io", "property password", &Presented::new()) else { panic!() };
        let issued = gate.issue(v, Payload::EMPTY, &Presented::new().peer(ip1).user_agent(Some(&ua))).unwrap();
        let p = Presented::new().peer(ip2).user_agent(Some(&ua)).token(Some(issued.token.as_str().as_bytes()));
        let Authentication::Member(m) = gate.authenticate(&p) else { panic!() };
        prop_assert_eq!(m.record().bindings, issued.record.bindings, "same client, no change");
        prop_assert_eq!(m.user(), user);
    }
}

#[test]
fn sessions_survive_until_their_limits() {
    let (gate, token) = gate();
    let _ = gate;
    let clock = Arc::new(ManualClock::new(UnixTime::from_secs(1_000)));
    let gate = AuthGate::builder(GateKeys::derive(&[3; 32]).unwrap())
        .password_policy(PasswordPolicy::insecure_for_tests())
        .clock(clock.clone())
        .build()
        .unwrap();
    gate.create_account("p@x.io", "property password", Standing::Active, &[])
        .unwrap();
    let SignIn::Verified(v) = gate.sign_in("p@x.io", "property password", &Presented::new()) else {
        panic!()
    };
    let t = gate.issue(v, Payload::EMPTY, &Presented::new()).unwrap();
    let p = Presented::new().token(Some(t.token.as_str().as_bytes()));
    // A request every 29 minutes keeps it alive until the absolute limit.
    let mut alive = 0;
    while matches!(gate.authenticate(&p), Authentication::Member(_)) {
        clock.advance(Duration::from_secs(29 * 60));
        alive += 1;
        assert!(alive < 100);
    }
    assert_eq!(alive, 25, "12 h / 29 min, rounded up");
    assert!(!token.is_empty());
}
