//! End-to-end authentication flows against the in-memory stores. Every
//! threat the gate claims to stop has a test here that must fail to get in.

use std::{net::IpAddr, sync::Arc, time::Duration};

use auth_gate::*;
use crypt_io::{hash, sign::Ed25519SigningKey};

const PW: &str = "correct horse battery staple";

struct World {
    gate: AuthGate,
    clock: Arc<ManualClock>,
    signals: Arc<MemorySignals>,
    sessions: Arc<MemorySessions>,
}

fn world_with(session: SessionPolicy, keys: GateKeys) -> World {
    let clock = Arc::new(ManualClock::new(UnixTime::from_secs(1_700_000_000)));
    let signals = Arc::new(MemorySignals::default());
    let sessions = Arc::new(MemorySessions::with_limits(1000, 3, 3_600_000));
    let gate = AuthGate::builder(keys)
        .password_policy(PasswordPolicy::insecure_for_tests())
        .session_policy(session)
        .clock(clock.clone())
        .signals(signals.clone())
        .sessions(sessions.clone())
        .build()
        .unwrap();
    World {
        gate,
        clock,
        signals,
        sessions,
    }
}

fn world() -> World {
    world_with(
        SessionPolicy::default(),
        GateKeys::derive(&[42; 32]).unwrap(),
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn client() -> Presented<'static> {
    Presented::new()
        .peer(ip("198.51.100.7"))
        .user_agent(Some(b"Mozilla/5.0 test"))
}

fn signed_in(w: &World, who: &str) -> (UserId, String) {
    let SignIn::Verified(v) = w.gate.sign_in(who, PW, &client()) else {
        panic!("sign-in failed")
    };
    let user = v.user();
    let issued = w
        .gate
        .issue(v, Payload::new(b"perms").unwrap(), &client())
        .unwrap();
    (user, issued.token.as_str().to_owned())
}

fn auth(w: &World, token: &str) -> Authentication {
    w.gate.authenticate(&client().token(Some(token.as_bytes())))
}

fn last_signal(w: &World) -> SignalKind {
    *w.signals.kinds().last().unwrap()
}

#[test]
fn sign_in_and_out() {
    let w = world();
    w.gate
        .create_account("Alice@Example.com", PW, Standing::Active, &["member"])
        .unwrap();
    let (user, token) = signed_in(&w, "alice@example.com ");
    assert_eq!(token.len(), TOKEN_TEXT_LEN);
    let Authentication::Member(m) = auth(&w, &token) else {
        panic!()
    };
    assert_eq!(m.user(), user);
    assert_eq!(m.payload().as_bytes(), b"perms");
    assert!(
        w.signals.kinds().is_empty(),
        "a good request raises nothing"
    );

    assert!(
        w.gate
            .sign_out(&client().token(Some(token.as_bytes())))
            .unwrap()
    );
    assert_eq!(
        auth(&w, &token),
        Authentication::Guest(Guest::Invalid(SignalKind::StaleToken))
    );
    assert_eq!(last_signal(&w), SignalKind::StaleToken);
}

#[test]
fn no_credential_is_a_quiet_guest() {
    let w = world();
    assert_eq!(
        w.gate.authenticate(&client()),
        Authentication::Guest(Guest::NoCredential)
    );
    assert!(w.signals.kinds().is_empty());
}

#[test]
fn forged_and_malformed_tokens() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");

    // Flip one character of the random part: the signature no longer holds.
    let mut forged = token.clone().into_bytes();
    forged[10] = if forged[10] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(forged).unwrap();
    assert_eq!(
        auth(&w, &forged),
        Authentication::Guest(Guest::Invalid(SignalKind::ForgedToken))
    );

    for bad in ["", "short", &"!".repeat(67), &format!("{token}x")] {
        let out = auth(&w, bad);
        assert_eq!(
            out,
            Authentication::Guest(Guest::Invalid(SignalKind::MalformedToken)),
            "{bad:?}"
        );
    }
    // A token from another deployment (other keys) is a forgery here.
    let other = world_with(
        SessionPolicy::default(),
        GateKeys::derive(&[1; 32]).unwrap(),
    );
    other
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, theirs) = signed_in(&other, "a@x.io");
    assert_eq!(
        auth(&w, &theirs),
        Authentication::Guest(Guest::Invalid(SignalKind::ForgedToken))
    );
    assert!(Guest::Invalid(SignalKind::ForgedToken).clear_cookie());
}

#[test]
fn expired_sessions() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    // Idle: 30 minutes without a request.
    w.clock.advance(Duration::from_secs(31 * 60));
    assert_eq!(
        auth(&w, &token),
        Authentication::Guest(Guest::Invalid(SignalKind::ExpiredSession))
    );
    assert_eq!(
        auth(&w, &token),
        Authentication::Guest(Guest::Invalid(SignalKind::ExpiredSession))
    );

    // Absolute: busy for 12 hours, still ends.
    let (_, token) = signed_in(&w, "a@x.io");
    for _ in 0..(12 * 4) {
        w.clock.advance(Duration::from_secs(15 * 60));
        let _ = auth(&w, &token);
    }
    assert!(matches!(auth(&w, &token), Authentication::Guest(_)));
}

#[test]
fn stolen_cookie_replay_is_told_from_a_stale_tab() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    w.gate
        .sign_out(&client().token(Some(token.as_bytes())))
        .unwrap();
    let thief = Presented::new()
        .peer(ip("203.0.113.9"))
        .user_agent(Some(b"curl/8"))
        .token(Some(token.as_bytes()));
    assert_eq!(
        w.gate.authenticate(&thief),
        Authentication::Guest(Guest::Invalid(SignalKind::ReplayedToken))
    );
}

#[test]
fn fixation_every_sign_in_gets_a_new_token() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, first) = signed_in(&w, "a@x.io");
    let with_old = client().token(Some(first.as_bytes()));
    let SignIn::Verified(v) = w.gate.sign_in("a@x.io", PW, &with_old) else {
        panic!()
    };
    let second = w.gate.issue(v, Payload::EMPTY, &with_old).unwrap();
    assert_ne!(second.token.as_str(), first);
    assert!(
        matches!(auth(&w, &first), Authentication::Guest(_)),
        "old token ended"
    );
    assert!(matches!(
        auth(&w, second.token.as_str()),
        Authentication::Member(_)
    ));
}

#[test]
fn uniform_failures() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let banned = w
        .gate
        .create_account("b@x.io", PW, Standing::Active, &[])
        .unwrap();
    w.gate
        .set_standing(
            banned,
            Standing::BannedPermanent {
                decision: Decision::new("spam", Actor::System, w.gate.now()),
            },
        )
        .unwrap();
    let mut messages = Vec::new();
    for (who, pw, why) in [
        ("nobody@x.io", PW, FailureReason::UnknownAccount),
        ("a@x.io", "wrong password!", FailureReason::WrongPassword),
        ("b@x.io", PW, FailureReason::Banned),
        ("", PW, FailureReason::InvalidInput),
    ] {
        let SignIn::Failed(f) = w.gate.sign_in(who, pw, &client()) else {
            panic!("{who}")
        };
        assert_eq!(f.reason(), why);
        messages.push(f.message());
    }
    messages.dedup();
    assert_eq!(messages, [FAILURE_MESSAGE]);
}

#[test]
fn lockout_does_not_end_the_real_users_session() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    for _ in 0..10 {
        let _ = w.gate.sign_in("a@x.io", "attacker guess", &client());
    }
    assert!(w.signals.kinds().contains(&SignalKind::AccountLocked));
    let SignIn::Failed(f) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    assert_eq!(f.reason(), FailureReason::Locked);
    assert!(
        matches!(auth(&w, &token), Authentication::Member(_)),
        "still signed in"
    );
    // The lock lifts by itself.
    w.clock.advance(Duration::from_secs(16 * 60));
    let _ = auth(&w, &token);
    assert!(matches!(
        w.gate.sign_in("a@x.io", PW, &client()),
        SignIn::Verified(_)
    ));
    // The lock sits beside the standing and never replaced it.
    let account = w.gate.identities().account(user).unwrap().unwrap();
    assert_eq!(account.standing, Standing::Active);
    assert_eq!(
        account.locked_until,
        Some(UnixTime::from_secs(1_700_000_000) + Duration::from_secs(15 * 60))
    );
}

#[test]
fn lockout_never_erases_a_standing() {
    let w = world();
    let pending = w
        .gate
        .create_account("p@x.io", PW, Standing::PendingVerification, &[])
        .unwrap();
    for _ in 0..12 {
        let _ = w.gate.sign_in("p@x.io", "attacker guess", &client());
    }
    assert_eq!(
        w.gate.identities().standing(pending).unwrap(),
        Some(Standing::PendingVerification),
        "a lock never replaces the standing (it would lift to active)"
    );
    assert!(w.signals.kinds().contains(&SignalKind::SignInFailed));
    assert!(
        w.signals.kinds().contains(&SignalKind::AccountLocked),
        "pending accounts are locked too"
    );
}

#[test]
fn bans_refuse_and_end_every_session() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, t1) = signed_in(&w, "a@x.io");
    let (_, t2) = signed_in(&w, "a@x.io");
    let until = w.gate.now() + Duration::from_secs(3600);
    let decision = Decision::new("abuse", Actor::Admin(UserId::from_u128(1)), w.gate.now());
    w.gate
        .set_standing(user, Standing::Banned { until, decision })
        .unwrap();
    assert!(matches!(auth(&w, &t1), Authentication::Guest(_)));
    assert!(matches!(auth(&w, &t2), Authentication::Guest(_)));
    assert_eq!(w.sessions.live(), 0);
}

#[test]
fn ban_set_elsewhere_is_caught_at_the_recheck() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    // Another node wrote the ban straight to the shared identity store.
    w.gate
        .identities()
        .set_standing(
            user,
            Standing::BannedPermanent {
                decision: Decision::new("x", Actor::System, w.gate.now()),
            },
        )
        .unwrap();
    assert!(
        matches!(auth(&w, &token), Authentication::Member(_)),
        "snapshot until recheck"
    );
    w.clock.advance(Duration::from_secs(5 * 60));
    assert_eq!(
        auth(&w, &token),
        Authentication::Refused(Refusal::Banned { until: None })
    );
    assert_eq!(last_signal(&w), SignalKind::BannedSession);
}

#[test]
fn suspension_lifts_by_itself() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    let until = w.gate.now() + Duration::from_secs(120);
    w.gate
        .set_standing(
            user,
            Standing::Suspended {
                until,
                decision: Decision::new("cool off", Actor::System, w.gate.now()),
            },
        )
        .unwrap();
    w.clock.advance(Duration::from_secs(5 * 60 + 1));
    let Authentication::Member(m) = auth(&w, &token) else {
        panic!()
    };
    assert_eq!(
        m.standing().class,
        StandingClass::Active,
        "the 2 minutes are over"
    );
}

#[test]
fn client_change_is_reported_once() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    let moved = Presented::new()
        .peer(ip("192.0.2.1"))
        .user_agent(Some(b"Mozilla/5.0 test"))
        .token(Some(token.as_bytes()));
    assert!(matches!(
        w.gate.authenticate(&moved),
        Authentication::Member(_)
    ));
    assert!(matches!(
        w.gate.authenticate(&moved),
        Authentication::Member(_)
    ));
    let n = w
        .signals
        .kinds()
        .iter()
        .filter(|k| **k == SignalKind::ClientChanged)
        .count();
    assert_eq!(n, 1);

    let strict = world_with(
        SessionPolicy {
            client_change: ClientChange::EndSession,
            ..SessionPolicy::default()
        },
        GateKeys::derive(&[42; 32]).unwrap(),
    );
    strict
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&strict, "a@x.io");
    let moved = moved.token(Some(token.as_bytes()));
    assert!(matches!(
        strict.gate.authenticate(&moved),
        Authentication::Guest(_)
    ));
}

#[test]
fn key_rotation() {
    let old = [5u8; 32];
    let new = [6u8; 32];
    let w = world_with(
        SessionPolicy::default(),
        GateKeys::derive(&[42; 32])
            .unwrap()
            .with_token_keys(TokenKeys::new(1, old)),
    );
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");

    // Same store, rotated ring: the old key still verifies.
    let rotated = AuthGate::builder(
        GateKeys::derive(&[42; 32])
            .unwrap()
            .with_token_keys(TokenKeys::new(2, new).accept(1, old)),
    )
    .password_policy(PasswordPolicy::insecure_for_tests())
    .clock(w.clock.clone())
    .signals(w.signals.clone())
    .sessions(w.sessions.clone())
    .identities(w.gate.identities().clone())
    .build()
    .unwrap();
    let p = client().token(Some(token.as_bytes()));
    assert!(matches!(
        rotated.authenticate(&p),
        Authentication::Member(_)
    ));

    // Old key retired: a low-severity guest, never a forgery alarm.
    let retired = AuthGate::builder(
        GateKeys::derive(&[42; 32])
            .unwrap()
            .with_token_keys(TokenKeys::new(2, new).retire(1, old)),
    )
    .password_policy(PasswordPolicy::insecure_for_tests())
    .sessions(w.sessions.clone())
    .build()
    .unwrap();
    assert_eq!(
        retired.authenticate(&p),
        Authentication::Guest(Guest::Invalid(SignalKind::RetiredKeyToken))
    );
}

#[test]
fn per_account_session_cap() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let tokens: Vec<String> = (0..4).map(|_| signed_in(&w, "a@x.io").1).collect();
    assert_eq!(w.gate.sessions_of(user).unwrap().len(), 3);
    assert!(
        matches!(auth(&w, &tokens[0]), Authentication::Guest(_)),
        "oldest ended"
    );
    assert!(matches!(auth(&w, &tokens[3]), Authentication::Member(_)));
    assert_eq!(w.gate.sign_out_everywhere(user).unwrap(), 3);
}

#[test]
fn totp_and_recovery_codes() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let secret = w.gate.enroll_totp(user).unwrap();
    // Not confirmed yet: password alone still signs in.
    assert!(matches!(
        w.gate.sign_in("a@x.io", PW, &client()),
        SignIn::Verified(_)
    ));
    let code = totp_now(&secret, w.gate.now()).unwrap();
    assert!(w.gate.confirm_totp(user, &code).unwrap());

    w.clock.advance(Duration::from_secs(30));
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let text = ch.to_text();
    assert!(matches!(
        w.gate.second_factor(&text, "000000", &client()),
        SignIn::Failed(_)
    ));
    let code = totp_now(&secret, w.gate.now()).unwrap();
    let SignIn::Verified(v) = w.gate.second_factor(&text, &code, &client()) else {
        panic!()
    };
    assert_eq!(v.factor_at(), Some(w.gate.now()));
    let issued = w.gate.issue(v, Payload::EMPTY, &client()).unwrap();
    assert_eq!(issued.record.factor_at, Some(w.gate.now()));

    // The same code cannot be used twice, nor the same challenge.
    let SignIn::NeedsSecondFactor(ch2) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let SignIn::Failed(f) = w.gate.second_factor(&ch2.to_text(), &code, &client()) else {
        panic!()
    };
    assert_eq!(f.reason(), FailureReason::WrongCode);
    assert!(w.signals.kinds().contains(&SignalKind::FactorReplayed));
    w.clock.advance(Duration::from_secs(30));
    let code = totp_now(&secret, w.gate.now()).unwrap();
    let SignIn::Failed(f) = w.gate.second_factor(&text, &code, &client()) else {
        panic!()
    };
    assert_eq!(f.reason(), FailureReason::Replayed);

    // Recovery codes: each works once.
    let codes = w.gate.new_recovery_codes(user).unwrap();
    assert_eq!(codes.len(), RECOVERY_CODES);
    let SignIn::NeedsSecondFactor(ch3) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    assert!(matches!(
        w.gate.second_factor(&ch3.to_text(), &codes[0], &client()),
        SignIn::Verified(_)
    ));
    let SignIn::NeedsSecondFactor(ch4) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    assert!(matches!(
        w.gate.second_factor(&ch4.to_text(), &codes[0], &client()),
        SignIn::Failed(_)
    ));

    // Expired and tampered challenges.
    let SignIn::NeedsSecondFactor(ch5) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    w.clock.advance(CHALLENGE_TTL);
    let code = totp_now(&secret, w.gate.now()).unwrap();
    assert!(matches!(
        w.gate.second_factor(&ch5.to_text(), &code, &client()),
        SignIn::Failed(_)
    ));
    assert!(matches!(
        w.gate.second_factor("garbage", &code, &client()),
        SignIn::Failed(_)
    ));
}

fn cose_ed25519(public: &[u8; 32]) -> Vec<u8> {
    // {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}
    let mut k = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    k.extend_from_slice(public);
    k
}

fn client_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        b64(challenge)
    )
    .into_bytes()
}

fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    s
}

#[test]
fn passkeys() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let rp = RelyingParty::new("example.com", "https://example.com");
    let key = Ed25519SigningKey::from_seed(&[9; 32]).unwrap();
    let cred = b"credential-1";

    // Registration.
    let reg = w.gate.passkey_registration(user).unwrap();
    let mut auth_data = hash::sha256(b"example.com").to_vec();
    auth_data.push(0x01 | 0x04 | 0x40);
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0; 16]);
    auth_data.extend_from_slice(&(cred.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(cred);
    auth_data.extend_from_slice(&cose_ed25519(&key.public_key()));
    let cd = client_json("webauthn.create", reg.as_bytes(), "https://example.com");
    assert_eq!(w.gate.register_passkey(user, &rp, &cd, &auth_data), Ok(()));
    assert_eq!(
        w.gate.register_passkey(user, &rp, &cd, &auth_data),
        Err(PasskeyError::Challenge),
        "a registration challenge works once"
    );
    let wrong_origin = client_json("webauthn.create", reg.as_bytes(), "https://evil.example");
    assert_eq!(
        w.gate
            .register_passkey(user, &rp, &wrong_origin, &auth_data),
        Err(PasskeyError::WrongContext)
    );

    // Sign-in.
    let assert_with = |count: u32, challenge: &Challenge| {
        let mut ad = hash::sha256(b"example.com").to_vec();
        ad.push(0x01 | 0x04);
        ad.extend_from_slice(&count.to_be_bytes());
        let cd = client_json("webauthn.get", challenge.as_bytes(), "https://example.com");
        let mut signed = ad.clone();
        signed.extend_from_slice(&hash::sha256(&cd));
        (ad, cd, key.sign(&signed).to_vec())
    };
    let ch = w.gate.passkey_challenge().unwrap();
    let (ad, cd, sig) = assert_with(1, &ch);
    let SignIn::Verified(v) = w.gate.sign_in_passkey(&rp, cred, &cd, &ad, &sig, &client()) else {
        panic!("passkey sign-in")
    };
    assert_eq!(v.user(), user);
    assert!(v.factor_at().is_some());

    // Replay of the same assertion: refused.
    assert!(matches!(
        w.gate.sign_in_passkey(&rp, cred, &cd, &ad, &sig, &client()),
        SignIn::Failed(_)
    ));
    // A bad signature.
    let ch = w.gate.passkey_challenge().unwrap();
    let (ad, cd, mut sig) = assert_with(2, &ch);
    sig[0] ^= 1;
    let SignIn::Failed(f) = w.gate.sign_in_passkey(&rp, cred, &cd, &ad, &sig, &client()) else {
        panic!()
    };
    assert_eq!(
        f.reason(),
        FailureReason::Passkey(PasskeyError::BadSignature)
    );
    // A counter going backwards: a cloned key.
    let ch = w.gate.passkey_challenge().unwrap();
    let (ad, cd, sig) = assert_with(1, &ch);
    let SignIn::Failed(f) = w.gate.sign_in_passkey(&rp, cred, &cd, &ad, &sig, &client()) else {
        panic!()
    };
    assert_eq!(
        f.reason(),
        FailureReason::Passkey(PasskeyError::CounterRegressed)
    );
    assert!(w.signals.kinds().contains(&SignalKind::PasskeyCloned));
    // An unknown credential.
    let ch = w.gate.passkey_challenge().unwrap();
    let (ad, cd, sig) = assert_with(3, &ch);
    let SignIn::Failed(f) = w
        .gate
        .sign_in_passkey(&rp, b"nope", &cd, &ad, &sig, &client())
    else {
        panic!()
    };
    assert_eq!(
        f.reason(),
        FailureReason::Passkey(PasskeyError::UnknownCredential)
    );
}

#[test]
fn change_password_ends_sessions() {
    let w = world();
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let (_, token) = signed_in(&w, "a@x.io");
    w.gate
        .change_password(user, "another long password")
        .unwrap();
    assert!(matches!(auth(&w, &token), Authentication::Guest(_)));
    assert!(matches!(
        w.gate.sign_in("a@x.io", PW, &client()),
        SignIn::Failed(_)
    ));
    assert!(matches!(
        w.gate.sign_in("a@x.io", "another long password", &client()),
        SignIn::Verified(_)
    ));
}

#[test]
fn purge_drops_expired_sessions() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let _ = signed_in(&w, "a@x.io");
    assert_eq!(w.sessions.live(), 1);
    w.clock.advance(Duration::from_secs(13 * 3600));
    assert!(w.gate.purge() >= 1);
    assert_eq!(w.sessions.live(), 0);
}

#[test]
fn secrets_never_print() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let SignIn::Verified(v) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let issued = w.gate.issue(v, Payload::EMPTY, &client()).unwrap();
    let dbg = format!("{issued:?} {:?}", w.gate.keys());
    assert!(!dbg.contains(issued.token.as_str()));
    let secret = TotpSecret::generate().unwrap();
    assert!(!format!("{secret:?}").contains(&*secret.to_base32()));
}
