//! Regression tests for the 2026-11-11 hardening pass. Each failed
//! before its fix.

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use auth_gate::*;

const PW: &str = "correct horse battery staple";

struct World {
    gate: AuthGate,
    clock: Arc<ManualClock>,
    signals: Arc<MemorySignals>,
}

fn world_with_ids(ids: Arc<dyn IdentityStore>) -> World {
    let clock = Arc::new(ManualClock::new(UnixTime::from_secs(1_700_000_000)));
    let signals = Arc::new(MemorySignals::new(100_000));
    let gate = AuthGate::builder(GateKeys::derive(&[42; 32]).unwrap())
        .password_policy(PasswordPolicy::insecure_for_tests())
        .clock(clock.clone())
        .signals(signals.clone())
        .identities(ids)
        .build()
        .unwrap();
    World {
        gate,
        clock,
        signals,
    }
}

fn world() -> World {
    world_with_ids(Arc::new(MemoryIdentities::new()))
}

fn client() -> Presented<'static> {
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    Presented::new()
        .peer(ip)
        .user_agent(Some(b"Mozilla/5.0 test"))
}

/// Codes wrong for every step in the accepted window at `now`.
fn wrong_codes(secret: &TotpSecret, now: UnixTime, n: usize) -> Vec<String> {
    let valid: Vec<String> = [-30i64, 0, 30]
        .iter()
        .map(|d| {
            totp_now(
                secret,
                UnixTime::from_secs((now.as_secs() as i64 + d) as u64),
            )
            .unwrap()
        })
        .collect();
    (0..)
        .map(|i| format!("{i:06}"))
        .filter(|c| !valid.contains(c))
        .take(n)
        .collect()
}

fn confirmed_totp(w: &World, who: &str, standing: Standing) -> (UserId, TotpSecret) {
    let user = w.gate.create_account(who, PW, standing, &[]).unwrap();
    let secret = w.gate.enroll_totp(user).unwrap();
    let code = totp_now(&secret, w.gate.now()).unwrap();
    assert!(w.gate.confirm_totp(user, &code).unwrap());
    w.clock.advance(Duration::from_secs(30));
    (user, secret)
}

fn locked(w: &World, user: UserId) -> bool {
    let a = w.gate.identities().account(user).unwrap().unwrap();
    a.locked_until.is_some_and(|t| w.gate.now() < t)
}

/// password plus wrong codes, repeated, ends in a lock; the password
/// step no longer resets the counter.
#[test]
fn test_second_factor_guessing_locks_the_account() {
    let w = world();
    let (user, secret) = confirmed_totp(&w, "a@x.io", Standing::Active);
    let mut guesses = 0;
    'rounds: for _ in 0..20 {
        let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
            break 'rounds;
        };
        for code in wrong_codes(&secret, w.gate.now(), usize::from(CODE_ATTEMPTS)) {
            let _ = w.gate.second_factor(&ch.to_text(), &code, &client());
            guesses += 1;
        }
    }
    assert!(locked(&w, user), "locked after {guesses} wrong codes");
    assert!(guesses <= 12, "locked within the threshold, took {guesses}");
    assert!(w.signals.kinds().contains(&SignalKind::AccountLocked));
    // Locked: even the right password and the right code are refused.
    assert!(matches!(
        w.gate.sign_in("a@x.io", PW, &client()),
        SignIn::Failed(_)
    ));
}

/// one prompt accepts at most CODE_ATTEMPTS codes, even a right one
/// after that.
#[test]
fn test_second_factor_prompt_is_capped() {
    let w = world();
    let (_, secret) = confirmed_totp(&w, "a@x.io", Standing::Active);
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let text = ch.to_text();
    for code in wrong_codes(&secret, w.gate.now(), usize::from(CODE_ATTEMPTS)) {
        let SignIn::Failed(f) = w.gate.second_factor(&text, &code, &client()) else {
            panic!()
        };
        assert_eq!(f.reason(), FailureReason::WrongCode);
    }
    let right = totp_now(&secret, w.gate.now()).unwrap();
    let SignIn::Failed(f) = w.gate.second_factor(&text, &right, &client()) else {
        panic!("a spent prompt must not sign in")
    };
    assert_eq!(f.reason(), FailureReason::Challenge);
}

/// a right code within the cap still signs in, and only then are the
/// failures forgotten.
#[test]
fn test_second_factor_success_within_cap() {
    let w = world();
    let (_, secret) = confirmed_totp(&w, "a@x.io", Standing::Active);
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let text = ch.to_text();
    let wrong = wrong_codes(&secret, w.gate.now(), 2);
    for code in &wrong {
        let _ = w.gate.second_factor(&text, code, &client());
    }
    let right = totp_now(&secret, w.gate.now()).unwrap();
    assert!(matches!(
        w.gate.second_factor(&text, &right, &client()),
        SignIn::Verified(_)
    ));
}

/// suspended and pending accounts are locked like any other.
#[test]
fn test_lockout_applies_to_every_standing() {
    let w = world();
    let far = UnixTime::from_secs(1_800_000_000);
    let suspended = Standing::Suspended {
        until: far,
        decision: Decision::new("abuse", Actor::System, w.gate.now()),
    };
    let s = w
        .gate
        .create_account("s@x.io", PW, suspended.clone(), &[])
        .unwrap();
    let p = w
        .gate
        .create_account("p@x.io", PW, Standing::PendingVerification, &[])
        .unwrap();
    for (who, user) in [("s@x.io", s), ("p@x.io", p)] {
        for _ in 0..10 {
            let _ = w.gate.sign_in(who, "wrong guess", &client());
        }
        assert!(locked(&w, user), "{who}");
        assert!(
            matches!(w.gate.sign_in(who, PW, &client()), SignIn::Failed(_)),
            "{who}"
        );
    }
    assert_eq!(w.gate.identities().standing(s).unwrap(), Some(suspended));
    assert_eq!(
        w.gate.identities().standing(p).unwrap(),
        Some(Standing::PendingVerification)
    );
}

/// An identity store that counts calls and can land a ban mid-sign-in.
struct Hooked {
    inner: MemoryIdentities,
    failures_seen: AtomicU32,
    ban_on_failure: AtomicU32,
    reads: AtomicU32,
    writes: AtomicU32,
}

impl Hooked {
    fn new() -> Self {
        Self {
            inner: MemoryIdentities::new(),
            failures_seen: AtomicU32::new(0),
            ban_on_failure: AtomicU32::new(u32::MAX),
            reads: AtomicU32::new(0),
            writes: AtomicU32::new(0),
        }
    }
    fn r(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
    }
    fn w(&self) {
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
    fn counts(&self) -> (u32, u32) {
        (
            self.reads.swap(0, Ordering::SeqCst),
            self.writes.swap(0, Ordering::SeqCst),
        )
    }
}

impl IdentityStore for Hooked {
    fn lookup(&self, i: &Identifier) -> Result<Option<UserId>, StoreError> {
        self.r();
        self.inner.lookup(i)
    }
    fn account_by_identifier(&self, i: &Identifier) -> Result<Option<Account>, StoreError> {
        self.r();
        self.inner.account_by_identifier(i)
    }
    fn account(&self, u: UserId) -> Result<Option<Account>, StoreError> {
        self.r();
        self.inner.account(u)
    }
    fn standing(&self, u: UserId) -> Result<Option<Standing>, StoreError> {
        self.r();
        self.inner.standing(u)
    }
    fn create(&self, a: NewAccount) -> Result<UserId, StoreError> {
        self.inner.create(a)
    }
    fn set_standing(&self, u: UserId, s: Standing) -> Result<(), StoreError> {
        self.w();
        self.inner.set_standing(u, s)
    }
    fn set_password(&self, u: UserId, h: PasswordHash) -> Result<(), StoreError> {
        self.w();
        self.inner.set_password(u, h)
    }
    fn set_roles(&self, u: UserId, r: &[&str]) -> Result<(), StoreError> {
        self.inner.set_roles(u, r)
    }
    fn record_failure(&self, u: UserId, at: UnixTime, win: u64) -> Result<u32, StoreError> {
        self.w();
        let n = self.failures_seen.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.ban_on_failure.load(Ordering::SeqCst) {
            // An administrator's ban lands while this sign-in was hashing.
            self.inner
                .set_standing(
                    u,
                    Standing::BannedPermanent {
                        decision: Decision::new("fraud", Actor::System, at),
                    },
                )
                .unwrap();
        }
        self.inner.record_failure(u, at, win)
    }
    fn record_unknown_failure(
        &self,
        i: &Identifier,
        at: UnixTime,
        win: u64,
    ) -> Result<u32, StoreError> {
        self.w();
        self.inner.record_unknown_failure(i, at, win)
    }
    fn lock_until(&self, u: UserId, until: UnixTime) -> Result<(), StoreError> {
        self.w();
        self.inner.lock_until(u, until)
    }
    fn clear_failures(&self, u: UserId) -> Result<(), StoreError> {
        self.w();
        self.inner.clear_failures(u)
    }
    fn set_totp(&self, u: UserId, t: Option<TotpState>) -> Result<(), StoreError> {
        self.inner.set_totp(u, t)
    }
    fn advance_totp(&self, u: UserId, s: u64) -> Result<bool, StoreError> {
        self.inner.advance_totp(u, s)
    }
    fn set_recovery_codes(&self, u: UserId, c: Vec<RecoveryDigest>) -> Result<(), StoreError> {
        self.inner.set_recovery_codes(u, c)
    }
    fn use_recovery_code(&self, u: UserId, c: &RecoveryDigest) -> Result<bool, StoreError> {
        self.inner.use_recovery_code(u, c)
    }
    fn add_passkey(&self, u: UserId, p: Passkey) -> Result<(), StoreError> {
        self.inner.add_passkey(u, p)
    }
    fn passkey(&self, c: &[u8]) -> Result<Option<(UserId, Passkey)>, StoreError> {
        self.inner.passkey(c)
    }
    fn passkeys(&self, u: UserId) -> Result<Vec<Passkey>, StoreError> {
        self.inner.passkeys(u)
    }
    fn advance_sign_count(&self, c: &[u8], n: u32) -> Result<bool, StoreError> {
        self.inner.advance_sign_count(c, n)
    }
    fn remove_passkey(&self, u: UserId, c: &[u8]) -> Result<bool, StoreError> {
        self.inner.remove_passkey(u, c)
    }
}

/// a ban that lands during a sign-in stays a ban; the lock never
/// overwrites it.
#[test]
fn test_lockout_keeps_a_concurrent_ban() {
    let ids = Arc::new(Hooked::new());
    let w = world_with_ids(ids.clone());
    let user = w
        .gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    ids.ban_on_failure.store(10, Ordering::SeqCst);
    for _ in 0..10 {
        let _ = w.gate.sign_in("a@x.io", "attacker guess", &client());
    }
    assert!(matches!(
        w.gate.identities().standing(user).unwrap(),
        Some(Standing::BannedPermanent { .. })
    ));
    w.clock.advance(Duration::from_secs(16 * 60));
    assert!(matches!(
        w.gate.sign_in("a@x.io", PW, &client()),
        SignIn::Failed(_)
    ));
}

/// an unknown identifier and a known one with a wrong password cost
/// the store the same work: one read, one write.
#[test]
fn test_unknown_and_known_accounts_do_equal_store_work() {
    let ids = Arc::new(Hooked::new());
    let w = world_with_ids(ids.clone());
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    ids.counts();
    let _ = w.gate.sign_in("nobody@x.io", "wrong guess", &client());
    let unknown = ids.counts();
    let _ = w.gate.sign_in("a@x.io", "wrong guess", &client());
    let known = ids.counts();
    assert_eq!(unknown, (1, 1));
    assert_eq!(known, unknown);
}

/// re-enrolling keeps the confirmed factor until the new one is
/// confirmed; then the new one is the factor.
#[test]
fn test_reenrolling_totp_keeps_the_second_factor() {
    let w = world();
    let (user, old) = confirmed_totp(&w, "a@x.io", Standing::Active);
    let new = w.gate.enroll_totp(user).unwrap();
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!("an abandoned re-enrolment must not turn the second factor off")
    };
    let code = totp_now(&old, w.gate.now()).unwrap();
    assert!(matches!(
        w.gate.second_factor(&ch.to_text(), &code, &client()),
        SignIn::Verified(_)
    ));
    // Confirm the new one: a code from the old secret does not confirm it.
    w.clock.advance(Duration::from_secs(30));
    assert!(
        !w.gate
            .confirm_totp(user, &totp_now(&old, w.gate.now()).unwrap())
            .unwrap()
    );
    assert!(
        w.gate
            .confirm_totp(user, &totp_now(&new, w.gate.now()).unwrap())
            .unwrap()
    );
    w.clock.advance(Duration::from_secs(30));
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let code = totp_now(&new, w.gate.now()).unwrap();
    assert!(matches!(
        w.gate.second_factor(&ch.to_text(), &code, &client()),
        SignIn::Verified(_)
    ));
}

/// look-alike letters from other scripts and decomposed accents are
/// refused as identifiers instead of becoming separate accounts.
#[test]
fn test_identifiers_are_printable_ascii() {
    let w = world();
    w.gate
        .create_account("alice@example.com", PW, Standing::Active, &[])
        .unwrap();
    for bad in [
        "alice@ex\u{0430}mple.com",
        "jos\u{e9}@x.io",
        "jose\u{301}@x.io",
        "a b@x.io",
    ] {
        assert!(
            matches!(
                w.gate.create_account(bad, PW, Standing::Active, &[]),
                Err(AuthError::InvalidInput(_))
            ),
            "{bad:?}"
        );
    }
    let SignIn::Failed(f) = w.gate.sign_in("alice@ex\u{0430}mple.com", PW, &client()) else {
        panic!()
    };
    assert_eq!(f.reason(), FailureReason::InvalidInput);
}

/// a replayed challenge with a fresh valid code fails without burning
/// that code, so the user can still use it on a new prompt.
#[test]
fn test_replayed_challenge_does_not_burn_a_code() {
    let w = world();
    let (user, _) = confirmed_totp(&w, "a@x.io", Standing::Active);
    let codes = w.gate.new_recovery_codes(user).unwrap();
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let text = ch.to_text();
    assert!(matches!(
        w.gate.second_factor(&text, &codes[0], &client()),
        SignIn::Verified(_)
    ));
    let SignIn::Failed(f) = w.gate.second_factor(&text, &codes[1], &client()) else {
        panic!()
    };
    assert_eq!(f.reason(), FailureReason::Replayed);
    let SignIn::NeedsSecondFactor(ch) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    assert!(
        matches!(
            w.gate.second_factor(&ch.to_text(), &codes[1], &client()),
            SignIn::Verified(_)
        ),
        "codes[1] was not burned by the replay"
    );
}

/// the default ends a session when both the network and the browser
/// change, and only reports a change of one.
#[test]
fn test_default_ends_session_when_client_wholly_changes() {
    let w = world();
    w.gate
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let SignIn::Verified(v) = w.gate.sign_in("a@x.io", PW, &client()) else {
        panic!()
    };
    let t = w.gate.issue(v, Payload::EMPTY, &client()).unwrap();
    let token = t.token.as_str().as_bytes();
    let other_net: IpAddr = "203.0.113.9".parse().unwrap();
    let moved = Presented::new()
        .peer(other_net)
        .user_agent(Some(b"Mozilla/5.0 test"))
        .token(Some(token));
    assert!(matches!(
        w.gate.authenticate(&moved),
        Authentication::Member(_)
    ));
    let thief = Presented::new()
        .peer("192.0.2.200".parse().unwrap())
        .user_agent(Some(b"curl/8"))
        .token(Some(token));
    assert!(matches!(
        w.gate.authenticate(&thief),
        Authentication::Guest(_)
    ));
}
