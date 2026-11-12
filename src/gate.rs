//! The gate: authenticate every request, sign in, sign out.

use core::{fmt, net::IpAddr, time::Duration};
use std::sync::Arc;

use crypt_io::Zeroizing;

use crate::{
    challenge::{self, Challenge, Purpose},
    error::{AuthError, StoreError},
    id::{Identifier, SessionId, UserId},
    keys::GateKeys,
    memory::{MemoryIdentities, MemorySessions},
    otp::{self, TotpSecret},
    passkey::{self, PasskeyError, RelyingParty},
    password::{Hasher, PasswordHash, PasswordPolicy},
    record::{Bindings, EndReason, Payload, SessionInfo, SessionRecord},
    signal::{MemorySignals, Signal, SignalKind, SignalSink},
    standing::{Standing, StandingClass, StandingSnapshot},
    store::{Account, Found, IdentityStore, NewAccount, SessionStore, TotpState},
    time::{Clock, SystemClock, UnixTime},
    token::{self, SessionToken, TokenCheck, TokenDigest},
    webauthn::Ceremony,
};

/// Session lifetimes and checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Ends after this long without a request. Default 30 minutes.
    pub idle: Duration,
    /// Ends this long after sign-in, however busy. Default 12 hours.
    pub absolute: Duration,
    /// Re-read the account's standing at least this often. Default 5 minutes.
    pub recheck: Duration,
    /// Record activity at most this often (one store write per interval,
    /// not per request). Default 60 seconds.
    pub touch: Duration,
    /// What a change of client network or browser does.
    pub client_change: ClientChange,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(30 * 60),
            absolute: Duration::from_secs(12 * 3600),
            recheck: Duration::from_secs(5 * 60),
            touch: Duration::from_secs(60),
            client_change: ClientChange::EndWhenBoth,
        }
    }
}

/// What a session does when its client's network prefix or browser changes.
/// Every change is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClientChange {
    /// Carry on (mobile networks change prefix often).
    Signal,
    /// End the session when both the network and the browser changed (a
    /// copied cookie on another machine); carry on when only one did. The
    /// default.
    #[default]
    EndWhenBoth,
    /// End the session on any change.
    EndSession,
}

/// Wrong codes one second-factor prompt accepts before it stops working
/// (the user signs in with the password again, and every wrong code also
/// counts toward the account lock).
pub const CODE_ATTEMPTS: u8 = 3;

/// Automatic locking after failed sign-ins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Failures in the window that lock the account. Default 10.
    pub failures: u32,
    /// The window. Default 15 minutes.
    pub window: Duration,
    /// How long the lock lasts. Default 15 minutes.
    pub lock_for: Duration,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            failures: 10,
            window: Duration::from_secs(15 * 60),
            lock_for: Duration::from_secs(15 * 60),
        }
    }
}

/// What the client presented, and where from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Presented<'a> {
    token: Option<&'a [u8]>,
    peer: Option<IpAddr>,
    user_agent: Option<&'a [u8]>,
}

impl<'a> Presented<'a> {
    /// Nothing presented yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            token: None,
            peer: None,
            user_agent: None,
        }
    }

    /// The session token, as read from the credential's location.
    #[must_use]
    pub const fn token(mut self, token: Option<&'a [u8]>) -> Self {
        self.token = token;
        self
    }

    /// The client address.
    #[must_use]
    pub const fn peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// The `User-Agent` header value.
    #[must_use]
    pub const fn user_agent(mut self, agent: Option<&'a [u8]>) -> Self {
        self.user_agent = agent;
        self
    }

    /// The token presented, if any.
    #[must_use]
    pub const fn presented_token(&self) -> Option<&'a [u8]> {
        self.token
    }

    /// The client address, if known.
    #[must_use]
    pub const fn peer_addr(&self) -> Option<IpAddr> {
        self.peer
    }
}

/// The outcome of authenticating one request.
// Kept inline: boxing the record would allocate on every request.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// A guest: no credential, or one that is no good. Never a refusal by
    /// itself; authorization decides what a guest may do.
    Guest(Guest),
    /// A signed-in session.
    Member(Member),
    /// Refused at the gate: the account is banned. Its sessions are ended.
    Refused(Refusal),
}

/// Why a request is a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guest {
    /// Nothing was presented.
    NoCredential,
    /// A credential was presented and is no good; the signal was reported.
    /// The client is never told why.
    Invalid(SignalKind),
    /// The stores could not answer; failing closed.
    Unavailable,
}

impl Guest {
    /// Whether the client should be told to drop its cookie (the token can
    /// never work again).
    #[must_use]
    pub const fn clear_cookie(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }
}

/// A request refused at the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The account is banned, until a time or with no end.
    Banned {
        /// When it lifts (`None`: permanent).
        until: Option<UnixTime>,
    },
}

/// A signed-in session, as the request sees it: a snapshot of the server's
/// record. No database was read for it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Member {
    record: SessionRecord,
    digest: TokenDigest,
}

impl Member {
    /// The account.
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.record.user
    }

    /// The session's public id (bind CSRF tokens to it).
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.record.id
    }

    /// The payload stored at sign-in.
    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.record.payload
    }

    /// The account's standing when last read.
    #[must_use]
    pub const fn standing(&self) -> StandingSnapshot {
        self.record.standing
    }

    /// When a second factor was last proven in this session.
    #[must_use]
    pub const fn factor_at(&self) -> Option<UnixTime> {
        self.record.factor_at
    }

    /// The whole record.
    #[must_use]
    pub const fn record(&self) -> &SessionRecord {
        &self.record
    }

    /// The token digest, for ending exactly this session.
    #[must_use]
    pub const fn digest(&self) -> &TokenDigest {
        &self.digest
    }
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("user", &self.record.user)
            .field("session", &self.record.id)
            .finish_non_exhaustive()
    }
}

/// The result of a sign-in step.
#[derive(Debug)]
pub enum SignIn {
    /// Proven: hand it to [`AuthGate::issue`] to start the session.
    Verified(Verified),
    /// The password was right and the account has a second factor: carry
    /// the challenge through the code form ([`AuthGate::second_factor`]).
    /// Not signed in yet.
    NeedsSecondFactor(Challenge),
    /// Refused. Show [`Failure::message`]: the same for every reason.
    Failed(Failure),
}

/// Proof that an account passed sign-in. Only the gate makes one, and
/// [`AuthGate::issue`] consumes it, so a session cannot be issued without
/// a sign-in.
#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    user: UserId,
    factor_at: Option<UnixTime>,
}

impl Verified {
    /// The account.
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }

    /// When a second factor was proven, if one was.
    #[must_use]
    pub const fn factor_at(&self) -> Option<UnixTime> {
        self.factor_at
    }
}

/// Why a sign-in step failed: for logs and audit only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureReason {
    /// No such account.
    UnknownAccount,
    /// Wrong password.
    WrongPassword,
    /// The account is locked after failed sign-ins.
    Locked,
    /// The account is banned.
    Banned,
    /// The account has no password (passkey only).
    NoPassword,
    /// The identifier or password broke a limit.
    InvalidInput,
    /// A wrong second-factor code.
    WrongCode,
    /// A replayed code.
    Replayed,
    /// The challenge was not ours, expired, or used.
    Challenge,
    /// A passkey was refused.
    Passkey(PasskeyError),
    /// A store could not answer.
    Unavailable,
}

/// A refused sign-in step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    reason: FailureReason,
}

/// The one message shown for every failed sign-in, so a response never says
/// whether an account exists.
pub const FAILURE_MESSAGE: &str = "Those sign-in details are not right. Please try again.";

impl Failure {
    /// Why, for audit.
    #[must_use]
    pub const fn reason(&self) -> FailureReason {
        self.reason
    }

    /// What to show the user: the same text for every reason.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        FAILURE_MESSAGE
    }
}

fn failed(reason: FailureReason) -> SignIn {
    SignIn::Failed(Failure { reason })
}

/// A new session: give the token to the client once.
#[derive(Debug)]
pub struct Issued {
    /// The token (the cookie value).
    pub token: SessionToken,
    /// The server's record.
    pub record: SessionRecord,
}

/// Configures an [`AuthGate`]. Start with [`AuthGate::builder`].
#[must_use = "a builder does nothing until `build` is called"]
pub struct AuthGateBuilder {
    keys: GateKeys,
    identities: Option<Arc<dyn IdentityStore>>,
    sessions: Option<Arc<dyn SessionStore>>,
    signals: Option<Arc<dyn SignalSink>>,
    clock: Option<Arc<dyn Clock>>,
    password: PasswordPolicy,
    session: SessionPolicy,
    lockout: LockoutPolicy,
}

impl AuthGateBuilder {
    /// Where accounts live. Default: a new [`MemoryIdentities`].
    pub fn identities(mut self, store: Arc<dyn IdentityStore>) -> Self {
        self.identities = Some(store);
        self
    }

    /// Where sessions live. Default: a new [`MemorySessions`].
    pub fn sessions(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.sessions = Some(store);
        self
    }

    /// Where signals go: the security bridge. Default: a
    /// [`MemorySignals`] ring, so nothing is dropped silently; a deployed
    /// gate is always wired to the bridge.
    pub fn signals(mut self, sink: Arc<dyn SignalSink>) -> Self {
        self.signals = Some(sink);
        self
    }

    /// The clock. Default: the system clock.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Password rules and hashing cost.
    pub fn password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.password = policy;
        self
    }

    /// Session lifetimes and checks.
    pub fn session_policy(mut self, policy: SessionPolicy) -> Self {
        self.session = policy;
        self
    }

    /// Automatic locking.
    pub fn lockout_policy(mut self, policy: LockoutPolicy) -> Self {
        self.lockout = policy;
        self
    }

    /// Build the gate.
    ///
    /// # Errors
    ///
    /// [`AuthError::Crypto`] or [`AuthError::Random`] while preparing the
    /// password hasher.
    pub fn build(self) -> Result<AuthGate, AuthError> {
        let hasher = Hasher::new(self.password, *self.keys.pepper)?;
        Ok(AuthGate {
            hasher,
            keys: self.keys,
            identities: self
                .identities
                .unwrap_or_else(|| Arc::new(MemoryIdentities::new())),
            sessions: self
                .sessions
                .unwrap_or_else(|| Arc::new(MemorySessions::new())),
            signals: self
                .signals
                .unwrap_or_else(|| Arc::new(MemorySignals::default())),
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            session: self.session,
            lockout: self.lockout,
        })
    }
}

/// How long a pending second factor or a passkey challenge lasts.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// Authentication: turns an unknown visitor into a guest or a signed-in
/// session, and runs sign-in and sign-out. Protocol-free: the caller reads
/// the token from wherever the credential lives and writes cookies itself.
///
/// ```
/// use std::sync::Arc;
/// use auth_gate::{Authentication, AuthGate, GateKeys, PasswordPolicy, Presented, SignIn, Payload, Standing};
///
/// let gate = AuthGate::builder(GateKeys::derive(&[7u8; 32])?)
///     .password_policy(PasswordPolicy::insecure_for_tests())
///     .build()?;
/// gate.create_account("alice@example.com", "correct horse battery", Standing::Active, &["member"])?;
///
/// // Sign in, then issue the session.
/// let SignIn::Verified(proof) = gate.sign_in("alice@example.com", "correct horse battery", &Presented::new()) else {
///     panic!("sign-in failed");
/// };
/// let issued = gate.issue(proof, Payload::EMPTY, &Presented::new())?;
///
/// // Every request: authenticate the token.
/// let visit = Presented::new().token(Some(issued.token.as_str().as_bytes()));
/// assert!(matches!(gate.authenticate(&visit), Authentication::Member(_)));
///
/// // Sign out: the same token is a guest from now on.
/// gate.sign_out(&visit)?;
/// assert!(matches!(gate.authenticate(&visit), Authentication::Guest(_)));
/// # Ok::<(), auth_gate::AuthError>(())
/// ```
pub struct AuthGate {
    keys: GateKeys,
    hasher: Hasher,
    identities: Arc<dyn IdentityStore>,
    sessions: Arc<dyn SessionStore>,
    signals: Arc<dyn SignalSink>,
    clock: Arc<dyn Clock>,
    session: SessionPolicy,
    lockout: LockoutPolicy,
}

impl fmt::Debug for AuthGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthGate")
            .field("session", &self.session)
            .field("lockout", &self.lockout)
            .finish_non_exhaustive()
    }
}

impl AuthGate {
    /// Start configuring a gate with these keys.
    pub fn builder(keys: GateKeys) -> AuthGateBuilder {
        AuthGateBuilder {
            keys,
            identities: None,
            sessions: None,
            signals: None,
            clock: None,
            password: PasswordPolicy::new(),
            session: SessionPolicy::default(),
            lockout: LockoutPolicy::default(),
        }
    }

    /// The clock's now.
    #[must_use]
    pub fn now(&self) -> UnixTime {
        self.clock.now()
    }

    /// The keys (for the CSRF key).
    #[must_use]
    pub fn keys(&self) -> &GateKeys {
        &self.keys
    }

    /// The identity store.
    #[must_use]
    pub fn identities(&self) -> &Arc<dyn IdentityStore> {
        &self.identities
    }

    /// The session store.
    #[must_use]
    pub fn sessions(&self) -> &Arc<dyn SessionStore> {
        &self.sessions
    }

    /// The session policy.
    #[must_use]
    pub fn session_policy(&self) -> &SessionPolicy {
        &self.session
    }

    fn report(
        &self,
        kind: SignalKind,
        confidence: u8,
        p: &Presented<'_>,
        user: Option<UserId>,
        session: Option<SessionId>,
        at: UnixTime,
    ) {
        self.signals.signal(&Signal {
            kind,
            confidence,
            source: p.peer,
            user,
            session,
            at,
        });
    }

    fn bindings(&self, user: UserId, p: &Presented<'_>) -> Bindings {
        Bindings::compute(&self.keys.binding, user, p.peer, p.user_agent)
    }

    // ------------------------------------------------------------ request

    /// Authenticate one request. Reads memory only, except for a standing
    /// re-check at most once per [`SessionPolicy::recheck`] per session.
    #[must_use]
    pub fn authenticate(&self, p: &Presented<'_>) -> Authentication {
        let Some(raw) = p.token else {
            return Authentication::Guest(Guest::NoCredential);
        };
        let now = self.clock.now();
        let invalid = |kind: SignalKind, confidence: u8, user, session| {
            self.report(kind, confidence, p, user, session, now);
            Authentication::Guest(Guest::Invalid(kind))
        };
        let digest = match token::check(&self.keys, raw) {
            TokenCheck::Valid(d) => d,
            TokenCheck::Malformed | TokenCheck::UnknownKey => {
                return invalid(SignalKind::MalformedToken, 50, None, None);
            }
            TokenCheck::RetiredKey => return invalid(SignalKind::RetiredKeyToken, 90, None, None),
            TokenCheck::BadSignature => return invalid(SignalKind::ForgedToken, 90, None, None),
        };
        let found = match self.sessions.find(&digest) {
            Ok(f) => f,
            Err(_) => return Authentication::Guest(Guest::Unavailable),
        };
        let mut rec = match found {
            Found::Unknown => return invalid(SignalKind::UnknownSession, 60, None, None),
            Found::Ended(t) => {
                let here = self.bindings(t.user, p);
                return match t.reason {
                    EndReason::Expired => {
                        invalid(SignalKind::ExpiredSession, 80, Some(t.user), None)
                    }
                    _ if here.same_client(&t.bindings) => {
                        invalid(SignalKind::StaleToken, 70, Some(t.user), None)
                    }
                    _ => invalid(SignalKind::ReplayedToken, 60, Some(t.user), None),
                };
            }
            Found::Live(r) => r,
        };
        if rec.expired(now) {
            let _ = self.sessions.end(&digest, EndReason::Expired, now);
            return invalid(SignalKind::ExpiredSession, 90, Some(rec.user), Some(rec.id));
        }
        let mut changed = false;

        // Standing: from the snapshot, re-read when due.
        if now >= rec.recheck_at {
            match self.identities.standing(rec.user) {
                Ok(Some(standing)) => {
                    if standing.ends_sessions(now) {
                        let _ = self.sessions.end_all(rec.user, EndReason::RevokedAll, now);
                        self.report(
                            SignalKind::BannedSession,
                            90,
                            p,
                            Some(rec.user),
                            Some(rec.id),
                            now,
                        );
                        return Authentication::Refused(Refusal::Banned {
                            until: standing.at(now).expires(),
                        });
                    }
                    rec.standing = standing.snapshot(now);
                    let next = now + self.session.recheck;
                    rec.recheck_at = standing.expires().map_or(next, |e| e.min(next));
                    changed = true;
                }
                Ok(None) => {
                    // The account is gone.
                    let _ = self.sessions.end(&digest, EndReason::Revoked, now);
                    return Authentication::Guest(Guest::Invalid(SignalKind::UnknownSession));
                }
                Err(_) => return Authentication::Guest(Guest::Unavailable),
            }
        } else if rec.standing.class == StandingClass::Banned {
            return Authentication::Refused(Refusal::Banned {
                until: rec.standing.until,
            });
        }

        // The client: the network prefix on every request; the keyed
        // browser hash when the prefix moved or at the touch interval.
        // Report a change once, then follow it.
        let touch_due = now.since(rec.last_seen) >= duration_ms(self.session.touch);
        let network_moved = !rec.bindings.network_is(p.peer);
        if network_moved || touch_due {
            let here = self.bindings(rec.user, p);
            let agent_moved = !here.same_agent(&rec.bindings);
            if network_moved || agent_moved {
                self.report(
                    SignalKind::ClientChanged,
                    50,
                    p,
                    Some(rec.user),
                    Some(rec.id),
                    now,
                );
                let end = match self.session.client_change {
                    ClientChange::Signal => false,
                    ClientChange::EndWhenBoth => network_moved && agent_moved,
                    ClientChange::EndSession => true,
                };
                if end {
                    let _ = self.sessions.end(&digest, EndReason::Revoked, now);
                    return Authentication::Guest(Guest::Invalid(SignalKind::ClientChanged));
                }
                rec.bindings = here;
                changed = true;
            }
        }

        // Activity, at most once per touch interval.
        if touch_due {
            rec.last_seen = now;
            rec.idle_until = (now + self.session.idle).min(rec.absolute_until);
            changed = true;
        }
        if changed {
            match self.sessions.update(&digest, &rec) {
                Ok(true) => {}
                // Ended meanwhile (signed out on another node).
                Ok(false) => return Authentication::Guest(Guest::Invalid(SignalKind::StaleToken)),
                Err(_) => return Authentication::Guest(Guest::Unavailable),
            }
        }
        Authentication::Member(Member {
            record: rec,
            digest,
        })
    }

    // ------------------------------------------------------------ sign-in

    /// Check an identifier and password. Unknown accounts, wrong passwords,
    /// and locked or banned accounts all fail the same way and cost the same
    /// Argon2id work; the real reason goes to the signal and to
    /// [`Failure::reason`].
    ///
    /// Argon2id takes tens of milliseconds by design: call it off any
    /// connection-serving thread.
    #[must_use]
    pub fn sign_in(&self, identifier: &str, password: &str, p: &Presented<'_>) -> SignIn {
        let now = self.clock.now();
        let Ok(id) = Identifier::new(identifier) else {
            let _ = self.hasher.dummy_check();
            return failed(FailureReason::InvalidInput);
        };
        // One read and, on failure, one write, whether or not the account
        // exists: the store work does not tell them apart.
        let account = match self.identities.account_by_identifier(&id) {
            Ok(Some(a)) => a,
            Ok(None) => {
                let _ = self.hasher.dummy_check();
                self.report(SignalKind::SignInUnknown, 50, p, None, None, now);
                let window = duration_ms(self.lockout.window);
                let _ = self.identities.record_unknown_failure(&id, now, window);
                return failed(FailureReason::UnknownAccount);
            }
            Err(_) => return failed(FailureReason::Unavailable),
        };
        // Count the attempt before checking it: the store's own atomic
        // increment is the gate, so requests in flight together cannot all
        // pass the threshold, and every known account gets one write, as an
        // unknown identifier does.
        let attempt = match self.attempt(&account, p, now) {
            Ok(a) => a,
            Err(_) => {
                let _ = self.hasher.dummy_check();
                return failed(FailureReason::Unavailable);
            }
        };
        let Some(hash) = account.password.clone() else {
            let _ = self.hasher.dummy_check();
            return failed(FailureReason::NoPassword);
        };
        // The hash is checked even for blocked accounts, so timing does not
        // tell a blocked account from a wrong password.
        let ok = self.hasher.check(&hash, password.as_bytes());
        if blocked(&account, now) || attempt == Attempt::OverLimit {
            self.report(
                SignalKind::SignInBlocked,
                90,
                p,
                Some(account.user),
                None,
                now,
            );
            let reason = if account.standing.ends_sessions(now) {
                FailureReason::Banned
            } else {
                FailureReason::Locked
            };
            return failed(reason);
        }
        if !ok {
            self.failed_attempt(&account, attempt, p, now, SignalKind::SignInFailed);
            return failed(FailureReason::WrongPassword);
        }
        if self.hasher.needs_rehash(&hash) {
            if let Ok(new) = self.hasher.hash(password) {
                let _ = self.identities.set_password(account.user, new);
            }
        }
        self.after_first_factor(&account, now)
    }

    /// Record a sign-in attempt for `account` before it is checked, and say
    /// whether it is still within the limit. Over the limit, the account is
    /// locked (if it is not already) and the attempt is refused unchecked.
    fn attempt(
        &self,
        account: &Account,
        p: &Presented<'_>,
        now: UnixTime,
    ) -> Result<Attempt, StoreError> {
        let window = duration_ms(self.lockout.window);
        let n = self.identities.record_failure(account.user, now, window)?;
        if n > self.lockout.failures {
            self.lock(account, p, now);
            return Ok(Attempt::OverLimit);
        }
        Ok(if n == self.lockout.failures {
            Attempt::Last
        } else {
            Attempt::Within
        })
    }

    /// An attempt checked and found wrong: report it, and lock the account
    /// when it was the last one allowed.
    fn failed_attempt(
        &self,
        account: &Account,
        attempt: Attempt,
        p: &Presented<'_>,
        now: UnixTime,
        kind: SignalKind,
    ) {
        self.report(kind, 70, p, Some(account.user), None, now);
        if attempt != Attempt::Within {
            self.lock(account, p, now);
        }
    }

    /// Lock the account for the lockout period. The lock is kept apart from
    /// the standing, so it never replaces one (a ban that lands meanwhile
    /// stays a ban).
    fn lock(&self, account: &Account, p: &Presented<'_>, now: UnixTime) {
        if account.locked_until.is_some_and(|t| now < t) {
            return;
        }
        let until = now + self.lockout.lock_for;
        if self.identities.lock_until(account.user, until).is_ok() {
            self.report(
                SignalKind::AccountLocked,
                90,
                p,
                Some(account.user),
                None,
                now,
            );
        }
    }

    fn after_first_factor(&self, account: &Account, now: UnixTime) -> SignIn {
        let wants_second = account.totp.as_ref().is_some_and(|t| t.confirmed);
        if !wants_second {
            // The whole sign-in passed: only now are failures forgotten. With
            // a second factor still owed, they stay counted.
            let _ = self.identities.clear_failures(account.user);
            return SignIn::Verified(Verified {
                user: account.user,
                factor_at: None,
            });
        }
        match challenge::issue(
            &self.keys,
            Purpose::SecondFactor,
            Some(account.user),
            now + CHALLENGE_TTL,
        ) {
            Ok(c) => SignIn::NeedsSecondFactor(c),
            Err(_) => failed(FailureReason::Unavailable),
        }
    }

    /// The second step: `code` is a TOTP code or a recovery code, for the
    /// challenge [`sign_in`](Self::sign_in) returned (its text form). Each
    /// challenge and each code works once.
    #[must_use]
    pub fn second_factor(&self, challenge_text: &str, code: &str, p: &Presented<'_>) -> SignIn {
        let now = self.clock.now();
        let opened = challenge::from_text(challenge_text)
            .and_then(|raw| challenge::open(&self.keys, &raw, Purpose::SecondFactor, now));
        let Some(opened) = opened else {
            self.report(SignalKind::FactorFailed, 60, p, None, None, now);
            return failed(FailureReason::Challenge);
        };
        let Some(user) = opened.user else {
            return failed(FailureReason::Challenge);
        };
        let account = match self.identities.account(user) {
            Ok(Some(a)) => a,
            Ok(None) => return failed(FailureReason::UnknownAccount),
            Err(_) => return failed(FailureReason::Unavailable),
        };
        if blocked(&account, now) {
            return failed(FailureReason::Banned);
        }
        // A prompt accepts at most CODE_ATTEMPTS codes, across every node
        // that shares the session store.
        let claimed = (0..CODE_ATTEMPTS).try_fold(false, |done, i| {
            if done {
                return Ok(true);
            }
            self.sessions.use_once(
                challenge::attempt_key(&self.keys, &opened.once_key, i),
                opened.expires,
                now,
            )
        });
        match claimed {
            Ok(true) => {}
            Ok(false) => {
                self.report(SignalKind::FactorFailed, 80, p, Some(user), None, now);
                return failed(FailureReason::Challenge);
            }
            Err(_) => return failed(FailureReason::Unavailable),
        }
        // Counted before it is checked, as on the password step.
        let attempt = match self.attempt(&account, p, now) {
            Ok(Attempt::OverLimit) => return failed(FailureReason::Locked),
            Ok(a) => a,
            Err(_) => return failed(FailureReason::Unavailable),
        };
        let recovery = otp::is_recovery_shape(code);
        let step = if recovery {
            None
        } else {
            let step = account
                .totp
                .as_ref()
                .filter(|t| t.confirmed)
                .and_then(|t| otp::totp_check(&t.secret, code, now));
            if step.is_none() {
                self.failed_attempt(&account, attempt, p, now, SignalKind::FactorFailed);
                return failed(FailureReason::WrongCode);
            }
            step
        };
        // The challenge is consumed before any code is: a replayed challenge
        // never burns a fresh code.
        match self.sessions.use_once(opened.once_key, opened.expires, now) {
            Ok(true) => {}
            Ok(false) => {
                self.report(SignalKind::FactorReplayed, 90, p, Some(user), None, now);
                return failed(FailureReason::Replayed);
            }
            Err(_) => return failed(FailureReason::Unavailable),
        }
        let accepted = match step {
            Some(step) => match self.identities.advance_totp(user, step) {
                Ok(true) => true,
                Ok(false) => {
                    self.report(SignalKind::FactorReplayed, 80, p, Some(user), None, now);
                    false
                }
                Err(_) => return failed(FailureReason::Unavailable),
            },
            None => match otp::recovery_digest(&self.keys, code)
                .map(|d| self.identities.use_recovery_code(user, &d))
            {
                Some(Ok(true)) => true,
                Some(Err(_)) => return failed(FailureReason::Unavailable),
                _ => false,
            },
        };
        if !accepted {
            self.failed_attempt(&account, attempt, p, now, SignalKind::FactorFailed);
            return failed(FailureReason::WrongCode);
        }
        let _ = self.identities.clear_failures(user);
        SignIn::Verified(Verified {
            user,
            factor_at: Some(now),
        })
    }

    /// Start a session for a verified sign-in. Any session the client
    /// presented is ended first (session fixation defence): every sign-in
    /// gets a new token.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the stores fail or the account is gone; no session
    /// exists then.
    pub fn issue(
        &self,
        verified: Verified,
        payload: Payload,
        p: &Presented<'_>,
    ) -> Result<Issued, AuthError> {
        let now = self.clock.now();
        if let Some(raw) = p.token {
            if let TokenCheck::Valid(old) = token::check(&self.keys, raw) {
                self.sessions.end(&old, EndReason::Replaced, now)?;
            }
        }
        let standing = self
            .identities
            .standing(verified.user)?
            .ok_or(AuthError::Store(StoreError::NotFound))?;
        if standing.blocks_sign_in(now) {
            return Err(AuthError::InvalidInput("account may not sign in"));
        }
        let (tok, digest) = token::issue(&self.keys)?;
        let absolute = now + self.session.absolute;
        let next = now + self.session.recheck;
        let record = SessionRecord {
            id: SessionId::generate()?,
            user: verified.user,
            created: now,
            last_seen: now,
            idle_until: (now + self.session.idle).min(absolute),
            absolute_until: absolute,
            recheck_at: standing.expires().map_or(next, |e| e.min(next)),
            standing: standing.snapshot(now),
            bindings: self.bindings(verified.user, p),
            factor_at: verified.factor_at,
            payload,
        };
        self.sessions.insert(digest, record)?;
        Ok(Issued { token: tok, record })
    }

    /// End the session whose token the client presented. Returns whether
    /// there was one.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn sign_out(&self, p: &Presented<'_>) -> Result<bool, AuthError> {
        let Some(raw) = p.token else { return Ok(false) };
        let TokenCheck::Valid(d) = token::check(&self.keys, raw) else {
            return Ok(false);
        };
        Ok(self
            .sessions
            .end(&d, EndReason::SignedOut, self.clock.now())?
            .is_some())
    }

    /// End exactly the session of `member`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn end_session(&self, member: &Member) -> Result<bool, AuthError> {
        Ok(self
            .sessions
            .end(member.digest(), EndReason::SignedOut, self.clock.now())?
            .is_some())
    }

    /// End every session of `user` (sign out everywhere).
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn sign_out_everywhere(&self, user: UserId) -> Result<u32, AuthError> {
        Ok(self
            .sessions
            .end_all(user, EndReason::RevokedAll, self.clock.now())?)
    }

    /// The live sessions of `user`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn sessions_of(&self, user: UserId) -> Result<Vec<SessionInfo>, AuthError> {
        Ok(self.sessions.sessions_of(user)?)
    }

    // ------------------------------------------------------------ accounts

    /// Hash a password under the policy (for a store adapter's sign-up).
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInput`] for a length outside the policy.
    pub fn hash_password(&self, password: &str) -> Result<PasswordHash, AuthError> {
        self.hasher.hash(password)
    }

    /// Create an account with a password.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInput`] for a bad identifier or password;
    /// [`StoreError::AlreadyExists`] if the identifier is taken.
    pub fn create_account(
        &self,
        identifier: &str,
        password: &str,
        standing: Standing,
        roles: &[&str],
    ) -> Result<UserId, AuthError> {
        let identifier = Identifier::new(identifier)?;
        let password = Some(self.hasher.hash(password)?);
        Ok(self.identities.create(NewAccount {
            identifier,
            password,
            standing,
            roles: roles.iter().map(|r| Box::from(*r)).collect(),
            tenant: None,
            created: self.clock.now(),
        })?)
    }

    /// Change a password and end every session of the account.
    ///
    /// # Errors
    ///
    /// As [`hash_password`](Self::hash_password), or [`AuthError::Store`].
    pub fn change_password(&self, user: UserId, new_password: &str) -> Result<(), AuthError> {
        let hash = self.hasher.hash(new_password)?;
        self.identities.set_password(user, hash)?;
        self.sessions
            .end_all(user, EndReason::RevokedAll, self.clock.now())?;
        Ok(())
    }

    /// Set an account's standing. A ban ends every session at once; other
    /// standings reach live sessions at their next standing re-check.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn set_standing(&self, user: UserId, standing: Standing) -> Result<(), AuthError> {
        let now = self.clock.now();
        let ends = standing.ends_sessions(now);
        self.identities.set_standing(user, standing)?;
        if ends {
            self.sessions.end_all(user, EndReason::RevokedAll, now)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ factors

    /// Start TOTP enrolment: a new secret. Show [`TotpSecret::uri`] as a QR
    /// code, then [`confirm_totp`](Self::confirm_totp) with the first code.
    /// Sign-in asks for codes only once a secret is confirmed. Enrolling
    /// again (a new phone) keeps the confirmed secret working until the new
    /// one is confirmed, so an abandoned enrolment never turns the second
    /// factor off.
    ///
    /// # Errors
    ///
    /// [`AuthError`].
    pub fn enroll_totp(&self, user: UserId) -> Result<TotpSecret, AuthError> {
        let secret = TotpSecret::generate()?;
        let current = self
            .identities
            .account(user)?
            .ok_or(AuthError::Store(StoreError::NotFound))?
            .totp;
        let state = match current {
            Some(t) if t.confirmed => TotpState {
                pending: Some(secret.clone()),
                ..t
            },
            _ => TotpState {
                secret: secret.clone(),
                last_step: 0,
                confirmed: false,
                pending: None,
            },
        };
        self.identities.set_totp(user, Some(state))?;
        Ok(secret)
    }

    /// Confirm TOTP enrolment with a first code.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn confirm_totp(&self, user: UserId, code: &str) -> Result<bool, AuthError> {
        let now = self.clock.now();
        let Some(account) = self.identities.account(user)? else {
            return Ok(false);
        };
        let Some(totp) = account.totp else {
            return Ok(false);
        };
        if let Some(pending) = totp.pending {
            // Replacing a confirmed secret: swap only on a code from the new one.
            let Some(step) = otp::totp_check(&pending, code, now) else {
                return Ok(false);
            };
            self.identities.set_totp(
                user,
                Some(TotpState {
                    secret: pending,
                    last_step: step,
                    confirmed: true,
                    pending: None,
                }),
            )?;
            return Ok(true);
        }
        let Some(step) = otp::totp_check(&totp.secret, code, now) else {
            return Ok(false);
        };
        Ok(self.identities.advance_totp(user, step)?)
    }

    /// Remove TOTP.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn remove_totp(&self, user: UserId) -> Result<(), AuthError> {
        Ok(self.identities.set_totp(user, None)?)
    }

    /// Ten new recovery codes, replacing any old ones. Show them once; the
    /// store keeps only keyed digests.
    ///
    /// # Errors
    ///
    /// [`AuthError`].
    pub fn new_recovery_codes(&self, user: UserId) -> Result<Vec<Zeroizing<String>>, AuthError> {
        let mut codes = Vec::with_capacity(otp::RECOVERY_CODES);
        let mut digests = Vec::with_capacity(otp::RECOVERY_CODES);
        for _ in 0..otp::RECOVERY_CODES {
            let code = otp::new_recovery_code()?;
            let d = otp::recovery_digest(&self.keys, &code).ok_or(AuthError::Crypto)?;
            digests.push(d);
            codes.push(code);
        }
        self.identities.set_recovery_codes(user, digests)?;
        Ok(codes)
    }

    /// A challenge for `navigator.credentials.create` (its bytes). Use
    /// `user.to_bytes()` as the WebAuthn `user.id`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Random`].
    pub fn passkey_registration(&self, user: UserId) -> Result<Challenge, AuthError> {
        challenge::issue(
            &self.keys,
            Purpose::PasskeyRegister,
            Some(user),
            self.clock.now() + CHALLENGE_TTL,
        )
    }

    /// Register a passkey from the browser's `clientDataJSON` and
    /// `getAuthenticatorData()` (both base64url-decoded by the caller).
    ///
    /// # Errors
    ///
    /// [`PasskeyError`] saying which check failed.
    pub fn register_passkey(
        &self,
        user: UserId,
        rp: &RelyingParty,
        client_data_json: &[u8],
        authenticator_data: &[u8],
    ) -> Result<(), PasskeyError> {
        let now = self.clock.now();
        let client = passkey::check_client(rp, client_data_json, Ceremony::Create)?;
        let opened = challenge::open(&self.keys, &client.challenge, Purpose::PasskeyRegister, now)
            .ok_or(PasskeyError::Challenge)?;
        if opened.user != Some(user) {
            return Err(PasskeyError::Challenge);
        }
        let data = passkey::check_authenticator(rp, authenticator_data)?;
        let key = passkey::registered(&data, now)?;
        match self.sessions.use_once(opened.once_key, opened.expires, now) {
            Ok(true) => {}
            _ => return Err(PasskeyError::Challenge),
        }
        self.identities
            .add_passkey(user, key)
            .map_err(|_| PasskeyError::UnknownCredential)
    }

    /// Remove a passkey from an account.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn remove_passkey(&self, user: UserId, credential: &[u8]) -> Result<bool, AuthError> {
        Ok(self.identities.remove_passkey(user, credential)?)
    }

    /// A challenge for `navigator.credentials.get` (its bytes).
    ///
    /// # Errors
    ///
    /// [`AuthError::Random`].
    pub fn passkey_challenge(&self) -> Result<Challenge, AuthError> {
        challenge::issue(
            &self.keys,
            Purpose::PasskeySignIn,
            None,
            self.clock.now() + CHALLENGE_TTL,
        )
    }

    /// Sign in with a passkey assertion: `rawId`, `clientDataJSON`,
    /// `authenticatorData`, `signature`, all base64url-decoded by the
    /// caller. A verified passkey counts as both factors.
    #[must_use]
    pub fn sign_in_passkey(
        &self,
        rp: &RelyingParty,
        credential: &[u8],
        client_data_json: &[u8],
        authenticator_data: &[u8],
        signature: &[u8],
        p: &Presented<'_>,
    ) -> SignIn {
        let now = self.clock.now();
        let fail = |e: PasskeyError, user: Option<UserId>| {
            let kind = if e == PasskeyError::CounterRegressed {
                SignalKind::PasskeyCloned
            } else {
                SignalKind::PasskeyFailed
            };
            self.report(kind, 80, p, user, None, now);
            failed(FailureReason::Passkey(e))
        };
        let client = match passkey::check_client(rp, client_data_json, Ceremony::Get) {
            Ok(c) => c,
            Err(e) => return fail(e, None),
        };
        let Some(opened) =
            challenge::open(&self.keys, &client.challenge, Purpose::PasskeySignIn, now)
        else {
            return fail(PasskeyError::Challenge, None);
        };
        let data = match passkey::check_authenticator(rp, authenticator_data) {
            Ok(d) => d,
            Err(e) => return fail(e, None),
        };
        let (user, key) = match self.identities.passkey(credential) {
            Ok(Some(found)) => found,
            Ok(None) => return fail(PasskeyError::UnknownCredential, None),
            Err(_) => return failed(FailureReason::Unavailable),
        };
        if let Err(e) =
            passkey::verify_signature(&key, authenticator_data, client_data_json, signature)
        {
            return fail(e, Some(user));
        }
        match self.sessions.use_once(opened.once_key, opened.expires, now) {
            Ok(true) => {}
            Ok(false) => return fail(PasskeyError::Challenge, Some(user)),
            Err(_) => return failed(FailureReason::Unavailable),
        }
        match self
            .identities
            .advance_sign_count(credential, data.sign_count)
        {
            Ok(true) => {}
            Ok(false) => return fail(PasskeyError::CounterRegressed, Some(user)),
            Err(_) => return failed(FailureReason::Unavailable),
        }
        // Without user verification a passkey is one factor (possession):
        // it signs in, but proves no second factor for step-up rules.
        let verified_user = data.flags & crate::webauthn::FLAG_UV != 0;
        match self.identities.account(user) {
            Ok(Some(a)) if !blocked(&a, now) => {
                let _ = self.identities.clear_failures(user);
                SignIn::Verified(Verified {
                    user,
                    factor_at: verified_user.then_some(now),
                })
            }
            Ok(_) => {
                self.report(SignalKind::SignInBlocked, 90, p, Some(user), None, now);
                failed(FailureReason::Banned)
            }
            Err(_) => failed(FailureReason::Unavailable),
        }
    }

    /// Drop expired sessions and spent challenges. Call from a timer.
    pub fn purge(&self) -> usize {
        self.sessions.purge(self.clock.now())
    }
}

/// Where a counted sign-in attempt stands against the lockout threshold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// Below the threshold.
    Within,
    /// The last attempt allowed: a wrong one locks the account.
    Last,
    /// Past the threshold: refused without being checked.
    OverLimit,
}

/// Whether `account` may not sign in at `now`: its standing refuses it, or
/// it is locked after failed sign-ins.
fn blocked(account: &Account, now: UnixTime) -> bool {
    account.standing.blocks_sign_in(now) || account.locked_until.is_some_and(|t| now < t)
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}
