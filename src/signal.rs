//! Security signals: what the gate saw, reported to the security bridge.
//!
//! The gate never isolates what it sees. Every suspicious event becomes a
//! [`Signal`] delivered to a [`SignalSink`]: the bridge that carries it to
//! the scoring module, the connection gate (which can slow or ban a
//! source), audit, and any other security object listening. The gate only
//! detects and reports; thresholds and enforcement belong to the policy on
//! the other side of the bridge.

use core::net::IpAddr;
use std::sync::Mutex;

use crate::{
    id::{SessionId, UserId},
    time::UnixTime,
};

/// The generator id the gate reports under (platform range, below 1000).
pub const GENERATOR: u16 = 20;

/// Signal categories (a subset of the shared catalog).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Category {
    /// Authentication: tokens, sign-ins, factors.
    Auth,
    /// Abuse: guessing at volume.
    Abuse,
    /// Policy: standings, administrative acts.
    Policy,
}

/// What was seen. Each kind has a stable numeric id, a readable path, a
/// category, a base severity (0 to 10), and the score points it adds to the
/// subject in the scoring module.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum SignalKind {
    /// Wrong length, alphabet, version, or an unknown key id.
    MalformedToken,
    /// A current key id with a bad signature: a forgery attempt.
    ForgedToken,
    /// Correctly signed by a retired key: an old rotation.
    RetiredKeyToken,
    /// Well formed and signed, but no such session (an old tab, or a
    /// restart of a memory-only store).
    UnknownSession,
    /// The session's idle or absolute limit passed.
    ExpiredSession,
    /// A token of a signed-out session from the same client: a stale tab.
    StaleToken,
    /// A token of a signed-out session from a different network or
    /// browser: a stolen cookie replayed.
    ReplayedToken,
    /// The client's network or browser changed mid-session.
    ClientChanged,
    /// A wrong password.
    SignInFailed,
    /// A sign-in for an account that does not exist.
    SignInUnknown,
    /// A sign-in for a locked or banned account.
    SignInBlocked,
    /// An account was locked after repeated failures.
    AccountLocked,
    /// A wrong second-factor code.
    FactorFailed,
    /// A second-factor code or challenge used twice.
    FactorReplayed,
    /// A passkey ceremony refused.
    PasskeyFailed,
    /// A passkey's signature counter went backwards (a cloned key).
    PasskeyCloned,
    /// A request presented the session of a banned account.
    BannedSession,
    /// Authorization refused a request (many across object ids look like
    /// enumeration).
    AccessDenied,
    /// A state-changing request failed its CSRF check.
    CsrfRejected,
}

impl SignalKind {
    /// The stable id within [`GENERATOR`].
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::MalformedToken => 1001,
            Self::ForgedToken => 1002,
            Self::RetiredKeyToken => 1003,
            Self::UnknownSession => 1004,
            Self::ExpiredSession => 1005,
            Self::StaleToken => 1006,
            Self::ReplayedToken => 1007,
            Self::ClientChanged => 1008,
            Self::SignInFailed => 1101,
            Self::SignInUnknown => 1102,
            Self::SignInBlocked => 1103,
            Self::AccountLocked => 1104,
            Self::FactorFailed => 1201,
            Self::FactorReplayed => 1202,
            Self::PasskeyFailed => 1203,
            Self::PasskeyCloned => 1204,
            Self::BannedSession => 1301,
            Self::AccessDenied => 1401,
            Self::CsrfRejected => 1402,
        }
    }

    /// The readable path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::MalformedToken => "auth.token.malformed",
            Self::ForgedToken => "auth.token.forged",
            Self::RetiredKeyToken => "auth.token.retired_key",
            Self::UnknownSession => "auth.session.unknown",
            Self::ExpiredSession => "auth.session.expired",
            Self::StaleToken => "auth.session.stale",
            Self::ReplayedToken => "auth.session.replay",
            Self::ClientChanged => "auth.session.client_changed",
            Self::SignInFailed => "auth.signin.failed",
            Self::SignInUnknown => "auth.signin.unknown_account",
            Self::SignInBlocked => "auth.signin.blocked",
            Self::AccountLocked => "auth.account.locked",
            Self::FactorFailed => "auth.factor.failed",
            Self::FactorReplayed => "auth.factor.replay",
            Self::PasskeyFailed => "auth.passkey.failed",
            Self::PasskeyCloned => "auth.passkey.cloned",
            Self::BannedSession => "auth.session.banned",
            Self::AccessDenied => "access.denied",
            Self::CsrfRejected => "access.csrf.rejected",
        }
    }

    /// The category.
    #[must_use]
    pub const fn category(self) -> Category {
        match self {
            Self::SignInFailed | Self::SignInUnknown | Self::FactorFailed => Category::Abuse,
            Self::AccountLocked
            | Self::BannedSession
            | Self::SignInBlocked
            | Self::AccessDenied => Category::Policy,
            _ => Category::Auth,
        }
    }

    /// Score points added to the subject (source, session, account) in the
    /// scoring module. Proposed thresholds there: 20 watch, 50 slow, 100 ban.
    #[must_use]
    pub const fn score(self) -> u16 {
        match self {
            Self::UnknownSession | Self::ExpiredSession | Self::RetiredKeyToken => 1,
            Self::AccessDenied => 2,
            Self::StaleToken | Self::SignInFailed | Self::SignInUnknown => 3,
            Self::FactorFailed | Self::SignInBlocked | Self::PasskeyFailed => 5,
            Self::MalformedToken | Self::AccountLocked | Self::CsrfRejected => 10,
            Self::ClientChanged | Self::FactorReplayed => 15,
            Self::ReplayedToken | Self::BannedSession => 30,
            Self::ForgedToken | Self::PasskeyCloned => 40,
        }
    }

    /// Base severity, 0 to 10 in tenths (35 = 3.5): how bad it is if true.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::UnknownSession | Self::ExpiredSession | Self::RetiredKeyToken => 10,
            Self::AccessDenied => 15,
            Self::StaleToken | Self::SignInFailed | Self::SignInUnknown => 20,
            Self::FactorFailed | Self::SignInBlocked | Self::PasskeyFailed => 35,
            Self::MalformedToken | Self::AccountLocked | Self::CsrfRejected => 40,
            Self::ClientChanged | Self::FactorReplayed => 55,
            Self::ReplayedToken | Self::BannedSession => 75,
            Self::ForgedToken | Self::PasskeyCloned => 85,
        }
    }
}

/// One detection: what, about whom, when. Fixed size; carries no secret
/// (never a token, a password, or a code).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signal {
    /// What was seen.
    pub kind: SignalKind,
    /// How sure the gate is, 0 to 100 (STIX scale).
    pub confidence: u8,
    /// The client address, when known.
    pub source: Option<IpAddr>,
    /// The account, when known.
    pub user: Option<UserId>,
    /// The session, when known.
    pub session: Option<SessionId>,
    /// When.
    pub at: UnixTime,
}

/// Where the gate reports signals: the security bridge. Called on the
/// request path, so implementations hand the signal on (a ring, a channel)
/// and return; scoring runs elsewhere.
pub trait SignalSink: Send + Sync {
    /// Take one signal.
    fn signal(&self, signal: &Signal);
}

/// Drops every signal. Only for tools and tests that do not care; a
/// deployed gate always reports to a bridge.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSignals;

impl SignalSink for NoSignals {
    fn signal(&self, _: &Signal) {}
}

/// Keeps the last signals in memory (bounded), for tests and local
/// development.
#[derive(Debug)]
pub struct MemorySignals {
    cap: usize,
    log: Mutex<std::collections::VecDeque<Signal>>,
}

impl Default for MemorySignals {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl MemorySignals {
    /// Keep at most `cap` signals; the oldest go first.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            log: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// A copy of what is kept, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Signal> {
        self.log
            .lock()
            .map(|l| l.iter().copied().collect())
            .unwrap_or_default()
    }

    /// The kinds kept, oldest first.
    #[must_use]
    pub fn kinds(&self) -> Vec<SignalKind> {
        self.snapshot().into_iter().map(|s| s.kind).collect()
    }

    /// Forget everything.
    pub fn clear(&self) {
        if let Ok(mut l) = self.log.lock() {
            l.clear();
        }
    }
}

impl SignalSink for MemorySignals {
    fn signal(&self, signal: &Signal) {
        if let Ok(mut l) = self.log.lock() {
            if l.len() == self.cap {
                l.pop_front();
            }
            l.push_back(*signal);
        }
    }
}

/// Sends every signal to each of several sinks (scoring, the connection
/// gate, audit) in order.
#[derive(Default)]
pub struct Fanout(Vec<std::sync::Arc<dyn SignalSink>>);

impl Fanout {
    /// No sinks yet.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Also send to `sink`.
    #[must_use]
    pub fn to(mut self, sink: std::sync::Arc<dyn SignalSink>) -> Self {
        self.0.push(sink);
        self
    }
}

impl SignalSink for Fanout {
    fn signal(&self, signal: &Signal) {
        for s in &self.0 {
            s.signal(signal);
        }
    }
}

impl core::fmt::Debug for Fanout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fanout({} sinks)", self.0.len())
    }
}
