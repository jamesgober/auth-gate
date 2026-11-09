//! Account standing, with time limits.

use crate::{id::UserId, time::UnixTime};

/// Who changed a standing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Actor {
    /// The gate itself (an automatic lock after failed sign-ins).
    System,
    /// An administrator's account.
    Admin(UserId),
}

/// Why a standing was set: short text for administrators and audit (at most
/// 200 bytes; longer text is cut at a character boundary). Never shown to
/// the subject.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Reason(Box<str>);

/// The longest reason kept, in bytes.
pub const MAX_REASON_LEN: usize = 200;

impl Reason {
    /// A reason with this text.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut end = text.len().min(MAX_REASON_LEN);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(text[..end].into())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who did it, when, and why: kept on every administrative standing.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Decision {
    /// Why.
    pub reason: Reason,
    /// By whom.
    pub by: Actor,
    /// When.
    pub at: UnixTime,
}

impl Decision {
    /// A decision by `by` at `at` for `reason`.
    #[must_use]
    pub fn new(reason: &str, by: Actor, at: UnixTime) -> Self {
        Self {
            reason: Reason::new(reason),
            by,
            at,
        }
    }
}

/// An account's standing. Timed standings lift by themselves: the first
/// request after `until` re-reads the record and finds the account active
/// again. A permanent ban changes only by an explicit administrative act.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Standing {
    /// In good standing.
    Active,
    /// Signed up, not verified yet.
    PendingVerification,
    /// Locked automatically after failed sign-ins, until a time. Sessions
    /// already signed in keep working: an attacker guessing passwords must
    /// not sign the real user out.
    Locked {
        /// When the lock lifts.
        until: UnixTime,
    },
    /// Suspended until a time: still signed in, and route rules decide what
    /// a suspended account may do.
    Suspended {
        /// When the suspension lifts.
        until: UnixTime,
        /// Who, when, why.
        decision: Decision,
    },
    /// Banned until a time: refused at the gate, every session ended.
    Banned {
        /// When the ban lifts.
        until: UnixTime,
        /// Who, when, why.
        decision: Decision,
    },
    /// Banned with no end.
    BannedPermanent {
        /// Who, when, why.
        decision: Decision,
    },
}

/// The kind of a standing, without its details: what a session record
/// carries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum StandingClass {
    /// In good standing.
    #[default]
    Active,
    /// Not verified yet.
    PendingVerification,
    /// Locked after failed sign-ins.
    Locked,
    /// Suspended.
    Suspended,
    /// Banned, timed or permanent.
    Banned,
}

/// A standing as a session carries it: the class and when it lifts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct StandingSnapshot {
    /// The class.
    pub class: StandingClass,
    /// When it lifts by itself (`None`: never, or nothing to lift).
    pub until: Option<UnixTime>,
}

impl Standing {
    /// When this standing changes by itself. `None` for active, pending,
    /// and a permanent ban.
    #[must_use]
    pub fn expires(&self) -> Option<UnixTime> {
        match self {
            Self::Locked { until } | Self::Suspended { until, .. } | Self::Banned { until, .. } => {
                Some(*until)
            }
            _ => None,
        }
    }

    /// The standing in effect at `now`: a timed standing whose `until` has
    /// passed reads as [`Standing::Active`].
    #[must_use]
    pub fn at(&self, now: UnixTime) -> &Self {
        const ACTIVE: &Standing = &Standing::Active;
        match self.expires() {
            Some(until) if now >= until => ACTIVE,
            _ => self,
        }
    }

    /// The class.
    #[must_use]
    pub fn class(&self) -> StandingClass {
        match self {
            Self::Active => StandingClass::Active,
            Self::PendingVerification => StandingClass::PendingVerification,
            Self::Locked { .. } => StandingClass::Locked,
            Self::Suspended { .. } => StandingClass::Suspended,
            Self::Banned { .. } | Self::BannedPermanent { .. } => StandingClass::Banned,
        }
    }

    /// The snapshot a session stores, as in effect at `now`.
    #[must_use]
    pub fn snapshot(&self, now: UnixTime) -> StandingSnapshot {
        let s = self.at(now);
        StandingSnapshot {
            class: s.class(),
            until: s.expires(),
        }
    }

    /// Whether this standing, in effect at `now`, refuses a new sign-in.
    #[must_use]
    pub fn blocks_sign_in(&self, now: UnixTime) -> bool {
        matches!(
            self.at(now),
            Self::Locked { .. } | Self::Banned { .. } | Self::BannedPermanent { .. }
        )
    }

    /// Whether this standing, in effect at `now`, ends existing sessions.
    #[must_use]
    pub fn ends_sessions(&self, now: UnixTime) -> bool {
        matches!(
            self.at(now),
            Self::Banned { .. } | Self::BannedPermanent { .. }
        )
    }
}
