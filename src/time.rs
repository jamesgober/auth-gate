//! Wall-clock time in Unix milliseconds, and clocks.

use core::{ops::Add, time::Duration};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// A UTC instant in milliseconds since the Unix epoch.
///
/// Expiry times, standing limits (`until`), and audit times are all
/// `UnixTime`. Nodes must keep their clocks synchronized; a skew of seconds
/// only shifts a lift or an expiry by seconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The epoch.
    pub const EPOCH: Self = Self(0);
    /// The last representable instant; used for "never".
    pub const MAX: Self = Self(u64::MAX);

    /// From milliseconds since the epoch.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// From seconds since the epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1000))
    }

    /// Milliseconds since the epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Whole seconds since the epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    /// The system clock now.
    #[must_use]
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self(ms)
    }

    /// `self + d`, saturating.
    #[must_use]
    pub fn plus(self, d: Duration) -> Self {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(ms))
    }

    /// Milliseconds from `earlier` to `self` (0 if `earlier` is later).
    #[must_use]
    pub const fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for UnixTime {
    type Output = Self;
    fn add(self, d: Duration) -> Self {
        self.plus(d)
    }
}

/// A source of the current time. The gate reads it once per call.
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> UnixTime;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTime {
        UnixTime::now()
    }
}

/// A clock that only moves when told to, for tests and replays.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock showing `at`.
    #[must_use]
    pub const fn new(at: UnixTime) -> Self {
        Self(AtomicU64::new(at.0))
    }

    /// Move to `at`.
    pub fn set(&self, at: UnixTime) {
        self.0.store(at.0, Ordering::SeqCst);
    }

    /// Move forward by `d`.
    pub fn advance(&self, d: Duration) {
        let now = UnixTime(self.0.load(Ordering::SeqCst));
        self.set(now + d);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> UnixTime {
        UnixTime(self.0.load(Ordering::SeqCst))
    }
}
