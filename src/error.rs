//! Errors.

use core::fmt;

/// A store could not answer. The gate fails closed on every one: a session
/// it cannot read is a guest, a sign-in it cannot check is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// The backend is unreachable or timed out.
    Unavailable,
    /// The record already exists (an identifier taken twice).
    AlreadyExists,
    /// The record does not exist.
    NotFound,
    /// A limit was reached (store capacity, identifiers per account).
    Full,
    /// The backend refused for its own reason.
    Backend(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("store unavailable"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::NotFound => f.write_str("not found"),
            Self::Full => f.write_str("store full"),
            Self::Backend(why) => write!(f, "store refused: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// An authentication call that could not complete. Never a wrong password:
/// that is an ordinary [`SignIn::Failed`](crate::SignIn::Failed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// A store failed.
    Store(StoreError),
    /// The OS random source failed.
    Random,
    /// A cryptographic primitive failed (bad parameters, never a mismatch).
    Crypto,
    /// An argument broke a documented limit.
    InvalidInput(&'static str),
    /// A session payload over the size limit.
    PayloadTooLarge,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Random => f.write_str("OS random source failed"),
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::InvalidInput(what) => write!(f, "invalid {what}"),
            Self::PayloadTooLarge => f.write_str("session payload too large"),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for AuthError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
