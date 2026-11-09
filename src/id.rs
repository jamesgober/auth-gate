//! Account, session, and passkey identifiers.

use core::fmt;

use crate::error::AuthError;

/// An account id: 128 bits, opaque, never the database's row number.
///
/// New ids are UUIDv7 (time-ordered, from id-forge), so they sort by
/// creation time in any store.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(u128);

impl UserId {
    /// A new time-ordered id.
    #[must_use]
    pub fn generate() -> Self {
        Self(u128::from_be_bytes(*id_forge::uuid::Uuid::v7().as_bytes()))
    }

    /// From the raw 128 bits.
    #[must_use]
    pub const fn from_u128(raw: u128) -> Self {
        Self(raw)
    }

    /// The raw 128 bits.
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// The 16 big-endian bytes (a UUID's byte order).
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({:032x})", self.0)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// A session's public id: 16 random bytes, unrelated to the token.
///
/// Safe to show (a devices page, logs, audit) and to bind CSRF tokens to:
/// knowing it does not help anyone present the session.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// A new random id.
    ///
    /// # Errors
    ///
    /// [`AuthError::Random`] if the OS random source fails.
    pub fn generate() -> Result<Self, AuthError> {
        let mut b = [0u8; 16];
        crate::rand::fill(&mut b)?;
        Ok(Self(b))
    }

    /// From raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        f.write_str("..)")
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// What a person signs in with: an email address or a user name.
///
/// Trimmed of surrounding whitespace and ASCII-lowercased, so `Alice@Example.com `
/// and `alice@example.com` find the same account. At most 254 bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier(Box<str>);

/// The longest identifier, in bytes (the longest email address).
pub const MAX_IDENTIFIER_LEN: usize = 254;

impl Identifier {
    /// Normalize `raw`.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInput`] when it is empty after trimming, longer
    /// than 254 bytes, or holds a control character.
    pub fn new(raw: &str) -> Result<Self, AuthError> {
        let t = raw.trim();
        if t.is_empty() || t.len() > MAX_IDENTIFIER_LEN || t.chars().any(char::is_control) {
            return Err(AuthError::InvalidInput("identifier"));
        }
        Ok(Self(t.to_ascii_lowercase().into_boxed_str()))
    }

    /// The normalized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identifier({} bytes)", self.0.len())
    }
}
