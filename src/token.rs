//! Session tokens: 256 random bits, signed with a key id, stored only as a
//! keyed digest.
//!
//! Wire form: base64url (no padding) of 50 bytes, 67 characters:
//!
//! ```text
//! version (1) | key id (1) | random (32) | tag (16)
//! tag = keyed BLAKE3(token key[key id], version | key id | random)[..16]
//! ```
//!
//! The signature lets the gate tell a forgery, a token from an old key, and
//! a broken client apart before it touches the session store, so garbage
//! never costs a store lookup. The client still holds no claim: the random
//! part is only a lookup key, and the session record on the server decides.

use core::fmt;

use crypt_io::{Zeroizing, mac};

use crate::{
    codec,
    error::AuthError,
    keys::{GateKeys, KeyRole},
    rand,
};

/// The token format version.
pub const TOKEN_VERSION: u8 = 1;
const RAW_LEN: usize = 50;
/// The length of a session token's text, in bytes.
pub const TOKEN_TEXT_LEN: usize = 67;

/// A session token as handed to the client. Shown once (the cookie value);
/// the server keeps only its [`TokenDigest`]. `Debug` never prints it, and
/// the text is wiped on drop.
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// The cookie value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(..)")
    }
}

/// The keyed digest of a token's random part: what stores index sessions by.
/// A leaked session table does not leak a usable token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// From raw bytes (for store adapters that read digests back).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenDigest({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// What reading a presented token found, before any store lookup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenCheck {
    /// Well formed and signed by a current or accepted key.
    Valid(TokenDigest),
    /// Wrong length, alphabet, or version: tampering or a broken client.
    Malformed,
    /// A key id the ring does not know.
    UnknownKey,
    /// Correctly signed by a retired key: an old rotation.
    RetiredKey,
    /// Signed by a current or accepted key id, but the tag is wrong: a
    /// forgery attempt.
    BadSignature,
}

fn tag(key: &[u8; 32], head: &[u8]) -> [u8; 16] {
    let full = mac::blake3_keyed(key, head);
    let mut t = [0u8; 16];
    t.copy_from_slice(&full[..16]);
    t
}

fn digest(keys: &GateKeys, random: &[u8]) -> TokenDigest {
    TokenDigest(mac::blake3_keyed(&keys.digest, random))
}

/// Issue a new token under the current key.
pub(crate) fn issue(keys: &GateKeys) -> Result<(SessionToken, TokenDigest), AuthError> {
    let (id, key) = keys.tokens.current();
    let mut raw = Zeroizing::new([0u8; RAW_LEN]);
    raw[0] = TOKEN_VERSION;
    raw[1] = id;
    rand::fill(&mut raw[2..34])?;
    let t = tag(key, &raw[..34]);
    raw[34..].copy_from_slice(&t);
    let text = Zeroizing::new(codec::b64_encode(&*raw));
    let d = digest(keys, &raw[2..34]);
    Ok((SessionToken(text), d))
}

/// Read a presented token. Constant time in the tag comparison; no
/// allocation.
#[must_use]
pub fn check(keys: &GateKeys, presented: &[u8]) -> TokenCheck {
    if presented.len() != TOKEN_TEXT_LEN {
        return TokenCheck::Malformed;
    }
    let mut raw = Zeroizing::new([0u8; RAW_LEN]);
    if codec::b64_decode_into(presented, &mut *raw).is_none() || raw[0] != TOKEN_VERSION {
        return TokenCheck::Malformed;
    }
    let Some((role, key)) = keys.tokens.find(raw[1]) else {
        return TokenCheck::UnknownKey;
    };
    if !ct_eq16(&tag(key, &raw[..34]), &raw[34..]) {
        return TokenCheck::BadSignature;
    }
    if role == KeyRole::Retired {
        return TokenCheck::RetiredKey;
    }
    TokenCheck::Valid(digest(keys, &raw[2..34]))
}

fn ct_eq16(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0 && a.len() == b.len()
}
