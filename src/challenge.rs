//! Signed, stateless challenges: the pending second factor after a correct
//! password, and WebAuthn challenges. Any node holding the keys can check
//! one; single use comes from [`SessionStore::use_once`](crate::SessionStore::use_once).
//!
//! ```text
//! purpose (1) | expires, Unix ms (8) | user (16) | nonce (16) | tag (16)
//! tag = keyed BLAKE3(challenge key, the first 41 bytes)[..16]
//! ```

use core::fmt;

use crypt_io::mac;

use crate::{codec, error::AuthError, id::UserId, keys::GateKeys, rand, time::UnixTime};

pub(crate) const RAW_LEN: usize = 57;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum Purpose {
    SecondFactor = 1,
    PasskeyRegister = 2,
    PasskeySignIn = 3,
}

/// A challenge to carry through a page: the pending second factor after a
/// correct password, or a WebAuthn challenge. It proves nothing by itself
/// and works once.
#[derive(Clone, PartialEq, Eq)]
pub struct Challenge([u8; RAW_LEN]);

impl Challenge {
    /// The raw bytes (WebAuthn's `challenge`, before base64url).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The base64url text, for a hidden form field.
    #[must_use]
    pub fn to_text(&self) -> String {
        codec::b64_encode(&self.0)
    }

    /// When it stops working.
    #[must_use]
    pub fn expires(&self) -> UnixTime {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.0[1..9]);
        UnixTime::from_millis(u64::from_be_bytes(b))
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge(..)")
    }
}

fn tag(keys: &GateKeys, head: &[u8]) -> [u8; 16] {
    let full = mac::blake3_keyed(&keys.challenge, head);
    let mut t = [0u8; 16];
    t.copy_from_slice(&full[..16]);
    t
}

pub(crate) fn issue(
    keys: &GateKeys,
    purpose: Purpose,
    user: Option<UserId>,
    expires: UnixTime,
) -> Result<Challenge, AuthError> {
    let mut raw = [0u8; RAW_LEN];
    raw[0] = purpose as u8;
    raw[1..9].copy_from_slice(&expires.as_millis().to_be_bytes());
    raw[9..25].copy_from_slice(&user.map_or([0; 16], UserId::to_bytes));
    rand::fill(&mut raw[25..41])?;
    let t = tag(keys, &raw[..41]);
    raw[41..].copy_from_slice(&t);
    Ok(Challenge(raw))
}

/// A checked challenge: who it was for, and the key that marks it used.
pub(crate) struct Opened {
    pub(crate) user: Option<UserId>,
    pub(crate) expires: UnixTime,
    pub(crate) once_key: [u8; 32],
}

/// Check signature, purpose, and expiry. Single use is the caller's next
/// step (`use_once` with `once_key`).
pub(crate) fn open(keys: &GateKeys, raw: &[u8], purpose: Purpose, now: UnixTime) -> Option<Opened> {
    if raw.len() != RAW_LEN || raw[0] != purpose as u8 {
        return None;
    }
    let want = tag(keys, &raw[..41]);
    let mut diff = 0u8;
    for (a, b) in want.iter().zip(&raw[41..]) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut e = [0u8; 8];
    e.copy_from_slice(&raw[1..9]);
    let expires = UnixTime::from_millis(u64::from_be_bytes(e));
    if now >= expires {
        return None;
    }
    let mut u = [0u8; 16];
    u.copy_from_slice(&raw[9..25]);
    let user = (u != [0; 16]).then(|| UserId::from_u128(u128::from_be_bytes(u)));
    Some(Opened {
        user,
        expires,
        once_key: mac::blake3_keyed(&keys.challenge, &raw[25..41]),
    })
}

/// Decode a challenge's text form.
pub(crate) fn from_text(text: &str) -> Option<[u8; RAW_LEN]> {
    let mut raw = [0u8; RAW_LEN];
    codec::b64_decode_into(text.as_bytes(), &mut raw)?;
    Some(raw)
}
