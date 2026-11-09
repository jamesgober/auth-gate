//! One-time codes: TOTP (RFC 6238), HOTP (RFC 4226), and recovery codes,
//! through crypt-io's `otp` feature.

use core::fmt;

use crypt_io::{Zeroizing, mac, otp};

use crate::{codec, error::AuthError, keys::GateKeys, rand, time::UnixTime};

/// TOTP code length.
pub const TOTP_DIGITS: u32 = 6;
/// Time steps accepted either side of now (30 seconds of drift each way).
pub const TOTP_WINDOW: u32 = 1;
/// Bytes of a new TOTP secret (160 bits, what authenticator apps expect).
pub const TOTP_SECRET_LEN: usize = 20;
/// How many recovery codes an account gets.
pub const RECOVERY_CODES: usize = 10;

/// A TOTP or HOTP shared secret. Wiped on drop; `Debug` never prints it.
#[derive(Clone)]
pub struct TotpSecret(Zeroizing<Vec<u8>>);

impl TotpSecret {
    /// A new random secret.
    ///
    /// # Errors
    ///
    /// [`AuthError::Random`].
    pub fn generate() -> Result<Self, AuthError> {
        let b: [u8; TOTP_SECRET_LEN] = rand::bytes()?;
        Ok(Self(Zeroizing::new(b.to_vec())))
    }

    /// A secret read back from a store.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInput`] under 16 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() < otp::OTP_MIN_SECRET_LEN || bytes.len() > 64 {
            return Err(AuthError::InvalidInput("OTP secret length"));
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// The bytes, for a store to seal and save.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The secret in base32, as typed into an authenticator app by hand.
    #[must_use]
    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(codec::b32_encode(&self.0))
    }

    /// The `otpauth://` URI for a QR code. `issuer` and `account` are
    /// percent-encoded.
    #[must_use]
    pub fn uri(&self, issuer: &str, account: &str) -> Zeroizing<String> {
        let issuer = pct(issuer);
        let account = pct(account);
        let secret = self.to_base32();
        Zeroizing::new(format!(
            "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period=30",
            secret.as_str()
        ))
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(..)")
    }
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Check a TOTP code at `now`; returns the time step it matched (store it
/// as the replay guard).
pub(crate) fn totp_check(secret: &TotpSecret, code: &str, now: UnixTime) -> Option<u64> {
    otp::totp_check(&secret.0, code, now.as_secs(), TOTP_DIGITS, TOTP_WINDOW).ok()
}

/// Check an HOTP `code` against `counter`, looking ahead up to
/// `look_ahead` counters. Returns the counter that matched: store
/// `matched + 1` as the next counter.
///
/// ```
/// use auth_gate::{hotp_check, TotpSecret};
///
/// // RFC 4226 appendix D.
/// let secret = TotpSecret::from_bytes(b"12345678901234567890")?;
/// assert_eq!(hotp_check(&secret, "755224", 0, 0), Some(0));
/// assert_eq!(hotp_check(&secret, "359152", 0, 3), Some(2));
/// assert_eq!(hotp_check(&secret, "359152", 0, 1), None);
/// # Ok::<(), auth_gate::AuthError>(())
/// ```
#[must_use]
pub fn hotp_check(secret: &TotpSecret, code: &str, counter: u64, look_ahead: u32) -> Option<u64> {
    otp::hotp_check(&secret.0, code, counter, TOTP_DIGITS, look_ahead).ok()
}

/// The current TOTP code for `secret` (for tests and enrolment screens).
///
/// # Errors
///
/// [`AuthError::Crypto`] for an unusable secret.
pub fn totp_now(secret: &TotpSecret, now: UnixTime) -> Result<String, AuthError> {
    let code = otp::totp(&secret.0, now.as_secs(), TOTP_DIGITS).map_err(|_| AuthError::Crypto)?;
    Ok(format!("{code:06}"))
}

/// The stored form of a recovery code: a keyed digest, never the code.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryDigest([u8; 32]);

impl RecoveryDigest {
    /// From raw bytes (for store adapters).
    #[must_use]
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RecoveryDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryDigest(..)")
    }
}

const RECOVERY_ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz23456789-";

/// A recovery code as text: 12 characters in groups of four
/// (`abcd-efgh-jkmn`), about 57 bits from the OS random source.
pub(crate) fn new_recovery_code() -> Result<Zeroizing<String>, AuthError> {
    let mut s = Zeroizing::new(String::with_capacity(14));
    let mut drawn = 0usize;
    while drawn < 12 {
        let raw: Zeroizing<[u8; 32]> = Zeroizing::new(rand::bytes()?);
        // Rejection sampling over 31 letters and digits (248 = 31 * 8), so
        // every symbol is equally likely; the dash is never drawn.
        for b in raw.iter().copied().filter(|b| *b < 248) {
            if drawn == 12 {
                break;
            }
            if drawn > 0 && drawn % 4 == 0 {
                s.push('-');
            }
            s.push(char::from(RECOVERY_ALPHABET[usize::from(b % 31)]));
            drawn += 1;
        }
    }
    Ok(s)
}

/// Normalize what a user typed (case, spaces, dashes) and digest it.
pub(crate) fn recovery_digest(keys: &GateKeys, typed: &str) -> Option<RecoveryDigest> {
    let mut norm = Zeroizing::new(String::with_capacity(12));
    for c in typed.chars() {
        match c {
            '-' | ' ' => {}
            c if c.is_ascii_alphanumeric() => norm.push(c.to_ascii_lowercase()),
            _ => return None,
        }
    }
    if norm.len() != 12 {
        return None;
    }
    Some(RecoveryDigest(mac::blake3_keyed(
        &keys.recovery,
        norm.as_bytes(),
    )))
}

/// Whether `code` looks like a recovery code rather than a TOTP code.
pub(crate) fn is_recovery_shape(code: &str) -> bool {
    code.len() > TOTP_DIGITS as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = TotpSecret::from_bytes(b"12345678901234567890").unwrap();
        // RFC 6238 appendix B, truncated to 6 digits.
        for (t, code) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(totp_now(&secret, UnixTime::from_secs(t)).unwrap(), code);
            assert!(totp_check(&secret, code, UnixTime::from_secs(t)).is_some());
        }
        assert!(totp_check(&secret, "287082", UnixTime::from_secs(59 + 90)).is_none());
    }

    #[test]
    fn recovery_codes() {
        let keys = GateKeys::derive(&[9; 32]).unwrap();
        let code = new_recovery_code().unwrap();
        assert_eq!(code.len(), 14);
        let d = recovery_digest(&keys, &code).unwrap();
        assert_eq!(
            recovery_digest(&keys, &code.to_uppercase().replace('-', " ")),
            Some(d)
        );
        assert_eq!(recovery_digest(&keys, "short"), None);
        assert!(is_recovery_shape(&code));
        assert!(!is_recovery_shape("123456"));
    }

    #[test]
    fn uri() {
        let s = TotpSecret::from_bytes(b"12345678901234567890").unwrap();
        let uri = s.uri("Example Site", "alice@example.com");
        assert_eq!(
            uri.as_str(),
            "otpauth://totp/Example%20Site:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20Site&algorithm=SHA1&digits=6&period=30"
        );
    }
}
