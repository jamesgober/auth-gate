//! Password hashing: Argon2id through crypt-io, with a pepper.

use core::fmt;

use crypt_io::{
    Zeroizing,
    kdf::{self, Argon2Params, Argon2Policy},
    mac,
};

use crate::{error::AuthError, rand};

/// The longest password accepted, in bytes. Bounds the work one sign-in can
/// cause; longer input is refused before any hashing.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// A stored password hash: an Argon2id PHC string (parameters and salt
/// included, so they can be raised later). `Debug` prints only its length.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(Box<str>);

impl PasswordHash {
    /// A hash read back from a store.
    #[must_use]
    pub fn from_phc(phc: &str) -> Self {
        Self(phc.into())
    }

    /// The PHC string, for a store to save.
    #[must_use]
    pub fn as_phc(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PasswordHash({} bytes)", self.0.len())
    }
}

/// What a password must be, and how it is hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordPolicy {
    min_len: usize,
    params: Argon2Params,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPolicy {
    /// At least 8 bytes; crypt-io's default Argon2id parameters (an OWASP
    /// configuration).
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_len: 8,
            params: Argon2Params::default(),
        }
    }

    /// Small Argon2id parameters for tests only: fast, and far too weak for
    /// real passwords.
    #[must_use]
    pub const fn insecure_for_tests() -> Self {
        Self {
            min_len: 8,
            params: Argon2Params::new(64, 1, 1, 32),
        }
    }

    /// Require at least `min` bytes.
    #[must_use]
    pub const fn min_len(mut self, min: usize) -> Self {
        self.min_len = min;
        self
    }

    /// Hash with these Argon2id parameters.
    #[must_use]
    pub const fn params(mut self, params: Argon2Params) -> Self {
        self.params = params;
        self
    }

    /// The Argon2id parameters.
    #[must_use]
    pub const fn argon2(&self) -> Argon2Params {
        self.params
    }
}

/// Hashes and checks passwords. The pepper (a secret derived from the gate's
/// master key, never stored with the hashes) is applied with keyed BLAKE3
/// before Argon2id, so a stolen table alone cannot be attacked offline.
pub(crate) struct Hasher {
    policy: PasswordPolicy,
    pepper: Zeroizing<[u8; 32]>,
    dummy: PasswordHash,
}

impl Hasher {
    pub(crate) fn new(policy: PasswordPolicy, pepper: [u8; 32]) -> Result<Self, AuthError> {
        let mut h = Self {
            policy,
            pepper: Zeroizing::new(pepper),
            dummy: PasswordHash(Box::from("")),
        };
        let filler: [u8; 32] = rand::bytes()?;
        h.dummy = h.hash_unchecked(&filler)?;
        Ok(h)
    }

    fn peppered(&self, password: &[u8]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(mac::blake3_keyed(&self.pepper, password))
    }

    fn hash_unchecked(&self, password: &[u8]) -> Result<PasswordHash, AuthError> {
        let p = self.peppered(password);
        let phc =
            kdf::argon2_hash_with_params(&*p, self.policy.params).map_err(|_| AuthError::Crypto)?;
        Ok(PasswordHash(phc.into_boxed_str()))
    }

    /// Hash a new password.
    pub(crate) fn hash(&self, password: &str) -> Result<PasswordHash, AuthError> {
        let len = password.len();
        if len < self.policy.min_len || len > MAX_PASSWORD_LEN {
            return Err(AuthError::InvalidInput("password length"));
        }
        self.hash_unchecked(password.as_bytes())
    }

    /// Whether `password` matches `hash`. A hash that does not parse, or
    /// whose costs are outside the policy, is a mismatch.
    pub(crate) fn check(&self, hash: &PasswordHash, password: &[u8]) -> bool {
        if password.len() > MAX_PASSWORD_LEN {
            // Spend the same work as a real check, then refuse.
            let _ = self.dummy_check();
            return false;
        }
        let p = self.peppered(password);
        kdf::argon2_check_with_policy(&hash.0, &*p, &Argon2Policy::new()).is_ok()
    }

    /// The same work as a check, for an account that does not exist, so
    /// timing does not tell whether it does.
    pub(crate) fn dummy_check(&self) -> bool {
        let p = self.peppered(b"no such account");
        let _ = kdf::argon2_check(&self.dummy.0, &*p);
        false
    }

    /// Whether `hash` was made with weaker parameters than the policy's now.
    pub(crate) fn needs_rehash(&self, hash: &PasswordHash) -> bool {
        let want = self.policy.params;
        match phc_costs(&hash.0) {
            Some((m, t, p)) => m < want.m_cost || t < want.t_cost || p != want.p_cost,
            None => true,
        }
    }
}

/// `m`, `t`, `p` from `$argon2id$v=19$m=..,t=..,p=..$salt$hash`.
fn phc_costs(phc: &str) -> Option<(u32, u32, u32)> {
    let params = phc.split('$').nth(3)?;
    let (mut m, mut t, mut p) = (None, None, None);
    for kv in params.split(',') {
        let (k, v) = kv.split_once('=')?;
        let v: u32 = v.parse().ok()?;
        match k {
            "m" => m = Some(v),
            "t" => t = Some(v),
            "p" => p = Some(v),
            _ => return None,
        }
    }
    Some((m?, t?, p?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_check() {
        let h = Hasher::new(PasswordPolicy::insecure_for_tests(), [3; 32]).unwrap();
        let hash = h.hash("correct horse").unwrap();
        assert!(h.check(&hash, b"correct horse"));
        assert!(!h.check(&hash, b"correct horsf"));
        assert!(!h.check(&PasswordHash::from_phc("garbage"), b"correct horse"));
        assert!(h.hash("short").is_err());
        assert!(!h.check(&hash, &[b'a'; MAX_PASSWORD_LEN + 1]));
        assert!(!h.needs_rehash(&hash));
        let stronger = Hasher::new(
            PasswordPolicy::insecure_for_tests().params(Argon2Params::new(128, 1, 1, 32)),
            [3; 32],
        )
        .unwrap();
        assert!(stronger.needs_rehash(&hash));
        assert!(
            stronger.check(&hash, b"correct horse"),
            "old hashes still verify"
        );
    }

    #[test]
    fn pepper_matters() {
        let a = Hasher::new(PasswordPolicy::insecure_for_tests(), [1; 32]).unwrap();
        let b = Hasher::new(PasswordPolicy::insecure_for_tests(), [2; 32]).unwrap();
        let hash = a.hash("correct horse").unwrap();
        assert!(!b.check(&hash, b"correct horse"));
    }

    #[test]
    fn phc_parse() {
        assert_eq!(
            phc_costs("$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA"),
            Some((64, 1, 1))
        );
        assert_eq!(phc_costs("$argon2id$v=19$m=64,t=1$c2FsdA$aGFzaA"), None);
        assert_eq!(phc_costs("nope"), None);
    }
}
