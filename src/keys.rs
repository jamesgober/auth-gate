//! The gate's own secrets, derived from one master secret.

use core::fmt;

use crypt_io::Zeroizing;

use crate::error::AuthError;

/// The shortest master secret accepted, in bytes.
pub const MIN_MASTER_LEN: usize = 32;

/// How a token-signing key may be used.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KeyRole {
    /// Signs new tokens, and verifies.
    Current,
    /// Verifies tokens signed before a rotation; signs nothing.
    Accepted,
    /// Known, but no longer accepted: a token signed with it is from an old
    /// rotation (a low-severity signal, never a forgery alarm).
    Retired,
}

type Key = Zeroizing<[u8; 32]>;

/// The ring of session-token signing keys, by one-byte key id.
///
/// Tokens carry their key id, so a rotation is: add the new key as
/// current, keep the old one as accepted for the session lifetime, then
/// retire it. A token from a retired key is a key-rotation event, not an
/// attack.
pub struct TokenKeys {
    keys: Vec<(u8, KeyRole, Key)>,
}

impl TokenKeys {
    /// A ring whose current key is `key`, with id `id`.
    #[must_use]
    pub fn new(id: u8, key: [u8; 32]) -> Self {
        Self {
            keys: vec![(id, KeyRole::Current, Zeroizing::new(key))],
        }
    }

    /// Also verify tokens signed with `key` (id `id`).
    #[must_use]
    pub fn accept(mut self, id: u8, key: [u8; 32]) -> Self {
        self.put(id, KeyRole::Accepted, key);
        self
    }

    /// Recognize tokens signed with `key` (id `id`) as from a retired key.
    #[must_use]
    pub fn retire(mut self, id: u8, key: [u8; 32]) -> Self {
        self.put(id, KeyRole::Retired, key);
        self
    }

    fn put(&mut self, id: u8, role: KeyRole, key: [u8; 32]) {
        if let Some(slot) = self.keys.iter_mut().find(|(i, _, _)| *i == id) {
            if slot.1 != KeyRole::Current {
                *slot = (id, role, Zeroizing::new(key));
            }
        } else {
            self.keys.push((id, role, Zeroizing::new(key)));
        }
    }

    pub(crate) fn current(&self) -> (u8, &[u8; 32]) {
        // The constructor always puts the current key first, and `put`
        // never replaces it.
        let (id, _, key) = &self.keys[0];
        (*id, key)
    }

    pub(crate) fn find(&self, id: u8) -> Option<(KeyRole, &[u8; 32])> {
        self.keys
            .iter()
            .find(|(i, _, _)| *i == id)
            .map(|(_, role, key)| (*role, &**key))
    }
}

impl fmt::Debug for TokenKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.keys.iter().map(|(id, role, _)| (id, role)))
            .finish()
    }
}

/// Every secret the gate uses, each derived from one master secret with
/// HKDF-SHA256 (crypt-io) under its own label, so no two purposes share a
/// key.
///
/// The master secret comes from key-vault; the gate never sees the store's
/// credentials or anything else in the vault.
///
/// ```
/// use auth_gate::GateKeys;
///
/// let keys = GateKeys::derive(&[7u8; 32])?;
/// # let _ = keys;
/// # Ok::<(), auth_gate::AuthError>(())
/// ```
pub struct GateKeys {
    pub(crate) tokens: TokenKeys,
    pub(crate) digest: Key,
    pub(crate) binding: Key,
    pub(crate) challenge: Key,
    pub(crate) pepper: Key,
    pub(crate) recovery: Key,
    csrf: Key,
    factor: Key,
    audit: Key,
}

fn derive_one(master: &[u8], label: &str) -> Result<Key, AuthError> {
    let mut out = Zeroizing::new([0u8; 32]);
    crypt_io::kdf::hkdf_sha256_into(master, Some(b"auth-gate/v1"), label.as_bytes(), &mut *out)
        .map_err(|_| AuthError::Crypto)?;
    Ok(out)
}

impl GateKeys {
    /// Derive every key from `master` (at least 32 bytes of secret).
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInput`] for a short master; [`AuthError::Crypto`]
    /// if derivation fails.
    pub fn derive(master: &[u8]) -> Result<Self, AuthError> {
        if master.len() < MIN_MASTER_LEN {
            return Err(AuthError::InvalidInput(
                "master secret shorter than 32 bytes",
            ));
        }
        let token = derive_one(master, "session token mac, key id 1")?;
        Ok(Self {
            tokens: TokenKeys::new(1, *token),
            digest: derive_one(master, "session token digest")?,
            binding: derive_one(master, "client binding")?,
            challenge: derive_one(master, "second factor challenge")?,
            pepper: derive_one(master, "password pepper")?,
            recovery: derive_one(master, "recovery code digest")?,
            csrf: derive_one(master, "csrf")?,
            factor: derive_one(master, "factor secrets at rest")?,
            audit: derive_one(master, "audit chain")?,
        })
    }

    /// Replace the token-signing ring (for rotation).
    #[must_use]
    pub fn with_token_keys(mut self, ring: TokenKeys) -> Self {
        self.tokens = ring;
        self
    }

    /// The CSRF key, for the web layer's CSRF check (csrf-sec).
    #[must_use]
    pub fn csrf_key(&self) -> [u8; 32] {
        *self.csrf
    }

    /// The key that keys the audit chain's hash (derived under its own
    /// label: holding the CSRF key does not let anyone rebuild the chain).
    #[must_use]
    pub fn audit_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.audit)
    }

    /// A key for sealing second-factor secrets at rest, for store
    /// adapters that encrypt them.
    #[must_use]
    pub fn factor_key(&self) -> [u8; 32] {
        *self.factor
    }
}

impl fmt::Debug for GateKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateKeys")
            .field("tokens", &self.tokens)
            .finish_non_exhaustive()
    }
}
