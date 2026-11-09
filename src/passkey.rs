//! Passkeys (WebAuthn): registration and assertion checks, with signatures
//! verified by crypt-io (`CosePublicKey`: ES256, EdDSA, RS256).

use core::fmt;

use crypt_io::{hash, sign::CosePublicKey};

use crate::{
    time::UnixTime,
    webauthn::{self, AuthenticatorData, Ceremony, ClientData, FLAG_BE, FLAG_UP, FLAG_UV},
};

/// The site passkeys belong to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelyingParty {
    id: String,
    origin: String,
    require_uv: bool,
}

impl RelyingParty {
    /// A relying party with id `id` (a registrable domain, `example.com`)
    /// whose pages are served from `origin` (`https://example.com`).
    /// Requires user verification (a PIN or biometric) by default.
    #[must_use]
    pub fn new(id: &str, origin: &str) -> Self {
        Self {
            id: id.into(),
            origin: origin.into(),
            require_uv: true,
        }
    }

    /// Accept user presence alone (a touch, no PIN or biometric).
    #[must_use]
    pub fn presence_only(mut self) -> Self {
        self.require_uv = false;
        self
    }

    /// The relying party id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The expected origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// A registered passkey: its credential id and COSE public key, as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct Passkey {
    /// The credential id (what the browser returns as `rawId`).
    pub credential: Box<[u8]>,
    /// The COSE public key.
    pub public_key: Box<[u8]>,
    /// The last signature counter seen.
    pub sign_count: u32,
    /// Whether the authenticator may sync it to other devices.
    pub backup_eligible: bool,
    /// When it was registered.
    pub created: UnixTime,
}

impl fmt::Debug for Passkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passkey")
            .field("credential_len", &self.credential.len())
            .field("sign_count", &self.sign_count)
            .finish_non_exhaustive()
    }
}

/// Why a passkey ceremony was refused (for audit; the client gets a generic
/// failure).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PasskeyError {
    /// `clientDataJSON` or authenticator data did not parse.
    Malformed,
    /// Wrong ceremony type, origin, relying party, or a cross-origin call.
    WrongContext,
    /// The challenge was not ours, expired, or already used.
    Challenge,
    /// The user was not present, or not verified when required.
    UserNotVerified,
    /// The public key is not usable (unsupported algorithm, bad encoding).
    UnsupportedKey,
    /// The signature does not check.
    BadSignature,
    /// No passkey with that credential id.
    UnknownCredential,
    /// The signature counter went backwards: a cloned authenticator.
    CounterRegressed,
}

pub(crate) fn check_client(
    rp: &RelyingParty,
    client_data_json: &[u8],
    ceremony: Ceremony,
) -> Result<ClientData, PasskeyError> {
    let c = webauthn::parse_client_data(client_data_json).ok_or(PasskeyError::Malformed)?;
    if c.ceremony != ceremony || c.origin != rp.origin || c.cross_origin {
        return Err(PasskeyError::WrongContext);
    }
    Ok(c)
}

pub(crate) fn check_authenticator<'a>(
    rp: &RelyingParty,
    data: &'a [u8],
) -> Result<AuthenticatorData<'a>, PasskeyError> {
    let a = webauthn::parse_authenticator_data(data).ok_or(PasskeyError::Malformed)?;
    if a.rp_id_hash != hash::sha256(rp.id.as_bytes()) {
        return Err(PasskeyError::WrongContext);
    }
    if a.flags & FLAG_UP == 0 || (rp.require_uv && a.flags & FLAG_UV == 0) {
        return Err(PasskeyError::UserNotVerified);
    }
    Ok(a)
}

/// Registration: the credential and key from authenticator data (the
/// browser's `getAuthenticatorData()`), checked.
pub(crate) fn registered(
    a: &AuthenticatorData<'_>,
    now: UnixTime,
) -> Result<Passkey, PasskeyError> {
    let (id, key) = a.credential.ok_or(PasskeyError::Malformed)?;
    CosePublicKey::from_cose_key(key).map_err(|_| PasskeyError::UnsupportedKey)?;
    Ok(Passkey {
        credential: id.into(),
        public_key: key.into(),
        sign_count: a.sign_count,
        backup_eligible: a.flags & FLAG_BE != 0,
        created: now,
    })
}

/// Assertion: the signature over `authenticatorData || SHA-256(clientDataJSON)`.
pub(crate) fn verify_signature(
    passkey: &Passkey,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<(), PasskeyError> {
    let key = CosePublicKey::from_cose_key(&passkey.public_key)
        .map_err(|_| PasskeyError::UnsupportedKey)?;
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&hash::sha256(client_data_json));
    key.check(&signed, signature)
        .map_err(|_| PasskeyError::BadSignature)
}
