//! The store traits: how the gate reads and writes, whatever the database.
//!
//! The gate holds no database driver and no schema. An adapter crate maps
//! these calls to one database; [`MemorySessions`](crate::MemorySessions)
//! and [`MemoryIdentities`](crate::MemoryIdentities) implement them in
//! memory for tests and local development.

use crate::{
    error::StoreError,
    id::{Identifier, UserId},
    otp::{RecoveryDigest, TotpSecret},
    passkey::Passkey,
    password::PasswordHash,
    record::{EndReason, SessionInfo, SessionRecord, Tombstone},
    standing::Standing,
    time::UnixTime,
    token::TokenDigest,
};

/// What a session lookup found.
// Kept inline: boxing the record would allocate on every request.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Found {
    /// A live record (it may still have expired: the gate checks).
    Live(SessionRecord),
    /// The session ended; the store still remembers how.
    Ended(Tombstone),
    /// Nothing known about this digest.
    Unknown,
}

/// Where sessions live. Called on every request, so implementations keep
/// `find` in memory (a durable tier behind it is the adapter's business).
pub trait SessionStore: Send + Sync {
    /// Look up a session by its token digest.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the store cannot answer; the request becomes a guest.
    fn find(&self, digest: &TokenDigest) -> Result<Found, StoreError>;

    /// Store a new session. A store with a per-account limit ends the
    /// account's oldest session to make room.
    ///
    /// # Errors
    ///
    /// [`StoreError`]; no session exists afterwards.
    fn insert(&self, digest: TokenDigest, record: SessionRecord) -> Result<(), StoreError>;

    /// Replace a live record (standing re-read, touch). Returns `false` if
    /// the session ended meanwhile.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn update(&self, digest: &TokenDigest, record: &SessionRecord) -> Result<bool, StoreError>;

    /// End one session, leaving a tombstone. Returns the record it ended.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn end(
        &self,
        digest: &TokenDigest,
        reason: EndReason,
        at: UnixTime,
    ) -> Result<Option<SessionRecord>, StoreError>;

    /// End every session of `user`. Returns how many ended.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn end_all(&self, user: UserId, reason: EndReason, at: UnixTime) -> Result<u32, StoreError>;

    /// The live sessions of `user`, for a devices page.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn sessions_of(&self, user: UserId) -> Result<Vec<SessionInfo>, StoreError>;

    /// Record that the single-use value `key` was used, remembering it until
    /// `until`. Returns `true` the first time and `false` on every later
    /// call: the replay guard for second-factor and passkey challenges,
    /// shared by every node that shares the store. `now` lets a full store
    /// forget values that expired, rather than refusing new ones.
    ///
    /// # Errors
    ///
    /// [`StoreError`]; the gate then refuses the challenge.
    fn use_once(&self, key: [u8; 32], until: UnixTime, now: UnixTime) -> Result<bool, StoreError>;

    /// Drop expired sessions, old tombstones, and spent single-use values.
    /// Returns how many entries went. Called from a timer, never per request.
    fn purge(&self, now: UnixTime) -> usize {
        let _ = now;
        0
    }
}

/// An account as the gate needs it. Profile fields (name, avatar) are not
/// here: they belong to the service.
#[derive(Clone, Debug)]
pub struct Account {
    /// The account id.
    pub user: UserId,
    /// Its standing.
    pub standing: Standing,
    /// The password hash, if the account has a password.
    pub password: Option<PasswordHash>,
    /// The TOTP secret and the last time step accepted, if enrolled.
    pub totp: Option<TotpState>,
    /// Whether the account has at least one passkey.
    pub has_passkeys: bool,
    /// Locked against sign-in until this time after repeated failures. Kept
    /// apart from the standing, so a lock never replaces or erases it.
    pub locked_until: Option<UnixTime>,
    /// Role names, compiled to permissions by the authorization side.
    pub roles: Vec<Box<str>>,
    /// The tenant, in a multi-tenant service.
    pub tenant: Option<u64>,
    /// Identity-side attributes rules may use (name, value).
    pub attrs: Vec<(Box<str>, u64)>,
    /// When it was created.
    pub created: UnixTime,
}

/// An enrolled TOTP factor.
#[derive(Clone, Debug)]
pub struct TotpState {
    /// The shared secret.
    pub secret: TotpSecret,
    /// The last time step accepted (replay guard); 0 before the first use.
    pub last_step: u64,
    /// Whether enrolment was confirmed with a first code.
    pub confirmed: bool,
    /// A replacement secret being enrolled (a new phone). The confirmed
    /// secret keeps working until a code from this one confirms it.
    pub pending: Option<TotpSecret>,
}

/// A new account.
#[derive(Clone, Debug)]
pub struct NewAccount {
    /// What it signs in with.
    pub identifier: Identifier,
    /// Its password hash (from [`AuthGate::hash_password`](crate::AuthGate::hash_password)).
    pub password: Option<PasswordHash>,
    /// Its first standing (usually pending verification).
    pub standing: Standing,
    /// Its roles.
    pub roles: Vec<Box<str>>,
    /// Its tenant.
    pub tenant: Option<u64>,
    /// When.
    pub created: UnixTime,
}

/// Where accounts live. Called at sign-in and at standing re-checks, never
/// on an ordinary request.
pub trait IdentityStore: Send + Sync {
    /// The account an identifier belongs to.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn lookup(&self, identifier: &Identifier) -> Result<Option<UserId>, StoreError>;

    /// The account an identifier belongs to, in one read (one round trip
    /// for a networked store). Sign-in calls only this, so a known and an
    /// unknown identifier cost the store the same work. Required, with no
    /// default: a default of two reads would make them cost differently.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn account_by_identifier(&self, identifier: &Identifier)
    -> Result<Option<Account>, StoreError>;

    /// An account.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn account(&self, user: UserId) -> Result<Option<Account>, StoreError>;

    /// An account's standing. The default reads the whole account; an
    /// adapter should answer from an index.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn standing(&self, user: UserId) -> Result<Option<Standing>, StoreError> {
        Ok(self.account(user)?.map(|a| a.standing))
    }

    /// Create an account. Generates its id.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlreadyExists`] if the identifier is taken.
    fn create(&self, account: NewAccount) -> Result<UserId, StoreError>;

    /// Set an account's standing.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] for an unknown account.
    fn set_standing(&self, user: UserId, standing: Standing) -> Result<(), StoreError>;

    /// Replace the password hash.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn set_password(&self, user: UserId, hash: PasswordHash) -> Result<(), StoreError>;

    /// Replace the role names.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn set_roles(&self, user: UserId, roles: &[&str]) -> Result<(), StoreError>;

    /// Count a failed sign-in at `at` and return how many failures fall in
    /// the last `window_ms` (this one included).
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn record_failure(&self, user: UserId, at: UnixTime, window_ms: u64)
    -> Result<u32, StoreError>;

    /// Count a failed sign-in for an identifier that has no account, and
    /// return how many fall in the last `window_ms`. One write, like
    /// [`record_failure`](Self::record_failure), so the store work does not
    /// tell an unknown identifier from a known one. Implementations bound
    /// what they keep.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn record_unknown_failure(
        &self,
        identifier: &Identifier,
        at: UnixTime,
        window_ms: u64,
    ) -> Result<u32, StoreError>;

    /// Lock the account against sign-in until `until` (or keep a later
    /// lock). Never touches the standing.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] for an unknown account.
    fn lock_until(&self, user: UserId, until: UnixTime) -> Result<(), StoreError>;

    /// Forget failed sign-ins (after a success).
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn clear_failures(&self, user: UserId) -> Result<(), StoreError>;

    /// Enrol (or remove, with `None`) a TOTP factor.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn set_totp(&self, user: UserId, totp: Option<TotpState>) -> Result<(), StoreError>;

    /// Accept TOTP time step `step` if it is later than the last one
    /// accepted, atomically. Returns `false` for a replay.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn advance_totp(&self, user: UserId, step: u64) -> Result<bool, StoreError>;

    /// Replace the recovery codes (their digests).
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn set_recovery_codes(
        &self,
        user: UserId,
        codes: Vec<RecoveryDigest>,
    ) -> Result<(), StoreError>;

    /// Use a recovery code: `true` and removed if it was there, `false`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn use_recovery_code(&self, user: UserId, code: &RecoveryDigest) -> Result<bool, StoreError>;

    /// Add a passkey.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlreadyExists`] if its credential id is registered.
    fn add_passkey(&self, user: UserId, passkey: Passkey) -> Result<(), StoreError>;

    /// The passkey with credential id `credential`, and its account.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn passkey(&self, credential: &[u8]) -> Result<Option<(UserId, Passkey)>, StoreError>;

    /// The passkeys of an account.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn passkeys(&self, user: UserId) -> Result<Vec<Passkey>, StoreError>;

    /// Store a passkey's new signature counter if it is greater than the
    /// stored one, atomically. Returns `false` if it is not (a cloned
    /// authenticator), unless both are zero (authenticators that keep no
    /// counter).
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn advance_sign_count(&self, credential: &[u8], count: u32) -> Result<bool, StoreError>;

    /// Remove a passkey.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn remove_passkey(&self, user: UserId, credential: &[u8]) -> Result<bool, StoreError>;
}
