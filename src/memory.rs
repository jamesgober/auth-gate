//! In-memory stores: correct, bounded, and lost on restart. For tests,
//! local development, and as the memory tier in front of a durable store.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, RwLock},
};

use crate::{
    error::StoreError,
    id::{Identifier, UserId},
    otp::RecoveryDigest,
    passkey::Passkey,
    password::PasswordHash,
    record::{EndReason, SessionInfo, SessionRecord, Tombstone},
    standing::Standing,
    store::{Account, Found, IdentityStore, NewAccount, SessionStore, TotpState},
    time::UnixTime,
    token::TokenDigest,
};

const SHARDS: usize = 16;

/// Token digests are keyed BLAKE3 output: already uniform and unknown to
/// clients, so hashing them again (SipHash) only costs time. This hasher
/// takes eight digest bytes as the hash.
#[derive(Clone, Copy, Default)]
struct DigestHasher(u64);

impl core::hash::Hasher for DigestHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // `[u8; 32]` hashes as a length prefix then the bytes; keep bytes
        // 8..16 of the digest (the shard is picked from byte 0).
        if bytes.len() >= 16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[8..16]);
            self.0 = u64::from_le_bytes(b);
        }
    }
}

type DigestMap<V> = HashMap<TokenDigest, V, core::hash::BuildHasherDefault<DigestHasher>>;

// Kept inline: boxing the record would allocate on every request.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy)]
enum Entry {
    Live(SessionRecord),
    Ended(Tombstone),
}

/// Sessions in memory, sharded by digest so requests rarely share a lock.
///
/// Bounded three ways: a total capacity, a per-account cap (a new sign-in
/// past it ends that account's oldest session), and a tombstone lifetime.
#[derive(Debug)]
pub struct MemorySessions {
    shards: Vec<RwLock<DigestMap<Entry>>>,
    by_user: Mutex<HashMap<UserId, Vec<TokenDigest>>>,
    once: Mutex<HashMap<[u8; 32], UnixTime>>,
    capacity: usize,
    per_user: usize,
    tombstone_ms: u64,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Live(_) => f.write_str("Live"),
            Self::Ended(_) => f.write_str("Ended"),
        }
    }
}

impl Default for MemorySessions {
    fn default() -> Self {
        Self::new()
    }
}

fn poisoned<T>(_: T) -> StoreError {
    StoreError::Unavailable
}

impl MemorySessions {
    /// Up to 1,000,000 sessions, 16 per account, tombstones kept a day.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(1_000_000, 16, 24 * 3600 * 1000)
    }

    /// Up to `capacity` sessions in total, `per_user` per account, and
    /// tombstones kept `tombstone_ms` milliseconds.
    #[must_use]
    pub fn with_limits(capacity: usize, per_user: usize, tombstone_ms: u64) -> Self {
        Self {
            shards: (0..SHARDS)
                .map(|_| RwLock::new(DigestMap::default()))
                .collect(),
            by_user: Mutex::new(HashMap::new()),
            once: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            per_user: per_user.max(1),
            tombstone_ms,
        }
    }

    fn shard(&self, d: &TokenDigest) -> &RwLock<DigestMap<Entry>> {
        &self.shards[usize::from(d.as_bytes()[0]) % SHARDS]
    }

    /// How many live sessions are held.
    #[must_use]
    pub fn live(&self) -> usize {
        self.by_user
            .lock()
            .map(|m| m.values().map(Vec::len).sum())
            .unwrap_or(0)
    }

    fn end_locked(
        &self,
        d: &TokenDigest,
        reason: EndReason,
        at: UnixTime,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let mut shard = self.shard(d).write().map_err(poisoned)?;
        match shard.get(d).copied() {
            Some(Entry::Live(rec)) => {
                shard.insert(
                    *d,
                    Entry::Ended(Tombstone {
                        user: rec.user,
                        reason,
                        at,
                        bindings: rec.bindings,
                    }),
                );
                Ok(Some(rec))
            }
            _ => Ok(None),
        }
    }
}

impl SessionStore for MemorySessions {
    fn find(&self, digest: &TokenDigest) -> Result<Found, StoreError> {
        let shard = self.shard(digest).read().map_err(poisoned)?;
        Ok(match shard.get(digest) {
            Some(Entry::Live(r)) => Found::Live(*r),
            Some(Entry::Ended(t)) => Found::Ended(*t),
            None => Found::Unknown,
        })
    }

    fn insert(&self, digest: TokenDigest, record: SessionRecord) -> Result<(), StoreError> {
        let mut users = self.by_user.lock().map_err(poisoned)?;
        let total: usize = users.values().map(Vec::len).sum();
        let list = users.entry(record.user).or_default();
        if list.len() >= self.per_user {
            // Make room: end the oldest session of this account.
            let oldest = list.remove(0);
            self.end_locked(&oldest, EndReason::Replaced, record.created)?;
        } else if total >= self.capacity {
            return Err(StoreError::Full);
        }
        list.push(digest);
        drop(users);
        self.shard(&digest)
            .write()
            .map_err(poisoned)?
            .insert(digest, Entry::Live(record));
        Ok(())
    }

    fn update(&self, digest: &TokenDigest, record: &SessionRecord) -> Result<bool, StoreError> {
        let mut shard = self.shard(digest).write().map_err(poisoned)?;
        match shard.get_mut(digest) {
            Some(Entry::Live(r)) if r.id == record.id => {
                *r = *record;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn end(
        &self,
        digest: &TokenDigest,
        reason: EndReason,
        at: UnixTime,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let ended = self.end_locked(digest, reason, at)?;
        if let Some(rec) = ended {
            let mut users = self.by_user.lock().map_err(poisoned)?;
            if let Some(list) = users.get_mut(&rec.user) {
                list.retain(|d| d != digest);
                if list.is_empty() {
                    users.remove(&rec.user);
                }
            }
        }
        Ok(ended)
    }

    fn end_all(&self, user: UserId, reason: EndReason, at: UnixTime) -> Result<u32, StoreError> {
        let list = self
            .by_user
            .lock()
            .map_err(poisoned)?
            .remove(&user)
            .unwrap_or_default();
        let mut n = 0u32;
        for d in &list {
            if self.end_locked(d, reason, at)?.is_some() {
                n += 1;
            }
        }
        Ok(n)
    }

    fn sessions_of(&self, user: UserId) -> Result<Vec<SessionInfo>, StoreError> {
        let list = self
            .by_user
            .lock()
            .map_err(poisoned)?
            .get(&user)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(list.len());
        for d in &list {
            if let Found::Live(r) = self.find(d)? {
                out.push(SessionInfo::from(&r));
            }
        }
        Ok(out)
    }

    fn use_once(&self, key: [u8; 32], until: UnixTime) -> Result<bool, StoreError> {
        let mut once = self.once.lock().map_err(poisoned)?;
        if once.contains_key(&key) {
            return Ok(false);
        }
        if once.len() >= self.capacity {
            return Err(StoreError::Full);
        }
        once.insert(key, until);
        Ok(true)
    }

    fn purge(&self, now: UnixTime) -> usize {
        let mut gone = 0usize;
        let mut expired: Vec<(TokenDigest, UserId)> = Vec::new();
        for shard in &self.shards {
            let Ok(mut map) = shard.write() else { continue };
            map.retain(|d, e| match e {
                Entry::Live(r) if r.expired(now) => {
                    expired.push((*d, r.user));
                    *e = Entry::Ended(Tombstone {
                        user: r.user,
                        reason: EndReason::Expired,
                        at: now,
                        bindings: r.bindings,
                    });
                    true
                }
                Entry::Ended(t) if now.since(t.at) > self.tombstone_ms => {
                    gone += 1;
                    false
                }
                _ => true,
            });
        }
        if let Ok(mut users) = self.by_user.lock() {
            for (d, u) in &expired {
                if let Some(list) = users.get_mut(u) {
                    list.retain(|x| x != d);
                    if list.is_empty() {
                        users.remove(u);
                    }
                }
            }
        }
        if let Ok(mut once) = self.once.lock() {
            let before = once.len();
            once.retain(|_, until| *until > now);
            gone += before - once.len();
        }
        gone + expired.len()
    }
}

#[derive(Debug)]
struct Row {
    account: Account,
    failures: VecDeque<UnixTime>,
    recovery: Vec<RecoveryDigest>,
    passkeys: Vec<Passkey>,
}

#[derive(Debug, Default)]
struct Inner {
    rows: HashMap<UserId, Row>,
    by_identifier: HashMap<Identifier, UserId>,
    by_credential: HashMap<Box<[u8]>, UserId>,
}

/// Accounts in memory.
#[derive(Debug, Default)]
pub struct MemoryIdentities {
    inner: RwLock<Inner>,
}

impl MemoryIdentities {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with_row<T>(&self, user: UserId, f: impl FnOnce(&mut Row) -> T) -> Result<T, StoreError> {
        let mut inner = self.inner.write().map_err(poisoned)?;
        let row = inner.rows.get_mut(&user).ok_or(StoreError::NotFound)?;
        Ok(f(row))
    }

    /// How many accounts are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map(|i| i.rows.len()).unwrap_or(0)
    }

    /// Whether no account is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

const MAX_FAILURES_KEPT: usize = 64;

impl IdentityStore for MemoryIdentities {
    fn lookup(&self, identifier: &Identifier) -> Result<Option<UserId>, StoreError> {
        Ok(self
            .inner
            .read()
            .map_err(poisoned)?
            .by_identifier
            .get(identifier)
            .copied())
    }

    fn account(&self, user: UserId) -> Result<Option<Account>, StoreError> {
        let inner = self.inner.read().map_err(poisoned)?;
        Ok(inner.rows.get(&user).map(|r| {
            let mut a = r.account.clone();
            a.has_passkeys = !r.passkeys.is_empty();
            a
        }))
    }

    fn standing(&self, user: UserId) -> Result<Option<Standing>, StoreError> {
        let inner = self.inner.read().map_err(poisoned)?;
        Ok(inner.rows.get(&user).map(|r| r.account.standing.clone()))
    }

    fn create(&self, new: NewAccount) -> Result<UserId, StoreError> {
        let mut inner = self.inner.write().map_err(poisoned)?;
        if inner.by_identifier.contains_key(&new.identifier) {
            return Err(StoreError::AlreadyExists);
        }
        let user = UserId::generate();
        inner.by_identifier.insert(new.identifier, user);
        inner.rows.insert(
            user,
            Row {
                account: Account {
                    user,
                    standing: new.standing,
                    password: new.password,
                    totp: None,
                    has_passkeys: false,
                    roles: new.roles,
                    tenant: new.tenant,
                    attrs: Vec::new(),
                    created: new.created,
                },
                failures: VecDeque::new(),
                recovery: Vec::new(),
                passkeys: Vec::new(),
            },
        );
        Ok(user)
    }

    fn set_standing(&self, user: UserId, standing: Standing) -> Result<(), StoreError> {
        self.with_row(user, |r| r.account.standing = standing)
    }

    fn set_password(&self, user: UserId, hash: PasswordHash) -> Result<(), StoreError> {
        self.with_row(user, |r| r.account.password = Some(hash))
    }

    fn set_roles(&self, user: UserId, roles: &[&str]) -> Result<(), StoreError> {
        self.with_row(user, |r| {
            r.account.roles = roles.iter().map(|s| Box::from(*s)).collect();
        })
    }

    fn record_failure(
        &self,
        user: UserId,
        at: UnixTime,
        window_ms: u64,
    ) -> Result<u32, StoreError> {
        self.with_row(user, |r| {
            while r.failures.front().is_some_and(|t| at.since(*t) > window_ms) {
                r.failures.pop_front();
            }
            if r.failures.len() == MAX_FAILURES_KEPT {
                r.failures.pop_front();
            }
            r.failures.push_back(at);
            r.failures.len() as u32
        })
    }

    fn clear_failures(&self, user: UserId) -> Result<(), StoreError> {
        self.with_row(user, |r| r.failures.clear())
    }

    fn set_totp(&self, user: UserId, totp: Option<TotpState>) -> Result<(), StoreError> {
        self.with_row(user, |r| r.account.totp = totp)
    }

    fn advance_totp(&self, user: UserId, step: u64) -> Result<bool, StoreError> {
        self.with_row(user, |r| match r.account.totp.as_mut() {
            Some(t) if step > t.last_step => {
                t.last_step = step;
                t.confirmed = true;
                true
            }
            _ => false,
        })
    }

    fn set_recovery_codes(
        &self,
        user: UserId,
        codes: Vec<RecoveryDigest>,
    ) -> Result<(), StoreError> {
        self.with_row(user, |r| r.recovery = codes)
    }

    fn use_recovery_code(&self, user: UserId, code: &RecoveryDigest) -> Result<bool, StoreError> {
        self.with_row(user, |r| {
            let before = r.recovery.len();
            r.recovery.retain(|c| c != code);
            r.recovery.len() != before
        })
    }

    fn add_passkey(&self, user: UserId, passkey: Passkey) -> Result<(), StoreError> {
        let mut inner = self.inner.write().map_err(poisoned)?;
        if inner.by_credential.contains_key(&passkey.credential) {
            return Err(StoreError::AlreadyExists);
        }
        let row = inner.rows.get_mut(&user).ok_or(StoreError::NotFound)?;
        if row.passkeys.len() >= 32 {
            return Err(StoreError::Full);
        }
        let cred = passkey.credential.clone();
        row.passkeys.push(passkey);
        inner.by_credential.insert(cred, user);
        Ok(())
    }

    fn passkey(&self, credential: &[u8]) -> Result<Option<(UserId, Passkey)>, StoreError> {
        let inner = self.inner.read().map_err(poisoned)?;
        let Some(user) = inner.by_credential.get(credential).copied() else {
            return Ok(None);
        };
        Ok(inner.rows.get(&user).and_then(|r| {
            r.passkeys
                .iter()
                .find(|p| &*p.credential == credential)
                .map(|p| (user, p.clone()))
        }))
    }

    fn passkeys(&self, user: UserId) -> Result<Vec<Passkey>, StoreError> {
        self.with_row(user, |r| r.passkeys.clone())
    }

    fn advance_sign_count(&self, credential: &[u8], count: u32) -> Result<bool, StoreError> {
        let mut inner = self.inner.write().map_err(poisoned)?;
        let Some(user) = inner.by_credential.get(credential).copied() else {
            return Err(StoreError::NotFound);
        };
        let row = inner.rows.get_mut(&user).ok_or(StoreError::NotFound)?;
        let Some(p) = row
            .passkeys
            .iter_mut()
            .find(|p| &*p.credential == credential)
        else {
            return Err(StoreError::NotFound);
        };
        if count == 0 && p.sign_count == 0 {
            return Ok(true);
        }
        if count > p.sign_count {
            p.sign_count = count;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_passkey(&self, user: UserId, credential: &[u8]) -> Result<bool, StoreError> {
        let mut inner = self.inner.write().map_err(poisoned)?;
        let Some(row) = inner.rows.get_mut(&user) else {
            return Ok(false);
        };
        let before = row.passkeys.len();
        row.passkeys.retain(|p| &*p.credential != credential);
        let removed = row.passkeys.len() != before;
        if removed {
            inner.by_credential.remove(credential);
        }
        Ok(removed)
    }
}
