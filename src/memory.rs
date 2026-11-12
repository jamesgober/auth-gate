//! In-memory stores: correct, bounded, and lost on restart. For tests,
//! local development, and as the memory tier in front of a durable store.

use std::collections::{HashMap, VecDeque};

use crate::{
    error::StoreError,
    id::{Identifier, UserId},
    otp::RecoveryDigest,
    passkey::Passkey,
    password::PasswordHash,
    record::{EndReason, SessionInfo, SessionRecord, Tombstone},
    standing::Standing,
    store::{Account, Found, IdentityStore, NewAccount, SessionStore, TotpState},
    sync::{Mutex, RwLock},
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

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Live(_) => f.write_str("Live"),
            Self::Ended(_) => f.write_str("Ended"),
        }
    }
}

/// The per-account index, the live count, and the tombstone queue, under
/// one lock. Lock order everywhere: the index, then a shard. A session is
/// indexed and written under the same index lock, so no revocation can run
/// between the two (an unindexed live session cannot exist).
#[derive(Debug, Default)]
struct Index {
    users: HashMap<UserId, Vec<TokenDigest>>,
    live: usize,
    ended: VecDeque<TokenDigest>,
}

#[cfg(test)]
type Hook = std::sync::Arc<dyn Fn() + Send + Sync>;

/// Sessions in memory, sharded by digest so requests rarely share a lock.
///
/// Bounded four ways: a total capacity of live sessions (expired ones count
/// until [`purge`](SessionStore::purge) turns them into tombstones), a
/// per-account cap (a new sign-in past it ends that account's oldest
/// session), a tombstone capacity (the oldest go first), and a tombstone
/// lifetime.
pub struct MemorySessions {
    shards: Vec<RwLock<DigestMap<Entry>>>,
    index: Mutex<Index>,
    once: Mutex<HashMap<[u8; 32], UnixTime>>,
    capacity: usize,
    per_user: usize,
    tombstones: usize,
    tombstone_ms: u64,
    #[cfg(test)]
    hook: Mutex<Option<Hook>>,
}

impl core::fmt::Debug for MemorySessions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemorySessions")
            .field("capacity", &self.capacity)
            .field("per_user", &self.per_user)
            .field("tombstones", &self.tombstones)
            .finish_non_exhaustive()
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
    /// Up to 1,000,000 sessions, 16 per account, as many tombstones, each
    /// kept a day.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(1_000_000, 16, 24 * 3600 * 1000)
    }

    /// Up to `capacity` live sessions and as many tombstones in total,
    /// `per_user` per account, and tombstones kept `tombstone_ms`
    /// milliseconds.
    #[must_use]
    pub fn with_limits(capacity: usize, per_user: usize, tombstone_ms: u64) -> Self {
        Self {
            shards: (0..SHARDS)
                .map(|_| RwLock::new(DigestMap::default()))
                .collect(),
            index: Mutex::new(Index::default()),
            once: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            per_user: per_user.max(1),
            tombstones: capacity.max(1),
            tombstone_ms,
            #[cfg(test)]
            hook: Mutex::new(None),
        }
    }

    fn shard(&self, d: &TokenDigest) -> &RwLock<DigestMap<Entry>> {
        &self.shards[usize::from(d.as_bytes()[0]) % SHARDS]
    }

    /// How many live sessions are held.
    #[must_use]
    pub fn live(&self) -> usize {
        self.index.lock().map(|i| i.live).unwrap_or(0)
    }

    /// How many entries (live and ended) are held.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().map(|m| m.len()).unwrap_or(0))
            .sum()
    }

    /// Remember an ended session, evicting the oldest tombstone past the
    /// capacity. Called with the index locked.
    fn remember(&self, idx: &mut Index, d: TokenDigest) -> Result<(), StoreError> {
        idx.ended.push_back(d);
        while idx.ended.len() > self.tombstones {
            let Some(old) = idx.ended.pop_front() else {
                break;
            };
            let mut shard = self.shard(&old).write().map_err(poisoned)?;
            if matches!(shard.get(&old), Some(Entry::Ended(_))) {
                shard.remove(&old);
            }
        }
        Ok(())
    }

    /// End one session. Called with the index locked.
    fn end_in(
        &self,
        idx: &mut Index,
        d: &TokenDigest,
        reason: EndReason,
        at: UnixTime,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let rec = {
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
                    rec
                }
                _ => return Ok(None),
            }
        };
        idx.live = idx.live.saturating_sub(1);
        if let Some(list) = idx.users.get_mut(&rec.user) {
            list.retain(|x| x != d);
            if list.is_empty() {
                idx.users.remove(&rec.user);
            }
        }
        self.remember(idx, *d)?;
        Ok(Some(rec))
    }

    #[cfg(test)]
    fn set_hook(&self, hook: Option<Hook>) {
        if let Ok(mut h) = self.hook.lock() {
            *h = hook;
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
        let mut idx = self.index.lock().map_err(poisoned)?;
        let full = idx.users.get(&record.user).map_or(0, Vec::len) >= self.per_user;
        if full {
            // Make room: end the oldest session of this account.
            let oldest = idx.users.get(&record.user).and_then(|l| l.first().copied());
            if let Some(oldest) = oldest {
                self.end_in(&mut idx, &oldest, EndReason::Replaced, record.created)?;
            }
        } else if idx.live >= self.capacity {
            return Err(StoreError::Full);
        }
        idx.users.entry(record.user).or_default().push(digest);
        idx.live += 1;
        #[cfg(test)]
        {
            let hook = self.hook.lock().ok().and_then(|h| h.clone());
            if let Some(hook) = hook {
                hook();
            }
        }
        // Written while the index is still locked (see `Index`).
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
        let mut idx = self.index.lock().map_err(poisoned)?;
        self.end_in(&mut idx, digest, reason, at)
    }

    fn end_all(&self, user: UserId, reason: EndReason, at: UnixTime) -> Result<u32, StoreError> {
        let mut idx = self.index.lock().map_err(poisoned)?;
        let list = idx.users.remove(&user).unwrap_or_default();
        let mut n = 0u32;
        for d in &list {
            if self.end_in(&mut idx, d, reason, at)?.is_some() {
                n += 1;
            }
        }
        Ok(n)
    }

    fn sessions_of(&self, user: UserId) -> Result<Vec<SessionInfo>, StoreError> {
        let list = self
            .index
            .lock()
            .map_err(poisoned)?
            .users
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

    fn use_once(&self, key: [u8; 32], until: UnixTime, now: UnixTime) -> Result<bool, StoreError> {
        let mut once = self.once.lock().map_err(poisoned)?;
        if once.contains_key(&key) {
            return Ok(false);
        }
        if once.len() >= self.capacity {
            // Full: forget what has expired before refusing anything.
            once.retain(|_, u| *u > now);
            if once.len() >= self.capacity {
                return Err(StoreError::Full);
            }
        }
        once.insert(key, until);
        Ok(true)
    }

    fn purge(&self, now: UnixTime) -> usize {
        let Ok(mut idx) = self.index.lock() else {
            return 0;
        };
        let mut gone = 0usize;
        let mut expired: Vec<TokenDigest> = Vec::new();
        for shard in &self.shards {
            let Ok(map) = shard.read() else { continue };
            for (d, e) in map.iter() {
                if let Entry::Live(r) = e {
                    if r.expired(now) {
                        expired.push(*d);
                    }
                }
            }
        }
        for d in &expired {
            if matches!(
                self.end_in(&mut idx, d, EndReason::Expired, now),
                Ok(Some(_))
            ) {
                gone += 1;
            }
        }
        for shard in &self.shards {
            let Ok(mut map) = shard.write() else { continue };
            let before = map.len();
            map.retain(|_, e| !matches!(e, Entry::Ended(t) if now.since(t.at) > self.tombstone_ms));
            gone += before - map.len();
        }
        // Forget queue entries whose tombstones are gone.
        let shards = &self.shards;
        idx.ended.retain(|d| {
            shards[usize::from(d.as_bytes()[0]) % SHARDS]
                .read()
                .is_ok_and(|m| matches!(m.get(d), Some(Entry::Ended(_))))
        });
        drop(idx);
        if let Ok(mut once) = self.once.lock() {
            let before = once.len();
            once.retain(|_, until| *until > now);
            gone += before - once.len();
        }
        gone
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier, mpsc},
        time::Duration,
    };

    use super::*;
    use crate::{id::SessionId, record::Bindings, record::Payload, standing::StandingSnapshot};

    fn record(user: UserId, now: UnixTime) -> SessionRecord {
        SessionRecord {
            id: SessionId::from_bytes([1; 16]),
            user,
            created: now,
            last_seen: now,
            idle_until: now + Duration::from_secs(3600),
            absolute_until: now + Duration::from_secs(3600),
            recheck_at: now + Duration::from_secs(300),
            standing: StandingSnapshot::default(),
            bindings: Bindings::default(),
            factor_at: None,
            payload: Payload::EMPTY,
        }
    }

    fn digest(i: u64) -> TokenDigest {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_le_bytes());
        b[8..16].copy_from_slice(&i.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
        TokenDigest::from_bytes(b)
    }

    /// Made deterministic: the insert stops between indexing the
    /// session and writing it, and `end_all` (a password change, a role
    /// change, sign out everywhere) is started at exactly that point. It
    /// must wait for the insert and then end the session. Before the fix
    /// it ran in the gap and left a live session no index could find.
    #[test]
    fn test_insert_paused_mid_write_end_all_still_ends_it() {
        let now = UnixTime::from_secs(1_700_000_000);
        let store = Arc::new(MemorySessions::new());
        let user = UserId::from_u128(7);
        let at_gap = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let (a, b) = (at_gap.clone(), resume.clone());
        store.set_hook(Some(Arc::new(move || {
            a.wait();
            b.wait();
        })));
        let inserter = {
            let store = store.clone();
            std::thread::spawn(move || store.insert(digest(1), record(user, now)).unwrap())
        };
        at_gap.wait();
        store.set_hook(None);
        let (tx, rx) = mpsc::channel();
        let revoker = {
            let store = store.clone();
            std::thread::spawn(move || {
                let n = store.end_all(user, EndReason::RevokedAll, now).unwrap();
                tx.send(n).unwrap();
            })
        };
        // The revocation cannot finish while the insert is mid-write.
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        resume.wait();
        inserter.join().unwrap();
        revoker.join().unwrap();
        assert_eq!(rx.recv().unwrap(), 1, "the new session was ended");
        assert!(matches!(store.find(&digest(1)).unwrap(), Found::Ended(_)));
        assert!(store.sessions_of(user).unwrap().is_empty());
        assert_eq!(store.live(), 0);
    }

    /// tombstones are bounded too.
    #[test]
    fn test_tombstones_are_bounded_by_capacity() {
        let now = UnixTime::from_secs(1_700_000_000);
        let store = MemorySessions::with_limits(4, 1, 24 * 3600 * 1000);
        let user = UserId::from_u128(7);
        for i in 0..20_000u64 {
            store.insert(digest(i), record(user, now)).unwrap();
        }
        assert_eq!(store.live(), 1);
        assert!(store.entries() <= 5, "held {}", store.entries());
        assert!(matches!(
            store.find(&digest(19_999)).unwrap(),
            Found::Live(_)
        ));
        assert!(matches!(
            store.find(&digest(19_998)).unwrap(),
            Found::Ended(_)
        ));
        assert!(matches!(store.find(&digest(0)).unwrap(), Found::Unknown));
    }

    /// the live count is kept, not summed per insert.
    #[test]
    fn test_live_count_follows_every_path() {
        let now = UnixTime::from_secs(1_700_000_000);
        let store = MemorySessions::with_limits(100, 2, 1000);
        for i in 0..10u64 {
            store
                .insert(digest(i), record(UserId::from_u128(u128::from(i % 3)), now))
                .unwrap();
        }
        assert_eq!(store.live(), 6, "two per account, three accounts");
        store.end(&digest(9), EndReason::SignedOut, now).unwrap();
        assert_eq!(store.live(), 5);
        store
            .end_all(UserId::from_u128(1), EndReason::RevokedAll, now)
            .unwrap();
        assert_eq!(store.live(), 3);
        assert!(store.purge(now + Duration::from_secs(7200)) >= 3);
        assert_eq!(store.live(), 0);
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
    unknown_failures: HashMap<Identifier, VecDeque<UnixTime>>,
}

/// How many unknown identifiers the memory store tracks failures for.
const MAX_UNKNOWN_TRACKED: usize = 100_000;

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

    fn account_by_identifier(
        &self,
        identifier: &Identifier,
    ) -> Result<Option<Account>, StoreError> {
        let inner = self.inner.read().map_err(poisoned)?;
        Ok(inner
            .by_identifier
            .get(identifier)
            .and_then(|u| inner.rows.get(u))
            .map(|r| {
                let mut a = r.account.clone();
                a.has_passkeys = !r.passkeys.is_empty();
                a
            }))
    }

    fn record_unknown_failure(
        &self,
        identifier: &Identifier,
        at: UnixTime,
        window_ms: u64,
    ) -> Result<u32, StoreError> {
        let mut inner = self.inner.write().map_err(poisoned)?;
        if inner.unknown_failures.len() >= MAX_UNKNOWN_TRACKED
            && !inner.unknown_failures.contains_key(identifier)
        {
            // Bounded: start over rather than grow (the counts only feed
            // signals; unknown identifiers have no account to lock).
            inner.unknown_failures.clear();
        }
        let q = inner
            .unknown_failures
            .entry(identifier.clone())
            .or_default();
        while q.front().is_some_and(|t| at.since(*t) > window_ms) {
            q.pop_front();
        }
        if q.len() == MAX_FAILURES_KEPT {
            q.pop_front();
        }
        q.push_back(at);
        Ok(q.len() as u32)
    }

    fn lock_until(&self, user: UserId, until: UnixTime) -> Result<(), StoreError> {
        self.with_row(user, |r| {
            r.account.locked_until = Some(r.account.locked_until.map_or(until, |t| t.max(until)));
        })
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
                    locked_until: None,
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
