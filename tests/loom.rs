//! Model checks of `MemorySessions` under every interleaving loom finds.
//! Run with `RUSTFLAGS="--cfg loom" cargo test --release --test loom`.
#![cfg(loom)]

use std::time::Duration;

use auth_gate::*;
use loom::{sync::Arc, thread};

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

fn digest(i: u8) -> TokenDigest {
    let mut b = [0u8; 32];
    b[0] = i;
    b[8] = i;
    TokenDigest::from_bytes(b)
}

const NOW: UnixTime = UnixTime::from_secs(1_700_000_000);

/// Issuing a session while every session of the account is being ended:
/// either the revocation ran first and the new session is live and indexed
/// (a later revocation will find it), or it ran after and ended it. Never a
/// live session that no index knows.
#[test]
fn test_insert_against_end_all_never_orphans() {
    loom::model(|| {
        let store = Arc::new(MemorySessions::with_limits(8, 4, 1000));
        let user = UserId::from_u128(1);
        let s = store.clone();
        let t = thread::spawn(move || s.insert(digest(1), record(user, NOW)).unwrap());
        let ended = store.end_all(user, EndReason::RevokedAll, NOW).unwrap();
        t.join().unwrap();
        match store.find(&digest(1)).unwrap() {
            Found::Live(_) => {
                assert_eq!(ended, 0);
                assert_eq!(store.sessions_of(user).unwrap().len(), 1);
                assert_eq!(store.live(), 1);
                assert_eq!(store.end_all(user, EndReason::RevokedAll, NOW).unwrap(), 1);
            }
            Found::Ended(_) => {
                assert_eq!(ended, 1);
                assert!(store.sessions_of(user).unwrap().is_empty());
                assert_eq!(store.live(), 0);
            }
            Found::Unknown => panic!("the session vanished"),
        }
    });
}

/// Two sign-ins racing past a per-account cap of one: exactly one stays
/// live, the other is ended, and the count agrees.
#[test]
fn test_racing_inserts_keep_the_cap() {
    loom::model(|| {
        let store = Arc::new(MemorySessions::with_limits(8, 1, 1000));
        let user = UserId::from_u128(1);
        let s = store.clone();
        let t = thread::spawn(move || s.insert(digest(1), record(user, NOW)).unwrap());
        store.insert(digest(2), record(user, NOW)).unwrap();
        t.join().unwrap();
        let live = [1, 2]
            .iter()
            .filter(|i| matches!(store.find(&digest(**i)).unwrap(), Found::Live(_)))
            .count();
        assert_eq!(live, 1);
        assert_eq!(store.live(), 1);
        assert_eq!(store.sessions_of(user).unwrap().len(), 1);
    });
}

/// Ending one session while the account's sessions are all ended: each
/// session is ended once, and the count never goes wrong.
#[test]
fn test_end_against_end_all_counts_once() {
    loom::model(|| {
        let store = Arc::new(MemorySessions::with_limits(8, 4, 1000));
        let user = UserId::from_u128(1);
        store.insert(digest(1), record(user, NOW)).unwrap();
        store.insert(digest(2), record(user, NOW)).unwrap();
        let s = store.clone();
        let t = thread::spawn(move || {
            s.end(&digest(1), EndReason::SignedOut, NOW)
                .unwrap()
                .is_some()
        });
        let all = store.end_all(user, EndReason::RevokedAll, NOW).unwrap();
        let one = t.join().unwrap();
        assert_eq!(u32::from(one) + all, 2, "each session ended exactly once");
        assert_eq!(store.live(), 0);
    });
}
