//! # auth_gate
//!
//! Authentication for Rust services: **who is this?** It turns an unknown
//! visitor into a guest or a signed-in session on every request, and runs
//! sign-in (password, TOTP, recovery codes, passkeys) and sign-out.
//! Protocol-free and storage-free: tokens come in as bytes, and accounts
//! and sessions live behind the [`IdentityStore`] and [`SessionStore`]
//! traits, with in-memory implementations included.
//!
//! ## Tier 1
//!
//! ```
//! use auth_gate::{Authentication, AuthGate, GateKeys, PasswordPolicy, Payload, Presented, SignIn, Standing};
//!
//! let gate = AuthGate::builder(GateKeys::derive(&[7u8; 32])?)
//!     .password_policy(PasswordPolicy::insecure_for_tests()) // fast, for this example only
//!     .build()?;
//! gate.create_account("alice@example.com", "correct horse battery", Standing::Active, &["member"])?;
//!
//! // POST /login
//! let client = Presented::new().peer("192.0.2.10".parse().unwrap());
//! let SignIn::Verified(proof) = gate.sign_in("alice@example.com", "correct horse battery", &client) else {
//!     unreachable!("right password");
//! };
//! let issued = gate.issue(proof, Payload::EMPTY, &client)?;   // a new token every sign-in
//! let cookie_value = issued.token.as_str();
//!
//! // Every request
//! let request = client.token(Some(cookie_value.as_bytes()));
//! match gate.authenticate(&request) {
//!     Authentication::Member(m) => assert_eq!(m.user(), issued.record.user),
//!     Authentication::Guest(_) | Authentication::Refused(_) => unreachable!(),
//! }
//!
//! // A forged token is a guest, and a signal goes to the security bridge.
//! let forged = "A".repeat(67);
//! assert!(matches!(gate.authenticate(&client.token(Some(forged.as_bytes()))), Authentication::Guest(_)));
//! # Ok::<(), auth_gate::AuthError>(())
//! ```
//!
//! ## What happens on a request
//!
//! 1. No token: a guest, no event.
//! 2. The token's length, alphabet, version, key id, and signature are
//!    checked before any store lookup. Garbage and forgeries become guests
//!    and raise [`Signal`]s with different severities, so a broken client
//!    and an attack are told apart.
//! 3. The session record is found by the token's keyed digest (the token
//!    itself is never stored). Ended sessions leave tombstones, so a stale
//!    tab and a replayed stolen cookie are told apart too.
//! 4. Expiry (idle and absolute), the standing snapshot (re-read from the
//!    identity store at most every few minutes, and when a timed standing
//!    lifts), and the client's network and browser are checked. A ban
//!    ends every session of the account and refuses the request.
//!
//! No step reads a database except the periodic standing re-check.
//!
//! ## Sign-in
//!
//! - **Passwords:** Argon2id through crypt-io, peppered with a key the
//!   store never sees. Unknown accounts, wrong passwords, and blocked
//!   accounts fail with the same message after the same work. Repeated
//!   failures lock the account for a while; signed-in sessions keep
//!   working, so an attacker cannot sign the real user out.
//! - **Second factor:** TOTP (RFC 6238) and recovery codes, each usable
//!   once; HOTP checks are available too.
//! - **Passkeys:** WebAuthn registration and assertion, with ES256,
//!   EdDSA, and RS256 signatures checked by crypt-io.
//! - Every sign-in issues a new token (session fixation defence).
//!
//! ## Never isolated
//!
//! Every detection is reported to a [`SignalSink`]: the security bridge
//! that carries it to scoring, the connection gate, and audit. The gate
//! detects and reports; thresholds and enforcement are configured on the
//! other side.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod challenge;
mod codec;
mod error;
mod gate;
mod id;
mod keys;
mod memory;
mod otp;
mod passkey;
mod password;
mod rand;
mod record;
mod signal;
mod standing;
mod store;
mod sync;
mod time;
mod token;
pub mod webauthn;

pub use crate::{
    challenge::Challenge,
    error::{AuthError, StoreError},
    gate::{
        AuthGate, AuthGateBuilder, Authentication, CHALLENGE_TTL, CODE_ATTEMPTS, ClientChange,
        FAILURE_MESSAGE, Failure, FailureReason, Guest, Issued, LockoutPolicy, Member, Presented,
        Refusal, SessionPolicy, SignIn, Verified,
    },
    id::{Identifier, MAX_IDENTIFIER_LEN, SessionId, UserId},
    keys::{GateKeys, KeyRole, MIN_MASTER_LEN, TokenKeys},
    memory::{MemoryIdentities, MemorySessions},
    otp::{
        RECOVERY_CODES, RecoveryDigest, TOTP_DIGITS, TOTP_SECRET_LEN, TOTP_WINDOW, TotpSecret,
        hotp_check, totp_now,
    },
    passkey::{Passkey, PasskeyError, RelyingParty},
    password::{MAX_PASSWORD_LEN, PasswordHash, PasswordPolicy},
    record::{Bindings, EndReason, MAX_PAYLOAD, Payload, SessionInfo, SessionRecord, Tombstone},
    signal::{
        Category, Fanout, GENERATOR, MemorySignals, NoSignals, Signal, SignalKind, SignalSink,
    },
    standing::{
        Actor, Decision, MAX_REASON_LEN, Reason, Standing, StandingClass, StandingSnapshot,
    },
    store::{Account, Found, IdentityStore, NewAccount, SessionStore, TotpState},
    time::{Clock, ManualClock, SystemClock, UnixTime},
    token::{
        SessionToken, TOKEN_TEXT_LEN, TOKEN_VERSION, TokenCheck, TokenDigest, check as check_token,
    },
};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
