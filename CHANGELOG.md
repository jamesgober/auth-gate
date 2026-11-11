<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>auth-gate</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.4.0] - 2026-11-11

Hardening fixes.

### Fixed

- A correct password no longer resets the failure count while a second
  factor is still owed, and a prompt accepts at most `CODE_ATTEMPTS` (3)
  codes: guessing TOTP codes ends in a lock (high).
- The automatic lock is kept beside the standing (`Account::locked_until`,
  `IdentityStore::lock_until`): every standing can be locked, and a ban that
  lands during a sign-in stays a ban.
- `MemorySessions` indexes and writes a session under one lock: a session
  being issued while the account's sessions are ended can no longer survive
  unindexed. Its live count is kept rather than summed (sign-in is O(1)),
  and tombstones are bounded too.
- Re-enrolling TOTP keeps the confirmed secret until the new one is
  confirmed (`TotpState::pending`).
- Sign-in does the same store work for an unknown identifier as for a known
  one (`IdentityStore::account_by_identifier`, `record_unknown_failure`).
- The second-factor challenge is consumed before a code is, so a replayed
  challenge never burns a fresh code.
- Identifiers are printable ASCII only until Unicode normalization ships.
- Tag comparisons use crypt-io's constant-time `Tag::ct_eq`.
- Stored password hashes are checked under a cost ceiling (four times the
  configured cost).
- A passkey without user verification signs in but proves no second factor.

### Changed

- `ClientChange::EndWhenBoth` is the default: a session ends when both its
  network and its browser change.
- The browser binding hash runs when the network prefix moves or at the
  touch interval, not on every request.
- `MemorySignals` is sharded per thread.

### Added

- `GateKeys::audit_key`, `AuthGate::remove_passkey`, `CODE_ATTEMPTS`,
  `Bindings::network_is`, `MemorySessions::entries`.

Breaking for store adapters: three new `IdentityStore` methods and new
fields on `Account` and `TotpState`.

See [`docs/release/v0.4.0.md`](./docs/release/v0.4.0.md).

---

## [0.3.0] - 2026-11-08

Hardening: property tests for every invariant, fuzz targets for every parser, and benchmarks with measured numbers.

See [`docs/release/v0.3.0.md`](./docs/release/v0.3.0.md).

---

## [0.2.0] - 2026-11-08

Design lock: the public API settled with the neighbouring server and router crates, documented item by item, with examples.

See [`docs/release/v0.2.0.md`](./docs/release/v0.2.0.md).

---

## [0.1.0] - 2026-11-08

First working core: the types, the main path, and the in-memory stores, with unit and integration tests. For gatekeeper-io this includes the end-to-end sign-in scenario: sign in and out, forged and expired tokens refused, CSRF on login and logout.

See [`docs/release/v0.1.0.md`](./docs/release/v0.1.0.md).

