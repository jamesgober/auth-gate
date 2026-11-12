# auth-gate: Plan

> Design and decision record. Read order: [`../REPS.md`](../REPS.md), [`DIRECTIVES.md`](./DIRECTIVES.md), this file, [`ROADMAP.md`](./ROADMAP.md).

## 1. Purpose

auth-gate is authentication: signed opaque session tokens, Argon2id passwords, TOTP, HOTP, recovery codes, passkeys, standing with time limits, and security signals. Protocol-free; storage behind traits. Authorization is access-gate.

## 2. Decisions

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-11-08 | Authentication only; authorization is access-gate | single-purpose crates |
| D-002 | 2026-11-08 | Opaque server-side sessions; the token is a signed lookup key, never a claim | instant revocation; nothing the client holds is trusted |
| D-003 | 2026-11-08 | Tokens carry a key id and a 128-bit keyed tag | garbage and forgeries never cost a store lookup; a rotation reads as low severity, not an attack |
| D-004 | 2026-11-08 | Stores keep only the keyed digest of the random part | a leaked table holds no usable token |
| D-005 | 2026-11-08 | A missing or bad credential is a guest, never a refusal; only bans refuse | authorization decides what guests may do |
| D-006 | 2026-11-08 | The session carries a standing snapshot, re-read at most every 5 minutes and when a timed standing lifts | no database read per request; bans also end sessions at once |
| D-007 | 2026-11-08 | Locks after failed sign-ins leave signed-in sessions alone | an attacker cannot sign the real user out |
| D-008 | 2026-11-08 | Second-factor and passkey challenges are signed and stateless, used once through `SessionStore::use_once` | works across nodes; no per-challenge state on a node |
| D-009 | 2026-11-08 | The session payload is opaque bytes (at most 192) | auth-gate stays independent of authorization; gatekeeper-io packs the permission set into it |
| D-010 | 2026-11-08 | Signals carry a stable id, a score, and a severity; the gate reports and never decides thresholds | detection here, enforcement in policy on the bridge |
| D-011 | 2026-11-08 | Session maps hash the digest with a pass-through hasher | the digest is already uniform keyed output; SipHash only cost time |
| D-012 | 2026-11-08 | Only an active account is locked after failed sign-ins | a lock replaces the standing and lifts to active, so locking a pending or suspended account would erase it (found in review; test `lockout_never_erases_a_standing`) |
| D-013 | 2026-11-11 | Failures are forgotten only when the whole sign-in passes; a prompt takes at most 3 codes, counted through `use_once` attempt keys | a correct password reset the count, so TOTP could be guessed forever |
| D-014 | 2026-11-11 | The lock is `Account::locked_until`, beside the standing; D-012's "only active accounts" rule is gone | non-active accounts were never locked, and a lock could overwrite a concurrent ban |
| D-015 | 2026-11-11 | `MemorySessions`: one index lock covers indexing and writing a session; lock order index then shard; kept live count; bounded tombstone queue | hardening |
| D-016 | 2026-11-11 | One store read for sign-in (`account_by_identifier`) and one write on any failure (`record_unknown_failure` for unknown identifiers) | equal store work, not only equal Argon2 work |
| D-017 | 2026-11-11 | Identifiers are printable ASCII only until normalization ships | look-alike scripts and NFC/NFD forms were distinct accounts |
| D-018 | 2026-11-11 | Default `ClientChange::EndWhenBoth`; browser hash at the touch interval | the per-request cost of the binding hash |
| D-019 | 2026-11-11 | Count each attempt before checking it; refuse unchecked past the threshold | concurrent attempts got more checks than the lockout allows; the store's increment is now the gate, and blocked accounts write like unknown ones |
| D-020 | 2026-11-11 | `account_by_identifier` required; `use_once` takes `now` and evicts expired values when full | equal store work cannot depend on an adapter overriding a default; a full map refused sign-ins until a purge |
