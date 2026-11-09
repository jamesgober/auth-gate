# auth-gate API

Everything is re-exported at the crate root; `webauthn` holds the WebAuthn parsers.

## The gate

| Item | Purpose |
|---|---|
| `AuthGate::builder(GateKeys) -> AuthGateBuilder` | `identities`, `sessions`, `signals`, `clock`, `password_policy`, `session_policy`, `lockout_policy`, `build` |
| `authenticate(&Presented) -> Authentication` | every request: `Guest(Guest)`, `Member(Member)`, `Refused(Refusal)` |
| `sign_in(identifier, password, &Presented) -> SignIn` | `Verified`, `NeedsSecondFactor(Challenge)`, `Failed(Failure)` |
| `second_factor(challenge_text, code, &Presented) -> SignIn` | a TOTP or recovery code |
| `sign_in_passkey(&RelyingParty, credential, client_data_json, authenticator_data, signature, &Presented) -> SignIn` | a passkey assertion |
| `issue(Verified, Payload, &Presented) -> Result<Issued>` | start the session (ends the presented one) |
| `sign_out`, `end_session`, `sign_out_everywhere`, `sessions_of` | ending sessions |
| `create_account`, `hash_password`, `change_password`, `set_standing` | accounts |
| `enroll_totp`, `confirm_totp`, `remove_totp`, `new_recovery_codes` | second factors |
| `passkey_registration`, `register_passkey`, `passkey_challenge` | passkeys |
| `purge` | drop expired sessions and spent challenges (timer) |

## Stores

`IdentityStore` (`lookup`, `account`, `standing`, `create`, `set_standing`, `set_password`, `set_roles`, `record_failure`, `clear_failures`, `set_totp`, `advance_totp`, `set_recovery_codes`, `use_recovery_code`, `add_passkey`, `passkey`, `passkeys`, `advance_sign_count`, `remove_passkey`) and `SessionStore` (`find`, `insert`, `update`, `end`, `end_all`, `sessions_of`, `use_once`, `purge`); `MemoryIdentities` and `MemorySessions` implement them.

## Types

`GateKeys` (`derive`, `with_token_keys`, `csrf_key`, `factor_key`), `TokenKeys`, `KeyRole`, `SessionToken`, `TokenDigest`, `TokenCheck`, `check_token`, `Presented`, `Member`, `Guest`, `Refusal`, `Verified`, `Failure`, `FailureReason`, `Issued`, `Payload` (at most 192 bytes), `SessionRecord`, `Bindings`, `Tombstone`, `EndReason`, `SessionInfo`, `Found`, `Account`, `NewAccount`, `TotpState`, `Standing`, `StandingClass`, `StandingSnapshot`, `Decision`, `Reason`, `Actor`, `UserId`, `SessionId`, `Identifier`, `PasswordHash`, `PasswordPolicy`, `SessionPolicy`, `ClientChange`, `LockoutPolicy`, `TotpSecret`, `hotp_check`, `totp_now`, `RecoveryDigest`, `Passkey`, `PasskeyError`, `RelyingParty`, `Challenge`, `Signal`, `SignalKind`, `SignalSink`, `MemorySignals`, `NoSignals`, `Fanout`, `Category`, `UnixTime`, `Clock`, `SystemClock`, `ManualClock`, `AuthError`, `StoreError`.

## Token format

base64url (no padding) of 50 bytes, 67 characters: `version (1) | key id (1) | random (32) | tag (16)`, with `tag = keyed BLAKE3(key[key id], version | key id | random)[..16]`. Stores index sessions by `keyed BLAKE3(digest key, random)`.

## Signals

| Kind | Id | Score | When |
|---|---|---|---|
| `UnknownSession`, `ExpiredSession`, `RetiredKeyToken` | 1004, 1005, 1003 | 1 | an old tab, a restart, a rotation |
| `StaleToken` | 1006 | 3 | an ended session's token from the same client |
| `MalformedToken` | 1001 | 10 | wrong length, alphabet, version, key id |
| `ClientChanged` | 1008 | 15 | network prefix or browser changed mid-session |
| `ReplayedToken` | 1007 | 30 | an ended session's token from another client |
| `ForgedToken` | 1002 | 40 | a current key id with a bad signature |

Sign-in, factor, passkey, ban, access, and CSRF kinds follow; see `SignalKind`.
