# auth-gate performance

Measured 2026-11-08 with criterion (`cargo bench`), Rust 1.99, release
profile, Windows 11 x86-64 on a shared development machine (other builds
were running). Median, with criterion's 95% interval. Treat them as
build-to-build comparisons, not reference-box numbers.

| Benchmark | Time | What it measures |
|---|---|---|
| `token/check_valid` | 317 ns (305 to 329) | length, base64url, version, key id, keyed BLAKE3 tag, keyed digest |
| `token/check_forged` | 234 ns (222 to 249) | the same up to the tag mismatch (no digest) |
| `authenticate/member` | 742 ns (682 to 813) | a signed-in request: token check, session lookup, expiry, client binding hash |
| `authenticate/no_credential` | 9.3 ns (9.0 to 9.6) | a guest with nothing presented |
| `authenticate/malformed` | 63.6 ns (57.5 to 70.3) | garbage, refused before any hash, plus the signal |
| `sign_in/argon2id_default` | 52.6 ms (47.0 to 59.3) | password sign-in at crypt-io's default Argon2id cost |
| `sign_in/unknown_account` | 40.4 ms (38.7 to 43.9) | the same work for an account that does not exist |

The per-request path reads memory only. Sign-in is Argon2id by design and
must run off any connection-serving thread.

## Where a signed-in request's time goes

About 320 ns verifying the token (two keyed BLAKE3 calls over 34 and 32
bytes, and a fixed-length base64url decode), 100 to 150 ns hashing the
client binding (keyed BLAKE3 over the user agent), and the rest on the
sharded lock, the lookup, and copying the record. Candidates for the
pre-1.0 polish: cache the binding hash per connection (it changes only if
the header does), fold the digest into the tag computation, and return the
record by reference from the memory store.

Run with `cargo bench --bench gate`.
