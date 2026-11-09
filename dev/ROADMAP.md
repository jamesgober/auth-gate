# auth-gate: Roadmap

| Version | Status | Scope |
|---|---|---|
| 0.1.0 | done | core types, the main path, in-memory stores, unit and integration tests |
| 0.2.0 | done | design lock: API settled with the server and router crates, docs, examples |
| 0.3.0 | done | property tests, fuzz targets, benchmarks, the end-to-end sign-in scenario |
| 0.4.0 | next | single-use tokens (email verification, reset, sign-in links) through the stores; API keys (prefixed, keyed digest, scopes); an optional `IdentityStore::verify_password` hook for stores that keep hashes inside the database; ending one session by its public id (devices page) |
| 0.5.0 | | rolling tokens with a grace window (theft detection); sudo mode (a short elevated window after a fresh factor); revocation epochs on the security bridge for multi-node stores |
| 0.6.0 | | store adapters in their own crates: the embedded document database first, then the content database's auth engine |
| 0.9.x | | polish and freeze; performance tuning of the request path (measured 0.74 us signed-in, see docs/PERFORMANCE.md): binding hash cached per connection, digest folded into the tag, record by reference |
| 1.0.0 | maintainer's call | after real use end to end and an adversarial review |

## Known limits at 0.3

- Identifiers are trimmed and ASCII-lowercased; passwords are not Unicode-normalized (two keyboards typing the same accented password differently do not match).
- `MemorySessions` loses every session on restart (by design); a durable store is an adapter.
- The CBOR reader accepts what a COSE key and an extension map need, nothing more (no tags, no indefinite lengths).
