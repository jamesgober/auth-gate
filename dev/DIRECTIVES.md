# auth-gate: Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (design and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase).

---

## 0. Philosophy

Built and maintained to a production standard. Plan the full path, then build one verified step at a time. A security component that cannot name the attack it stops, and prove it with a test, does not ship.

## 1. What this is

auth-gate is authentication: signed opaque session tokens, Argon2id passwords, TOTP, HOTP, recovery codes, passkeys, standing with time limits, and security signals. Protocol-free; storage behind traits. Authorization is access-gate.

## 2. Engineering law

- **Ours, not rented.** No third-party runtime dependency, except audited cryptographic primitives reached through `crypt-io`. First-party crates at published versions only: no `path` dependency in `Cargo.toml` (a local, untracked `.cargo/config.toml` may patch unpublished siblings for development).
- **Protocol-free.** Adapters translate the wire format; the gates take plain values.
- **Storage-free.** Data lives behind traits; in-memory implementations ship for tests.
- **Fail closed.** When a check cannot run, the answer is no.
- **Never isolated.** Every detection is reported to the security bridge (`SignalSink`).
- **Secrets.** Compared in constant time, wiped after use, never in logs, errors, or `Debug` output.
- **Unsafe.** `#![forbid(unsafe_code)]`.
- **Errors.** Every fallible path returns `Result`; error enums are `#[non_exhaustive]`; no `unwrap`, `expect`, `panic!`, `todo!`, or `dbg!` in library code.
- **Docs.** `#![deny(missing_docs)]`; every public item documented; every claim maps to a test.

## 3. Definition of done

1. `cargo fmt --all -- --check` clean.
2. `cargo clippy --all-targets -- -D warnings` on every feature set, on stable and on MSRV 1.85.
3. `cargo test --all-features` green on stable and 1.85.
4. `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` clean.
5. `cargo audit` and `cargo deny check` pass.
6. Property tests cover every invariant below; a fuzz target exists for every parser; every threat in `PLAN.md` has a test that must fail to get in.
7. Hot-path changes carry benchmarks.
8. `README.md`, `docs/API.md`, `CHANGELOG.md`, and `docs/release/vX.Y.Z.md` updated.
9. `1.0.0` only with the maintainer's explicit go, after real integration and an adversarial review.

## 4. Invariants

- No input other than a token this gate issued and has not ended yields a session.
- A token is never stored; only its keyed digest.
- Every sign-in failure shows the same message and costs the same Argon2id work.
- Every sign-in issues a new token.
- A ban ends every session of the account.
- Each TOTP step, recovery code, and challenge is accepted once.
- Secrets never appear in `Debug` output.
- When a store cannot answer, the request is a guest and the sign-in fails.

## 5. Writing style

Plain, specific prose. Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", the em-dash character, and emoji.
