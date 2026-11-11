<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>auth-gate</b>
    <br>
    <sub><sup>AUTHENTICATION</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/auth-gate"><img alt="Crates.io" src="https://img.shields.io/crates/v/auth-gate"></a>
    <a href="https://docs.rs/auth-gate"><img alt="docs.rs" src="https://img.shields.io/docsrs/auth-gate"></a>
    <a href="https://github.com/jamesgober/auth-gate/actions"><img alt="CI" src="https://github.com/jamesgober/auth-gate/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>auth-gate</strong> answers <strong>who is this?</strong> for every request: it turns an unknown visitor into a guest or a signed-in session. A missing or bad credential never stops a request by itself; it becomes a guest, and authorization decides what a guest may do. Bans are refused at the gate.
    </p>
    <p>
        Session tokens are 256 random bits, signed with a key id and stored only as a keyed digest, so garbage and forgeries are told apart before any store lookup and a leaked session table holds no usable token. Passwords use Argon2id with a pepper; second factors are TOTP, HOTP, and recovery codes; passkeys are WebAuthn with ES256, EdDSA, and RS256. Every primitive comes from <code>crypt-io</code>. Accounts and sessions live behind the <code>IdentityStore</code> and <code>SessionStore</code> traits; in-memory stores ship with the crate. Every suspicious event is a signal to the security bridge.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: <code>0.4.0</code>, pre-release.</strong> Built and tested locally; not yet published. The API may still change before 1.0.
    </blockquote>
</div>

<hr>
<br>

## Installation

```toml
[dependencies]
auth-gate = "0.4"
```

On Windows without NASM, set `AWS_LC_SYS_PREBUILT_NASM=1` or enable the `prebuilt-nasm` feature (crypt-io's OTP and signature checks use AWS-LC).

## Usage

```rust
use auth_gate::{Authentication, AuthGate, GateKeys, Payload, Presented, SignIn, Standing};

let gate = AuthGate::builder(GateKeys::derive(&master_secret)?).build()?;
gate.create_account("alice@example.com", "correct horse battery", Standing::Active, &["member"])?;

// POST /login
let client = Presented::new().peer(peer_ip).user_agent(user_agent);
match gate.sign_in("alice@example.com", "correct horse battery", &client) {
    SignIn::Verified(proof) => {
        let issued = gate.issue(proof, Payload::EMPTY, &client)?; // a new token every sign-in
        // set the cookie to issued.token.as_str()
    }
    SignIn::NeedsSecondFactor(challenge) => { /* show the code form with challenge.to_text() */ }
    SignIn::Failed(f) => { /* show f.message(): the same for every reason */ }
}

// Every request
match gate.authenticate(&client.token(cookie_value)) {
    Authentication::Member(m) => { /* m.user(), m.payload() */ }
    Authentication::Guest(g) => { /* if g.clear_cookie(), drop the cookie */ }
    Authentication::Refused(_) => { /* banned: 403 */ }
}
```

## What it stops

| Threat | Defence |
|---|---|
| forged or tampered tokens | keyed signature checked before any lookup; a signal with high severity |
| a stolen session table | only keyed digests are stored |
| a replayed stolen cookie | ended sessions leave tombstones: a stale tab and a replay from another client are told apart |
| session fixation | every sign-in issues a new token and ends the one presented |
| account enumeration | one message, the same Argon2id work, and the same store work (one read, one write) for every failure |
| password and code guessing | password failures and wrong second-factor codes counted together per account, never reset until the whole sign-in passes; at most 3 codes per prompt; a timed lock kept beside the standing (it never replaces a ban or a suspension) that leaves signed-in sessions alone |
| replayed codes and challenges | each TOTP step, recovery code, and challenge works once, across nodes sharing a store |
| cloned passkeys | the signature counter must increase |
| bans and suspensions | a ban ends every session at once; a standing re-read every few minutes and when a timed standing lifts |

## Documentation

- [`docs/API.md`](./docs/API.md): every public item.
- [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md): measured costs.
- [`dev/PLAN.md`](./dev/PLAN.md): design and decisions.
- [`CHANGELOG.md`](./CHANGELOG.md).

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
