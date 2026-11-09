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

