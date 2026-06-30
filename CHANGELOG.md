# Changelog

All notable changes to `vgi-saml` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-29

Initial release.

### Added

- **Decode** SAML 2.0 Responses and Assertions across all wire shapes (raw XML,
  base64 POST binding, base64+raw-DEFLATE Redirect binding, URL-encoded) via a
  content-sniffing transport layer (`decode`, `conditions`, `authn`,
  `message_type`, and the `b64decode` / `inflate` / `unwrap` plumbing).
- **XML-DSig verification** with a vendored, pinned **pure-Rust exclusive XML
  canonicalization** (`xml-exc-c14n#`) validated byte-for-byte against
  `signxml`/`lxml` golden vectors. `signature` returns `c14n_ok` / `digest_ok` /
  `sig_valid` plus the embedded signer cert and its SHA-256 fingerprint;
  RSA-SHA256/384/512, ECDSA-P256/P384, and EdDSA signature math (no native
  `xmlsec1`). `signatures` exposes the multi-signature view.
- **XSW / Golden-SAML detection** (`anomalies`) emitting the structural
  invariants every XSW1–XSW8 variant violates, tested with positive and negative
  (attack) fixtures.
- **Untrusted-input hardening**: DTD/entity processing off (XXE / billion-laughs
  defeated and surfaced via `well_formed`), bounded node count + 64 MiB inflate
  cap (DEFLATE-bomb guard), per-row error capture, and a zero-panic property
  fuzz over arbitrary/truncated XML.
- Fan-out scalars returning `LIST<STRUCT>` (`attributes`, `signatures`,
  `assertions`) for per-row `UNNEST` over a column.
- haybarn SQLLogic E2E suite, `vgi-lint`-clean metadata (100/100), and CI.
