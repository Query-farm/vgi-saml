# CLAUDE.md — vgi-saml

Guidance for working in this repo. It is a **VGI worker** (a binary DuckDB
launches and talks to over Arrow IPC) that decodes SAML 2.0 and verifies XML-DSig
signatures with **pure-Rust exclusive C14N**, plus XSW / Golden-SAML detection.

## Layout

- `crates/saml-core/` — the pure-compute engine. **No Arrow, no VGI, no network,
  no key store.** Every entry point is a total function over a byte slice and
  **must never panic** (untrusted input). Modules: `transport` (base64 + raw
  DEFLATE + URL-decode + content-sniff, bomb-bounded), `xml` (hardened roxmltree
  load — DTD/entity OFF), `c14n` (exclusive XML canonicalization), `cert` +
  `signature` (dsig verify), `message`/`conditions`/`authn`/`attributes`
  (decode), `detect` (XSW/golden), `api` (the bytes→model chain the worker calls).
- `crates/saml-worker/` — thin Arrow adapter. `scalar/*` marshal `saml-core`
  outputs into Arrow `STRUCT`/`LIST`/`TIMESTAMPTZ`. `main.rs` registers the
  catalog `saml` + schema `main` and the function metadata (vgi-lint).

## The moat: exclusive C14N

`c14n::exclusive_c14n` is the highest-risk code — XML-DSig signs the *canonical
octets*, so a byte wrong = every `digest_ok`/`sig_valid` wrong. It is validated
**byte-for-byte against real `signxml`/`lxml` signatures** in
`tests/c14n_oracle.rs` (RSA + EC). If you touch it, that test is the gate. Key
subtlety: exclusive C14N only renders *visibly-utilized* namespaces (the
element's own prefix + attribute prefixes + the `InclusiveNamespaces` PrefixList)
— an `xmlns:xs` used only inside an `xsi:type="xs:string"` *value* is dropped.

## Fixtures

`crates/saml-core/tests/vectors/` holds golden SAML (signed RSA + EC, tampered,
XSW3, comment-splice, XXE, billion-laughs, …). Regenerate with
`tests/vectors/_generate.py` (uses `signxml`; run via
`uv run --with signxml --with cryptography python _generate.py vectors`). The
worker's E2E fixtures are copied into `test/data/`.

## Gates (all must be green)

```sh
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test --workspace --all-features        # unit + c14n oracle + golden + zero-panic proptest
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
./run_tests.sh                               # haybarn SQLLogic E2E
uvx --from vgi-lint-check vgi-lint lint "$PWD/target/release/saml-worker" --execute --ai --ai-concurrency 1 --fail-on info
```

## Gotchas

- **Fan-outs are scalar `LIST<STRUCT>`, not table functions.** DuckDB's
  table-function binder only accepts *literal* constant args (a correlated
  `r.col` errors with "the function only supports literals as parameters"), so
  `attributes`/`signatures`/`assertions` are scalars you `UNNEST`:
  `FROM raw_saml r, UNNEST(saml.main.attributes(r.saml_response)) AS _(a)`.
- **`decode`/`conditions`/`authn`/`signature` return `STRUCT`** — use
  `(expr).field` or a CTE; you can't `LATERAL` a scalar struct.
- **SQLLogic tests must NOT `SET search_path`** to the worker catalog (it's
  read-only — `CREATE TABLE` would fail). Fully-qualify worker calls as
  `saml.main.<fn>` and create test tables in the default `memory` catalog.
- Use `LOAD vgi;` (not `require vgi`) and `require-env VGI_SAML_WORKER` in `.test`.
- `value_type` is the **literal** `xsi:type` QName (`xs:string`), not `string`.
- vgi-lint flags any data-type word in an argument description (e.g. the word
  "any" matches the `ANY` type) — describe *meaning*, not type.
- vgi-lint execution is ENABLED: every shipped example / agent test task uses a
  literal SAML message, so `--execute` runs them against a live worker with no
  external dependency. The natural LATERAL-over-a-column shape is additionally
  covered by the haybarn E2E against committed signed fixtures.

## Non-goals (do not add without a feature gate)

Trust-store key validation, `EncryptedAssertion` decryption, SAML metadata
parsing, issuing/signing SAML, replay-cache state. The worker is verify-only,
stateless, and has no egress.
