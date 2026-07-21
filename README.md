<p align="center">
  <img src="docs/vgi-logo.png" alt="VGI" width="120">
</p>

# vgi-saml

**Decode SAML 2.0 single-sign-on messages, verify their XML-DSig signatures, and
detect XML Signature Wrapping (XSW) / Golden-SAML attacks — directly in DuckDB
SQL.**

`vgi-saml` is a [VGI](https://query.farm) worker for DuckDB. It base64-decodes
(and, for the HTTP-Redirect binding, raw-DEFLATE inflates) a column of
`SAMLResponse` blobs, shreds them into typed rows — subject, issuer, audience,
the `Conditions` validity window, `AuthnContext`, and attribute statements — and,
more importantly, runs the **XML-DSig structural check the one-off tools only do
one message at a time**: exclusive XML canonicalization (`xml-exc-c14n#`),
per-`Reference` digest verification, and signature math (RSA / ECDSA / EdDSA)
against the **embedded** certificate.

The defensible value is **bulk security compute** — running XSW and Golden-SAML
detection across millions of historical SAML messages in a forensic lake, in
SQL, joinable against your IdP cert inventory and login telemetry. No native
`xmlsec1`/OpenSSL toolchain: the canonicalization and verification are **pure
Rust**.

> **Trust stays with you.** `sig_valid = true` means the *embedded* cert signed
> these bytes — never that the cert is *authorized*. The worker holds no private
> keys, no trust store, makes no network calls, and decrypts nothing. Detecting
> Golden SAML (a forgery with a stolen-but-valid IdP key) is a downstream
> `LEFT JOIN` of `signer_cert_sha256` against your known-good cert inventory.

## Install & attach

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'vgi-saml' AS saml (TYPE vgi, LOCATION '/path/to/saml-worker');  -- spawns the worker binary
```

Everything lives under the catalog `saml`, schema `main` (e.g.
`saml.main.decode(...)`).

## SQL examples

Assume a table `raw_saml(login_id, saml_response)` where `saml_response` is a
`VARCHAR`/`BLOB` holding raw XML, base64 (POST binding), base64+DEFLATE (Redirect
binding), or a URL-encoded wrapper — `decode` and every typed function
content-sniff all of them.

```sql
-- 1. Decode a column of SAMLResponses to subject + core fields.
WITH decoded AS (
  SELECT login_id, saml.main.decode(saml_response) AS d FROM raw_saml
)
SELECT login_id, (d).subject, (d).issuer, (d).audience,
       (d).authn_context, (d).not_before, (d).not_on_or_after
FROM decoded;

-- 2. Explode attribute statements to long form and pivot/join downstream.
--    (The fan-outs return LIST<STRUCT>; UNNEST them over a column.)
SELECT r.login_id, a.name, a.value
FROM raw_saml r, UNNEST(saml.main.attributes(r.saml_response)) AS _(a)
WHERE a.name IN ('http://schemas.../role', 'groups', 'eduPersonAffiliation');

-- 3. Flag XSW / Golden-SAML anomalies — the actual product.
WITH sig AS (
  SELECT login_id,
         saml.main.anomalies(saml_response)  AS flags,
         saml.main.signature(saml_response)  AS s
  FROM raw_saml
)
SELECT login_id, flags,
       (s).signed, (s).c14n_ok, (s).digest_ok, (s).sig_valid,
       (s).algo, (s).signer_cert_sha256
FROM sig
WHERE len(flags) > 0 OR (s).c14n_ok = false OR (s).digest_ok = false;

-- 4. Validity-window + trust check against now() and a known-IdP cert table.
WITH x AS (
  SELECT login_id,
         saml.main.conditions(saml_response) AS c,
         saml.main.signature(saml_response)  AS s
  FROM raw_saml
)
SELECT x.login_id, (c).not_before, (c).not_on_or_after,
       (now() BETWEEN (c).not_before AND (c).not_on_or_after) AS currently_valid,
       (idp.cert_sha256 IS NOT NULL)                          AS signer_is_known_idp
FROM x
LEFT JOIN idp_trust idp ON idp.cert_sha256 = (x.s).signer_cert_sha256;

-- 5. Raw plumbing: base64 + inflate a HTTP-Redirect SAMLRequest to its XML text.
SELECT saml.main.inflate(saml.main.b64decode(req)) AS xml FROM redirect_params;
```

> The spec sketches `attributes` / `signatures` / `assertions` as LATERAL **table
> functions**. DuckDB's table-function binder only accepts *literal* constant
> arguments (a correlated `r.saml_response` is rejected), so to fan out **per row
> over a column** these are **scalar functions returning `LIST<STRUCT>`** that you
> `UNNEST` — the identical long-form result. `decode` / `conditions` / `authn` /
> `signature` return a `STRUCT`; access fields with `(expr).field` or a CTE as
> above.

## Function reference

| Function | Returns | What it does |
| --- | --- | --- |
| `decode(msg)` | `STRUCT` | Subject, issuer, audience, `Conditions` window, `AuthnContext`, ids, counts, `signed`. Never errors on bad input (null fields + `signed=false`). |
| `conditions(msg)` | `STRUCT` | `not_before`/`not_on_or_after` window, audiences, `one_time_use`, proxy restriction. |
| `authn(msg)` | `STRUCT` | `AuthnStatement` + `AuthnContext`: instant, session, class ref, authority. |
| `signature(msg)` | `STRUCT` | XML-DSig check of the outermost signature: `signed, c14n_ok, digest_ok, sig_valid, algo, c14n_method, digest_method, signer_cert, signer_cert_sha256, signer_subject, signer_issuer, references`. |
| `anomalies(msg)` | `LIST<VARCHAR>` | XSW / Golden-SAML / structural flags (empty ≠ safe). |
| `well_formed(msg)` | `STRUCT(ok, kind, detail)` | Hostile-input triage; `dtd-present`/`entity-blocked` double as XXE signals. |
| `message_type(msg)` | `VARCHAR` | Root-element discriminator (`Response`/`AuthnRequest`/`Assertion`/…). |
| `attributes(msg)` | `LIST<STRUCT>` | One struct per `AttributeValue` (multi-valued fan out). UNNEST it. |
| `signatures(msg)` | `LIST<STRUCT>` | Every signature with its scope — the multi-sig view that makes XSW visible. UNNEST it. |
| `assertions(msg)` | `LIST<STRUCT>` | Every assertion and its parent element (parent reveals wrapping). UNNEST it. |
| `b64decode(s)` | `BLOB` | Base64 decode (standard + URL-safe). |
| `inflate(b)` | `VARCHAR` | Raw-DEFLATE inflate (Redirect binding), bomb-bounded. |
| `unwrap(s)` | `VARCHAR` | URL-decode + base64 + inflate-sniff → XML. |

## Security model

### XML Signature Wrapping (XSW) — `anomalies()`

XSW exploits the gap between the module that *verifies* a signature and the one
that *consumes* the assertion: they resolve different elements. The worker
detects the **structural invariants** every XSW1–XSW8 variant violates rather
than enumerating them by name:

`multiple-assertions`, `signature-covers-other-element`,
`reference-uri-id-mismatch`, `unsigned-assertion-in-signed-response`,
`signature-placement-anomaly`, `detached-signature`, `nameid-comment-splitting`,
`digest-mismatch`, `c14n-inclusive-on-moved-assertion`,
`encrypted-assertion-present`.

### Golden SAML

A forgery with a stolen IdP token-signing key is cryptographically perfect
(`sig_valid = true`, `digest_ok = true`) and leaves **no structural tell**. The
worker surfaces the forensic signals — `signer_cert_sha256`, the validity
windows, instant skew — and leaves the verdict to your `LEFT JOIN` against a
known-good IdP cert table (`… WHERE idp.cert_sha256 IS NULL`).

### Untrusted-input hardening

Every SAML blob is attacker-controlled, so the XML loader is locked down:

- **No DTD, no external entities, no entity expansion** — a `<!DOCTYPE`/`<!ENTITY`
  is rejected *unparsed* (`well_formed(kind='dtd-present')`), defeating **XXE**,
  **billion-laughs / exponential entity expansion**, and SSRF-via-external-entity.
- **Bounded** document node count and a 64 MiB inflate cap (**DEFLATE-bomb** guard).
- **Per-row catch** — a hostile message returns an error verdict / null-filled
  struct, **never** a panic that crashes the scan. A `cargo`-level proptest fuzz
  asserts the parser never panics on arbitrary/truncated XML.

## Architecture

```
crates/
  saml-core/    pure-compute engine (no Arrow/VGI): transport, hardened xml load,
                exclusive C14N, dsig verify, cert, decode, XSW/golden detect
  saml-worker/  thin Arrow/VGI adapter (scalar functions over saml-core)
```

The **exclusive XML canonicalization** is vendored, pinned, and validated
byte-for-byte against `signxml`/`lxml`-produced golden vectors (see
`crates/saml-core/tests/c14n_oracle.rs`). Signature math is pure Rust (`rsa`,
`p256`, `p384`, `ed25519-dalek`); cert parsing is `x509-parser`; XML is
`roxmltree`. **No GPL/AGPL dependencies, no native `xmlsec1`.**

## Building & testing

```sh
cargo build --release                              # builds target/release/saml-worker
cargo test --workspace                             # unit + golden vectors + zero-panic fuzz
cargo clippy --all-targets -- -D warnings
./run_tests.sh                                     # haybarn SQLLogic E2E (needs the vgi community ext)
```

## License

MIT © Query Farm LLC — https://query.farm
