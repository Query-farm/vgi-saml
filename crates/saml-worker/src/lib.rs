//! The `saml` VGI worker (library).
//!
//! Function registration and catalog metadata live here so both entrypoints
//! share them verbatim: `main.rs` (the native binary, stdio/HTTP transport) and
//! the `saml-wasm` crate (the browser build, which serves the same `Worker`
//! over a SharedArrayBuffer byte channel instead).
//!
//! A standalone binary that DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'vgi-saml' AS saml (TYPE vgi)`). It decodes SAML 2.0 messages and
//! verifies their XML-DSig signatures (exclusive XML canonicalization, pure
//! Rust — no native xmlsec1), and surfaces XML Signature Wrapping (XSW) and
//! Golden-SAML detection signals — all as typed DuckDB rows under the catalog
//! `saml`, schema `main`:
//!
//! ```sql
//! ATTACH 'vgi-saml' AS saml (TYPE vgi, LOCATION './target/release/saml-worker');
//! SELECT (saml.main.decode(r.saml_response)).subject FROM raw_saml r;
//! SELECT (saml.main.signature(r.saml_response)).sig_valid FROM raw_saml r;
//! SELECT saml.main.anomalies(r.saml_response) FROM raw_saml r;
//! ```
//!
//! The pure decode/C14N/verify/detect engine lives in the `saml-core` crate; the
//! `scalar/` module here is a thin Arrow adapter over it.

mod arrow_io;
mod meta;
mod scalar;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// The worker's build version, published as the catalog's `implementation_version`
/// (VGI328: version belongs in catalog metadata, not a parameterless SQL function).
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata surfaced to DuckDB and the `vgi-lint` linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "SAML 2.0 decode + XML-DSig / exclusive-C14N signature verification + XSW / \
             Golden-SAML detection, in SQL."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "SAML Decode, Signature Verification & Attack Detection".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "saml, sso, saml response, assertion, xml-dsig, xml signature, \
                     exclusive c14n, canonicalization, xsw, signature wrapping, golden saml, \
                     dfir, iam forensics, idp, okta, adfs, entra, ping, shibboleth, keycloak",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Decode SAML 2.0 Responses and Assertions (base64 / DEFLATE / URL-encoded \
                 transport) into typed rows — subject, issuer, audience, the Conditions window, \
                 AuthnContext, and attribute statements — and verify their XML-DSig signatures \
                 using exclusive XML canonicalization against the embedded certificate. Surfaces \
                 XML Signature Wrapping (XSW) and Golden-SAML detection signals (signer cert \
                 fingerprint, digest/structure checks, anomaly flags) for bulk forensic SQL over \
                 SSO-token data. No network, no key store, no decryption."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# SAML — Decode, Signature Verification & Attack Detection in SQL\n\n\
                 **Shred and security-check SAML 2.0 single-sign-on messages directly in DuckDB.** \
                 The `saml` worker base64-decodes (and, for the HTTP-Redirect binding, raw-DEFLATE \
                 inflates) a column of `SAMLResponse` blobs, decodes them into typed rows — \
                 subject, issuer, audience, the `Conditions` validity window, `AuthnContext`, and \
                 attribute statements — and, more importantly, runs the **XML-DSig** structural \
                 check the one-off tools only do one message at a time: exclusive XML \
                 canonicalization (`xml-exc-c14n#`), per-`Reference` digest verification, and \
                 signature math (RSA / ECDSA / EdDSA) against the **embedded** certificate.\n\n\
                 The defensible value is **bulk security compute**: running **XML Signature \
                 Wrapping (XSW)** and **Golden-SAML** detection across millions of historical SAML \
                 messages in a forensic lake — in SQL, joinable against your IdP cert inventory and \
                 login telemetry. The worker flags the structural invariants every XSW1-XSW8 \
                 attack violates (multiple assertions, a signature that covers a different element \
                 than the consumer reads, duplicate/dangling reference IDs, an unsigned assertion \
                 inside a signed response, comment-splitting NameIDs, digest mismatches), and \
                 surfaces the signer certificate SHA-256 fingerprint so a left join against your \
                 known-good IdP certs surfaces the Golden-SAML smoking gun (a cryptographically \
                 perfect signature from a key you do not trust).\n\n\
                 **Trust stays with you.** `sig_valid = true` means the embedded cert signed these \
                 bytes — never that the cert is authorized. The worker holds no private keys, no \
                 trust store, makes no network calls, and decrypts nothing; an `EncryptedAssertion` \
                 is counted and flagged, not opened. All decode and canonicalization is local CPU \
                 on bytes you already hold, so it is safe for air-gapped / regulated forensic \
                 data.\n\n\
                 **Hardened against hostile input.** Every blob is attacker-controlled, so the XML \
                 loader rejects DTDs and entities unparsed (defeating XXE and \
                 billion-laughs/exponential-entity-expansion), bounds document size and inflate \
                 ratio (DEFLATE-bomb guard), and never panics — a hostile message returns an error \
                 verdict, it does not crash the scan. A well-formedness triage verdict reports the \
                 reason, and its dtd-present / entity-blocked kinds double as XXE and \
                 billion-laughs signals.\n\n\
                 **When to reach for it.** Use it whenever you already hold a column of raw or \
                 encoded SAML messages and need to shred, verify, or threat-hunt over them at \
                 warehouse scale rather than one message at a time in a browser plugin. The signer \
                 certificate SHA-256 fingerprint left-joins against your IdP cert inventory, and \
                 decoded NameIDs can be scrubbed before sharing extracts when the source data is \
                 sensitive."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    (
                        "message_kind",
                        "What kind of SAML message is this XML: \
                         '<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>'? \
                         Return one column named kind.",
                        "SELECT saml.main.message_type('<samlp:Response \
                         xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>') AS kind",
                    ),
                    (
                        "decode_issuer",
                        "Decode this assertion and return its issuer as a column named issuer: \
                         '<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
                         ID=\"_a\"><saml:Issuer>https://idp.example.com</saml:Issuer>\
                         </saml:Assertion>'.",
                        "SELECT (saml.main.decode('<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>'))\
                         .issuer AS issuer",
                    ),
                    (
                        "triage_kind",
                        "I have a blob that is supposed to be SAML but looks wrong: 'not a message'. \
                         Classify why. Return one column named kind.",
                        "SELECT (saml.main.well_formed('not a message')).kind AS kind",
                    ),
                    (
                        "anomalies_multi",
                        "This SAML Response carries two assertions. Does it show the \
                         'multiple-assertions' structural attack indicator? Return one boolean \
                         column named has_multi. XML: '<samlp:Response \
                         xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\">\
                         <saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com\
                         </saml:Issuer></saml:Assertion><saml:Assertion ID=\"_a2\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>\
                         </samlp:Response>'.",
                        "SELECT list_contains(saml.main.anomalies('<samlp:Response \
                         xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\">\
                         <saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com\
                         </saml:Issuer></saml:Assertion><saml:Assertion ID=\"_a2\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>\
                         </samlp:Response>'), 'multiple-assertions') AS has_multi",
                    ),
                    (
                        "count_assertions",
                        "How many assertions are inside this SAML Response? Return one column \
                         named n. XML: '<samlp:Response \
                         xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\">\
                         <saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com\
                         </saml:Issuer></saml:Assertion><saml:Assertion ID=\"_a2\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>\
                         </samlp:Response>'.",
                        "SELECT len(saml.main.assertions('<samlp:Response \
                         xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\">\
                         <saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com\
                         </saml:Issuer></saml:Assertion><saml:Assertion ID=\"_a2\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>\
                         </samlp:Response>')) AS n",
                    ),
                    (
                        "count_attribute_values",
                        "How many attribute values does this assertion's AttributeStatement \
                         contain? Return one column named n. XML: '<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
                         <saml:AttributeStatement><saml:Attribute Name=\"role\">\
                         <saml:AttributeValue>admin</saml:AttributeValue>\
                         <saml:AttributeValue>user</saml:AttributeValue></saml:Attribute>\
                         </saml:AttributeStatement></saml:Assertion>'.",
                        "SELECT len(saml.main.attributes('<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
                         <saml:AttributeStatement><saml:Attribute Name=\"role\">\
                         <saml:AttributeValue>admin</saml:AttributeValue>\
                         <saml:AttributeValue>user</saml:AttributeValue></saml:Attribute>\
                         </saml:AttributeStatement></saml:Assertion>')) AS n",
                    ),
                    (
                        "authn_class",
                        "What AuthnContext class reference did the identity provider assert in \
                         this assertion? Return one column named class_ref. XML: '<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:AuthnStatement AuthnInstant=\"2024-01-01T00:00:00Z\">\
                         <saml:AuthnContext><saml:AuthnContextClassRef>\
                         urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\
                         </saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>\
                         </saml:Assertion>'.",
                        "SELECT (saml.main.authn('<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:AuthnStatement AuthnInstant=\"2024-01-01T00:00:00Z\">\
                         <saml:AuthnContext><saml:AuthnContextClassRef>\
                         urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\
                         </saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>\
                         </saml:Assertion>')).class_ref AS class_ref",
                    ),
                    (
                        "b64decode_text",
                        "Base64-decode the string 'PHNhbWw+' and return its UTF-8 text as one \
                         column named decoded.",
                        "SELECT saml.main.b64decode('PHNhbWw+')::VARCHAR AS decoded",
                    ),
                    (
                        "conditions_window",
                        "Does this assertion's Conditions validity window stay open past the start \
                         of 2030? Return one boolean column named expires_after_2030. XML: \
                         '<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
                         ID=\"_a\"><saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" \
                         NotOnOrAfter=\"2035-06-01T00:00:00Z\"><saml:AudienceRestriction>\
                         <saml:Audience>https://sp.example.com</saml:Audience>\
                         </saml:AudienceRestriction></saml:Conditions></saml:Assertion>'.",
                        "SELECT ((saml.main.conditions('<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" \
                         NotOnOrAfter=\"2035-06-01T00:00:00Z\"><saml:AudienceRestriction>\
                         <saml:Audience>https://sp.example.com</saml:Audience>\
                         </saml:AudienceRestriction></saml:Conditions></saml:Assertion>'))\
                         .not_on_or_after > TIMESTAMPTZ '2030-01-01') AS expires_after_2030",
                    ),
                    (
                        "inflate_redirect",
                        "Base64-decode then raw-DEFLATE-inflate this HTTP-Redirect-binding \
                         SAMLRequest and return its XML text as one column named xml. Value: \
                         'sylOzM0psHIsLcnIC0otLE0tLlGoyM3JK7YCS9gqlRblWeUnFmcWW+Ul5qYWW5UkWwU7+vpYGekZWBUU5ZfkJ+fnKCl4utgqxRcZKunbAQA='.",
                        "SELECT saml.main.inflate(saml.main.b64decode('sylOzM0psHIsLcnIC0otLE0tLlGoyM3JK7YCS9gqlRblWeUnFmcWW+Ul5qYWW5UkWwU7+vpYGekZWBUU5ZfkJ+fnKCl4utgqxRcZKunbAQA=')) AS xml",
                    ),
                    (
                        "signature_valid",
                        "Is the embedded XML-DSig signature on this assertion internally valid? \
                         Return one boolean column named sig_valid. XML: '<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>'.",
                        "SELECT (saml.main.signature('<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>'))\
                         .sig_valid AS sig_valid",
                    ),
                    (
                        "count_signatures",
                        "How many XML-DSig signatures does this SAML message contain? Return one \
                         column named n. XML: '<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>'.",
                        "SELECT len(saml.main.signatures('<saml:Assertion \
                         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                         <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>')) \
                         AS n",
                    ),
                    (
                        "unwrap_transport",
                        "Recover the SAML XML from this URL-encoded, base64-wrapped transport \
                         parameter and return it as one column named xml. Value: \
                         'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiLz4%3D'.",
                        "SELECT saml.main.unwrap('PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiLz4%3D') AS xml",
                    ),
                ]),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-saml/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-saml/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-saml".to_string()),
        implementation_version: Some(version().to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "SAML decode, signature-verification, and XSW / Golden-SAML detection functions."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "SAML — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "saml, decode, signature, anomalies, conditions, authn, attributes, \
                         signatures, assertions, well_formed, message_type, b64decode, inflate, \
                         unwrap, xsw, golden saml, xml-dsig",
                    ),
                ),
                ("domain".to_string(), "security-and-identity".to_string()),
                ("category".to_string(), "saml-forensics".to_string()),
                ("topic".to_string(), "xml-signature-verification".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "SAML decode and XML-DSig verification functions: decode a message to a \
                     struct, explode attribute statements, read the Conditions window and \
                     AuthnContext, verify the signature (exclusive C14N + embedded-cert math), \
                     enumerate signatures and assertions, flag XSW / Golden-SAML anomalies, triage \
                     well-formedness, and decode the base64/DEFLATE/URL transport."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "SAML 2.0 forensic decoding and XML-DSig verification, in-database.\n\n\
                     ## What it does\n\n\
                     Turns an opaque SAML message — a base64 / DEFLATE / URL-encoded blob or raw \
                     XML — into typed, queryable rows, and independently re-verifies its \
                     cryptographic signature so you can trust (or distrust) what an identity \
                     provider asserted, without leaving SQL. Each capability is a separate \
                     function that takes one content-sniffed message argument (raw XML, base64, \
                     base64+DEFLATE, or a URL-encoded wrapper).\n\n\
                     ## Key concepts\n\n\
                     - **Signature verification is real, not implied.** The outermost XML-DSig \
                     signature is re-checked here — SignedInfo is re-canonicalized with exclusive \
                     C14N, per-Reference digests are recomputed, and SignatureValue is verified \
                     (RSA / ECDSA / EdDSA) against the certificate embedded in the message itself. \
                     A validity result reports whether that embedded key signed these exact bytes; \
                     it never asserts the key is trusted, so Golden-SAML detection is a downstream \
                     JOIN of the signer certificate SHA-256 fingerprint against your own IdP cert \
                     inventory. No key store, no network egress.\n\
                     - **Attack detection.** Structural red flags for XML Signature Wrapping (XSW) \
                     and Golden-SAML — multiple assertions, a signature that covers a different \
                     element than the consumer reads, duplicate/dangling reference IDs, digest \
                     mismatches, comment-splitting NameIDs — surface tampering a naive parser \
                     misses.\n\
                     - **Hostile-input safety.** Every entry point is total and panic-free, with \
                     DTD / entity expansion disabled (defeating XXE and billion-laughs) and \
                     decompression bomb-bounded.\n\n\
                     ## When to use\n\n\
                     Reach for this schema to audit or bulk-scan SAML responses and assertions \
                     offline: confirming who signed a message, reading its subject / issuer / \
                     audience / validity window / AuthnContext / attribute statements, checking \
                     whether its signature holds, and flagging attack fingerprints — over millions \
                     of historical messages, joinable against your cert inventory and login \
                     telemetry."
                        .to_string(),
                ),
                (
                    // VGI413: the ordered category registry that drives navigation / SEO;
                    // every object carries a `vgi.category` naming one of these names.
                    "vgi.categories".to_string(),
                    r#"[
  {"name":"Decode","description":"Parse SAML 2.0 messages into typed rows: message type, subject, issuer, audience, the Conditions validity window, AuthnContext, attribute statements, and assertions."},
  {"name":"Verify","description":"Verify XML-DSig signatures with exclusive XML canonicalization and per-Reference digests against the message's embedded certificate."},
  {"name":"Detect","description":"Surface XML Signature Wrapping (XSW) and Golden-SAML structural attack signals for bulk forensic scanning."},
  {"name":"Transport","description":"Decode the SAML transport envelope: base64, raw DEFLATE (HTTP-Redirect binding), and URL-encoding."},
  {"name":"Diagnostics","description":"Triage hostile or malformed input into a safe verdict and report the running worker build."}
]"#
                        .to_string(),
                ),
                // VGI515: a JSON list of {description, sql} so every schema-level
                // example query carries a human-readable description.
                (
                    "vgi.example_queries".to_string(),
                    r#"[
  {"description": "Identify a SAML message by its root element.", "sql": "SELECT saml.main.message_type('<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>') AS kind"},
  {"description": "Triage why a blob is not a usable SAML message.", "sql": "SELECT (saml.main.well_formed('not a saml message')).kind AS kind"},
  {"description": "Decode an assertion and read its issuer.", "sql": "SELECT (saml.main.decode('<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>')).issuer AS issuer"},
  {"description": "Base64-decode a SAMLResponse POST field to text.", "sql": "SELECT saml.main.b64decode('PHNhbWw+')::VARCHAR AS decoded"},
  {"description": "Count the structural anomaly flags on a message.", "sql": "SELECT len(saml.main.anomalies('<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>')) AS n"}
]"#
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

/// The catalog name, defaulting `VGI_WORKER_CATALOG_NAME` to `saml`. The catalog
/// name must match the ATTACH name.
pub fn catalog_name() -> String {
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "saml");
    }
    std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "saml".to_string())
}

/// Build the fully-registered worker (scalars + catalog metadata) shared by the
/// native binary and the browser (wasm) build. Does NOT call `.run()` — the
/// entrypoint chooses the transport.
pub fn build_worker() -> Worker {
    let name = catalog_name();
    let mut worker = Worker::new();
    scalar::register(&mut worker);
    worker.set_catalog(catalog_metadata(&name));
    worker
}
