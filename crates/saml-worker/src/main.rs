//! The `saml` VGI worker.
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
                 login telemetry. `anomalies()` flags the structural invariants every XSW1-XSW8 \
                 attack violates (multiple assertions, a signature that covers a different element \
                 than the consumer reads, duplicate/dangling reference IDs, an unsigned assertion \
                 inside a signed response, comment-splitting NameIDs, digest mismatches), while \
                 `signature()` hands you `signer_cert_sha256` so a `LEFT JOIN` against your \
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
                 verdict, it does not crash the scan. `well_formed()` reports the reason \
                 (`dtd-present` / `entity-blocked` double as XXE signals).\n\n\
                 **Function surface.** Scalars: `decode`, `conditions`, `authn`, `signature`, \
                 `anomalies`, `well_formed`, `message_type`, and the transport helpers \
                 `b64decode` / `inflate` / `unwrap`. Fan-out scalars returning `LIST<STRUCT>` (use \
                 `UNNEST(...)` over a column): `attributes` (explode attribute statements), \
                 `signatures` (every signature with its scope — the multi-sig view that makes XSW \
                 visible), and `assertions` (each assertion and its parent element). Pairs with \
                 `vgi-x509` (cert chains / CA trust), `vgi-jwt` / \
                 `vgi-cbor` (sibling token decoders), and `vgi-pii` / `vgi-mask` (scrub decoded \
                 NameIDs before sharing extracts). Part of the [Query.Farm](https://query.farm) \
                 VGI ecosystem of DuckDB workers — see the \
                 [source repository](https://github.com/Query-farm/vgi-saml)."
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
                        "worker_version",
                        "What version of the saml worker is running? Return one row, one column \
                         named version.",
                        "SELECT saml.main.saml_version() AS version",
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
                    "The single schema for the `saml` worker. It holds the decode functions \
                     (`decode`, `conditions`, `authn`, `attributes`, `assertions`, \
                     `message_type`), the XML-DSig verification functions (`signature`, \
                     `signatures`), the attack-detection function (`anomalies`), the \
                     hostile-input triage (`well_formed`), and the transport helpers \
                     (`b64decode`, `inflate`, `unwrap`)."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT saml.main.message_type('<samlp:Response \
                     xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>');\n\
                     SELECT (saml.main.well_formed('not a saml message')).kind;\n\
                     SELECT (saml.main.decode('<saml:Assertion \
                     xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                     <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>')).issuer;\n\
                     SELECT saml.main.b64decode('PHNhbWw+');\n\
                     SELECT len(saml.main.anomalies('<saml:Assertion \
                     xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>'));"
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

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "saml");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "saml".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
