//! `saml-core` — the pure-compute SAML 2.0 engine behind the `vgi-saml` worker.
//!
//! No Arrow, no VGI, no network, no key store: every entry point is a stateless
//! transform from an attacker-controlled byte slice to typed Rust values, and
//! **never panics** on hostile input. The Arrow/VGI marshalling lives in the
//! sibling `saml-worker` crate.
//!
//! Module map:
//! * [`transport`] — base64 + raw-DEFLATE + URL-decode, content-sniffed, bounded.
//! * [`xml`] — the hardened (DTD-off, entity-off, bounded) read-only loader.
//! * [`c14n`] — exclusive XML canonicalization + the enveloped-signature transform.
//! * [`cert`] — signer-cert parse, SHA-256 fingerprint, signature math.
//! * [`signature`] — per-`Reference` digest + `SignedInfo` verify pipeline.
//! * [`detect`] — XSW / Golden-SAML structural & forensic signals.
//! * decode side: [`message`], [`attributes`], [`conditions`], [`authn`].
//! * [`wellformed`] — the `(ok, kind, detail)` triage verdict.

#![forbid(unsafe_code)]

pub mod api;
pub mod attributes;
pub mod authn;
pub mod c14n;
pub mod cert;
pub mod conditions;
pub mod detect;
pub mod message;
pub mod model;
pub mod signature;
pub mod time;
pub mod transport;
pub mod wellformed;
pub mod xml;

/// Shared XML navigation helpers used across the decode/detect modules.
pub(crate) mod xmlutil;

/// Worker version (the crate version), surfaced by `saml_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub use wellformed::{WellFormed, WfKind};
