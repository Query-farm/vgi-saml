//! Byte-level convenience API: the full `normalize → hardened-parse → analyze`
//! chain behind one call per catalog function. The worker calls these so it
//! never needs to touch roxmltree (or the borrow dance between a parsed document
//! and its backing source string). Every function is total — hostile input maps
//! to `None` / an empty `Vec` / a `false`-filled struct, never a panic.

use crate::model::{AssertionRow, Authn, Conditions, Decoded, SignatureInfo, SignatureRow};
use crate::wellformed::{WellFormed, WfKind};
use crate::{attributes, authn, conditions, detect, message, signature, transport, xml};

// Re-export the row/struct types the worker marshals, so it depends only on
// `saml_core::api::*`.
pub use crate::model::{AttributeRow, Reference};

/// Internal: normalize bytes to XML text and hardened-parse, mapping each
/// failure to a [`WfKind`].
fn load(bytes: &[u8]) -> Result<String, WfKind> {
    transport::normalize(bytes)
}

/// `saml.well_formed(msg)` — the `(ok, kind, detail)` triage verdict.
pub fn well_formed(bytes: &[u8]) -> WellFormed {
    let src = match load(bytes) {
        Ok(s) => s,
        Err(k) => return WellFormed::err(k, "input did not decode to XML"),
    };
    match xml::parse(&src) {
        Err(k) => WellFormed::err(k, "XML did not parse under the hardened loader"),
        Ok(doc) => {
            if message::message_type(&doc) == "unknown" {
                WellFormed::err(
                    WfKind::NotSaml,
                    "root element is not a recognized SAML message",
                )
            } else {
                WellFormed::ok()
            }
        }
    }
}

/// `saml.message_type(msg)` — root-element discriminator (`unknown` on failure).
pub fn message_type(bytes: &[u8]) -> String {
    match load(bytes).ok().and_then(|src| {
        xml::parse(&src)
            .ok()
            .map(|doc| message::message_type(&doc).to_string())
    }) {
        Some(t) => t,
        None => "unknown".to_string(),
    }
}

/// `saml.decode(msg)` — never errors: a struct with null fields + `signed=false`.
pub fn decode(bytes: &[u8]) -> Decoded {
    load(bytes)
        .ok()
        .and_then(|src| xml::parse(&src).ok().map(|doc| message::decode(&doc)))
        .unwrap_or_default()
}

/// `saml.conditions(msg)` — `None` when the document does not parse.
pub fn conditions(bytes: &[u8]) -> Option<Conditions> {
    let src = load(bytes).ok()?;
    let doc = xml::parse(&src).ok()?;
    Some(conditions::conditions(&doc))
}

/// `saml.authn(msg)` — `None` when the document does not parse.
pub fn authn(bytes: &[u8]) -> Option<Authn> {
    let src = load(bytes).ok()?;
    let doc = xml::parse(&src).ok()?;
    Some(authn::authn(&doc))
}

/// `saml.signature(msg)` — the outermost signature (`signed=false` on failure).
pub fn signature(bytes: &[u8]) -> SignatureInfo {
    load(bytes)
        .ok()
        .and_then(|src| {
            xml::parse(&src)
                .ok()
                .map(|doc| signature::signature_info(&doc, &src))
        })
        .unwrap_or_default()
}

/// `saml.signatures(msg)` — every signature in the document.
pub fn signatures(bytes: &[u8]) -> Vec<SignatureRow> {
    load(bytes)
        .ok()
        .and_then(|src| {
            xml::parse(&src)
                .ok()
                .map(|doc| signature::signature_rows(&doc, &src))
        })
        .unwrap_or_default()
}

/// `saml.anomalies(msg)` — XSW / structural flag set (empty on failure).
pub fn anomalies(bytes: &[u8]) -> Vec<String> {
    load(bytes)
        .ok()
        .and_then(|src| {
            xml::parse(&src)
                .ok()
                .map(|doc| detect::anomalies(&doc, &src))
        })
        .unwrap_or_default()
}

/// `saml.attributes(msg)` — one row per `AttributeValue` (empty on failure).
pub fn attributes(bytes: &[u8]) -> Vec<AttributeRow> {
    load(bytes)
        .ok()
        .and_then(|src| {
            xml::parse(&src)
                .ok()
                .map(|doc| attributes::attributes(&doc))
        })
        .unwrap_or_default()
}

/// `saml.assertions(msg)` — one row per `Assertion` (empty on failure).
pub fn assertions(bytes: &[u8]) -> Vec<AssertionRow> {
    load(bytes)
        .ok()
        .and_then(|src| {
            xml::parse(&src)
                .ok()
                .map(|doc| attributes::assertion_rows(&doc))
        })
        .unwrap_or_default()
}
