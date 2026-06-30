//! Untrusted-input hardening: the parser and every analysis entry point must
//! **never panic** on arbitrary or truncated input — a hostile message returns
//! an error verdict / null-filled struct, it does not crash the scan.
//!
//! These are property-based zero-panic gates over the transport sniffer, the
//! hardened XML loader, and the decode / signature / detection chain. A panic
//! here fails the test; `cargo-fuzz` targets (see `fuzz/`) extend this with
//! coverage-guided exploration.

use proptest::prelude::*;
use saml_core::{attributes, authn, conditions, detect, message, signature, transport, xml};

/// Run the full chain over whatever XML string we managed to obtain — must not panic.
fn drive_xml(src: &str) {
    if let Ok(doc) = xml::parse(src) {
        let _ = message::message_type(&doc);
        let _ = message::decode(&doc);
        let _ = conditions::conditions(&doc);
        let _ = authn::authn(&doc);
        let _ = attributes::attributes(&doc);
        let _ = attributes::assertion_rows(&doc);
        let _ = signature::signature_info(&doc, src);
        let _ = signature::signature_rows(&doc, src);
        let _ = detect::anomalies(&doc, src);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Arbitrary bytes through the transport sniffer never panic.
    #[test]
    fn transport_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = transport::b64decode(&bytes);
        let _ = transport::inflate(&bytes);
        if let Ok(xml) = transport::normalize(&bytes) {
            drive_xml(&xml);
        }
    }

    /// Arbitrary UTF-8 strings through the XML loader + analysis never panic.
    #[test]
    fn xml_never_panics(s in ".{0,2048}") {
        drive_xml(&s);
        let _ = transport::unwrap(&s);
    }

    /// Mutating a known-good signed message — random byte flips and truncations —
    /// never panics (it just yields false/None verdicts).
    #[test]
    fn mutated_real_message_never_panics(
        cut in 0usize..6000,
        flip in proptest::collection::vec((0usize..6000, any::<u8>()), 0..32),
    ) {
        let base = std::fs::read("tests/vectors/signed_response_rsa.xml").unwrap();
        let mut bytes = base.clone();
        for (pos, b) in flip {
            if pos < bytes.len() {
                bytes[pos] ^= b;
            }
        }
        bytes.truncate(cut.min(bytes.len()));
        if let Ok(xml) = transport::normalize(&bytes) {
            drive_xml(&xml);
        } else if let Ok(s) = String::from_utf8(bytes) {
            drive_xml(&s);
        }
    }
}

/// A few fixed hostile inputs that must each parse-fail cleanly (no panic).
#[test]
fn pathological_fixed_inputs() {
    let cases: &[&[u8]] = &[
        b"",
        b"<",
        b"<a",
        b"<a>",
        b"<a></b>",
        b"<!DOCTYPE x>",
        b"\xff\xfe\x00\x00",
        b"<a xmlns:p=",
        b"<a p:b=\"c\"/>",
        b"<>><<<",
        b"PD94bWw+", // base64 of "<?xml>"
    ];
    for c in cases {
        let _ = transport::normalize(c);
        if let Ok(s) = std::str::from_utf8(c) {
            drive_xml(s);
        }
    }
}
