//! Validate exclusive C14N against signxml/lxml-produced golden vectors: the
//! digest we compute over the canonicalized (enveloped-transform-applied)
//! referenced element MUST equal the `DigestValue` a real XML-DSig signer wrote.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_core::c14n::exclusive_c14n;
use sha2::{Digest, Sha256};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const ASSERT_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

fn digest_matches(path: &str) {
    let src = std::fs::read_to_string(path).unwrap();
    let doc = saml_core::xml::parse(&src).unwrap();

    // Find the signed Assertion and its enveloped Signature.
    let assertion = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Assertion")
        .expect("assertion");
    let signature = assertion
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .expect("enveloped signature");

    // Pull the Reference's DigestValue written by the signer.
    let digest_value = signature
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "DigestValue")
        .and_then(|n| n.text())
        .expect("DigestValue")
        .trim()
        .to_string();

    // Enveloped transform = canonicalize the Assertion with the Signature removed.
    let canon = exclusive_c14n(assertion, &src, Some(signature.id()), &[]);
    let mut h = Sha256::new();
    h.update(&canon);
    let got = STANDARD.encode(h.finalize());

    assert_eq!(got, digest_value, "digest mismatch for {path}");
    let _ = (DS, ASSERT_NS);
}

#[test]
fn rsa_assertion_digest_matches_signxml() {
    digest_matches("tests/vectors/signed_assertion_rsa.xml");
    digest_matches("tests/vectors/signed_response_rsa.xml");
}

#[test]
fn ec_assertion_digest_matches_signxml() {
    digest_matches("tests/vectors/signed_assertion_ec.xml");
    digest_matches("tests/vectors/signed_response_ec.xml");
}
