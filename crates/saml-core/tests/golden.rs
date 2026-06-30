//! End-to-end engine tests against the signxml/lxml-produced golden corpus and
//! hand-built attack variants. The crypto path (`sig_valid`) is validated
//! against *real* RSA-SHA256 / ECDSA-P256 signatures, and the detection path
//! against tampered + signature-wrapping fixtures.

use saml_core::{detect, message, signature, transport, xml};

fn load(name: &str) -> String {
    std::fs::read_to_string(format!("tests/vectors/{name}")).unwrap()
}

fn parse(name: &str) -> String {
    // normalize then return the XML text (most vectors are raw XML already)
    let bytes = std::fs::read(format!("tests/vectors/{name}")).unwrap();
    transport::normalize(&bytes).unwrap()
}

#[test]
fn decode_signed_response() {
    let src = load("signed_response_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let d = message::decode(&doc);
    assert_eq!(d.message_type.as_deref(), Some("Response"));
    assert_eq!(d.subject.as_deref(), Some("alice@example.com"));
    assert_eq!(d.issuer.as_deref(), Some("https://idp.example.com/saml"));
    assert_eq!(d.audience.as_deref(), Some("https://sp.example.com"));
    assert_eq!(
        d.authn_context.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    );
    assert!(d.not_before.is_some() && d.not_on_or_after.is_some());
    assert_eq!(d.assertion_count, 1);
    assert_eq!(
        d.status.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:status:Success")
    );
}

#[test]
fn attributes_fan_out() {
    let src = load("signed_response_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let rows = saml_core::attributes::attributes(&doc);
    // email (1) + role (admin, user) = 3 values
    assert_eq!(rows.len(), 3);
    let role: Vec<_> = rows
        .iter()
        .filter(|r| r.name.as_deref() == Some("role"))
        .collect();
    assert_eq!(role.len(), 2);
    let vals: Vec<_> = role.iter().filter_map(|r| r.value.as_deref()).collect();
    assert!(vals.contains(&"admin") && vals.contains(&"user"));
}

#[test]
fn conditions_and_authn() {
    let src = load("signed_response_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let c = saml_core::conditions::conditions(&doc);
    assert_eq!(c.audiences, vec!["https://sp.example.com".to_string()]);
    assert!(c.not_before.unwrap() < c.not_on_or_after.unwrap());
    let a = saml_core::authn::authn(&doc);
    assert_eq!(a.session_index.as_deref(), Some("_sess123"));
    assert!(a.session_not_on_or_after.is_some());
}

#[test]
fn rsa_signature_fully_valid() {
    let src = load("signed_response_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let s = signature::signature_info(&doc, &src);
    assert!(s.signed);
    assert!(s.c14n_ok, "SignedInfo must canonicalize");
    assert!(s.digest_ok, "reference digest must match");
    assert!(s.sig_valid, "embedded RSA cert must verify SignedInfo");
    assert_eq!(s.algo.as_deref(), Some("RS256"));
    let want = load("cert_rsa.sha256");
    assert_eq!(s.signer_cert_sha256.as_deref(), Some(want.trim()));
    assert!(detect::anomalies(&doc, &src).is_empty());
}

#[test]
fn ec_signature_fully_valid() {
    let src = load("signed_response_ec.xml");
    let doc = xml::parse(&src).unwrap();
    let s = signature::signature_info(&doc, &src);
    assert!(s.sig_valid, "embedded ECDSA cert must verify SignedInfo");
    assert_eq!(s.algo.as_deref(), Some("ES256"));
    let want = load("cert_ec.sha256");
    assert_eq!(s.signer_cert_sha256.as_deref(), Some(want.trim()));
}

#[test]
fn tampered_response_digest_breaks_but_signedinfo_still_verifies() {
    // The classic Golden-SAML-adjacent split: SignatureValue still verifies over
    // the (unchanged) SignedInfo, but the recomputed digest of the tampered
    // assertion no longer matches the DigestValue.
    let src = load("tampered_response_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let s = signature::signature_info(&doc, &src);
    assert!(s.signed);
    assert!(!s.digest_ok, "tamper must break the reference digest");
    assert!(
        s.sig_valid,
        "SignedInfo itself is untouched, so it still verifies"
    );
    let flags = detect::anomalies(&doc, &src);
    assert!(
        flags.contains(&"digest-mismatch".to_string()),
        "flags = {flags:?}"
    );
}

#[test]
fn xsw3_is_flagged() {
    let src = load("xsw3_response_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let flags = detect::anomalies(&doc, &src);
    assert!(
        flags.contains(&"multiple-assertions".to_string()),
        "flags = {flags:?}"
    );
    assert!(
        flags.contains(&"signature-covers-other-element".to_string()),
        "flags = {flags:?}"
    );
}

#[test]
fn comment_splicing_is_flagged() {
    let src = load("comment_splice_rsa.xml");
    let doc = xml::parse(&src).unwrap();
    let flags = detect::anomalies(&doc, &src);
    assert!(
        flags.contains(&"nameid-comment-splitting".to_string()),
        "flags = {flags:?}"
    );
}

#[test]
fn unsigned_response_has_no_signature() {
    let src = load("unsigned_response.xml");
    let doc = xml::parse(&src).unwrap();
    let s = signature::signature_info(&doc, &src);
    assert!(!s.signed);
    let d = message::decode(&doc);
    assert!(!d.signed);
}

#[test]
fn message_type_discriminates() {
    let src = load("authnrequest.xml");
    let doc = xml::parse(&src).unwrap();
    assert_eq!(message::message_type(&doc), "AuthnRequest");
}

#[test]
fn redirect_binding_b64_deflate_roundtrips() {
    // base64 + raw DEFLATE (HTTP-Redirect) → normalized XML, then decode.
    let xml = parse("signed_response_rsa.deflate.b64");
    assert!(xml.starts_with("<samlp:Response") || xml.contains("Response"));
    let doc = xml::parse(&xml).unwrap();
    assert_eq!(message::message_type(&doc), "Response");
}

#[test]
fn post_binding_b64_roundtrips() {
    let xml = parse("signed_response_rsa.b64");
    let doc = xml::parse(&xml).unwrap();
    let s = signature::signature_info(&doc, &xml);
    assert!(s.sig_valid);
}

#[test]
fn xxe_and_billion_laughs_are_rejected_unparsed() {
    for name in ["xxe.xml", "billion_laughs.xml"] {
        let src = load(name);
        let err = xml::parse(&src).unwrap_err();
        // DOCTYPE present → rejected before any entity expansion.
        assert_eq!(err, saml_core::WfKind::DtdPresent, "{name}");
    }
}
