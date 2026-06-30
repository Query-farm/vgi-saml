//! In-process Arrow-boundary tests: drive each scalar end to end (build the
//! input batch, run `on_bind` + `process`, inspect the result) without the
//! RPC/IPC plumbing. The deep correctness lives in `saml-core`; these assert the
//! Arrow marshalling (struct field agreement, null handling, types).

use super::*;
use crate::arrow_io::test_support::{bound_type, run_scalar_blob};
use arrow_array::cast::AsArray;
use arrow_array::Array;
use arrow_schema::DataType;

fn signed_response() -> Vec<u8> {
    std::fs::read("../saml-core/tests/vectors/signed_response_rsa.xml").unwrap()
}

#[test]
fn version_returns_string() {
    let out = run_scalar_blob(&version::SamlVersion, &[Some(b"x")]).unwrap();
    assert_eq!(out.as_string::<i32>().value(0), saml_core::version());
}

#[test]
fn message_type_binds_utf8_and_resolves() {
    assert_eq!(bound_type(&message_type::MessageType), DataType::Utf8);
    let resp = signed_response();
    let out = run_scalar_blob(
        &message_type::MessageType,
        &[Some(&resp), Some(b"garbage"), None],
    )
    .unwrap();
    let s = out.as_string::<i32>();
    assert_eq!(s.value(0), "Response");
    assert_eq!(s.value(1), "unknown");
    assert!(out.is_null(2));
}

#[test]
fn decode_struct_subject_and_signed() {
    assert!(matches!(bound_type(&decode::Decode), DataType::Struct(_)));
    let resp = signed_response();
    let out = run_scalar_blob(&decode::Decode, &[Some(&resp), None]).unwrap();
    let st = out.as_struct();
    // field 4 = subject (0:message_type 1:response_id 2:assertion_id 3:issuer 4:subject)
    let subject = st.column(4).as_string::<i32>();
    assert_eq!(subject.value(0), "alice@example.com");
    // Row 1 (NULL input) → null struct row.
    assert!(out.is_null(1));
}

#[test]
fn signature_struct_sig_valid_true_for_real_signature() {
    let resp = signed_response();
    let out = run_scalar_blob(&signature::Signature, &[Some(&resp)]).unwrap();
    let st = out.as_struct();
    // field order: 0 signed, 1 c14n_ok, 2 digest_ok, 3 sig_valid
    assert!(st.column(0).as_boolean().value(0), "signed");
    assert!(st.column(2).as_boolean().value(0), "digest_ok");
    assert!(st.column(3).as_boolean().value(0), "sig_valid");
    // references is the last child: LIST<STRUCT>
    let refs = st.column(11).as_list::<i32>();
    assert_eq!(refs.value(0).len(), 1, "one reference");
}

#[test]
fn anomalies_list_empty_for_clean_message() {
    assert_eq!(
        bound_type(&anomalies::Anomalies),
        crate::arrow_io::list_varchar_type()
    );
    let resp = signed_response();
    let out = run_scalar_blob(&anomalies::Anomalies, &[Some(&resp), None]).unwrap();
    let list = out.as_list::<i32>();
    assert_eq!(list.value(0).len(), 0, "clean message → no flags");
    assert!(out.is_null(1));
}

#[test]
fn well_formed_struct_kinds() {
    let out = run_scalar_blob(
        &well_formed::WellFormed,
        &[Some(b"<a/>"), Some(b"not xml at all !!!")],
    )
    .unwrap();
    let st = out.as_struct();
    let kind = st.column(1).as_string::<i32>();
    // "<a/>" parses but is not SAML → not-saml.
    assert_eq!(kind.value(0), "not-saml");
}

#[test]
fn conditions_and_authn_bind_structs() {
    assert!(matches!(
        bound_type(&conditions::Conditions),
        DataType::Struct(_)
    ));
    assert!(matches!(bound_type(&authn::AuthnFn), DataType::Struct(_)));
    let resp = signed_response();
    let out = run_scalar_blob(&conditions::Conditions, &[Some(&resp)]).unwrap();
    let st = out.as_struct();
    // field 2 = audiences LIST<VARCHAR>
    let aud = st.column(2).as_list::<i32>();
    assert_eq!(aud.value(0).len(), 1);
}

#[test]
fn b64decode_roundtrip() {
    let out = run_scalar_blob(&transport::B64Decode, &[Some(b"PHNhbWw+"), Some(b"!!!")]).unwrap();
    let b = out.as_binary::<i32>();
    assert_eq!(b.value(0), b"<saml>");
    assert!(out.is_null(1), "bad base64 → NULL");
}

#[test]
fn fanout_attributes_list_of_struct() {
    // The fan-out scalars return LIST<STRUCT>; assert the list+struct shape and
    // that the multi-valued `role` attribute fans out.
    assert!(matches!(bound_type(&fanout::Attributes), DataType::List(_)));
    let resp = signed_response();
    let out = run_scalar_blob(&fanout::Attributes, &[Some(&resp), None]).unwrap();
    let list = out.as_list::<i32>();
    // 3 AttributeValues (email, role=admin, role=user).
    assert_eq!(list.value(0).len(), 3);
    assert!(out.is_null(1), "NULL input → NULL list");
}

#[test]
fn fanout_assertions_and_signatures() {
    let resp = signed_response();
    let a = run_scalar_blob(&fanout::Assertions, &[Some(&resp)]).unwrap();
    assert_eq!(a.as_list::<i32>().value(0).len(), 1, "one assertion");
    let s = run_scalar_blob(&fanout::Signatures, &[Some(&resp)]).unwrap();
    assert_eq!(s.as_list::<i32>().value(0).len(), 1, "one signature");
}
