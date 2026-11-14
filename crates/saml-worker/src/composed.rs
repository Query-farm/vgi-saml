//! Composed example queries: realistic SQL that combines two or more of the
//! worker's own functions in one query (a fan-out joined to another fan-out, a
//! triage gate in front of the decoders, a per-message security verdict).
//!
//! Each query is defined exactly once here and referenced from both the
//! schema-level `vgi.example_queries` list (`lib.rs`) and the example list of
//! the function that drives it (that function's first five examples are what
//! the vgi-lint agent simulator shows). Every query is self-contained (literal
//! SAML), offline, and deterministic.

use vgi::FunctionExample;

/// Build a [`FunctionExample`] from a `(description, sql)` pair.
pub fn example((description, sql): (&str, &str)) -> FunctionExample {
    FunctionExample {
        sql: sql.into(),
        description: description.into(),
        expected_output: None,
    }
}

/// XSW coverage check — `assertions` LEFT JOIN `signatures` on the signed
/// Reference ID. Driven by `assertions`.
pub const UNSIGNED_ASSERTIONS: (&str, &str) = (
    "XSW coverage check: list every assertion in a Response next to the signature (if any) whose Reference points at it; the wrapped evil assertion _evil shows no covering signature.",
    "WITH m AS (SELECT '<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" ID=\"_r\"><saml:Assertion ID=\"_evil\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion><saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com</saml:Issuer><ds:Signature><ds:SignedInfo><ds:Reference URI=\"#_a1\"/></ds:SignedInfo></ds:Signature><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>' AS msg), asr AS (SELECT a.* FROM m, UNNEST(saml.main.assertions(m.msg)) AS _(a)), sig AS (SELECT s.* FROM m, UNNEST(saml.main.signatures(m.msg)) AS _(s)) SELECT asr.idx, asr.id, asr.subject, sig.idx AS covering_signature FROM asr LEFT JOIN sig ON sig.references_id = asr.id ORDER BY asr.idx",
);

/// Triage gate in front of the decoders — `well_formed` decides, then
/// `message_type` + `decode` read only the usable blobs. Driven by `well_formed`.
pub const TRIAGE_THEN_DECODE: (&str, &str) = (
    "Triage a batch of blobs before decoding: well_formed classifies each one, and only the usable messages are passed on to message_type and decode for their issuer.",
    "SELECT t.blob_id, (saml.main.well_formed(t.blob)).kind AS triage, CASE WHEN (saml.main.well_formed(t.blob)).ok THEN saml.main.message_type(t.blob) END AS msg_type, CASE WHEN (saml.main.well_formed(t.blob)).ok THEN (saml.main.decode(t.blob)).issuer END AS issuer FROM (VALUES (1, '<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>'), (2, 'not a saml message'), (3, '<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>')) AS t(blob_id, blob) ORDER BY t.blob_id",
);

/// Per-login security verdict — `decode` (who/what), `signature` (signed?) and
/// `anomalies` (structural flags) in one row per message. Driven by `anomalies`.
pub const LOGIN_VERDICT: (&str, &str) = (
    "Per-login security verdict: who each message claims to be (decode), whether it carries a signature (signature), and which XSW flags fire (anomalies); only the two-assertion response is flagged.",
    "WITH logins AS (SELECT * FROM (VALUES ('login-1', '<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion>'), ('login-2', '<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\"><saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject></saml:Assertion><saml:Assertion ID=\"_a2\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>')) AS v(login_id, msg)) SELECT login_id, (saml.main.decode(msg)).subject AS subject, (saml.main.signature(msg)).signed AS signed, saml.main.anomalies(msg) AS flags FROM logins ORDER BY login_id",
);

/// Who holds which role — `decode` for the subject + `attributes` fanned out
/// and re-aggregated per subject. Driven by `attributes`.
pub const SUBJECT_ROLES: (&str, &str) = (
    "Roll a multi-valued role attribute up per subject: decode supplies the NameID and the attributes fan-out supplies each role value.",
    "WITH m AS (SELECT '<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\"><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name=\"role\"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"dept\"><saml:AttributeValue>finance</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>' AS msg) SELECT (saml.main.decode(m.msg)).subject AS subject, list_sort(list(a.value)) AS roles FROM m, UNNEST(saml.main.attributes(m.msg)) AS _(a) WHERE a.name = 'role' GROUP BY ALL ORDER BY subject",
);

/// Every composed example, in schema-level order.
pub const ALL: [(&str, &str); 4] = [
    UNSIGNED_ASSERTIONS,
    TRIAGE_THEN_DECODE,
    LOGIN_VERDICT,
    SUBJECT_ROLES,
];
