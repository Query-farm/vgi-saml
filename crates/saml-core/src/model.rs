//! The typed outputs of the engine — one struct per catalog function. The
//! `saml-worker` crate maps these onto Arrow `STRUCT` / `LIST` / `TABLE` shapes.
//! Timestamps are microseconds since the Unix epoch (UTC); `None` means absent.

/// `saml.decode(msg) -> STRUCT(...)` — the §A field map.
#[derive(Debug, Default, Clone)]
pub struct Decoded {
    pub message_type: Option<String>,
    pub response_id: Option<String>,
    pub assertion_id: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub subject_format: Option<String>,
    pub subject_sp_qualifier: Option<String>,
    pub confirmation_method: Option<String>,
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub subject_not_on_or_after: Option<i64>,
    pub not_before: Option<i64>,
    pub not_on_or_after: Option<i64>,
    pub audience: Option<String>,
    pub audiences: Vec<String>,
    pub authn_instant: Option<i64>,
    pub session_index: Option<String>,
    pub authn_context: Option<String>,
    pub status: Option<String>,
    pub destination: Option<String>,
    pub issue_instant: Option<i64>,
    pub version: Option<String>,
    pub assertion_count: u32,
    pub encrypted_count: u32,
    pub signed: bool,
}

/// One row of `saml.attributes(msg)`.
#[derive(Debug, Clone)]
pub struct AttributeRow {
    pub statement_idx: u32,
    pub name: Option<String>,
    pub name_format: Option<String>,
    pub friendly_name: Option<String>,
    pub value: Option<String>,
    pub value_type: Option<String>,
}

/// `saml.conditions(msg) -> STRUCT(...)`.
#[derive(Debug, Default, Clone)]
pub struct Conditions {
    pub not_before: Option<i64>,
    pub not_on_or_after: Option<i64>,
    pub audiences: Vec<String>,
    pub one_time_use: bool,
    pub proxy_restriction_count: u32,
    pub proxy_audiences: Vec<String>,
}

/// `saml.authn(msg) -> STRUCT(...)`.
#[derive(Debug, Default, Clone)]
pub struct Authn {
    pub authn_instant: Option<i64>,
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<i64>,
    pub class_ref: Option<String>,
    pub decl_ref: Option<String>,
    pub authenticating_authority: Option<String>,
}

/// One `Reference` inside a signature.
#[derive(Debug, Clone)]
pub struct Reference {
    pub uri: String,
    pub digest_method: String,
    pub digest_ok: bool,
    pub resolved_element: String,
}

/// `saml.signature(msg) -> STRUCT(...)` — the §B.1 schema for the outermost sig.
#[derive(Debug, Default, Clone)]
pub struct SignatureInfo {
    pub signed: bool,
    pub c14n_ok: bool,
    pub digest_ok: bool,
    pub sig_valid: bool,
    pub algo: Option<String>,
    pub c14n_method: Option<String>,
    pub digest_method: Option<String>,
    pub signer_cert: Option<Vec<u8>>,
    pub signer_cert_sha256: Option<String>,
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub references: Vec<Reference>,
}

/// One row of `saml.signatures(msg)` — every `Signature` in the document.
#[derive(Debug, Clone)]
pub struct SignatureRow {
    pub idx: u32,
    pub scope: String,
    pub references_id: Option<String>,
    pub signed_element: Option<String>,
    pub c14n_ok: bool,
    pub digest_ok: bool,
    pub sig_valid: bool,
    pub signer_cert_sha256: Option<String>,
}

/// One row of `saml.assertions(msg)`.
#[derive(Debug, Clone)]
pub struct AssertionRow {
    pub idx: u32,
    pub id: Option<String>,
    pub signed: bool,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub in_response_to: Option<String>,
    pub parent: Option<String>,
}
