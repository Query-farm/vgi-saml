//! The fan-out functions — `attributes`, `signatures`, `assertions` — as scalar
//! functions returning `LIST<STRUCT>`.
//!
//! ## Why scalar `LIST<STRUCT>` and not a table function
//!
//! These naturally fan one message into ≥0 rows, which the spec sketches as a
//! LATERAL table function (`FROM raw_saml r, LATERAL saml.attributes(r.msg) a`).
//! But DuckDB's table-function binder only accepts **literal constant**
//! arguments — a correlated column (`r.msg`) is rejected with "the function only
//! supports literals as parameters". So per-row fan-out **over a column** —
//! which is the entire point of bulk forensic SQL over millions of messages —
//! cannot be a table function. We deliver it as a scalar returning a
//! `LIST<STRUCT>` and the caller `UNNEST`s it, which *does* accept a correlated
//! column and yields the identical long-form result:
//!
//! ```sql
//! SELECT r.login_id, a.name, a.value
//! FROM raw_saml r, UNNEST(saml.main.attributes(r.saml_response)) AS _(a)
//! WHERE a.name = 'role';
//! ```

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, ListBuilder, StringBuilder, StructBuilder, UInt32Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::input_bytes;

fn list_of(fields: Fields) -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Struct(fields), true)))
}

fn list_builder(fields: Fields) -> ListBuilder<StructBuilder> {
    let sb = StructBuilder::from_fields(fields.clone(), 0);
    ListBuilder::new(sb).with_field(Arc::new(Field::new("item", DataType::Struct(fields), true)))
}

fn opt_str(b: &mut StructBuilder, idx: usize, v: &Option<String>) {
    let sb = b.field_builder::<StringBuilder>(idx).unwrap();
    match v {
        Some(s) => sb.append_value(s),
        None => sb.append_null(),
    }
}
fn put_str(b: &mut StructBuilder, idx: usize, v: &str) {
    b.field_builder::<StringBuilder>(idx)
        .unwrap()
        .append_value(v);
}
fn put_u32(b: &mut StructBuilder, idx: usize, v: u32) {
    b.field_builder::<UInt32Builder>(idx)
        .unwrap()
        .append_value(v);
}
fn put_bool(b: &mut StructBuilder, idx: usize, v: bool) {
    b.field_builder::<BooleanBuilder>(idx)
        .unwrap()
        .append_value(v);
}

fn msg_arg() -> Vec<ArgSpec> {
    vec![ArgSpec::any_column(
        "msg",
        0,
        "The SAML message (raw XML, base64, base64+DEFLATE, or URL-encoded). Fan its rows out with \
         UNNEST(...) over a column.",
    )]
}

// ------------------------------- attributes --------------------------------

pub fn attribute_fields() -> Fields {
    Fields::from(vec![
        Field::new("statement_idx", DataType::UInt32, true),
        Field::new("name", DataType::Utf8, true),
        Field::new("name_format", DataType::Utf8, true),
        Field::new("friendly_name", DataType::Utf8, true),
        Field::new("value", DataType::Utf8, true),
        Field::new("value_type", DataType::Utf8, true),
    ])
}

pub struct Attributes;

impl ScalarFunction for Attributes {
    fn name(&self) -> &str {
        "attributes"
    }
    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Explode SAML Attributes",
            "Return a SAML assertion's AttributeStatement(s) as a LIST<STRUCT(statement_idx, name, \
             name_format, friendly_name, value, value_type)>, one struct per AttributeValue. \
             UNNEST it to long form to pivot or join attributes downstream (multi-valued \
             attributes fan out): `FROM raw_saml r, UNNEST(saml.main.attributes(r.saml_response)) \
             AS _(a)`. Returns an empty list for a message with no attributes and NULL for a NULL \
             input.",
            "Return SAML attribute values as a `LIST<STRUCT(statement_idx, name, name_format, \
             friendly_name, value, value_type)>`; UNNEST to explode to long form.",
            "saml attributes, attributestatement, attributevalue, claims, roles, groups, explode, \
             unnest, long form, list of struct, pivot",
            "scalar/fanout.rs",
        );
        tags.push((
            "vgi.executable_examples".into(),
            r#"[
  {
    "description": "Explode a multi-valued attribute from a literal assertion into one row per value.",
    "sql": "SELECT a.name, a.value FROM UNNEST(saml.main.attributes('<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:AttributeStatement><saml:Attribute Name=\"role\"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>')) AS _(a) ORDER BY a.value"
  }
]"#
            .into(),
        ));
        FunctionMetadata {
            description:
                "Explode SAML attribute statements to a LIST<STRUCT> (statement_idx, name, \
                          name_format, friendly_name, value, value_type); UNNEST to long form"
                    .into(),
            return_type: Some(list_of(attribute_fields())),
            examples: vec![FunctionExample {
                sql: "SELECT a.name, a.value FROM raw_saml r, \
                      UNNEST(saml.main.attributes(r.saml_response)) AS _(a);"
                    .into(),
                description: "Explode each message's attributes to long form for joining.".into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        msg_arg()
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(list_of(attribute_fields())))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut lb = list_builder(attribute_fields());
        for i in 0..batch.num_rows() {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    for r in saml_core::api::attributes(&bytes) {
                        let sb = lb.values();
                        put_u32(sb, 0, r.statement_idx);
                        opt_str(sb, 1, &r.name);
                        opt_str(sb, 2, &r.name_format);
                        opt_str(sb, 3, &r.friendly_name);
                        opt_str(sb, 4, &r.value);
                        opt_str(sb, 5, &r.value_type);
                        sb.append(true);
                    }
                    lb.append(true);
                }
                None => lb.append(false),
            }
        }
        let arr: ArrayRef = Arc::new(lb.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// ------------------------------- signatures --------------------------------

pub fn signature_row_fields() -> Fields {
    Fields::from(vec![
        Field::new("idx", DataType::UInt32, true),
        Field::new("scope", DataType::Utf8, true),
        Field::new("references_id", DataType::Utf8, true),
        Field::new("signed_element", DataType::Utf8, true),
        Field::new("c14n_ok", DataType::Boolean, true),
        Field::new("digest_ok", DataType::Boolean, true),
        Field::new("sig_valid", DataType::Boolean, true),
        Field::new("signer_cert_sha256", DataType::Utf8, true),
    ])
}

pub struct Signatures;

impl ScalarFunction for Signatures {
    fn name(&self) -> &str {
        "signatures"
    }
    fn metadata(&self) -> FunctionMetadata {
        let tags = crate::meta::object_tags(
            "All SAML Signatures",
            "Return every ds:Signature in a SAML message as a LIST<STRUCT(idx, scope, \
             references_id, signed_element, c14n_ok, digest_ok, sig_valid, signer_cert_sha256)>, \
             one struct per signature. UNNEST it for the multi-signature view that makes XML \
             Signature Wrapping visible — a response with two assertions where only one is signed, \
             or a signature whose signed_element is not the element a consumer reads, jumps out: \
             `FROM raw_saml r, UNNEST(saml.main.signatures(r.saml_response)) AS _(s)`. Empty list \
             for an unsigned message; NULL for a NULL input.",
            "Return every signature as a `LIST<STRUCT(idx, scope, references_id, signed_element, \
             c14n_ok, digest_ok, sig_valid, signer_cert_sha256)>`; UNNEST for the XSW multi-sig \
             view.",
            "saml signatures, multi signature, xsw, signature wrapping, scope, signed element, \
             digest_ok, sig_valid, signer_cert_sha256, unnest, list of struct",
            "scalar/fanout.rs",
        );
        FunctionMetadata {
            description: "Return every signature in a SAML message as a LIST<STRUCT> (idx, scope, \
                          references_id, signed_element, c14n_ok, digest_ok, sig_valid, \
                          signer_cert_sha256); UNNEST for the multi-sig view"
                .into(),
            return_type: Some(list_of(signature_row_fields())),
            examples: vec![FunctionExample {
                sql: "SELECT s.* FROM raw_saml r, \
                      UNNEST(saml.main.signatures(r.saml_response)) AS _(s);"
                    .into(),
                description: "Enumerate every signature to spot wrapping.".into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        msg_arg()
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(list_of(signature_row_fields())))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut lb = list_builder(signature_row_fields());
        for i in 0..batch.num_rows() {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    for r in saml_core::api::signatures(&bytes) {
                        let sb = lb.values();
                        put_u32(sb, 0, r.idx);
                        put_str(sb, 1, &r.scope);
                        opt_str(sb, 2, &r.references_id);
                        opt_str(sb, 3, &r.signed_element);
                        put_bool(sb, 4, r.c14n_ok);
                        put_bool(sb, 5, r.digest_ok);
                        put_bool(sb, 6, r.sig_valid);
                        opt_str(sb, 7, &r.signer_cert_sha256);
                        sb.append(true);
                    }
                    lb.append(true);
                }
                None => lb.append(false),
            }
        }
        let arr: ArrayRef = Arc::new(lb.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// ------------------------------- assertions --------------------------------

pub fn assertion_row_fields() -> Fields {
    Fields::from(vec![
        Field::new("idx", DataType::UInt32, true),
        Field::new("id", DataType::Utf8, true),
        Field::new("signed", DataType::Boolean, true),
        Field::new("issuer", DataType::Utf8, true),
        Field::new("subject", DataType::Utf8, true),
        Field::new("in_response_to", DataType::Utf8, true),
        Field::new("parent", DataType::Utf8, true),
    ])
}

pub struct Assertions;

impl ScalarFunction for Assertions {
    fn name(&self) -> &str {
        "assertions"
    }
    fn metadata(&self) -> FunctionMetadata {
        let tags = crate::meta::object_tags(
            "List SAML Assertions",
            "Return every Assertion in a SAML message as a LIST<STRUCT(idx, id, signed, issuer, \
             subject, in_response_to, parent)>, one struct per assertion. UNNEST it to list \
             assertions with their parent element — a legitimate assertion is a child of the \
             Response, so an assertion parented under Extensions, Object, or another Assertion is \
             an XSW red flag: `FROM raw_saml r, UNNEST(saml.main.assertions(r.saml_response)) AS \
             _(a)`. Empty list for a message with no assertions; NULL for a NULL input.",
            "Return every assertion as a `LIST<STRUCT(idx, id, signed, issuer, subject, \
             in_response_to, parent)>`; UNNEST it (parent reveals wrapping).",
            "saml assertions, assertion list, wrapping, parent element, signed, issuer, subject, \
             nameid, xsw, unnest, list of struct",
            "scalar/fanout.rs",
        );
        FunctionMetadata {
            description: "Return every assertion as a LIST<STRUCT> (idx, id, signed, issuer, \
                          subject, in_response_to, parent); UNNEST it (parent reveals wrapping)"
                .into(),
            return_type: Some(list_of(assertion_row_fields())),
            examples: vec![FunctionExample {
                sql: "SELECT a.* FROM raw_saml r, \
                      UNNEST(saml.main.assertions(r.saml_response)) AS _(a);"
                    .into(),
                description: "Enumerate assertions and their parents to reveal wrapping.".into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        msg_arg()
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(list_of(assertion_row_fields())))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut lb = list_builder(assertion_row_fields());
        for i in 0..batch.num_rows() {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    for r in saml_core::api::assertions(&bytes) {
                        let sb = lb.values();
                        put_u32(sb, 0, r.idx);
                        opt_str(sb, 1, &r.id);
                        put_bool(sb, 2, r.signed);
                        opt_str(sb, 3, &r.issuer);
                        opt_str(sb, 4, &r.subject);
                        opt_str(sb, 5, &r.in_response_to);
                        opt_str(sb, 6, &r.parent);
                        sb.append(true);
                    }
                    lb.append(true);
                }
                None => lb.append(false),
            }
        }
        let arr: ArrayRef = Arc::new(lb.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
