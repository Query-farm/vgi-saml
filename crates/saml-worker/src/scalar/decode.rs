//! `saml.decode(msg) -> STRUCT(...)` — the §A field map. Accepts raw XML,
//! base64, base64+DEFLATE, or URL-encoded; content-sniffs and normalizes. Never
//! errors on malformed input — returns a struct with null fields and
//! `signed=false` (use `well_formed` for the reason).

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, ListBuilder, StringBuilder, UInt32Builder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{input_bytes, list_varchar_type, ts_array, ts_type};

pub fn fields() -> Fields {
    let s = |n: &str| Field::new(n, DataType::Utf8, true);
    let t = |n: &str| Field::new(n, ts_type(), true);
    Fields::from(vec![
        s("message_type"),
        s("response_id"),
        s("assertion_id"),
        s("issuer"),
        s("subject"),
        s("subject_format"),
        s("subject_sp_qualifier"),
        s("confirmation_method"),
        s("recipient"),
        s("in_response_to"),
        t("subject_not_on_or_after"),
        t("not_before"),
        t("not_on_or_after"),
        s("audience"),
        Field::new("audiences", list_varchar_type(), true),
        t("authn_instant"),
        s("session_index"),
        s("authn_context"),
        s("status"),
        s("destination"),
        t("issue_instant"),
        s("version"),
        Field::new("assertion_count", DataType::UInt32, true),
        Field::new("encrypted_count", DataType::UInt32, true),
        Field::new("signed", DataType::Boolean, true),
    ])
}

pub struct Decode;

impl ScalarFunction for Decode {
    fn name(&self) -> &str {
        "decode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT (saml.main.decode('<saml:Assertion \
                  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                  <saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject>\
                  <saml:NameID>alice@example.com</saml:NameID></saml:Subject>\
                  </saml:Assertion>')).subject;"
                .into(),
            description: "Decode a SAML assertion to its subject + core fields.".into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "Decode SAML Message",
            "Decode a SAML 2.0 Response or Assertion to a struct of its core fields — \
             response_id / assertion_id, issuer, subject (+ NameID format and SP qualifier), \
             SubjectConfirmation recipient / in_response_to, the Conditions NotBefore / \
             NotOnOrAfter window, audience(s), AuthnInstant / SessionIndex / AuthnContext class, \
             Status, Destination, IssueInstant, Version, the assertion/encrypted counts, and \
             whether a top-level Signature is present. The input is content-sniffed: it accepts \
             raw XML, base64 (HTTP-POST binding), base64+raw-DEFLATE (HTTP-Redirect binding), \
             or a URL-encoded wrapper. It never errors on malformed input — a bad blob yields a \
             struct with null fields and signed=false (call well_formed for the reason). \
             Timestamps are `TIMESTAMPTZ` (UTC); the worker surfaces the window but does not \
             decide 'expired'.",
            "Decode a SAML Response/Assertion to a struct of subject, issuer, audience, the \
             validity window, authn context, status, ids and counts; null fields on bad input.",
            "decode saml, samlresponse, assertion, subject, issuer, audience, nameid, \
             conditions, authn context, status, base64, deflate, redirect binding, post binding",
            "Decode",
            "scalar/decode.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description: "Decode a SAML message (raw XML / base64 / base64+DEFLATE / URL-encoded) \
                          to a STRUCT of core fields: subject, issuer, audience, conditions window, \
                          authn_context, status, ids, counts, and signed. Never errors on bad \
                          input — returns null fields + signed=false (see well_formed)."
                .into(),
            examples,
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "msg",
            0,
            "The SAML message to decode: raw XML, base64, base64+DEFLATE (HTTP-Redirect), or a \
             URL-encoded wrapper. Content-sniffed automatically; malformed input yields null \
             fields, not an error.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        // String columns (in field order, minus timestamps/list/counts/signed).
        let mut message_type = StringBuilder::new();
        let mut response_id = StringBuilder::new();
        let mut assertion_id = StringBuilder::new();
        let mut issuer = StringBuilder::new();
        let mut subject = StringBuilder::new();
        let mut subject_format = StringBuilder::new();
        let mut subject_sp_qualifier = StringBuilder::new();
        let mut confirmation_method = StringBuilder::new();
        let mut recipient = StringBuilder::new();
        let mut in_response_to = StringBuilder::new();
        let mut audience = StringBuilder::new();
        let mut session_index = StringBuilder::new();
        let mut authn_context = StringBuilder::new();
        let mut status = StringBuilder::new();
        let mut destination = StringBuilder::new();
        let mut version = StringBuilder::new();
        let mut subject_noa = Vec::with_capacity(rows);
        let mut not_before = Vec::with_capacity(rows);
        let mut not_after = Vec::with_capacity(rows);
        let mut authn_instant = Vec::with_capacity(rows);
        let mut issue_instant = Vec::with_capacity(rows);
        let mut audiences = ListBuilder::new(StringBuilder::new())
            .with_field(Arc::new(Field::new("item", DataType::Utf8, true)));
        let mut assertion_count = UInt32Builder::new();
        let mut encrypted_count = UInt32Builder::new();
        let mut signed = BooleanBuilder::new();
        let mut valid = Vec::with_capacity(rows);

        let opt = |b: &mut StringBuilder, v: &Option<String>| match v {
            Some(s) => b.append_value(s),
            None => b.append_null(),
        };

        for i in 0..rows {
            let Some(bytes) = input_bytes(col, i)? else {
                // NULL input → null struct row; still feed every child once.
                message_type.append_null();
                response_id.append_null();
                assertion_id.append_null();
                issuer.append_null();
                subject.append_null();
                subject_format.append_null();
                subject_sp_qualifier.append_null();
                confirmation_method.append_null();
                recipient.append_null();
                in_response_to.append_null();
                audience.append_null();
                session_index.append_null();
                authn_context.append_null();
                status.append_null();
                destination.append_null();
                version.append_null();
                subject_noa.push(None);
                not_before.push(None);
                not_after.push(None);
                authn_instant.push(None);
                issue_instant.push(None);
                audiences.append(false);
                assertion_count.append_null();
                encrypted_count.append_null();
                signed.append_null();
                valid.push(false);
                continue;
            };

            // Non-null input always yields a non-null struct (fields may be null).
            let d = saml_core::api::decode(&bytes);
            opt(&mut message_type, &d.message_type);
            opt(&mut response_id, &d.response_id);
            opt(&mut assertion_id, &d.assertion_id);
            opt(&mut issuer, &d.issuer);
            opt(&mut subject, &d.subject);
            opt(&mut subject_format, &d.subject_format);
            opt(&mut subject_sp_qualifier, &d.subject_sp_qualifier);
            opt(&mut confirmation_method, &d.confirmation_method);
            opt(&mut recipient, &d.recipient);
            opt(&mut in_response_to, &d.in_response_to);
            opt(&mut audience, &d.audience);
            opt(&mut session_index, &d.session_index);
            opt(&mut authn_context, &d.authn_context);
            opt(&mut status, &d.status);
            opt(&mut destination, &d.destination);
            opt(&mut version, &d.version);
            subject_noa.push(d.subject_not_on_or_after);
            not_before.push(d.not_before);
            not_after.push(d.not_on_or_after);
            authn_instant.push(d.authn_instant);
            issue_instant.push(d.issue_instant);
            for a in &d.audiences {
                audiences.values().append_value(a);
            }
            audiences.append(true);
            assertion_count.append_value(d.assertion_count);
            encrypted_count.append_value(d.encrypted_count);
            signed.append_value(d.signed);
            valid.push(true);
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(message_type.finish()),
            Arc::new(response_id.finish()),
            Arc::new(assertion_id.finish()),
            Arc::new(issuer.finish()),
            Arc::new(subject.finish()),
            Arc::new(subject_format.finish()),
            Arc::new(subject_sp_qualifier.finish()),
            Arc::new(confirmation_method.finish()),
            Arc::new(recipient.finish()),
            Arc::new(in_response_to.finish()),
            ts_array(subject_noa),
            ts_array(not_before),
            ts_array(not_after),
            Arc::new(audience.finish()),
            Arc::new(audiences.finish()),
            ts_array(authn_instant),
            Arc::new(session_index.finish()),
            Arc::new(authn_context.finish()),
            Arc::new(status.finish()),
            Arc::new(destination.finish()),
            ts_array(issue_instant),
            Arc::new(version.finish()),
            Arc::new(assertion_count.finish()),
            Arc::new(encrypted_count.finish()),
            Arc::new(signed.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
