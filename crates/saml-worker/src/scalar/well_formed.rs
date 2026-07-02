//! `saml.well_formed(msg) -> STRUCT(ok BOOL, kind VARCHAR, detail VARCHAR)`.
//!
//! `kind ∈ {ok, not-xml, not-saml, bad-base64, bad-deflate, dtd-present,
//! entity-blocked, truncated, encoding-error}`. `dtd-present` / `entity-blocked`
//! double as XXE / billion-laughs signals. Never panics.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::input_bytes;

pub fn fields() -> Fields {
    Fields::from(vec![
        Field::new("ok", DataType::Boolean, true),
        Field::new("kind", DataType::Utf8, true),
        Field::new("detail", DataType::Utf8, true),
    ])
}

pub struct WellFormed;

impl ScalarFunction for WellFormed {
    fn name(&self) -> &str {
        "well_formed"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Triage a SAML blob into STRUCT(ok BOOL, kind VARCHAR, detail VARCHAR); \
                          kind is one of ok / not-xml / not-saml / bad-base64 / bad-deflate / \
                          dtd-present / entity-blocked / truncated / encoding-error. Never panics."
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT (saml.main.well_formed('not a saml message')).kind;".into(),
                description: "Classify why a blob is not a usable SAML message (kind = \
                              'not-saml' here)."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "SAML Well-Formedness",
                "Classify an attacker-controlled blob into a (ok, kind, detail) triage verdict \
                 without ever panicking. `kind` is one of ok, not-xml, not-saml, bad-base64, \
                 bad-deflate, dtd-present, entity-blocked, truncated, or encoding-error. The \
                 dtd-present and entity-blocked kinds double as XXE / billion-laughs signals: the \
                 hardened loader rejects any DOCTYPE/entity before it can be expanded, so their \
                 presence is reported rather than processed.",
                "Triage a SAML blob into `(ok, kind, detail)`; `dtd-present`/`entity-blocked` flag \
                 XXE / billion-laughs attempts.",
                "well formed, validate, xxe, billion laughs, dtd, entity, triage, bad base64, \
                 truncated, not xml, not saml, parse error",
                "Diagnostics",
                "scalar/well_formed.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "msg",
            0,
            "The SAML message (raw XML, base64, base64+DEFLATE, or URL-encoded). \
             Classified without expanding DTDs or entities.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut ok = BooleanBuilder::new();
        let mut kind = StringBuilder::new();
        let mut detail = StringBuilder::new();
        let mut valid = Vec::with_capacity(rows);

        for i in 0..rows {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    let wf = saml_core::api::well_formed(&bytes);
                    ok.append_value(wf.ok);
                    kind.append_value(wf.kind.as_str());
                    if wf.detail.is_empty() {
                        detail.append_null();
                    } else {
                        detail.append_value(&wf.detail);
                    }
                    valid.push(true);
                }
                None => {
                    ok.append_null();
                    kind.append_null();
                    detail.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ok.finish()),
            Arc::new(kind.finish()),
            Arc::new(detail.finish()),
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
