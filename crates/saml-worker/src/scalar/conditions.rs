//! `saml.conditions(msg) -> STRUCT(...)` — the validity window + audience/usage
//! constraints. The worker does NOT decide "expired" (clock-skew policy is the
//! caller's — compare to `now()` in SQL).

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
    Fields::from(vec![
        Field::new("not_before", ts_type(), true),
        Field::new("not_on_or_after", ts_type(), true),
        Field::new("audiences", list_varchar_type(), true),
        Field::new("one_time_use", DataType::Boolean, true),
        Field::new("proxy_restriction_count", DataType::UInt32, true),
        Field::new("proxy_audiences", list_varchar_type(), true),
    ])
}

fn list_builder() -> ListBuilder<StringBuilder> {
    ListBuilder::new(StringBuilder::new()).with_field(Arc::new(Field::new(
        "item",
        DataType::Utf8,
        true,
    )))
}

pub struct Conditions;

impl ScalarFunction for Conditions {
    fn name(&self) -> &str {
        "conditions"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Extract the assertion Conditions: STRUCT(not_before TIMESTAMPTZ, \
                          not_on_or_after TIMESTAMPTZ, audiences LIST<VARCHAR>, one_time_use BOOL, \
                          proxy_restriction_count UINTEGER, proxy_audiences LIST<VARCHAR>). No \
                          'expired' verdict — compare to now() yourself."
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT (saml.main.conditions('<saml:Assertion \
                      xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
                      <saml:Conditions NotBefore=\"2026-01-01T00:00:00Z\" \
                      NotOnOrAfter=\"2026-01-01T01:00:00Z\"/></saml:Assertion>')).not_on_or_after;"
                    .into(),
                description: "Read the assertion validity window for an own-skew expiry check."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "SAML Conditions Window",
                "Extract a SAML assertion's Conditions as a struct: the NotBefore / NotOnOrAfter \
                 validity window (TIMESTAMPTZ, UTC), the AudienceRestriction audiences, the \
                 OneTimeUse flag, and any ProxyRestriction count and audiences. The worker \
                 surfaces the window but never decides 'expired' — clock-skew tolerance is the \
                 caller's policy, so compare against now() in SQL.",
                "Get the assertion validity window + audiences as a struct; you decide expiry \
                 against `now()`.",
                "conditions, validity window, notbefore, notonorafter, audience, audiencerestriction, \
                 onetimeuse, proxyrestriction, expiry, timestamptz",
                "Decode",
                "scalar/conditions.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "msg",
            0,
            "The SAML message (raw XML, base64, base64+DEFLATE, or URL-encoded) whose \
             assertion Conditions to extract.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut not_before = Vec::with_capacity(rows);
        let mut not_after = Vec::with_capacity(rows);
        let mut audiences = list_builder();
        let mut one_time = BooleanBuilder::new();
        let mut proxy_count = UInt32Builder::new();
        let mut proxy_aud = list_builder();
        let mut valid = Vec::with_capacity(rows);

        for i in 0..rows {
            let parsed = match input_bytes(col, i)? {
                Some(bytes) => saml_core::api::conditions(&bytes),
                None => None,
            };
            match parsed {
                Some(c) => {
                    not_before.push(c.not_before);
                    not_after.push(c.not_on_or_after);
                    for a in &c.audiences {
                        audiences.values().append_value(a);
                    }
                    audiences.append(true);
                    one_time.append_value(c.one_time_use);
                    proxy_count.append_value(c.proxy_restriction_count);
                    for a in &c.proxy_audiences {
                        proxy_aud.values().append_value(a);
                    }
                    proxy_aud.append(true);
                    valid.push(true);
                }
                None => {
                    not_before.push(None);
                    not_after.push(None);
                    audiences.append(false);
                    one_time.append_null();
                    proxy_count.append_null();
                    proxy_aud.append(false);
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            ts_array(not_before),
            ts_array(not_after),
            Arc::new(audiences.finish()),
            Arc::new(one_time.finish()),
            Arc::new(proxy_count.finish()),
            Arc::new(proxy_aud.finish()),
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
