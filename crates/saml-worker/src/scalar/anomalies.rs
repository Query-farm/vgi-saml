//! `saml.anomalies(msg) -> LIST<VARCHAR>` — the XSW / Golden-SAML / structural
//! flag set. Empty list = no structural red flag found (NOT a safety guarantee;
//! Golden SAML leaves none — that verdict is a downstream trust-table JOIN).

use std::sync::Arc;

use arrow_array::builder::{ListBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{input_bytes, list_varchar_type};

pub struct Anomalies;

impl ScalarFunction for Anomalies {
    fn name(&self) -> &str {
        "anomalies"
    }

    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT saml.main.anomalies('<samlp:Response \
                  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
                  <saml:Assertion ID=\"_a1\"/><saml:Assertion ID=\"_a2\"/></samlp:Response>');"
                .into(),
            description: "Surface signature-wrapping / structural red flags (here, \
                          multiple-assertions) for a message."
                .into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "SAML Signature-Wrapping Anomalies",
            "Return the structural anomaly flags for a SAML message as a `LIST(VARCHAR)`. These \
             are the invariants every XML Signature Wrapping (XSW1-XSW8) attack violates plus \
             the XXE-class text-extraction tells: multiple-assertions, \
             signature-covers-other-element, reference-uri-id-mismatch, \
             unsigned-assertion-in-signed-response, signature-placement-anomaly, \
             detached-signature, nameid-comment-splitting, digest-mismatch, \
             c14n-inclusive-on-moved-assertion, and encrypted-assertion-present. An EMPTY list \
             is not a safety guarantee — Golden SAML (a forgery with a stolen but valid IdP \
             key) leaves no structural trace, so combine this with a trust-table JOIN on \
             signer_cert_sha256.",
            "List XSW / structural red flags for a SAML message (e.g. `multiple-assertions`, \
             `signature-covers-other-element`, `digest-mismatch`); empty != safe.",
            "xsw, signature wrapping, golden saml, anomalies, multiple assertions, \
             digest mismatch, detached signature, comment splitting, attack detection, \
             detection engineering",
            "Detect",
            "scalar/anomalies.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description:
                "Flag XSW (XML Signature Wrapping) / Golden-SAML / structural anomalies as \
                          a LIST<VARCHAR>; empty list = no structural red flag found (not a safety \
                          guarantee)"
                    .into(),
            return_type: Some(list_varchar_type()),
            examples,
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "msg",
            0,
            "A SAML 2.0 message to scan for signature-wrapping and structural attack indicators. \
             Pass the value straight from your column — the worker content-sniffs and normalizes \
             the transport wrapper automatically, whether the message arrived as raw XML or an \
             encoded SAMLResponse blob.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(list_varchar_type()))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let field = Arc::new(Field::new("item", DataType::Utf8, true));
        let mut b = ListBuilder::new(StringBuilder::new()).with_field(field);
        for i in 0..batch.num_rows() {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    for flag in saml_core::api::anomalies(&bytes) {
                        b.values().append_value(flag);
                    }
                    b.append(true); // non-null (possibly empty) list
                }
                None => b.append(false), // NULL input → NULL list
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
