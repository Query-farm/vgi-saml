//! `saml.message_type(msg) -> VARCHAR` — the root-element discriminator.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::input_bytes;

pub struct MessageType;

impl ScalarFunction for MessageType {
    fn name(&self) -> &str {
        "message_type"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Root-element discriminator: 'Response', 'AuthnRequest', \
                          'LogoutRequest', 'LogoutResponse', 'Assertion', 'ArtifactResolve', or \
                          'unknown'"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT saml.main.message_type('<samlp:Response xmlns:samlp=\
                      \"urn:oasis:names:tc:SAML:2.0:protocol\"/>');"
                    .into(),
                description: "Identify the kind of a SAML message from its root element.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "SAML Message Type",
                "Return the kind of a SAML message from its root element — 'Response', \
                 'AuthnRequest', 'LogoutRequest', 'LogoutResponse', 'Assertion', 'ArtifactResolve', \
                 'ArtifactResponse', or 'unknown'. Accepts raw XML, base64, base64+DEFLATE, or \
                 URL-encoded input; returns 'unknown' for anything that does not decode to a \
                 recognized SAML element.",
                "Discriminate a SAML message by root element, e.g. \
                 `message_type(resp)` -> 'Response'.",
                "message type, saml kind, response, authnrequest, logoutrequest, assertion, \
                 discriminator, root element, classify saml",
                "Decode",
                "scalar/message_type.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "msg",
            0,
            "The SAML message: raw XML, base64, base64+DEFLATE (HTTP-Redirect), or a URL-encoded \
             wrapper. Content-sniffed automatically.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut out = StringBuilder::new();
        for i in 0..batch.num_rows() {
            match input_bytes(col, i)? {
                Some(bytes) => out.append_value(saml_core::api::message_type(&bytes)),
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
