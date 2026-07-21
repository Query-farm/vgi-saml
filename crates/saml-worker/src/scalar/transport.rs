//! Transport plumbing exposed for callers holding partially-processed data:
//! `saml.b64decode(VARCHAR) -> BLOB`, `saml.inflate(BLOB) -> VARCHAR`,
//! `saml.unwrap(VARCHAR) -> VARCHAR`. All bounded against decompression bombs.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::input_bytes;

/// `b64decode(VARCHAR) -> BLOB` — standard + URL-safe base64.
pub struct B64Decode;

impl ScalarFunction for B64Decode {
    fn name(&self) -> &str {
        "b64decode"
    }
    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT saml.main.b64decode('PHNhbWw+');".into(),
            description: "Decode a base64 SAMLResponse form field to raw bytes.".into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "Base64 Decode",
            "Decode a base64 string to a `BLOB`, accepting both the standard (`+/`) and URL-safe \
             (`-_`) alphabets, padded or unpadded. This is the HTTP-POST-binding step: a \
             SAMLResponse form field is base64 of the XML (or of DEFLATE-compressed XML for the \
             redirect binding). Returns NULL when the input is not valid base64.",
            "Base64-decode a string to bytes (standard or URL-safe), e.g. the SAMLResponse POST \
             field; NULL if not base64.",
            "base64, b64decode, decode, post binding, samlresponse, url-safe base64, bytes",
            "Transport",
            "scalar/transport.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description: "Base64-decode a string to bytes (accepts standard and URL-safe \
                          alphabets, padded or not); NULL on failure"
                .into(),
            return_type: Some(DataType::Binary),
            examples,
            tags,
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "data",
            0,
            "The base64-encoded text to decode. Both common base64 alphabets are recognized and \
             padding is optional; input that is not valid base64 yields NULL.",
        )]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Binary))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut out = BinaryBuilder::new();
        for i in 0..batch.num_rows() {
            match input_bytes(col, i)? {
                Some(bytes) => match saml_core::transport::b64decode(&bytes) {
                    Ok(v) => out.append_value(v),
                    Err(_) => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `inflate(BLOB) -> VARCHAR` — raw DEFLATE (redirect binding), bomb-bounded.
pub struct Inflate;

impl ScalarFunction for Inflate {
    fn name(&self) -> &str {
        "inflate"
    }
    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT saml.main.inflate(saml.main.b64decode('sylOzM0psHIsLcnIC0otLE0tLlGoy\
                  M3JK7YCS9gqlRblWeUnFmcWW+Ul5qYWW5UkWwU7+vpYGekZWBUU5ZfkJ+fnKCl4utgqxRcZKunbA\
                  QA='));"
                .into(),
            description: "Base64-decode then raw-DEFLATE-inflate a redirect-binding \
                          SAMLRequest to its XML text."
                .into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "DEFLATE Inflate",
            "Inflate raw-DEFLATE (and zlib-wrapped) bytes to text — the HTTP-Redirect binding \
             compresses the XML with raw DEFLATE before base64. The inflate is bounded by a \
             64 MiB cap so a DEFLATE bomb (tiny payload, gigabytes inflated) is rejected rather \
             than exhausting memory. Returns NULL when the bytes do not inflate or exceed the \
             cap.",
            "Inflate raw-DEFLATE bytes (redirect binding) to text, bomb-bounded; NULL on \
             failure.",
            "inflate, deflate, decompress, redirect binding, samlrequest, zlib, \
             decompression bomb, gzip",
            "Transport",
            "scalar/transport.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description: "Raw-DEFLATE-inflate bytes to text (HTTP-Redirect binding), bounded \
                          against decompression bombs; NULL on failure"
                .into(),
            return_type: Some(DataType::Utf8),
            examples,
            tags,
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "data",
            0,
            "The raw-DEFLATE (or zlib-wrapped) compressed bytes to inflate, e.g. the output of \
             b64decode on a redirect-binding query parameter.",
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
                Some(bytes) => match saml_core::transport::inflate(&bytes) {
                    Ok(v) => match String::from_utf8(v) {
                        Ok(s) => out.append_value(s),
                        Err(_) => out.append_null(),
                    },
                    Err(_) => out.append_null(),
                },
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `unwrap(VARCHAR) -> VARCHAR` — URL-decode + base64 + inflate sniff → XML.
pub struct Unwrap;

impl ScalarFunction for Unwrap {
    fn name(&self) -> &str {
        "unwrap"
    }
    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT saml.main.unwrap('PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM\
                  6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiLz4%3D');"
                .into(),
            description: "Recover the XML from a URL-encoded, base64-wrapped transport parameter."
                .into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "Unwrap SAML Transport",
            "Unwrap a SAML transport parameter to its XML text in one call: URL-decode the \
             value, base64-decode it, and content-sniff whether the result is XML or \
             DEFLATE-compressed XML (inflating if so). Handles both the HTTP-Redirect \
             (URL-encoded base64 of raw DEFLATE) and HTTP-POST (base64) shapes. Returns NULL \
             when the value does not resolve to XML.",
            "URL-decode + base64 + inflate-sniff a redirect/POST parameter to its SAML XML; \
             NULL on failure.",
            "unwrap, url decode, percent decode, redirect binding, post binding, base64, \
             deflate, saml transport, query parameter",
            "Transport",
            "scalar/transport.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description: "Unwrap a redirect/POST-binding parameter (URL-decode + base64 + \
                          DEFLATE sniff) to its SAML XML text; NULL on failure"
                .into(),
            return_type: Some(DataType::Utf8),
            examples,
            tags,
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "param",
            0,
            DataType::Utf8,
            "The URL-encoded transport parameter (a SAMLRequest/SAMLResponse query value or POST \
             field) to unwrap to XML text.",
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
                Some(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    match saml_core::transport::unwrap(&text) {
                        Ok(s) => out.append_value(s),
                        Err(_) => out.append_null(),
                    }
                }
                None => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
