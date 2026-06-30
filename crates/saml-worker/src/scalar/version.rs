//! `saml_version()` — the worker's version string.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct SamlVersion;

impl ScalarFunction for SamlVersion {
    fn name(&self) -> &str {
        "saml_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Returns the saml worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT saml.main.saml_version();".into(),
                description: "Return the saml worker version string.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "SAML Worker Version",
                "Return the semantic version string of the running saml worker binary. Useful for \
                 diagnostics and confirming which build is attached.",
                "Return the saml worker version string, e.g. `saml_version()` -> '0.1.0'.",
                "version, build version, saml_version, diagnostics, worker version, semver",
                "scalar/version.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let out: ArrayRef = Arc::new(StringArray::from(vec![saml_core::version(); rows]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
