//! `saml.authn(msg) -> STRUCT(...)` — the `AuthnStatement` + `AuthnContext`.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{input_bytes, ts_array, ts_type};

pub fn fields() -> Fields {
    Fields::from(vec![
        Field::new("authn_instant", ts_type(), true),
        Field::new("session_index", DataType::Utf8, true),
        Field::new("session_not_on_or_after", ts_type(), true),
        Field::new("class_ref", DataType::Utf8, true),
        Field::new("decl_ref", DataType::Utf8, true),
        Field::new("authenticating_authority", DataType::Utf8, true),
    ])
}

pub struct AuthnFn;

impl ScalarFunction for AuthnFn {
    fn name(&self) -> &str {
        "authn"
    }

    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT (saml.main.authn('<saml:Assertion \
                  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:AuthnStatement>\
                  <saml:AuthnContext><saml:AuthnContextClassRef>\
                  urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\
                  </saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>\
                  </saml:Assertion>')).class_ref;"
                .into(),
            description: "Read the AuthnContext class (e.g. detect MFA downgrade).".into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "SAML AuthnContext",
            "Extract a SAML assertion's AuthnStatement and AuthnContext as a struct: the \
             AuthnInstant and SessionNotOnOrAfter (`TIMESTAMPTZ`, UTC), the SessionIndex, the \
             AuthnContextClassRef / DeclRef (the authentication method, e.g. \
             PasswordProtectedTransport vs an MFA class — useful for spotting downgrades), and \
             any AuthenticatingAuthority. Returns NULL when there is no AuthnStatement.",
            "Get the AuthnStatement/AuthnContext (instant, session, auth class) as a struct.",
            "authn, authncontext, authnstatement, session index, authninstant, class ref, \
             authentication method, mfa downgrade, sso session",
            "Decode",
            "scalar/authn.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description: "Extract the AuthnStatement + AuthnContext: STRUCT(authn_instant \
                          TIMESTAMPTZ, session_index VARCHAR, session_not_on_or_after TIMESTAMPTZ, \
                          class_ref VARCHAR, decl_ref VARCHAR, authenticating_authority VARCHAR)"
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
            "A SAML 2.0 message whose AuthnStatement to extract. The worker content-sniffs and \
             normalizes the transport wrapper automatically, whether the message arrived as raw \
             XML or an encoded SAMLResponse blob, so pass the value straight from your column.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut instant = Vec::with_capacity(rows);
        let mut session_index = StringBuilder::new();
        let mut session_noa = Vec::with_capacity(rows);
        let mut class_ref = StringBuilder::new();
        let mut decl_ref = StringBuilder::new();
        let mut authority = StringBuilder::new();
        let mut valid = Vec::with_capacity(rows);

        let opt_str = |b: &mut StringBuilder, v: &Option<String>| match v {
            Some(s) => b.append_value(s),
            None => b.append_null(),
        };

        for i in 0..rows {
            let parsed = match input_bytes(col, i)? {
                Some(bytes) => saml_core::api::authn(&bytes),
                None => None,
            };
            match parsed {
                Some(a) => {
                    instant.push(a.authn_instant);
                    opt_str(&mut session_index, &a.session_index);
                    session_noa.push(a.session_not_on_or_after);
                    opt_str(&mut class_ref, &a.class_ref);
                    opt_str(&mut decl_ref, &a.decl_ref);
                    opt_str(&mut authority, &a.authenticating_authority);
                    valid.push(true);
                }
                None => {
                    instant.push(None);
                    session_index.append_null();
                    session_noa.push(None);
                    class_ref.append_null();
                    decl_ref.append_null();
                    authority.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            ts_array(instant),
            Arc::new(session_index.finish()),
            ts_array(session_noa),
            Arc::new(class_ref.finish()),
            Arc::new(decl_ref.finish()),
            Arc::new(authority.finish()),
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
