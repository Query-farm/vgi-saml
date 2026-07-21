//! `saml.signature(msg) -> STRUCT(...)` — the §B.1 XML-DSig structural check for
//! the outermost signature.
//!
//! `sig_valid = true` means the **embedded** cert signed these bytes; it says
//! nothing about whether that cert is *authorized* — join `signer_cert_sha256`
//! to your own IdP trust table for that (the Golden-SAML check).

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder,
};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::input_bytes;

/// The per-`Reference` struct: `STRUCT(uri, digest_method, digest_ok, resolved_element)`.
pub fn reference_fields() -> Fields {
    Fields::from(vec![
        Field::new("uri", DataType::Utf8, true),
        Field::new("digest_method", DataType::Utf8, true),
        Field::new("digest_ok", DataType::Boolean, true),
        Field::new("resolved_element", DataType::Utf8, true),
    ])
}

fn references_list_type() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(reference_fields()),
        true,
    )))
}

pub fn fields() -> Fields {
    let s = |n: &str| Field::new(n, DataType::Utf8, true);
    let b = |n: &str| Field::new(n, DataType::Boolean, true);
    Fields::from(vec![
        b("signed"),
        b("c14n_ok"),
        b("digest_ok"),
        b("sig_valid"),
        s("algo"),
        s("c14n_method"),
        s("digest_method"),
        Field::new("signer_cert", DataType::Binary, true),
        s("signer_cert_sha256"),
        s("signer_subject"),
        s("signer_issuer"),
        Field::new("references", references_list_type(), true),
    ])
}

fn references_builder() -> ListBuilder<StructBuilder> {
    let sb = StructBuilder::from_fields(reference_fields(), 0);
    ListBuilder::new(sb).with_field(Arc::new(Field::new(
        "item",
        DataType::Struct(reference_fields()),
        true,
    )))
}

pub struct Signature;

impl ScalarFunction for Signature {
    fn name(&self) -> &str {
        "signature"
    }

    fn metadata(&self) -> FunctionMetadata {
        let examples = vec![FunctionExample {
            sql: "SELECT (saml.main.signature('<saml:Assertion \
                  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">\
                  <saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>'))\
                  .sig_valid;"
                .into(),
            description: "Check whether a SAML message's embedded signature is internally \
                          valid (false here — the assertion is unsigned)."
                .into(),
            expected_output: None,
        }];
        let mut tags = crate::meta::object_tags(
            "Verify SAML Signature",
            "Run the XML-DSig structural check on a SAML message's outermost signature using \
             exclusive XML canonicalization, and return a struct: signed (is there a \
             signature), digest_ok (do the per-Reference digests match the referenced nodes — \
             i.e. does the signature cover the bytes you think it does), c14n_ok (does \
             SignedInfo canonicalize under a recognized exclusive-C14N method), sig_valid (does \
             SignatureValue verify against the EMBEDDED KeyInfo cert — RSA/ECDSA/EdDSA math), \
             algo (RS256/ES256/EdDSA/…), the c14n/digest method URIs, the signer_cert (DER \
             `BLOB`), signer_cert_sha256 (the join key to your IdP trust table), signer_subject / \
             signer_issuer, and the references list. Crucially, sig_valid=true means only that \
             the embedded cert signed these bytes — NOT that the key is trusted. Detecting \
             Golden SAML (a forgery with a stolen-but-valid IdP key) is a downstream LEFT JOIN \
             of signer_cert_sha256 against your known-good cert inventory.",
            "Structurally verify a SAML signature (exclusive C14N + digest + embedded-cert \
             math) → `(signed, c14n_ok, digest_ok, sig_valid, algo, signer_cert_sha256, …)`. \
             Trust is your JOIN.",
            "xml-dsig, signature, verify, c14n, exclusive canonicalization, digest, \
             signer_cert_sha256, golden saml, rsa-sha256, ecdsa, eddsa, keyinfo, x509",
            "Verify",
            "scalar/signature.rs",
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        FunctionMetadata {
            description: "Verify the outermost XML-DSig signature: STRUCT(signed, c14n_ok, \
                          digest_ok, sig_valid, algo, c14n_method, digest_method, signer_cert BLOB, \
                          signer_cert_sha256, signer_subject, signer_issuer, references LIST<STRUCT>). \
                          sig_valid is math against the EMBEDDED cert — trust is your JOIN."
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
            "A SAML 2.0 message whose outermost XML-DSig signature to check. The worker \
             content-sniffs and normalizes the transport wrapper automatically, whether the \
             message arrived as raw XML or an encoded SAMLResponse blob, so pass the value \
             straight from your column.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        let mut signed = BooleanBuilder::new();
        let mut c14n_ok = BooleanBuilder::new();
        let mut digest_ok = BooleanBuilder::new();
        let mut sig_valid = BooleanBuilder::new();
        let mut algo = StringBuilder::new();
        let mut c14n_method = StringBuilder::new();
        let mut digest_method = StringBuilder::new();
        let mut signer_cert = BinaryBuilder::new();
        let mut signer_cert_sha256 = StringBuilder::new();
        let mut signer_subject = StringBuilder::new();
        let mut signer_issuer = StringBuilder::new();
        let mut references = references_builder();
        let mut valid = Vec::with_capacity(rows);

        let opt = |b: &mut StringBuilder, v: &Option<String>| match v {
            Some(s) => b.append_value(s),
            None => b.append_null(),
        };

        for i in 0..rows {
            let Some(bytes) = input_bytes(col, i)? else {
                signed.append_null();
                c14n_ok.append_null();
                digest_ok.append_null();
                sig_valid.append_null();
                algo.append_null();
                c14n_method.append_null();
                digest_method.append_null();
                signer_cert.append_null();
                signer_cert_sha256.append_null();
                signer_subject.append_null();
                signer_issuer.append_null();
                references.append(false);
                valid.push(false);
                continue;
            };

            let s = saml_core::api::signature(&bytes);
            signed.append_value(s.signed);
            c14n_ok.append_value(s.c14n_ok);
            digest_ok.append_value(s.digest_ok);
            sig_valid.append_value(s.sig_valid);
            opt(&mut algo, &s.algo);
            opt(&mut c14n_method, &s.c14n_method);
            opt(&mut digest_method, &s.digest_method);
            match &s.signer_cert {
                Some(der) => signer_cert.append_value(der),
                None => signer_cert.append_null(),
            }
            opt(&mut signer_cert_sha256, &s.signer_cert_sha256);
            opt(&mut signer_subject, &s.signer_subject);
            opt(&mut signer_issuer, &s.signer_issuer);

            let rb = references.values();
            for r in &s.references {
                rb.field_builder::<StringBuilder>(0)
                    .unwrap()
                    .append_value(&r.uri);
                rb.field_builder::<StringBuilder>(1)
                    .unwrap()
                    .append_value(&r.digest_method);
                rb.field_builder::<BooleanBuilder>(2)
                    .unwrap()
                    .append_value(r.digest_ok);
                rb.field_builder::<StringBuilder>(3)
                    .unwrap()
                    .append_value(&r.resolved_element);
                rb.append(true);
            }
            references.append(true);
            valid.push(true);
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(signed.finish()),
            Arc::new(c14n_ok.finish()),
            Arc::new(digest_ok.finish()),
            Arc::new(sig_valid.finish()),
            Arc::new(algo.finish()),
            Arc::new(c14n_method.finish()),
            Arc::new(digest_method.finish()),
            Arc::new(signer_cert.finish()),
            Arc::new(signer_cert_sha256.finish()),
            Arc::new(signer_subject.finish()),
            Arc::new(signer_issuer.finish()),
            Arc::new(references.finish()),
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
