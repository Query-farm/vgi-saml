//! The XML-DSig structural check (`saml.signature` / `saml.signatures`).
//!
//! For each `ds:Signature` the pipeline (per the W3C `xmldsig-core` +
//! `xml-exc-c14n` specs) is:
//!
//! 1. Resolve every `Reference URI="#id"` to its `ID`-typed element.
//! 2. Apply the `Transforms` chain (enveloped-signature → exclusive C14N with the
//!    declared `InclusiveNamespaces`).
//! 3. Digest the canonical octets and compare to `DigestValue` → **`digest_ok`**
//!    (*does the signature actually cover the bytes we think it does?*).
//! 4. Canonicalize `SignedInfo` and verify `SignatureValue` against the
//!    **embedded** cert → **`sig_valid`** (math against the embedded key) and
//!    **`c14n_ok`** (SignedInfo canonicalizes under a recognized method).
//!
//! Trust stays with the caller: `sig_valid = true` says the embedded cert signed
//! these bytes, never that the cert is *authorized*.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use roxmltree::{Document, Node};

use crate::cert::{self, SigAlgo};
use crate::model::{Reference, SignatureInfo, SignatureRow};
use crate::xmlutil::{self, NS_DSIG};

const EXCLUSIVE_C14N: &str = "xml-exc-c14n";

/// Every `ds:Signature` element in document order.
fn signature_nodes<'a, 'i>(doc: &'a Document<'i>) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "Signature"
                && n.tag_name().namespace() == Some(NS_DSIG)
        })
        .collect()
}

/// All elements carrying an `ID`-typed attribute equal to `id` (SAML uses the
/// `ID` attribute). More than one match is itself a wrapping red flag.
pub fn elements_by_id<'a, 'i>(doc: &'a Document<'i>, id: &str) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| n.is_element() && xmlutil::attr(*n, "ID") == Some(id))
        .collect()
}

/// Whitespace-strip a base64 blob (XML wraps long values across lines).
fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

/// The InclusiveNamespaces PrefixList declared anywhere under `transforms_or_method`.
fn inclusive_prefixes(node: Node) -> Vec<String> {
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "InclusiveNamespaces")
        .and_then(|n| xmlutil::attr(n, "PrefixList"))
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// The full analysis of one `Signature`. Shared by the scalar and table fns.
pub struct Analyzed {
    pub c14n_ok: bool,
    pub digest_ok: bool,
    pub sig_valid: bool,
    pub algo: Option<String>,
    pub c14n_method: Option<String>,
    pub digest_method: Option<String>,
    pub cert: Option<cert::CertInfo>,
    pub references: Vec<Reference>,
    /// Local name of the (first) element the signature covers, if resolved.
    pub signed_element: Option<String>,
    /// The first reference's target id (sans `#`).
    pub references_id: Option<String>,
}

/// Analyze a single `ds:Signature` node within `doc` (source `src`).
pub fn analyze<'a, 'i>(sig: Node<'a, 'i>, doc: &'a Document<'i>, src: &str) -> Analyzed {
    let signed_info = xmlutil::child(sig, "SignedInfo");
    let c14n_method = signed_info
        .and_then(|si| xmlutil::child(si, "CanonicalizationMethod"))
        .and_then(|m| xmlutil::attr(m, "Algorithm"))
        .map(str::to_string);
    let sig_method_uri = signed_info
        .and_then(|si| xmlutil::child(si, "SignatureMethod"))
        .and_then(|m| xmlutil::attr(m, "Algorithm"));
    let algo = sig_method_uri.map(|u| SigAlgo::from_uri(u).label().to_string());
    let sig_algo = sig_method_uri
        .map(SigAlgo::from_uri)
        .unwrap_or(SigAlgo::Unknown);

    // --- per-reference digest checks ---
    let mut references = Vec::new();
    let mut all_digests_ok = true;
    let mut any_reference = false;
    let mut signed_element = None;
    let mut references_id = None;
    let mut digest_method_out = None;

    if let Some(si) = signed_info {
        for refn in xmlutil::children(si, "Reference") {
            any_reference = true;
            let uri = xmlutil::attr(refn, "URI").unwrap_or("").to_string();
            let target_id = uri.strip_prefix('#').unwrap_or(&uri).to_string();
            if references_id.is_none() {
                references_id = Some(target_id.clone());
            }

            let transforms = xmlutil::child(refn, "Transforms");
            let enveloped = transforms
                .map(|t| {
                    t.descendants().any(|n| {
                        n.is_element()
                            && n.tag_name().name() == "Transform"
                            && xmlutil::attr(n, "Algorithm")
                                .map(|a| a.contains("enveloped-signature"))
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            let incl = transforms.map(inclusive_prefixes).unwrap_or_default();

            let digest_method = xmlutil::child(refn, "DigestMethod")
                .and_then(|d| xmlutil::attr(d, "Algorithm"))
                .unwrap_or("")
                .to_string();
            if digest_method_out.is_none() {
                digest_method_out = Some(digest_method.clone());
            }
            let digest_value = xmlutil::child(refn, "DigestValue")
                .and_then(xmlutil::text)
                .map(|t| strip_ws(&t))
                .unwrap_or_default();

            // Resolve the referenced element.
            let target = if target_id.is_empty() {
                doc.root_element().into()
            } else {
                elements_by_id(doc, &target_id).into_iter().next()
            };

            let mut ref_ok = false;
            let mut resolved = String::new();
            if let Some(t) = target {
                resolved = t.tag_name().name().to_string();
                if signed_element.is_none() {
                    signed_element = Some(resolved.clone());
                }
                let omit = if enveloped { Some(sig.id()) } else { None };
                let canon = crate::c14n::exclusive_c14n(t, src, omit, &incl);
                if let Some(d) = cert::digest_by_uri(&digest_method, &canon) {
                    ref_ok = STANDARD.encode(d) == digest_value && !digest_value.is_empty();
                }
            }
            all_digests_ok &= ref_ok;
            references.push(Reference {
                uri,
                digest_method,
                digest_ok: ref_ok,
                resolved_element: resolved,
            });
        }
    }
    let digest_ok = any_reference && all_digests_ok;

    // --- SignedInfo canonicalization + signature math against the embedded cert ---
    let is_exclusive = c14n_method
        .as_deref()
        .map(|m| m.contains(EXCLUSIVE_C14N))
        .unwrap_or(false);
    let cert = signer_cert(sig);

    let mut sig_valid = false;
    let mut c14n_ok = false;
    if let (Some(si), true) = (signed_info, is_exclusive) {
        c14n_ok = true;
        let si_incl = xmlutil::child(si, "CanonicalizationMethod")
            .map(inclusive_prefixes)
            .unwrap_or_default();
        let signed_info_canon = crate::c14n::exclusive_c14n(si, src, None, &si_incl);
        let sig_value = xmlutil::child(sig, "SignatureValue")
            .and_then(xmlutil::text)
            .map(|t| strip_ws(&t))
            .and_then(|t| STANDARD.decode(t).ok());
        if let (Some(c), Some(sv)) = (&cert, sig_value) {
            sig_valid = cert::verify(&c.spki_der, sig_algo, &signed_info_canon, &sv);
        }
    }

    Analyzed {
        c14n_ok,
        digest_ok,
        sig_valid,
        algo,
        c14n_method,
        digest_method: digest_method_out,
        cert,
        references,
        signed_element,
        references_id,
    }
}

/// First `X509Certificate` under a `Signature` → parsed cert facts.
fn signer_cert(sig: Node) -> Option<cert::CertInfo> {
    let node = sig
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "X509Certificate")?;
    let b64 = strip_ws(&xmlutil::text(node)?);
    let der = STANDARD.decode(b64).ok()?;
    cert::parse_cert(&der)
}

/// `saml.signature(msg)` — the outermost (document-order first) signature.
pub fn signature_info(doc: &Document, src: &str) -> SignatureInfo {
    let sigs = signature_nodes(doc);
    let Some(first) = sigs.first().copied() else {
        return SignatureInfo {
            signed: false,
            ..Default::default()
        };
    };
    let a = analyze(first, doc, src);
    SignatureInfo {
        signed: true,
        c14n_ok: a.c14n_ok,
        digest_ok: a.digest_ok,
        sig_valid: a.sig_valid,
        algo: a.algo,
        c14n_method: a.c14n_method,
        digest_method: a.digest_method,
        signer_cert: a.cert.as_ref().map(|c| c.der.clone()),
        signer_cert_sha256: a.cert.as_ref().map(|c| c.sha256_hex.clone()),
        signer_subject: a.cert.as_ref().map(|c| c.subject.clone()),
        signer_issuer: a.cert.as_ref().map(|c| c.issuer.clone()),
        references: a.references,
    }
}

/// `saml.signatures(msg)` — every signature in the document, with its scope.
pub fn signature_rows(doc: &Document, src: &str) -> Vec<SignatureRow> {
    signature_nodes(doc)
        .into_iter()
        .enumerate()
        .map(|(i, sig)| {
            let a = analyze(sig, doc, src);
            let scope = scope_of(sig, a.signed_element.as_deref());
            SignatureRow {
                idx: i as u32,
                scope,
                references_id: a.references_id,
                signed_element: a.signed_element,
                c14n_ok: a.c14n_ok,
                digest_ok: a.digest_ok,
                sig_valid: a.sig_valid,
                signer_cert_sha256: a.cert.map(|c| c.sha256_hex),
            }
        })
        .collect()
}

/// Classify a signature's scope by what it covers (falling back to its parent).
fn scope_of(sig: Node, signed_element: Option<&str>) -> String {
    let by_signed = signed_element.map(classify_scope);
    if let Some(s) = by_signed {
        if s != "other" {
            return s.to_string();
        }
    }
    let parent = sig
        .parent_element()
        .map(|p| p.tag_name().name().to_string());
    parent
        .map(|p| classify_scope(&p).to_string())
        .unwrap_or_else(|| "other".to_string())
}

fn classify_scope(local: &str) -> &'static str {
    match local {
        "Response" | "LogoutResponse" | "ArtifactResponse" => "response",
        "Assertion" => "assertion",
        _ => "other",
    }
}
