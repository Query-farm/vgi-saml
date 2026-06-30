//! XSW / Golden-SAML detection (`saml.anomalies`).
//!
//! XSW (XML Signature Wrapping) exploits the gap between the module that
//! *verifies* a signature and the module that *consumes* the assertion: they
//! resolve different elements. Rather than enumerate XSW1–XSW8 by name, the
//! worker detects the **structural invariants** all of them violate, plus the
//! forensic tells of Golden-SAML and the XXE-class text-extraction bugs.
//! Output is a sorted, de-duplicated `LIST<VARCHAR>`; an empty list is **not** a
//! safety guarantee (Golden SAML leaves no structural trace — that verdict is a
//! downstream trust-table `JOIN`).

use std::collections::BTreeSet;

use roxmltree::{Document, Node};

use crate::signature;
use crate::xmlutil::{self, NS_DSIG};

/// All `ds:Signature` elements in document order.
fn signatures<'a, 'i>(doc: &'a Document<'i>) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "Signature"
                && n.tag_name().namespace() == Some(NS_DSIG)
        })
        .collect()
}

fn elements_named<'a, 'i>(doc: &'a Document<'i>, local: &str) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == local)
        .collect()
}

/// Does `node` directly contain an XML comment among its children (the
/// node-splitting trick `user@good.com<!---->.evil.com`)?
fn has_comment_child(node: Node) -> bool {
    node.children().any(|c| c.is_comment())
}

/// The structural anomaly flags for a message. Sorted + de-duplicated.
pub fn anomalies(doc: &Document, src: &str) -> Vec<String> {
    let mut flags: BTreeSet<String> = BTreeSet::new();

    let assertions = elements_named(doc, "Assertion");
    let encrypted = elements_named(doc, "EncryptedAssertion");

    // >1 assertion of any kind — legit responses carry exactly one.
    if assertions.len() + encrypted.len() > 1 {
        flags.insert("multiple-assertions".into());
    }
    if !encrypted.is_empty() {
        flags.insert("encrypted-assertion-present".into());
    }

    // NameID / AttributeValue / Issuer text split by an embedded comment.
    for local in ["NameID", "AttributeValue", "Issuer"] {
        if elements_named(doc, local)
            .iter()
            .any(|n| has_comment_child(*n))
        {
            flags.insert("nameid-comment-splitting".into());
        }
    }

    let sigs = signatures(doc);
    let mut signed_assertion_ids: BTreeSet<String> = BTreeSet::new();
    let mut response_is_signed = false;

    for sig in &sigs {
        let a = signature::analyze(*sig, doc, src);

        // Tampered-after-signing: signed bytes ≠ referenced node.
        if !a.references.is_empty() && !a.digest_ok {
            flags.insert("digest-mismatch".into());
        }

        // Inclusive C14N where exclusive is required for a movable assertion.
        if let Some(m) = &a.c14n_method {
            if !m.contains("xml-exc-c14n") {
                flags.insert("c14n-inclusive-on-moved-assertion".into());
            }
        }

        // Per-reference ID resolution: dangling or duplicate IDs.
        for r in &a.references {
            let id = r.uri.strip_prefix('#').unwrap_or(&r.uri);
            if id.is_empty() {
                continue;
            }
            let n = signature::elements_by_id(doc, id).len();
            if n != 1 {
                flags.insert("reference-uri-id-mismatch".into());
            }
            // Track which assertions are actually covered.
            if r.resolved_element == "Assertion" {
                signed_assertion_ids.insert(id.to_string());
            }
        }
        if a.signed_element.as_deref() == Some("Response")
            || a.signed_element
                .as_deref()
                .map(ends_response)
                .unwrap_or(false)
        {
            response_is_signed = true;
        }

        // Placement anomaly: a Signature parked under Extensions/Object.
        if let Some(parent) = sig.parent_element() {
            let pn = parent.tag_name().name();
            if pn == "Extensions" || pn == "Object" {
                flags.insert("signature-placement-anomaly".into());
            }
        }

        // Detached: SAML signatures are enveloped, so the referenced element
        // must be an ancestor of the Signature. If the (resolved) target is
        // neither an ancestor nor a descendant of the Signature, it is detached.
        if let Some(first_ref) = a.references.first() {
            let id = first_ref.uri.strip_prefix('#').unwrap_or(&first_ref.uri);
            if !id.is_empty() {
                if let Some(target) = signature::elements_by_id(doc, id).into_iter().next() {
                    let ancestor = sig.ancestors().any(|x| x.id() == target.id());
                    let descendant = target.descendants().any(|x| x.id() == sig.id());
                    if !ancestor && !descendant {
                        flags.insert("detached-signature".into());
                    }
                }
            }
        }
    }

    // signature-covers-other-element: the assertion a consumer would read (the
    // first one) is NOT the one that is signed, while some other assertion is.
    if let Some(first) = assertions.first() {
        let first_id = xmlutil::attr(*first, "ID").unwrap_or("");
        if !signed_assertion_ids.is_empty() && !signed_assertion_ids.contains(first_id) {
            flags.insert("signature-covers-other-element".into());
        }
    }

    // unsigned-assertion-in-signed-response: envelope is signed but a payload
    // assertion is not individually signed (its subject/attributes are swappable).
    if response_is_signed {
        let any_unsigned = assertions.iter().any(|a| !assertion_self_signed(*a));
        if any_unsigned {
            flags.insert("unsigned-assertion-in-signed-response".into());
        }
    }

    flags.into_iter().collect()
}

fn ends_response(name: &str) -> bool {
    name.ends_with("Response")
}

/// An assertion is "self-signed" if it carries an enveloped `ds:Signature`
/// child (one whose reference points back at the assertion's own ID).
fn assertion_self_signed(a: Node) -> bool {
    a.children().any(|n| {
        n.is_element()
            && n.tag_name().name() == "Signature"
            && n.tag_name().namespace() == Some(NS_DSIG)
    })
}
