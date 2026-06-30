//! Root-element discrimination and the `saml.decode` field extraction (§A map).

use roxmltree::{Document, Node};

use crate::model::Decoded;
use crate::time::parse_xsd_datetime;
use crate::xmlutil::{self, NS_DSIG};

/// Root-element discriminator: `Response`, `AuthnRequest`, `LogoutRequest`,
/// `LogoutResponse`, `Assertion`, `ArtifactResolve`, … or `unknown`.
pub fn message_type(doc: &Document) -> &'static str {
    match doc.root_element().tag_name().name() {
        "Response" => "Response",
        "AuthnRequest" => "AuthnRequest",
        "LogoutRequest" => "LogoutRequest",
        "LogoutResponse" => "LogoutResponse",
        "Assertion" => "Assertion",
        "EncryptedAssertion" => "EncryptedAssertion",
        "ArtifactResolve" => "ArtifactResolve",
        "ArtifactResponse" => "ArtifactResponse",
        "AttributeQuery" => "AttributeQuery",
        "ManageNameIDRequest" => "ManageNameIDRequest",
        _ => "unknown",
    }
}

/// First `Assertion` element anywhere in the document, if any.
fn first_assertion<'a, 'i>(doc: &'a Document<'i>) -> Option<Node<'a, 'i>> {
    doc.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Assertion")
}

fn count_local(doc: &Document, local: &str) -> u32 {
    doc.descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == local)
        .count() as u32
}

/// `saml.decode(msg)` — the §A field map. Never errors: absent fields are `None`.
pub fn decode(doc: &Document) -> Decoded {
    let root = doc.root_element();
    let mut d = Decoded {
        message_type: Some(message_type(doc).to_string()),
        version: xmlutil::attr(root, "Version").map(str::to_string),
        destination: xmlutil::attr(root, "Destination").map(str::to_string),
        issue_instant: xmlutil::attr(root, "IssueInstant").and_then(parse_xsd_datetime),
        ..Default::default()
    };

    // Response-level ids / status.
    if root.tag_name().name() == "Response" || root.tag_name().name().ends_with("Response") {
        d.response_id = xmlutil::attr(root, "ID").map(str::to_string);
    }
    d.in_response_to = xmlutil::attr(root, "InResponseTo").map(str::to_string);
    d.status = xmlutil::child(root, "Status")
        .and_then(|s| xmlutil::child(s, "StatusCode"))
        .and_then(|c| xmlutil::attr(c, "Value"))
        .map(str::to_string);

    // Assertion.
    let assertion = first_assertion(doc);
    if let Some(a) = assertion {
        d.assertion_id = xmlutil::attr(a, "ID").map(str::to_string);
        if root.tag_name().name() == "Assertion" {
            d.response_id = None; // root IS the assertion
        }
        // Issuer: prefer the assertion's, else the response's.
        d.issuer = xmlutil::child(a, "Issuer")
            .and_then(xmlutil::text)
            .or_else(|| xmlutil::child(root, "Issuer").and_then(xmlutil::text));

        if let Some(subject) = xmlutil::child(a, "Subject") {
            if let Some(nameid) = xmlutil::child(subject, "NameID") {
                d.subject = xmlutil::text(nameid);
                d.subject_format = xmlutil::attr(nameid, "Format").map(str::to_string);
                d.subject_sp_qualifier =
                    xmlutil::attr(nameid, "SPNameQualifier").map(str::to_string);
            }
            if let Some(sc) = xmlutil::child(subject, "SubjectConfirmation") {
                d.confirmation_method = xmlutil::attr(sc, "Method").map(str::to_string);
                if let Some(scd) = xmlutil::child(sc, "SubjectConfirmationData") {
                    d.recipient = xmlutil::attr(scd, "Recipient").map(str::to_string);
                    if d.in_response_to.is_none() {
                        d.in_response_to = xmlutil::attr(scd, "InResponseTo").map(str::to_string);
                    }
                    d.subject_not_on_or_after =
                        xmlutil::attr(scd, "NotOnOrAfter").and_then(parse_xsd_datetime);
                }
            }
        }

        // Conditions window + audiences.
        if let Some(cond) = xmlutil::child(a, "Conditions") {
            d.not_before = xmlutil::attr(cond, "NotBefore").and_then(parse_xsd_datetime);
            d.not_on_or_after = xmlutil::attr(cond, "NotOnOrAfter").and_then(parse_xsd_datetime);
            for ar in xmlutil::children(cond, "AudienceRestriction") {
                for aud in xmlutil::children(ar, "Audience") {
                    if let Some(t) = xmlutil::text(aud) {
                        d.audiences.push(t);
                    }
                }
            }
            d.audience = d.audiences.first().cloned();
        }

        // AuthnStatement + context.
        if let Some(authn) = xmlutil::child(a, "AuthnStatement") {
            d.authn_instant = xmlutil::attr(authn, "AuthnInstant").and_then(parse_xsd_datetime);
            d.session_index = xmlutil::attr(authn, "SessionIndex").map(str::to_string);
            d.authn_context = xmlutil::child(authn, "AuthnContext")
                .and_then(|c| xmlutil::child(c, "AuthnContextClassRef"))
                .and_then(xmlutil::text);
        }
    } else if root.tag_name().name() != "Response" {
        // A bare request/other message: still surface its Issuer.
        d.issuer = xmlutil::child(root, "Issuer").and_then(xmlutil::text);
    }

    d.assertion_count = count_local(doc, "Assertion");
    d.encrypted_count = count_local(doc, "EncryptedAssertion");
    // `signed` = a top-level (direct-child-of-root) ds:Signature is present.
    d.signed = root.children().any(|n| {
        n.is_element()
            && n.tag_name().name() == "Signature"
            && n.tag_name().namespace() == Some(NS_DSIG)
    });
    d
}
