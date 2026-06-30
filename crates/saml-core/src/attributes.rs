//! `saml.attributes(msg)` — one row per `AttributeValue`, multi-valued
//! attributes fanned out. `value_type` carries `@xsi:type` when present.

use roxmltree::Document;

use crate::model::AttributeRow;
use crate::xmlutil;

pub fn attributes(doc: &Document) -> Vec<AttributeRow> {
    let mut rows = Vec::new();
    let statements: Vec<_> = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "AttributeStatement")
        .collect();

    for (idx, stmt) in statements.into_iter().enumerate() {
        let statement_idx = idx as u32;
        for attr in xmlutil::children(stmt, "Attribute") {
            let name = xmlutil::attr(attr, "Name").map(str::to_string);
            let name_format = xmlutil::attr(attr, "NameFormat").map(str::to_string);
            let friendly_name = xmlutil::attr(attr, "FriendlyName").map(str::to_string);

            let values: Vec<_> = xmlutil::children(attr, "AttributeValue").collect();
            if values.is_empty() {
                rows.push(AttributeRow {
                    statement_idx,
                    name: name.clone(),
                    name_format: name_format.clone(),
                    friendly_name: friendly_name.clone(),
                    value: None,
                    value_type: None,
                });
                continue;
            }
            for v in values {
                // `@xsi:type` — match by local name "type" (any namespace).
                let value_type = xmlutil::attr(v, "type").map(str::to_string);
                rows.push(AttributeRow {
                    statement_idx,
                    name: name.clone(),
                    name_format: name_format.clone(),
                    friendly_name: friendly_name.clone(),
                    value: xmlutil::text(v),
                    value_type,
                });
            }
        }
    }
    rows
}

/// `saml.assertions(msg)` — one row per `Assertion`; `parent` is the enclosing
/// element's local name (reveals wrapping). Lives here as a sibling fan-out.
pub fn assertion_rows(doc: &Document) -> Vec<crate::model::AssertionRow> {
    use crate::model::AssertionRow;
    let mut rows = Vec::new();
    for (idx, a) in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "Assertion")
        .enumerate()
    {
        let signed = a.children().any(|n| {
            n.is_element()
                && n.tag_name().name() == "Signature"
                && n.tag_name().namespace() == Some(xmlutil::NS_DSIG)
        });
        let issuer = xmlutil::child(a, "Issuer").and_then(xmlutil::text);
        let subject = xmlutil::child(a, "Subject")
            .and_then(|s| xmlutil::child(s, "NameID"))
            .and_then(xmlutil::text);
        let in_response_to = xmlutil::child(a, "Subject")
            .and_then(|s| xmlutil::child(s, "SubjectConfirmation"))
            .and_then(|sc| xmlutil::child(sc, "SubjectConfirmationData"))
            .and_then(|scd| xmlutil::attr(scd, "InResponseTo"))
            .map(str::to_string);
        let parent = a.parent_element().map(|p| p.tag_name().name().to_string());
        rows.push(AssertionRow {
            idx: idx as u32,
            id: xmlutil::attr(a, "ID").map(str::to_string),
            signed,
            issuer,
            subject,
            in_response_to,
            parent,
        });
    }
    rows
}
