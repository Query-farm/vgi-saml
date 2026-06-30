//! `saml.authn(msg)` — `AuthnStatement` + `AuthnContext`.

use roxmltree::Document;

use crate::model::Authn;
use crate::time::parse_xsd_datetime;
use crate::xmlutil;

pub fn authn(doc: &Document) -> Authn {
    let mut a = Authn::default();
    let Some(st) = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "AuthnStatement")
    else {
        return a;
    };

    a.authn_instant = xmlutil::attr(st, "AuthnInstant").and_then(parse_xsd_datetime);
    a.session_index = xmlutil::attr(st, "SessionIndex").map(str::to_string);
    a.session_not_on_or_after =
        xmlutil::attr(st, "SessionNotOnOrAfter").and_then(parse_xsd_datetime);

    if let Some(ctx) = xmlutil::child(st, "AuthnContext") {
        a.class_ref = xmlutil::child(ctx, "AuthnContextClassRef").and_then(xmlutil::text);
        a.decl_ref = xmlutil::child(ctx, "AuthnContextDeclRef").and_then(xmlutil::text);
        a.authenticating_authority =
            xmlutil::child(ctx, "AuthenticatingAuthority").and_then(xmlutil::text);
    }
    a
}
