//! `saml.conditions(msg)` — the validity window + audience/usage constraints.
//! No "expired" verdict (the caller compares to `now()` with its own skew).

use roxmltree::Document;

use crate::model::Conditions;
use crate::time::parse_xsd_datetime;
use crate::xmlutil;

pub fn conditions(doc: &Document) -> Conditions {
    let mut c = Conditions::default();
    let Some(cond) = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Conditions")
    else {
        return c;
    };

    c.not_before = xmlutil::attr(cond, "NotBefore").and_then(parse_xsd_datetime);
    c.not_on_or_after = xmlutil::attr(cond, "NotOnOrAfter").and_then(parse_xsd_datetime);

    for ar in xmlutil::children(cond, "AudienceRestriction") {
        for aud in xmlutil::children(ar, "Audience") {
            if let Some(t) = xmlutil::text(aud) {
                c.audiences.push(t);
            }
        }
    }

    c.one_time_use = xmlutil::child(cond, "OneTimeUse").is_some();

    let proxy: Vec<_> = xmlutil::children(cond, "ProxyRestriction").collect();
    c.proxy_restriction_count = proxy.len() as u32;
    for pr in proxy {
        for aud in xmlutil::children(pr, "Audience") {
            if let Some(t) = xmlutil::text(aud) {
                c.proxy_audiences.push(t);
            }
        }
    }
    c
}
