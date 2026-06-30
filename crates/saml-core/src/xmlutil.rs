//! Small, allocation-light helpers for walking a hardened roxmltree document by
//! **local name** (SAML mixes the `saml:`, `samlp:`, and `ds:` prefixes, so we
//! match on local names and namespace URIs rather than literal prefixes).

use roxmltree::Node;

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// First direct-child element with the given local name.
pub fn child<'a, 'i>(node: Node<'a, 'i>, local: &str) -> Option<Node<'a, 'i>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == local)
}

/// All direct-child elements with the given local name.
pub fn children<'a, 'i>(node: Node<'a, 'i>, local: &'a str) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children()
        .filter(move |n| n.is_element() && n.tag_name().name() == local)
}

/// The concatenated text of an element's direct text children, trimmed.
pub fn text(node: Node) -> Option<String> {
    let mut s = String::new();
    for c in node.children() {
        if c.is_text() {
            if let Some(t) = c.text() {
                s.push_str(t);
            }
        }
    }
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// An attribute by local name (namespace-agnostic), trimmed of surrounding ws.
pub fn attr<'a>(node: Node<'a, '_>, local: &str) -> Option<&'a str> {
    node.attributes()
        .find(|a| a.name() == local)
        .map(|a| a.value())
}
