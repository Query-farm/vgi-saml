//! Exclusive XML Canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`)
//! plus the enveloped-signature transform.
//!
//! This is the load-bearing crypto-adjacent code: XML-DSig for SAML signs the
//! **canonical octets** of an element, and SAML mandates *exclusive* C14N
//! precisely because a signed `Assertion` is designed to be lifted out of one
//! document and embedded in another. Get the byte serialization wrong and every
//! `digest_ok` / `sig_valid` is wrong. The algorithm is small and fully
//! specified, so we vendor it here, pin it, and validate it against
//! signxml/lxml-produced golden vectors (see `tests/oracle.rs`).
//!
//! ## What "exclusive" means
//!
//! Unlike inclusive C14N, an element only emits the namespace declarations it
//! **visibly utilizes** — its own element prefix and the prefixes of its
//! attributes — plus any prefixes named in an `InclusiveNamespaces PrefixList`.
//! Namespaces merely *in scope* (e.g. an `xmlns:xs` declared on an ancestor and
//! used only inside an attribute *value* as a QName) are dropped. That is the
//! whole reason a lifted assertion keeps a valid signature.

use std::collections::HashSet;

use roxmltree::{Node, NodeId};

/// Exclusively canonicalize the subtree rooted at `node`.
///
/// * `src` is the original document text (needed to recover literal prefixes,
///   which roxmltree resolves away).
/// * `omit` — if `Some`, that node (and its whole subtree) is skipped; this is
///   how the **enveloped-signature transform** removes the `ds:Signature`
///   before digesting its enclosing element.
/// * `inclusive_prefixes` — the `InclusiveNamespaces PrefixList` (use `#default`
///   for the default namespace); these prefixes are rendered as if visibly used.
pub fn exclusive_c14n(
    node: Node,
    src: &str,
    omit: Option<NodeId>,
    inclusive_prefixes: &[String],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rendered: Vec<(Option<String>, String)> = Vec::new();
    write_node(node, src, omit, inclusive_prefixes, &mut rendered, &mut out);
    out
}

fn write_node(
    node: Node,
    src: &str,
    omit: Option<NodeId>,
    incl: &[String],
    rendered: &mut Vec<(Option<String>, String)>,
    out: &mut Vec<u8>,
) {
    if Some(node.id()) == omit {
        return;
    }
    if node.is_element() {
        write_element(node, src, omit, incl, rendered, out);
    } else if node.is_text() {
        if let Some(t) = node.text() {
            escape_text(t, out);
        }
    } else if node.is_pi() {
        if let Some(pi) = node.pi() {
            out.extend_from_slice(b"<?");
            out.extend_from_slice(pi.target.as_bytes());
            if let Some(v) = pi.value {
                if !v.is_empty() {
                    out.push(b' ');
                    out.extend_from_slice(v.as_bytes());
                }
            }
            out.extend_from_slice(b"?>");
        }
    }
    // Comments are omitted under the `#WithComments`-free exc-c14n profile.
}

fn write_element(
    node: Node,
    src: &str,
    omit: Option<NodeId>,
    incl: &[String],
    rendered: &mut Vec<(Option<String>, String)>,
    out: &mut Vec<u8>,
) {
    // Literal qualified name straight from source — exact prefix, no guessing.
    let qname = element_qname(node, src);
    let eprefix: Option<&str> = qname.split_once(':').map(|(p, _)| p);

    out.push(b'<');
    out.extend_from_slice(qname.as_bytes());

    // --- compute visibly-utilized prefixes ---
    let mut utilized: Vec<Option<String>> = Vec::new();
    utilized.push(eprefix.map(str::to_string)); // element's own prefix (None = default)
    for attr in node.attributes() {
        if let Some(uri) = attr.namespace() {
            if let Some(p) = node.lookup_prefix(uri) {
                utilized.push(Some(p.to_string()));
            }
        }
        // Unprefixed attributes are in no namespace → utilize nothing.
    }
    for p in incl {
        if p == "#default" {
            utilized.push(None);
        } else {
            utilized.push(Some(p.clone()));
        }
    }

    // --- decide which declarations to render against the output context ---
    let mut to_render: Vec<(Option<String>, String)> = Vec::new();
    let mut seen: HashSet<Option<String>> = HashSet::new();
    for p in utilized {
        if !seen.insert(p.clone()) {
            continue;
        }
        let uri = match &p {
            None => node.default_namespace(),
            Some(px) => node.lookup_namespace_uri(Some(px.as_str())),
        };
        match uri {
            Some(u) if !u.is_empty() => {
                if current_binding(rendered, &p) != Some(u) {
                    to_render.push((p.clone(), u.to_string()));
                }
            }
            _ => {
                // Default-namespace undeclaration: only when an ancestor output a
                // non-empty default that is no longer in scope here.
                if p.is_none() {
                    if let Some(cur) = current_binding(rendered, &None) {
                        if !cur.is_empty() {
                            to_render.push((None, String::new()));
                        }
                    }
                }
            }
        }
    }
    // Default namespace first, then prefixed declarations sorted by prefix.
    to_render.sort_by(|a, b| match (&a.0, &b.0) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, _) => std::cmp::Ordering::Less,
        (_, None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    });

    let base_len = rendered.len();
    for (p, u) in &to_render {
        match p {
            None => {
                out.extend_from_slice(b" xmlns=\"");
            }
            Some(px) => {
                out.extend_from_slice(b" xmlns:");
                out.extend_from_slice(px.as_bytes());
                out.extend_from_slice(b"=\"");
            }
        }
        escape_attr(u, out);
        out.push(b'"');
        rendered.push((p.clone(), u.clone()));
    }

    // Attributes sorted by (namespace-uri, local-name); empty uri sorts first.
    let mut attrs: Vec<_> = node.attributes().collect();
    attrs.sort_by(|a, b| {
        (a.namespace().unwrap_or(""), a.name()).cmp(&(b.namespace().unwrap_or(""), b.name()))
    });
    for attr in attrs {
        out.push(b' ');
        if let Some(uri) = attr.namespace() {
            if let Some(px) = node.lookup_prefix(uri) {
                out.extend_from_slice(px.as_bytes());
                out.push(b':');
            }
        }
        out.extend_from_slice(attr.name().as_bytes());
        out.extend_from_slice(b"=\"");
        escape_attr(attr.value(), out);
        out.push(b'"');
    }

    out.push(b'>');

    for child in node.children() {
        write_node(child, src, omit, incl, rendered, out);
    }

    out.extend_from_slice(b"</");
    out.extend_from_slice(qname.as_bytes());
    out.push(b'>');

    rendered.truncate(base_len);
}

/// Recover an element's **literal** qualified name (`saml:Assertion`) from the
/// source. roxmltree resolves prefixes away, so we read the bytes after the
/// opening `<` up to the first whitespace / `>` / `/`.
fn element_qname<'a>(node: Node, src: &'a str) -> &'a str {
    let r = node.range();
    let bytes = src.as_bytes();
    let start = (r.start + 1).min(r.end); // skip '<'
    let mut end = start;
    while end < r.end {
        match bytes[end] {
            b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/' => break,
            _ => end += 1,
        }
    }
    &src[start..end]
}

/// The currently-output URI bound to `prefix` (nearest ancestor declaration).
fn current_binding<'a>(
    rendered: &'a [(Option<String>, String)],
    prefix: &Option<String>,
) -> Option<&'a str> {
    rendered
        .iter()
        .rev()
        .find(|(p, _)| p == prefix)
        .map(|(_, u)| u.as_str())
}

/// Escape text-node content: `&`,`<`,`>` and carriage return.
fn escape_text(s: &str, out: &mut Vec<u8>) {
    for &b in s.as_bytes() {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
}

/// Escape attribute-value content: `&`,`<`,`"`, tab, newline, carriage return.
/// (`>` is intentionally NOT escaped in attribute values.)
fn escape_attr(s: &str, out: &mut Vec<u8>) {
    for &b in s.as_bytes() {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
}
