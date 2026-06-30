//! Hardened, read-only XML load — the security gate that everything else sits
//! behind.
//!
//! Every SAML blob is attacker-controlled, so the loader is locked down:
//!
//! * **No DTD, no external entities, no entity expansion.** `roxmltree` parses
//!   with `allow_dtd = false`, so a `<!DOCTYPE`/`<!ENTITY` is rejected
//!   *unparsed* ([`WfKind::DtdPresent`]) — defeating **XXE**, **billion-laughs /
//!   exponential entity expansion**, and SSRF-via-external-entity. This is
//!   non-negotiable and a test gate.
//! * **Bounded node count** ([`MAX_NODES`]) — deeply-nested or oversized
//!   documents hit the cap and error rather than exhausting memory/stack.
//! * **Never panics** — a malformed blob maps to a [`WfKind`], not a crash.

use roxmltree::{Document, Error as RoError, ParsingOptions};

use crate::wellformed::WfKind;

/// Cap on parsed node count (depth/size backstop). A real SAML message is a few
/// hundred nodes; 100k is generous while still bounding a hostile blob.
pub const MAX_NODES: u32 = 100_000;

/// Parse `src` into a hardened read-only [`Document`], or a [`WfKind`] reason.
pub fn parse(src: &str) -> Result<Document<'_>, WfKind> {
    let opt = ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_NODES,
    };
    Document::parse_with_options(src, opt).map_err(classify)
}

/// Map a `roxmltree` parse error to a stable [`WfKind`].
fn classify(e: RoError) -> WfKind {
    match e {
        // DOCTYPE present — rejected before any entity could be expanded. This
        // is the XXE / billion-laughs gate.
        RoError::DtdDetected => WfKind::DtdPresent,
        // Entity machinery tripped (e.g. an undefined/looping/malformed entity
        // reference that slipped past the DTD gate) — blocked, never expanded.
        RoError::UnknownEntityReference(..)
        | RoError::MalformedEntityReference(..)
        | RoError::EntityReferenceLoop(..)
        | RoError::UnexpectedEntityCloseTag(..) => WfKind::EntityBlocked,
        // Ran out of the node budget — treat as oversized/hostile.
        RoError::NodesLimitReached
        | RoError::AttributesLimitReached
        | RoError::NamespacesLimitReached => WfKind::NotXml,
        // Ended mid-token / unclosed root → truncated.
        RoError::UnexpectedEndOfStream | RoError::UnclosedRootNode | RoError::NoRootNode => {
            WfKind::Truncated
        }
        // Bad byte / non-XML char / bad encoding declaration.
        RoError::NonXmlChar(..) | RoError::InvalidChar(..) => WfKind::EncodingError,
        // Everything else is "structurally not XML".
        _ => WfKind::NotXml,
    }
}
