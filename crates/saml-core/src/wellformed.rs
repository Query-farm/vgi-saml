//! `well_formed` classification: turn an attacker-controlled blob into a
//! `(ok, kind, detail)` triage verdict that **never panics**.
//!
//! `kind` is one of the stable strings in [`WfKind`]. Two of them —
//! `dtd-present` and `entity-blocked` — double as **XXE / billion-laughs**
//! signals: the hardened loader (`crate::xml`) rejects any DOCTYPE/entity
//! before it can be expanded, so their mere presence is surfaced rather than
//! processed.

/// The discriminator returned by `well_formed`. Every variant has a stable
/// lowercase wire string (see [`WfKind::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfKind {
    /// Decodes/parses cleanly into a SAML message.
    Ok,
    /// Decoded to bytes, but they are not XML.
    NotXml,
    /// Parses as XML, but the root is not a recognized SAML element.
    NotSaml,
    /// The input claimed to be base64 but did not decode.
    BadBase64,
    /// The input claimed to be DEFLATE but did not inflate (or hit the bomb cap).
    BadDeflate,
    /// A `<!DOCTYPE` was present — rejected unparsed (XXE / billion-laughs guard).
    DtdPresent,
    /// An entity reference / DTD construct was blocked (XXE guard).
    EntityBlocked,
    /// The document ended mid-token (truncated input).
    Truncated,
    /// The bytes are not valid UTF-8 / declared encoding could not be honored.
    EncodingError,
}

impl WfKind {
    /// The stable lowercase wire string for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            WfKind::Ok => "ok",
            WfKind::NotXml => "not-xml",
            WfKind::NotSaml => "not-saml",
            WfKind::BadBase64 => "bad-base64",
            WfKind::BadDeflate => "bad-deflate",
            WfKind::DtdPresent => "dtd-present",
            WfKind::EntityBlocked => "entity-blocked",
            WfKind::Truncated => "truncated",
            WfKind::EncodingError => "encoding-error",
        }
    }
}

/// The full `well_formed(msg) -> STRUCT(ok, kind, detail)` result.
#[derive(Debug, Clone)]
pub struct WellFormed {
    pub ok: bool,
    pub kind: WfKind,
    pub detail: String,
}

impl WellFormed {
    pub fn ok() -> Self {
        WellFormed {
            ok: true,
            kind: WfKind::Ok,
            detail: String::new(),
        }
    }

    pub fn err(kind: WfKind, detail: impl Into<String>) -> Self {
        WellFormed {
            ok: false,
            kind,
            detail: detail.into(),
        }
    }
}
