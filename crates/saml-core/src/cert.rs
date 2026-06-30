//! Signer-certificate parsing and **key-trust-free** signature math.
//!
//! The worker only ever uses the **embedded** `KeyInfo/X509Certificate` to check
//! that the signature is internally consistent. It holds no private keys, no
//! trust store, and makes no network calls — `sig_valid = true` means "the
//! embedded cert signed these bytes", never "this key is authorized" (that
//! decision is the caller's `JOIN` against their own IdP cert inventory). All
//! verification is pure Rust (`rsa` / `p256` / `p384` / `ed25519-dalek`) — no
//! native `xmlsec1` / OpenSSL toolchain.

use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey as RsaVk};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::prelude::*;

/// Parsed signer-certificate facts (everything the worker surfaces about a cert).
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub der: Vec<u8>,
    pub sha256_hex: String,
    pub subject: String,
    pub issuer: String,
    /// The SubjectPublicKeyInfo DER, for the verifier crates.
    pub spki_der: Vec<u8>,
}

/// Parse an X.509 cert (DER) into the facts we expose. `None` on garbage.
pub fn parse_cert(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let sha256_hex = hex_lower(&Sha256::digest(der));
    Some(CertInfo {
        der: der.to_vec(),
        sha256_hex,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        spki_der: cert.public_key().raw.to_vec(),
    })
}

/// SHA-256 hex fingerprint of arbitrary bytes (e.g. a raw DER cert).
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Signature algorithm families we recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgo {
    RsaSha1,
    RsaSha256,
    RsaSha384,
    RsaSha512,
    EcdsaSha1,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
    Unknown,
}

impl SigAlgo {
    /// Classify a `SignatureMethod` Algorithm URI.
    pub fn from_uri(uri: &str) -> SigAlgo {
        let u = uri.to_ascii_lowercase();
        if u.contains("rsa-sha256") {
            SigAlgo::RsaSha256
        } else if u.contains("rsa-sha384") {
            SigAlgo::RsaSha384
        } else if u.contains("rsa-sha512") {
            SigAlgo::RsaSha512
        } else if u.contains("rsa-sha1") {
            SigAlgo::RsaSha1
        } else if u.contains("ecdsa-sha256") {
            SigAlgo::EcdsaSha256
        } else if u.contains("ecdsa-sha384") {
            SigAlgo::EcdsaSha384
        } else if u.contains("ecdsa-sha512") {
            SigAlgo::EcdsaSha512
        } else if u.contains("ecdsa-sha1") {
            SigAlgo::EcdsaSha1
        } else if u.contains("ed25519") || u.contains("eddsa") {
            SigAlgo::Ed25519
        } else {
            SigAlgo::Unknown
        }
    }

    /// The JOSE-style short label (`RS256`, `ES256`, `EdDSA`, …) surfaced as `algo`.
    pub fn label(self) -> &'static str {
        match self {
            SigAlgo::RsaSha1 => "RS1",
            SigAlgo::RsaSha256 => "RS256",
            SigAlgo::RsaSha384 => "RS384",
            SigAlgo::RsaSha512 => "RS512",
            SigAlgo::EcdsaSha1 => "ES1",
            SigAlgo::EcdsaSha256 => "ES256",
            SigAlgo::EcdsaSha384 => "ES384",
            SigAlgo::EcdsaSha512 => "ES512",
            SigAlgo::Ed25519 => "EdDSA",
            SigAlgo::Unknown => "unknown",
        }
    }
}

/// Compute a reference digest by its `DigestMethod` Algorithm URI. Returns the
/// raw digest bytes, or `None` for an unsupported method (e.g. SHA-1, which we
/// deliberately do not implement).
pub fn digest_by_uri(uri: &str, data: &[u8]) -> Option<Vec<u8>> {
    let u = uri.to_ascii_lowercase();
    if u.contains("sha256") {
        Some(Sha256::digest(data).to_vec())
    } else if u.contains("sha384") {
        Some(Sha384::digest(data).to_vec())
    } else if u.contains("sha512") {
        Some(Sha512::digest(data).to_vec())
    } else {
        None
    }
}

/// Verify `signature` over `msg` (the canonicalized `SignedInfo` octets) using
/// the embedded cert's public key. Returns `false` for any failure — bad key,
/// unsupported algorithm, or a genuine signature mismatch — never panics.
pub fn verify(spki_der: &[u8], algo: SigAlgo, msg: &[u8], signature: &[u8]) -> bool {
    // The RSA arms build the verifying key with a concrete digest type, so the
    // `Verifier` impl (which needs the digest's OID prefix) resolves.
    let rsa_ok = |vk_verify: &dyn Fn(&[u8], &RsaSig) -> bool| -> bool {
        match RsaSig::try_from(signature) {
            Ok(sig) => vk_verify(msg, &sig),
            Err(_) => false,
        }
    };
    match algo {
        SigAlgo::RsaSha256 => match rsa::RsaPublicKey::from_public_key_der(spki_der) {
            Ok(pk) => {
                let vk = RsaVk::<Sha256>::new(pk);
                rsa_ok(&|m, s| vk.verify(m, s).is_ok())
            }
            Err(_) => false,
        },
        SigAlgo::RsaSha384 => match rsa::RsaPublicKey::from_public_key_der(spki_der) {
            Ok(pk) => {
                let vk = RsaVk::<Sha384>::new(pk);
                rsa_ok(&|m, s| vk.verify(m, s).is_ok())
            }
            Err(_) => false,
        },
        SigAlgo::RsaSha512 => match rsa::RsaPublicKey::from_public_key_der(spki_der) {
            Ok(pk) => {
                let vk = RsaVk::<Sha512>::new(pk);
                rsa_ok(&|m, s| vk.verify(m, s).is_ok())
            }
            Err(_) => false,
        },
        SigAlgo::EcdsaSha256 => ecdsa_verify(spki_der, &Sha256::digest(msg), signature),
        SigAlgo::EcdsaSha384 => ecdsa_verify(spki_der, &Sha384::digest(msg), signature),
        SigAlgo::EcdsaSha512 => ecdsa_verify(spki_der, &Sha512::digest(msg), signature),
        SigAlgo::Ed25519 => ed25519_verify(spki_der, msg, signature),
        // SHA-1 families and unknowns are intentionally unverified.
        SigAlgo::RsaSha1 | SigAlgo::EcdsaSha1 | SigAlgo::Unknown => false,
    }
}

/// ECDSA over a prehash. XML-DSig ECDSA signatures are the raw IEEE-P1363
/// `r || s` concatenation, which `Signature::from_slice` accepts. Try P-256
/// then P-384 (the `SignatureMethod` URI does not name the curve).
fn ecdsa_verify(spki_der: &[u8], prehash: &[u8], sig: &[u8]) -> bool {
    use p256::pkcs8::DecodePublicKey as _;
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        if let Ok(s) = p256::ecdsa::Signature::from_slice(sig) {
            return vk.verify_prehash(prehash, &s).is_ok();
        }
    }
    if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        if let Ok(s) = p384::ecdsa::Signature::from_slice(sig) {
            return vk.verify_prehash(prehash, &s).is_ok();
        }
    }
    false
}

fn ed25519_verify(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::pkcs8::DecodePublicKey as _;
    use ed25519_dalek::Verifier as _;
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}
