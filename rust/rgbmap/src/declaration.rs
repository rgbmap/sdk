//! The asset layer: the bytes a declaration is signed over, and the signature on them.
//!
//! Specified at <https://rgbmap.org/docs/declarations>.
//!
//! 🚨 This is the second implementation of the asset layer. Until it existed, one piece of
//! JavaScript decided on its own whether a declaration was signed by who it claims. Two
//! implementations are worth having only while they share nothing: when they disagree, neither
//! is right until the cause is found.

use serde_json::Value;

use crate::canonical::{canonicalize, CanonicalError};
use crate::ledger::sha256_hex;

/// The single line a wallet signs: the convention, its version, and the digest of the rest.
pub fn message_for(standard: &str, version: &str, digest: &str) -> String {
    format!("RGBMap {standard} v{version} {digest}")
}

/// The digest a signature covers: the declaration with `signature.value` emptied.
///
/// 🚨 Emptied every time, not only while signing. A signature is over exactly these bytes or
/// it is worthless, so a tool that hashed the signed copy would produce a digest nothing else
/// agrees with. `signature.address` stays: the address is part of what is signed.
pub fn signing_digest(declaration: &Value) -> Result<String, CanonicalError> {
    let mut stripped = declaration.clone();
    match stripped.get_mut("signature").and_then(Value::as_object_mut) {
        Some(signature) => {
            signature.insert("value".to_string(), Value::String(String::new()));
        }
        None => {
            return Err(CanonicalError {
                path: "$.signature".to_string(),
                message: "a declaration carries a signature object".to_string(),
            })
        }
    }
    Ok(sha256_hex(canonicalize(&stripped, "$")?.as_bytes()))
}

/// Whether `signature` is a valid BIP-322 simple signature by `address` over `message`.
///
/// 🚨 Accepting one signature a reference implementation rejects is an authentication bypass.
/// Rejecting one it accepts locks out a legitimate issuer. Both directions are pinned by
/// `vectors/bip322.json`, which was produced by an implementation written by someone else.
///
/// Malformed input is refused, not raised: the verifier this is checked against throws for
/// some malformed input and returns false for the rest, and both mean the same thing here.
pub fn verify_bip322(address: &str, message: &str, signature: &str) -> bool {
    bip322::verify_simple_encoded(address, message, signature).is_ok()
}

/// The digest, the message and the signature check in one step.
pub fn check_signature(declaration: &Value, standard: &str, version: &str) -> Result<bool, CanonicalError> {
    let digest = signing_digest(declaration)?;
    let signature = declaration.get("signature").and_then(Value::as_object);
    let address = signature.and_then(|s| s.get("address")).and_then(Value::as_str).unwrap_or("");
    let value = signature.and_then(|s| s.get("value")).and_then(Value::as_str).unwrap_or("");
    if address.is_empty() || value.is_empty() {
        return Ok(false);
    }
    Ok(verify_bip322(address, &message_for(standard, version, &digest), value))
}
