//! Deterministic JSON serialisation, for ledger records and for declarations.
//!
//! Specified at <https://rgbmap.org/docs/declarations#canonical-form>.
//!
//! The ledger hash is computed over these bytes, and the whole point of the hash chain
//! is that an outsider can recompute it. So the serialisation must be fixed, not
//! "whatever the JSON library does today":
//!
//! - object keys sorted by name
//! - `undefined` members dropped
//! - no whitespace anywhere
//! - values that cannot be represented deterministically are rejected, not coerced
//!
//! 🚨 A divergence from the JavaScript implementation raises no error anywhere: it produces a
//! different hash, the chain stops verifying, and "tampering is detectable" quietly stops
//! being true. Every rule below is pinned by `tests/vectors.rs` against `vectors/canonical.json`,
//! which both implementations are held to.

use serde_json::Value;

#[derive(Debug, PartialEq)]
pub struct CanonicalError {
    pub path: String,
    pub message: String,
}

fn reject(path: &str, message: &str) -> CanonicalError {
    CanonicalError { path: path.to_string(), message: message.to_string() }
}

/// Serialise a value canonically. `path` is only used to make rejections locatable.
pub fn canonicalize(value: &Value, path: &str) -> Result<String, CanonicalError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true".into() } else { "false".into() }),
        Value::String(s) => Ok(quote(s)),
        Value::Number(n) => number(n, path),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for (i, v) in items.iter().enumerate() {
                parts.push(canonicalize(v, &format!("{path}[{i}]"))?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            // Keys are sorted by name: insertion order depends on the code path that
            // built the object, and two paths producing the same state must hash alike.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for k in keys {
                let v = &map[k];
                parts.push(format!("{}:{}", quote(k), canonicalize(v, &format!("{path}.{k}"))?));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

/// Numbers must be integers within the range JavaScript can represent exactly.
///
/// Floats are rejected because their decimal form varies between implementations, and
/// because amounts are supposed to be decimal strings in the first place. Integers past
/// 2^53 are rejected for the same reason the API uses strings: JSON.parse would have
/// silently truncated them long before they reached here.
fn number(n: &serde_json::Number, path: &str) -> Result<String, CanonicalError> {
    if let Some(i) = n.as_i64() {
        if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&i) {
            return Err(reject(path, "integer outside the safe range, use a decimal string"));
        }
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        if u > 9_007_199_254_740_991 {
            return Err(reject(path, "integer outside the safe range, use a decimal string"));
        }
        return Ok(u.to_string());
    }
    if n.as_f64().is_some() {
        return Err(reject(path, "floating point values are not accepted, use a decimal string"));
    }
    Err(reject(path, "value cannot be represented deterministically"))
}

/// Quote a string the way `JSON.stringify` does.
///
/// The escaping rules matter as much as the ordering: `"`, `\` and the C0 control
/// characters are escaped, with `\b \t \n \f \r` using their short forms and everything
/// else below 0x20 using `\u00xx`. Characters above 0x7F are emitted as-is — JSON.stringify
/// does not escape them, and escaping them here would change every hash involving
/// non-ASCII text.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        assert_eq!(canonicalize(&v, "p").unwrap(), r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn rejects_floats_and_unsafe_integers() {
        assert!(canonicalize(&json!(1.5), "p").is_err());
        assert!(canonicalize(&json!(9007199254740993i64), "p").is_err());
        assert!(canonicalize(&json!(-9007199254740993i64), "p").is_err());
        assert!(canonicalize(&json!(9007199254740991i64), "p").is_ok());
    }

    #[test]
    fn emits_no_whitespace() {
        let v = json!({ "a": [1, 2, { "b": "c" }] });
        let s = canonicalize(&v, "p").unwrap();
        assert!(!s.contains(' '), "canonical form must not contain spaces: {s}");
    }
}
