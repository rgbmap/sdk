//! The ledger layer: the hash chain, the commitments and the balance rule.
//!
//! Specified at <https://rgbmap.org/docs/ledgers-and-anchors>.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Fields of a hashed tuple are joined by one 0x1F byte.
pub const SEP: u8 = 0x1F;

/// The `prev_hash` the first record continues from.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The entry hash: fields joined by a single 0x1F byte, hashed as UTF-8.
///
/// The chain commits to the public half rather than carrying it, so a record hashes the same
/// whether or not its contents were published.
pub fn entry_hash(prev: &str, seq: &str, ts: &str, public_commitment: &str, private_commitment: &str) -> String {
    let mut buf = Vec::new();
    for (i, part) in [prev, seq, ts, public_commitment, private_commitment].iter().enumerate() {
        if i > 0 {
            buf.push(SEP);
        }
        buf.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&buf)
}

/// The commitment to a record's public half, for the records published in full.
pub fn public_commitment(public: &str, salt: &str) -> String {
    let mut buf = Vec::new();
    for (i, part) in ["rgb-ledger-pub-v1", public, salt].iter().enumerate() {
        if i > 0 {
            buf.push(SEP);
        }
        buf.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&buf)
}

/// The anchor commitment a snapshot claims.
pub fn anchor_commitment(snapshot: &Value) -> String {
    let liabilities = snapshot
        .get("liabilities")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(asset, amount)| (asset.clone(), string_of(amount)))
                .collect::<BTreeMap<_, _>>()
                .iter()
                .map(|(asset, amount)| format!("{asset}={amount}"))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    let parts = [
        "rgb-anchor-v1".to_string(),
        string_of(&snapshot["network"]),
        string_of(&snapshot["snapshotId"]),
        string_of(&snapshot["ledgerSeq"]),
        string_of(&snapshot["ledgerHash"]),
        string_of(&snapshot["liabilitiesRoot"]),
        liabilities,
    ];

    let mut buf = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            buf.push(SEP);
        }
        buf.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&buf)
}

/// Numbers arrive as strings or as JSON numbers depending on the field; both hash as decimal.
pub fn string_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Whether one record's legs sum to zero per asset. i128 covers sats and token amounts.
pub fn legs_balance(public: &Value) -> bool {
    let Some(legs) = public.get("legs").and_then(Value::as_array) else {
        return true;
    };
    let mut sums: BTreeMap<String, i128> = BTreeMap::new();
    for leg in legs {
        let asset = string_of(&leg["assetId"]);
        let Ok(delta) = string_of(&leg["delta"]).parse::<i128>() else {
            return false;
        };
        *sums.entry(asset).or_insert(0) += delta;
    }
    sums.values().all(|v| *v == 0)
}
