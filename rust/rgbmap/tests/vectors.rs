//! Both implementations are held to `vectors/`, and neither is held to the other.
//!
//! 🚨 A divergence raises no error anywhere on its own: the hash simply differs, the chain
//! stops verifying, and "tampering is detectable" quietly stops being true. These vectors are
//! what turns that into a failing test.
//!
//! The BIP-322 set was produced by `bip322-js`, an implementation written by someone else. A
//! set produced by the code it checks would prove only that the code agrees with itself.

use rgbmap::canonical::canonicalize;
use rgbmap::declaration::verify_bip322;
use rgbmap::ledger::{anchor_commitment, entry_hash, public_commitment, GENESIS};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/");
    serde_json::from_str(&std::fs::read_to_string(format!("{path}{name}")).expect(name)).unwrap()
}

#[test]
fn canonical_form_matches_the_vectors() {
    let v = load("canonical.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 18, "too few vectors: {}", cases.len());
    for case in cases {
        let got = canonicalize(&case["value"], "$").unwrap_or_else(|e| panic!("{}: {:?}", case["name"], e));
        assert_eq!(got, case["canonical"].as_str().unwrap(), "case {}", case["name"]);
    }
}

#[test]
fn what_has_no_canonical_form_is_refused() {
    let v = load("canonical.json");
    for case in v["rejected"].as_array().unwrap() {
        assert!(canonicalize(&case["value"], "$").is_err(), "accepted {}", case["name"]);
    }
}

#[test]
fn the_chain_recomputes_from_the_genesis_record() {
    let v = load("signet-ledger.json");
    let entries = v["entries"].as_array().unwrap();
    assert!(entries.len() > 10, "too few records: {}", entries.len());
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
        assert_eq!(s("prevHash"), prev, "record {} does not continue the chain", i + 1);
        let got = entry_hash(&s("prevHash"), &s("seq"), &s("ts"), &s("publicCommitment"), &s("privateCommitment"));
        assert_eq!(got, s("hash"), "record {} does not hash to what was published", i + 1);
        prev = s("hash");
    }
}

#[test]
fn records_opened_in_full_match_the_commitment_the_chain_carries() {
    let v = load("signet-ledger.json");
    let mut opened = 0;
    for e in v["entries"].as_array().unwrap() {
        let (Some(public), Some(salt)) = (e["public"].as_str(), e["publicSalt"].as_str()) else { continue };
        assert_eq!(public_commitment(public, salt), e["publicCommitment"].as_str().unwrap(), "record {}", e["seq"]);
        opened += 1;
    }
    assert!(opened > 0, "no record in the vectors is published in full");
}

#[test]
fn every_snapshot_recomputes_its_own_anchor_commitment() {
    let v = load("signet-snapshots.json");
    let snapshots = v["snapshots"].as_array().unwrap();
    assert!(!snapshots.is_empty());
    for s in snapshots {
        assert_eq!(anchor_commitment(s), s["commitment"].as_str().unwrap(), "snapshot {}", s["snapshotId"]);
    }
}

#[test]
fn bip322_accepts_and_refuses_exactly_what_the_reference_does() {
    let v = load("bip322.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 60, "too few vectors: {}", cases.len());
    for c in cases {
        let got = verify_bip322(c["address"].as_str().unwrap(), c["message"].as_str().unwrap(), c["signature"].as_str().unwrap());
        assert_eq!(got, c["verifies"].as_bool().unwrap(), "{} / {} / {}", c["network"], c["kind"], c["name"]);
    }
}

#[test]
fn bip322_refuses_every_negative_case() {
    let v = load("bip322.json");
    for c in v["negative"].as_array().unwrap() {
        let got = verify_bip322(c["address"].as_str().unwrap(), c["message"].as_str().unwrap(), c["signature"].as_str().unwrap());
        assert!(!got, "accepted a case meant to be refused: {}", c["name"]);
    }
}
