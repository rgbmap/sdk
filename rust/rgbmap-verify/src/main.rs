//! Recompute a published RGBMap archive from the objects alone.
//! The checks are specified at https://rgbmap.org/docs/verification
//!
//!     rgbmap-verify --objects https://data.rgbmap.org --index https://api.rgbmap.org
//!     rgbmap-verify --arweave https://turbo-gateway.com --index https://api.rgbmap.org
//!     rgbmap-verify --objects ./objects --list objects.json --bitcoin https://mempool.space/api
//!
//! It asks the index for one thing: which object paths exist. Everything that list names is
//! fetched and hashed here, and every conclusion is recomputed from those bytes.
//!
//! 🚨 This is a second implementation on purpose, sharing no code with the JavaScript one. A
//! hash chain proves history was not altered only when the side recomputing it is not the side
//! that wrote it.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use rgbmap::ledger::{anchor_commitment, entry_hash, legs_balance, public_commitment, sha256_hex, string_of, GENESIS};

struct Args {
    objects: Option<String>,
    arweave: Option<String>,
    list: Option<String>,
    index: Option<String>,
    bitcoin: Option<String>,
    publisher: Option<String>,
}

fn parse_args() -> Args {
    let mut args = Args {
        objects: None,
        arweave: None,
        list: None,
        index: None,
        bitcoin: None,
        publisher: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--objects" => args.objects = it.next(),
            "--arweave" => args.arweave = it.next(),
            "--list" => args.list = it.next(),
            "--index" => args.index = it.next(),
            "--bitcoin" => args.bitcoin = it.next(),
            "--publisher" => args.publisher = it.next(),
            "-h" | "--help" => {
                eprintln!("usage: rgbmap-verify --objects <dir|url> | --arweave <gateway>");
                eprintln!("                     [--list <file> | --index <api>] [--bitcoin <api>] [--publisher <id>]");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    args
}

/// mempool.space puts mainnet at the root and every other network under its own name.
fn mempool_for(network: &str) -> String {
    if network == "mainnet" || network.is_empty() {
        "https://mempool.space/api".into()
    } else {
        format!("https://mempool.space/{network}/api")
    }
}

fn get_json(url: &str) -> Result<Value, String> {
    ureq::get(url)
        .call()
        .map_err(|e| format!("{url}: {e}"))?
        .into_json()
        .map_err(|e| format!("{url}: {e}"))
}

fn get_bytes(url: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ureq::get(url)
        .call()
        .map_err(|e| format!("{url}: {e}"))?
        .into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("{url}: {e}"))?;
    Ok(buf)
}

fn main() {
    let args = parse_args();
    let mut problems: Vec<String> = Vec::new();
    let mut mark = 0usize;

    macro_rules! note {
        ($($arg:tt)*) => {{
            let message = format!($($arg)*);
            println!("  \u{2715} {message}");
            problems.push(message);
        }};
    }
    macro_rules! section {
        ($($arg:tt)*) => {{
            let found = problems.len() - mark;
            mark = problems.len();
            let tick = if found == 0 { "\u{2713}" } else { "\u{2715}" };
            let tail = if found == 0 { String::new() } else { format!(" \u{2014} {found} problem(s) above") };
            println!("  {tick} {}{tail}", format!($($arg)*));
        }};
    }

    // ---------- the object list ----------

    let listing: Vec<Value> = if let Some(file) = &args.list {
        serde_json::from_str(&fs::read_to_string(file).expect("read list")).expect("parse list")
    } else if let Some(index) = &args.index {
        let publisher = args.publisher.clone().unwrap_or_default();
        let url = format!("{}/v1/objects?publisher={}", index.trim_end_matches('/'), urlencode(&publisher));
        get_json(&url)
            .expect("object listing")
            .get("objects")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    } else {
        eprintln!("give --list <file> or --index <api> for the object paths");
        std::process::exit(2);
    };

    let mut shards: Vec<&Value> = listing.iter().filter(|o| o["kind"] == "ledger").collect();
    shards.sort_by_key(|o| string_of(&o["from_seq"]).parse::<u64>().unwrap_or(0));
    let snapshots: Vec<&Value> = listing.iter().filter(|o| o["kind"] == "snapshot").collect();
    println!(
        "{} objects named: {} ledger shards, {} snapshots",
        listing.len(),
        shards.len(),
        snapshots.len()
    );

    // ---------- 1. every object re-hashed ----------

    let mut bodies: BTreeMap<String, String> = BTreeMap::new();
    for object in shards.iter().chain(snapshots.iter()) {
        let path = string_of(&object["path"]);
        let bytes = match read_object(&args, object) {
            Ok(b) => b,
            Err(e) => {
                note!("{path}: {e}");
                continue;
            }
        };
        let digest = sha256_hex(&bytes);
        let listed = string_of(&object["sha256"]);
        if !listed.is_empty() && digest != listed {
            note!("{path}: hashes to {digest}, listed as {listed}");
        }
        bodies.insert(path, String::from_utf8_lossy(&bytes).into_owned());
    }
    section!(
        "{} objects fetched from {} and hashed",
        bodies.len(),
        args.arweave.clone().or(args.objects.clone()).unwrap_or_default()
    );

    // ---------- 2. shards continuous ----------

    let mut entries: Vec<Value> = Vec::new();
    let mut expected: u64 = 1;
    for object in &shards {
        let path = string_of(&object["path"]);
        let Some(text) = bodies.get(&path) else { continue };
        let parsed: Value = serde_json::from_str(text).expect("shard is JSON");
        let from = string_of(&parsed["from_seq"]).parse::<u64>().unwrap_or(0);
        let to = string_of(&parsed["to_seq"]).parse::<u64>().unwrap_or(0);
        if from != expected {
            note!("shard {from}-{to}: expected it to start at {expected}");
        }
        expected = to + 1;
        if let Some(list) = parsed["entries"].as_array() {
            entries.extend(list.iter().cloned());
        }
    }
    section!("{} shards, continuous through #{}", shards.len(), expected - 1);

    // ---------- 3 + 4. hash chain and balance ----------

    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        let seq = string_of(&e["seq"]);
        let recomputed = entry_hash(
            &string_of(&e["prev_hash"]),
            &seq,
            &string_of(&e["ts"]),
            &string_of(&e["public_commitment"]),
            &string_of(&e["private_commitment"]),
        );
        if recomputed != string_of(&e["hash"])
            || string_of(&e["prev_hash"]) != prev
            || seq.parse::<usize>().unwrap_or(0) != i + 1
        {
            note!("record #{seq}: hash or link does not recompute");
        }
        prev = string_of(&e["hash"]);

        // Only the records the publisher opened carry bytes to check; the rest carry a
        // commitment, and the chain says nothing about what is behind it.
        if !e["public"].is_null() {
            if public_commitment(&string_of(&e["public"]), &string_of(&e["public_salt"]))
                != string_of(&e["public_commitment"])
            {
                note!("record #{seq}: public bytes do not match the commitment");
            }
            match serde_json::from_str::<Value>(&string_of(&e["public"])) {
                Ok(public) => {
                    if !legs_balance(&public) {
                        note!("record #{seq}: legs do not sum to zero");
                    }
                }
                Err(_) => note!("record #{seq}: public segment is not JSON"),
            }
        }
    }
    let opened = entries.iter().filter(|e| !e["public"].is_null()).count();
    section!("{} records recompute from the genesis record, {opened} of them opened in full", entries.len());

    // ---------- 5 + 6 + 7. commitments, heads, bitcoin ----------

    let by_seq: BTreeMap<u64, String> = entries
        .iter()
        .map(|e| (string_of(&e["seq"]).parse::<u64>().unwrap_or(0), string_of(&e["hash"])))
        .collect();

    // 🚨 The bitcoin API has to match the network the snapshots name. Defaulting to one
    // network would make a mainnet anchor look missing on signet, which reads like
    // tampering rather than like the wrong URL.
    let network = snapshots
        .iter()
        .filter_map(|o| bodies.get(&string_of(&o["path"])))
        .filter_map(|text| serde_json::from_str::<Value>(text).ok())
        .map(|s| string_of(&s["network"]))
        .find(|n| !n.is_empty())
        .unwrap_or_default();
    let bitcoin = args.bitcoin.clone().unwrap_or_else(|| mempool_for(&network));

    let mut anchors = 0usize;
    for object in &snapshots {
        let path = string_of(&object["path"]);
        let Some(text) = bodies.get(&path) else { continue };
        let snapshot: Value = serde_json::from_str(text).expect("snapshot is JSON");
        let id = string_of(&snapshot["snapshotId"]);
        let commitment = anchor_commitment(&snapshot);
        if commitment != string_of(&snapshot["commitment"]) {
            note!("anchor {id}: commitment does not recompute");
        }

        let ledger_seq = string_of(&snapshot["ledgerSeq"]).parse::<u64>().unwrap_or(0);
        let claimed = string_of(&snapshot["ledgerHash"]);
        if ledger_seq > 0 {
            match by_seq.get(&ledger_seq) {
                Some(hash) if *hash == claimed => {}
                Some(_) => note!("anchor {id}: record #{ledger_seq} does not hash to the claimed head"),
                None => note!("anchor {id}: record #{ledger_seq} is missing from the objects"),
            }
        }

        let txid = string_of(&snapshot["anchorTxid"]);
        let url = format!("{}/tx/{txid}", bitcoin.trim_end_matches('/'));
        match get_json(&url) {
            Ok(tx) => {
                let confirmed = tx["status"]["confirmed"].as_bool().unwrap_or(false);
                let want = format!("6a20{commitment}");
                let carries = tx["vout"]
                    .as_array()
                    .map(|outs| outs.iter().any(|o| string_of(&o["scriptpubkey"]).to_lowercase() == want))
                    .unwrap_or(false);
                if !confirmed || !carries {
                    note!("anchor {id}: no confirmed OP_RETURN carrying this commitment");
                }
            }
            Err(e) => note!("anchor {id}: {e}"),
        }
        anchors += 1;
    }
    section!("{anchors} anchors carry their commitment on bitcoin");

    println!();
    if problems.is_empty() {
        println!(
            "nothing failed to check out: {} records under {} anchors, recomputed from {} objects",
            entries.len(),
            anchors,
            bodies.len()
        );
    } else {
        println!("{} problems", problems.len());
        std::process::exit(1);
    }
}

/// Read one object: from Arweave by transaction id, from a directory, or from a mirror.
fn read_object(args: &Args, object: &Value) -> Result<Vec<u8>, String> {
    let path = string_of(&object["path"]);
    if let Some(gateway) = &args.arweave {
        let txid = string_of(&object["arweave_txid"]);
        if txid.is_empty() {
            return Err("no Arweave id in the listing".into());
        }
        return get_bytes(&format!("{}/{txid}", gateway.trim_end_matches('/')));
    }
    let base = args.objects.clone().ok_or("no object source given")?;
    if base.starts_with("http://") || base.starts_with("https://") {
        get_bytes(&format!("{}/{path}", base.trim_end_matches('/')))
    } else {
        fs::read(PathBuf::from(base).join(&path)).map_err(|e| e.to_string())
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}
