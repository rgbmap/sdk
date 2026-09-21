// Recomputation of a publisher's hash chain, entry balance and anchor commitment.
//
// Every rule here is stated at https://rgbmap.org/docs/ledgers-and-anchors; the
// publisher's implementations are
// backend trade-api-rs/src/ledger.rs (entry hash) and rgb-gateway-rs/src/snapshot.rs
// (anchor commitment).
//
// 🚨 The chain hashes commitments, not contents. A record's public half is published only for
// the platform events the publisher opens in full; for everything else the feed carries a
// commitment and nothing more, and the chain still recomputes end to end.
//
// 🚨 Where `public` is present, hash it verbatim: parsing and re-serialising it may change the
// byte sequence and produces a different digest.

const SEP = '\x1f';
const enc = new TextEncoder();

export const GENESIS_HASH = '0'.repeat(64);

export const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function sha256Hex(input) {
    const bytes = typeof input === 'string' ? enc.encode(input) : input;
    return hex(await crypto.subtle.digest('SHA-256', bytes));
}

/** The hash of one ledger entry. Fields join with a single 0x1F byte. */
export function entryHash(entry) {
    return sha256Hex([entry.prevHash, entry.seq, entry.ts, entry.publicCommitment, entry.privateCommitment].join(SEP));
}

/**
 * The commitment to a record's public half.
 *
 * Only records the publisher opens in full carry `public` and `publicSalt`; for those, this
 * recomputes what the chain committed to, so the bytes can be checked rather than believed.
 */
export function publicCommitment(publicBytes, publicSalt) {
    return sha256Hex(['rgb-ledger-pub-v1', publicBytes, publicSalt].join(SEP));
}

/** The anchor commitment a snapshot claims, `rgb-anchor-v1`. */
export function anchorCommitment(snapshot) {
    const liabilities = Object.entries(snapshot.liabilities || {})
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([asset, amount]) => `${asset}=${amount}`)
        .join(',');
    return sha256Hex([
        'rgb-anchor-v1',
        snapshot.network,
        String(snapshot.snapshotId),
        String(snapshot.ledgerSeq),
        snapshot.ledgerHash,
        snapshot.liabilitiesRoot,
        liabilities,
    ].join(SEP));
}

/** The OP_RETURN scriptPubKey hex that carries a 32-byte commitment. */
export const opReturnFor = (commitment) => '6a20' + commitment;

/**
 * Whether an entry's legs sum to zero per asset.
 *
 * Entries without legs (`issue`, `param_change`, …) are balanced by definition.
 */
export function legsBalance(publicJson) {
    const sums = new Map();
    for (const leg of publicJson.legs || []) {
        sums.set(leg.assetId, (sums.get(leg.assetId) || 0n) + BigInt(leg.delta));
    }
    return [...sums.values()].every((v) => v === 0n);
}

/**
 * Recompute a run of entries.
 *
 * `prevHash` is the hash the run continues from: the genesis constant for a run that
 * starts at seq 1. Returns the problems found; an empty array means the run recomputes.
 */
export async function verifyEntries(entries, prevHash = GENESIS_HASH, expectedFirstSeq = 1) {
    const problems = [];
    let prev = prevHash;
    let expected = BigInt(expectedFirstSeq);
    for (const e of entries) {
        if (BigInt(e.seq) !== expected) problems.push(`record #${e.seq}: expected seq ${expected}`);
        if (e.prevHash !== prev) problems.push(`record #${e.seq}: prevHash does not continue the chain`);
        if ((await entryHash(e)) !== e.hash) problems.push(`record #${e.seq}: hash does not match its contents`);

        // A record opened in full has to match the commitment the chain carries. A record
        // that is not opened is not a problem: the chain says nothing about its contents.
        if (e.public != null && e.publicSalt != null) {
            if ((await publicCommitment(e.public, e.publicSalt)) !== e.publicCommitment) {
                problems.push(`record #${e.seq}: public bytes do not match the commitment`);
            }
            let parsed;
            try {
                parsed = JSON.parse(e.public);
            } catch {
                problems.push(`record #${e.seq}: public segment is not JSON`);
                parsed = {};
            }
            if (!legsBalance(parsed)) problems.push(`record #${e.seq}: legs do not sum to zero`);
        }

        prev = e.hash;
        expected += 1n;
    }
    return problems;
}

/** Fields of the public segment that would mean private data leaked into it. */
export const PRIVATE_FIELDS = ['userId', 'address', 'destination', 'recipientId', 'vout'];

export function leakedFields(publicJson) {
    return PRIVATE_FIELDS.filter((k) => k in publicJson);
}
