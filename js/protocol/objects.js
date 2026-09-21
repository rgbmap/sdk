// Archive objects: identity, paths, and the byte form that gets hashed.
//
// 🚨 A published object is final. Its bytes are what `sha256` covers and what the manifest,
// the D1 index and Arweave all refer to; regenerating an object with different contents
// under the same path breaks every reference to it.

import { canonicalize } from './canonical.js';
import { sha256Hex } from './ledger.js';

export const STANDARD_VERSION = '1';

/** A publisher's identity: network and the hash of its genesis ledger entry. */
export const publisherId = (network, genesisHash) => `${network}:${genesisHash}`;

/** Objects of one publisher share a path prefix. */
export const pathPrefix = (network, genesisHash) => `${network}/${genesisHash}/`;

export const ledgerPath = (prefix, fromSeq, toSeq) => `${prefix}ledger/${fromSeq}-${toSeq}.json`;
export const snapshotPath = (prefix, snapshotId) => `${prefix}snapshot/${snapshotId}.json`;
export const manifestPath = (prefix, date) => `${prefix}manifest/${date}.json`;

/** Canonical bytes plus their digest: everything that refers to an object uses both. */
export async function serialize(object) {
    const text = canonicalize(object);
    const bytes = new TextEncoder().encode(text);
    return { text, bytes, sha256: await sha256Hex(bytes), size: bytes.length };
}

/**
 * A ledger shard.
 *
 * Entries keep the publisher's field names and values verbatim, `public` included: the
 * shard is a carrier for the committed bytes, not a second rendering of them.
 */
export function ledgerObject(publisher, entries) {
    return {
        standard: 'rgbmap-ledger',
        standard_version: STANDARD_VERSION,
        publisher,
        from_seq: String(entries[0].seq),
        to_seq: String(entries[entries.length - 1].seq),
        entries: entries.map((e) => {
            const record = {
                seq: String(e.seq),
                ts: String(e.ts),
                public_commitment: e.publicCommitment,
                private_commitment: e.privateCommitment,
                prev_hash: e.prevHash,
                hash: e.hash,
            };
            // Records the publisher opens in full carry their bytes and the salt that ties
            // them to the commitment. The rest carry the commitment and nothing else: the
            // archive publishes no more than the publisher did.
            if (e.public != null && e.publicSalt != null) {
                record.op = e.op;
                record.public = e.public;
                record.public_salt = e.publicSalt;
            }
            return record;
        }),
    };
}

/** Read an archived record back into the shape the recomputation functions take. */
export function restoreEntry(record) {
    const entry = {
        seq: record.seq,
        ts: record.ts,
        publicCommitment: record.public_commitment,
        privateCommitment: record.private_commitment,
        prevHash: record.prev_hash,
        hash: record.hash,
    };
    if (record.public != null) {
        entry.op = record.op;
        entry.public = record.public;
        entry.publicSalt = record.public_salt;
    }
    return entry;
}

/** A reserve snapshot, with the publisher's own fields kept as they came. */
export function snapshotObject(publisher, snapshot) {
    const { anchorState, disclaimer, ...rest } = snapshot;
    return {
        standard: 'rgbmap-snapshot',
        standard_version: STANDARD_VERSION,
        publisher,
        ...rest,
        snapshotId: String(snapshot.snapshotId),
        ledgerSeq: String(snapshot.ledgerSeq),
        at: String(snapshot.at),
    };
}

/**
 * One day's objects.
 *
 * `arweave_txid` is null for an object that has no finalised upload. The digest and the
 * anchor chain are what make an object checkable; Arweave is one of the places it is kept.
 */
export function manifestObject(publisher, date, objects, previousSha256) {
    return {
        standard: 'rgbmap-manifest',
        standard_version: STANDARD_VERSION,
        publisher,
        date,
        objects: objects.map((o) => ({
            path: o.path,
            sha256: o.sha256,
            bytes: String(o.bytes),
            arweave_txid: o.arweave_txid ?? null,
        })),
        previous_manifest_sha256: previousSha256 || '',
    };
}

/**
 * Split a run of entries into shards no larger than `maxBytes`.
 *
 * Splitting happens on entry boundaries, so the shards stay continuous: the next shard
 * starts at the seq after the previous one ends.
 */
export async function splitShards(publisher, entries, maxBytes) {
    const shards = [];
    let start = 0;
    while (start < entries.length) {
        let lo = 1;
        let hi = entries.length - start;
        let take = 1;
        let serialized = await serialize(ledgerObject(publisher, entries.slice(start, start + 1)));
        // The first entry goes in whatever its size: an oversized single entry cannot be split.
        while (lo <= hi) {
            const mid = (lo + hi) >> 1;
            const candidate = await serialize(ledgerObject(publisher, entries.slice(start, start + mid)));
            if (candidate.size <= maxBytes) {
                take = mid;
                serialized = candidate;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        shards.push({ entries: entries.slice(start, start + take), serialized });
        start += take;
    }
    return shards;
}
