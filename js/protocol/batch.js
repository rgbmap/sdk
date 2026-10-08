// Registration packages: one archive, one signature, many entries. The package is the unit
// of submission and signing; a manifest inside it stays the unit of record.

import { verify as verifyBip322 } from './bip322.js';
import { sha256Hex } from './ledger.js';
import { messageFor, signingDigest } from './declaration.js';

export const BATCH_STANDARD = 'rgbmap-batch';
export const BATCH_VERSION = '1';

const ENTRY_DIGEST = /^[0-9a-f]{64}$/;

/** The root a package signature covers: its entry digests, sorted, hashed as one JSON array. */
export async function batchRoot(entries) {
    const sorted = [...(entries || [])].sort();
    return sha256Hex(new TextEncoder().encode(JSON.stringify(sorted)));
}

/** The single line a wallet signs for a package. */
export const batchMessage = (root) => messageFor(BATCH_STANDARD, BATCH_VERSION, root);

/**
 * What a package record has to satisfy before any entry is opened: the shape of its record,
 * and one signature that covers every entry digest it lists.
 */
export async function checkBatch(pkg) {
    const problems = [];
    if (!pkg || typeof pkg !== 'object') return { ok: false, problems: ['send the package record as an object'], root: null };
    if (pkg.standard !== BATCH_STANDARD) problems.push(`unknown standard ${pkg.standard}`);
    if (String(pkg.standard_version) !== BATCH_VERSION) problems.push(`${BATCH_STANDARD} version ${pkg.standard_version} is not ${BATCH_VERSION}`);
    if (!pkg.network) problems.push('no network');
    if (!['0.11.1', '0.12'].includes(pkg.rgb_protocol_version)) problems.push('unknown rgb_protocol_version');

    const entries = pkg.entries;
    if (!Array.isArray(entries) || entries.length === 0) {
        problems.push('entries is not a non-empty list');
    } else {
        if (new Set(entries).size !== entries.length) problems.push('entries lists a digest twice');
        for (const e of entries) if (!ENTRY_DIGEST.test(String(e))) problems.push(`entry ${e} is not a sha256`);
    }

    const signature = pkg.signature;
    if (!signature || signature.scheme !== 'bip322-simple') problems.push('signature scheme has to be bip322-simple');
    if (!signature?.address) problems.push('signature carries no address');
    if (!signature?.value) problems.push('signature carries no value');
    if (problems.length) return { ok: false, problems, root: null };

    const root = await batchRoot(entries);
    if (!verifyBip322(signature.address, batchMessage(root), signature.value)) {
        problems.push(`signature does not verify for ${signature.address}`);
    }
    return { ok: problems.length === 0, problems, root };
}

/**
 * One entry against its package: listed in it, and signed for by the same address that signed
 * the package. The entry digest is the manifest's own signing digest, so a byte out of place
 * leaves the entry list and is refused here.
 */
export async function checkEntry(pkg, manifest) {
    const problems = [];
    if (!manifest || typeof manifest !== 'object') return { ok: false, problems: ['send the manifest as an object'], digest: null };
    const signature = manifest.signature;
    if (!signature || typeof signature !== 'object') return { ok: false, problems: ['the entry has no signature object'], digest: null };
    // The package signature is the binding; a per-entry value would say two things about one
    // binding and neither could be checked alone.
    if (signature.value) problems.push('an entry signature value has to be empty');
    if (signature.scheme !== undefined && signature.scheme !== 'bip322-simple') problems.push('signature scheme has to be bip322-simple');
    if (!signature.address) problems.push('the entry carries no address');

    let digest = null;
    try {
        digest = await signingDigest(manifest);
    } catch (err) {
        return { ok: false, problems: [`cannot be serialised canonically: ${err.message}`], digest };
    }
    if (!Array.isArray(pkg?.entries) || !pkg.entries.includes(digest)) problems.push(`${digest} is not in the package's entry list`);
    if (signature.address && pkg?.signature?.address && signature.address !== pkg.signature.address) {
        problems.push(`entry address ${signature.address} is not the package signer ${pkg.signature.address}`);
    }
    return { ok: problems.length === 0, problems, digest };
}
