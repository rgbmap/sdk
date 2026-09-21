// Declarations: what they have to satisfy before anything is indexed.
// Specified at https://rgbmap.org/docs/declarations
//
// A declaration is self-published and nobody approves it. What decides whether it counts is
// this check and nothing else, so a mistake here is the difference between "anyone can
// register" and "anyone can claim anyone's asset".

import { canonicalize } from './canonical.js';
import { sha256Hex } from './ledger.js';
import { verify as verifyBip322 } from './bip322.js';

// `version` is what a new declaration is written as; `accepts` is every version that still
// verifies. 🚨 An old version is never dropped: a UDA's genesis is immutable, so an asset
// registered under v1 can never be migrated to v2.
// https://rgbmap.org/docs/nfts-and-collections
export const STANDARDS = {
    'rgbmap-asset': { version: '2', accepts: ['1', '2'] },
    'rgbmap-collection': { version: '1' },
    'rgbmap-publisher': { version: '0' },
    'rgbmap-rotate': { version: '1' },
    'rgbmap-review': { version: '1' },
    'rgbmap-dispute': { version: '1' },
    'rgbmap-mark': { version: '1' },
};

const accepts = (spec) => spec.accepts ?? [spec.version];

/** Media roles and the largest each may be: https://rgbmap.org/docs/media */
export const MEDIA_LIMITS = {
    logo: 102_400,
    preview: 262_144,
    artwork: 524_288,
    original: 33_554_432,
    sealed: 33_554_432,
};
const MEDIA_TOTAL_BYTES = 67_108_864;
// A cover is shown at preview size; nothing needs the artwork allowance.
const COLLECTION_ROLES = ['logo', 'preview'];
const TRAIT_MAX = 64;
const TRAIT_TEXT_MAX = 128;

/** The single line a wallet signs: the standard, its version, and the digest of the rest. */
export const messageFor = (standard, version, digest) => `RGBMap ${standard} v${version} ${digest}`;

/** The bytes a signature covers: the declaration with `signature.value` emptied. */
export async function signingDigest(declaration) {
    const stripped = structuredClone(declaration);
    if (!stripped.signature || typeof stripped.signature !== 'object') throw new Error('no signature object');
    stripped.signature.value = '';
    return sha256Hex(new TextEncoder().encode(canonicalize(stripped)));
}

/**
 * Check a declaration's own consistency and its signature.
 *
 * Returns `{ ok, problems, digest }`. It does not decide what the declaration means for an
 * asset — that is the caller's job, and it depends on the proof, not on this check.
 */
export async function checkDeclaration(declaration) {
    const problems = [];
    const standard = declaration?.standard;
    const spec = STANDARDS[standard];

    if (!spec) return { ok: false, problems: [`unknown standard ${standard}`], digest: null };
    const version = String(declaration.standard_version);
    if (!accepts(spec).includes(version)) {
        problems.push(`${standard} version ${declaration.standard_version} is not one of ${accepts(spec).join(', ')}`);
    }

    const signature = declaration.signature;
    if (!signature || signature.scheme !== 'bip322-simple') problems.push('signature scheme has to be bip322-simple');
    if (!signature?.address) problems.push('signature carries no address');
    if (!signature?.value) problems.push('signature carries no value');
    if (problems.length) return { ok: false, problems, digest: null };

    let digest;
    try {
        digest = await signingDigest(declaration);
    } catch (err) {
        return { ok: false, problems: [`cannot be serialised canonically: ${err.message}`], digest: null };
    }

    const message = messageFor(standard, version, digest);
    if (!verifyBip322(signature.address, message, signature.value)) {
        problems.push(`signature does not verify for ${signature.address}`);
    }

    return { ok: problems.length === 0, problems, digest };
}

/**
 * What every media list has to satisfy: a digest, a durable location, a known role, and a
 * size within that role's allowance (https://rgbmap.org/docs/media).
 *
 * 🚨 `bytes` is checked here against what the declaration claims, which only binds the
 * issuer to a number. Whoever fetches the file checks the digest, and that is what decides.
 */
function mediaProblems(media, roles) {
    const problems = [];
    if (media !== undefined && !Array.isArray(media)) return ['media is not a list'];
    let total = 0;
    for (const item of media || []) {
        if (!item.sha256) problems.push('a media item has no sha256');
        // Reachable by content, not only by location.
        if (!(item.locations || []).some((l) => String(l).startsWith('ar://') || String(l).includes('arweave'))) {
            problems.push('a media item has no Arweave location');
        }
        const limit = MEDIA_LIMITS[item.role];
        if (!roles.includes(item.role)) {
            problems.push(`media role ${item.role} is not one of ${roles.join(', ')}`);
        } else if (item.bytes !== undefined) {
            if (!Number.isInteger(item.bytes) || item.bytes <= 0) problems.push(`media ${item.role} has no size`);
            else {
                total += item.bytes;
                if (item.bytes > limit) problems.push(`media ${item.role} is ${item.bytes} bytes, over ${limit}`);
            }
        }
    }
    if (total > MEDIA_TOTAL_BYTES) problems.push(`media totals ${total} bytes, over ${MEDIA_TOTAL_BYTES}`);
    return problems;
}

/** Per-standard rules that go beyond the signature. */
export function checkBinding(declaration, context = {}) {
    const problems = [];
    const address = declaration.signature?.address;

    if (declaration.standard === 'rgbmap-asset') {
        if (!declaration.contract_id) problems.push('no contract_id');
        if (!declaration.network) problems.push('no network');
        if (!['0.11.1', '0.12'].includes(declaration.rgb_protocol_version)) problems.push('unknown rgb_protocol_version');
        // 🚨 A ledger entry decides name, ticker and precision. A manifest that disagrees
        // with the genesis data is invalid, not a second opinion.
        for (const field of ['name', 'ticker', 'precision']) {
            const known = context.ledger?.[field];
            if (known != null && String(declaration[field]) !== String(known)) {
                problems.push(`${field} is ${declaration[field]}, the ledger records ${known}`);
            }
        }
        problems.push(...mediaProblems(declaration.media, Object.keys(MEDIA_LIMITS)));

        const v2 = String(declaration.standard_version) === '2';
        // 🚨 A v1 reader ignores fields it does not know. Carrying them under v1 would mean
        // the same bytes say different things to two readers, so it is refused outright.
        if (!v2) {
            for (const field of ['collection', 'traits']) {
                if (declaration[field] !== undefined) problems.push(`${field} needs standard_version 2`);
            }
            for (const item of declaration.media || []) {
                if (['artwork', 'sealed'].includes(item.role)) problems.push(`media role ${item.role} needs standard_version 2`);
            }
        }
        if (declaration.collection !== undefined) {
            const { id, serial } = declaration.collection || {};
            if (!/^[0-9a-f]{64}$/.test(String(id))) problems.push('collection.id is not a sha256');
            if (!Number.isInteger(serial) || serial < 0) problems.push('collection.serial is not a whole number');
        }
        if (declaration.traits !== undefined) {
            if (!Array.isArray(declaration.traits)) problems.push('traits is not a list');
            else if (declaration.traits.length > TRAIT_MAX) problems.push(`more than ${TRAIT_MAX} traits`);
            else for (const t of declaration.traits) {
                for (const field of ['type', 'value']) {
                    const v = t?.[field];
                    if (typeof v !== 'string' || !v) problems.push(`a trait has no ${field}`);
                    else if (v.length > TRAIT_TEXT_MAX) problems.push(`a trait ${field} is longer than ${TRAIT_TEXT_MAX}`);
                }
            }
        }
    }

    if (declaration.standard === 'rgbmap-collection') {
        if (!declaration.network) problems.push('no network');
        if (!['0.11.1', '0.12'].includes(declaration.rgb_protocol_version)) problems.push('unknown rgb_protocol_version');
        if (!declaration.name) problems.push('no name');
        // 0 says "not declared". Anything else is a claim the index will count against.
        const size = declaration.declared_size;
        if (!Number.isInteger(size) || size < 0) problems.push('declared_size is not a whole number');
        problems.push(...mediaProblems(declaration.media, COLLECTION_ROLES));
    }

    if (declaration.standard === 'rgbmap-publisher') {
        if (!declaration.ledger_genesis) problems.push('no ledger_genesis');
        // The declaration is signed by the address that writes the anchors.
        if (declaration.anchor_address && declaration.anchor_address !== address) {
            problems.push('the signing address is not the anchor address');
        }
    }

    if (['rgbmap-review', 'rgbmap-dispute', 'rgbmap-mark'].includes(declaration.standard)) {
        // Only RGBMap's own address may publish these.
        if (!context.rgbmapAddress) problems.push('no RGBMap address is configured to check against');
        else if (address !== context.rgbmapAddress) problems.push('not signed by the RGBMap address');
    }

    return { ok: problems.length === 0, problems };
}
