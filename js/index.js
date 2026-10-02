// RGBMap client: read an index, and check what it says without taking its word for it.
//
// Two halves on purpose. `client()` is convenience — it asks an index and hands back what it
// answered. The verification functions take bytes and recompute; they never call an index.
// Anything that reads like a conclusion ("this asset is fine") is not here, because the
// protocol does not produce one: https://rgbmap.org/docs/what-rgbmap-does-not-state
//
// No build step: plain ES modules, usable from a browser, a Worker or Node. The only
// dependencies are @noble/curves and @noble/hashes, which signature verification needs.

export { canonicalize } from './protocol/canonical.js';
export {
    anchorCommitment,
    entryHash,
    GENESIS_HASH,
    legsBalance,
    leakedFields,
    opReturnFor,
    publicCommitment,
    sha256Hex,
    verifyEntries,
} from './protocol/ledger.js';
export { restoreEntry } from './protocol/objects.js';
export { checkBinding, checkDeclaration, messageFor, signingDigest, STANDARDS } from './protocol/declaration.js';
export { verify as verifyBip322 } from './protocol/bip322.js';

/**
 * A reader for one index.
 *
 * `fetch` is injectable so a caller can add caching, a timeout, or their own transport.
 */
export function client({ api = 'https://api.rgbmap.org', network = 'mainnet', fetch: f = globalThis.fetch } = {}) {
    const base = api.replace(/\/+$/, '');

    const get = async (path, params = {}) => {
        const url = new URL(base + path);
        for (const [k, v] of Object.entries({ network, ...params })) if (v != null) url.searchParams.set(k, String(v));
        const res = await f(url, { headers: { accept: 'application/json' } });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw Object.assign(new Error(body.message || res.statusText), { code: body.code, status: res.status });
        return body;
    };

    return {
        health: () => get('/v1/health'),
        publishers: () => get('/v1/publishers'),
        assets: () => get('/v1/assets'),
        /** What a wallet needs to show one asset: https://rgbmap.org/docs/query-api */
        resolve: (contractId) => get('/v1/resolve', { asset: contractId }),
        ledger: ({ cursor, limit, order } = {}) => get('/v1/ledger', { cursor, limit, order }),
        entry: (publisher, seq) => get(`/v1/ledger/${encodeURIComponent(publisher)}/${seq}`),
        anchors: ({ cursor, limit } = {}) => get('/v1/anchors', { cursor, limit }),
        anchor: (publisher, snapshotId) => get(`/v1/anchors/${encodeURIComponent(publisher)}/${snapshotId}`),
        objects: (publisher) => get('/v1/objects', { publisher }),
        manifests: (publisher) => get('/v1/manifests', { publisher }),
        search: (q) => get('/v1/search', { q }),
        collections: () => get('/v1/collections'),
        collection: (id) => get(`/v1/collections/${encodeURIComponent(id)}`),
        /**
         * Every transfer output the index holds, newest-seen first. `q` matches only what
         * names a transfer on the chain: the witness txid, or a bitcoin address on either
         * side of it.
         */
        transfers: ({ q, cursor, limit } = {}) => get('/v1/transfers', { q, cursor, limit }),

        /**
         * Records as the index returned them, recomputed here from the bytes it sent.
         *
         * 🚨 This is the point of the interface: a page that does not recompute is a page you
         * are taking on trust.
         */
        async ledgerChecked(options = {}) {
            const page = await this.ledger(options);
            const { restoreEntry } = await import('./protocol/objects.js');
            const entries = page.entries.map(restoreEntry);
            const { verifyEntries, GENESIS_HASH } = await import('./protocol/ledger.js');
            const first = Number(entries[0]?.seq ?? 1);
            const previous = first === 1 ? GENESIS_HASH : entries[0]?.prevHash;
            return { ...page, problems: await verifyEntries(entries, previous, first) };
        },
    };
}

/**
 * Fetch one published object and check it against the digest it is published under.
 *
 * Returns the bytes, so a caller that wants the records can parse them itself.
 */
export async function fetchObject({ mirror, path, sha256, fetch: f = globalThis.fetch }) {
    const { sha256Hex } = await import('./protocol/ledger.js');
    const res = await f(`${mirror.replace(/\/+$/, '')}/${path}`, { redirect: 'follow' });
    if (!res.ok) throw new Error(`${path}: ${res.status}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    const digest = await sha256Hex(bytes);
    if (sha256 && digest !== sha256) throw new Error(`${path}: hashes to ${digest}, published as ${sha256}`);
    return { bytes, sha256: digest };
}
