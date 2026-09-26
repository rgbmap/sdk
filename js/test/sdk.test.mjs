// The SDK's promises: it recomputes, and it never invents a verdict.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { client, fetchObject, GENESIS_HASH, sha256Hex, verifyEntries } from '../index.js';

const fixture = JSON.parse(readFileSync(new URL('../../vectors/signet-ledger.json', import.meta.url), 'utf8'));

/**
 * A stored record as the read interface returns it.
 *
 * 🚨 Every field the hash is taken over has to be here. Leaving one out makes a recomputation
 * fail against records that are in fact sound, which reads as "the index is lying" — and a
 * checker that cries wolf is worse than one that does not run.
 */
const asInterface = (e) => ({
    seq: e.seq,
    ts: e.ts,
    public_commitment: e.publicCommitment,
    private_commitment: e.privateCommitment,
    prev_hash: e.prevHash,
    hash: e.hash,
    ...(e.public == null ? {} : { op: e.op, public: e.public, public_salt: e.publicSalt }),
});

test('a page the index returns is recomputed, not trusted', async () => {
    const entries = fixture.entries.slice(0, 20);
    const stub = async () => new Response(JSON.stringify({
        entries: entries.map(asInterface),
    }), { headers: { 'content-type': 'application/json' } });

    const page = await client({ fetch: stub, network: 'signet' }).ledgerChecked();
    assert.deepEqual(page.problems, []);
});

test('a page with one altered record comes back with the problem named', async () => {
    // 🚨 The altered field has to be one a commitment covers. `op` is not: neither the chain
    // hash nor the public commitment is taken over it, so changing it is invisible to any
    // recomputation — a reader checks what a record says by its published bytes, not by `op`.
    const entries = fixture.entries.slice(0, 20).map((e, i) => (i === 5 ? { ...e, ts: String(Number(e.ts) + 1) } : e));
    const stub = async () => new Response(JSON.stringify({
        entries: entries.map(asInterface),
    }), { headers: { 'content-type': 'application/json' } });

    const page = await client({ fetch: stub, network: 'signet' }).ledgerChecked();
    assert.equal(page.problems.length >= 1, true);
    assert.match(page.problems[0], /#6/);
});

test('an object that does not match its digest is refused', async () => {
    const bytes = new TextEncoder().encode('{"standard":"rgbmap-ledger"}');
    const stub = async () => new Response(bytes);
    const digest = await sha256Hex(bytes);
    const got = await fetchObject({ mirror: 'https://example.org', path: 'x.json', sha256: digest, fetch: stub });
    assert.equal(got.sha256, digest);
    await assert.rejects(
        fetchObject({ mirror: 'https://example.org', path: 'x.json', sha256: '0'.repeat(64), fetch: stub }),
        /hashes to/,
    );
});

test('the module exposes no combined verdict', async () => {
    const sdk = await import('../index.js');
    for (const name of Object.keys(sdk)) {
        assert.ok(!/^(isValid|isVerified|isTrusted|isSafe)$/.test(name), `${name} would be a verdict`);
    }
});

test('records recompute from the genesis record', async () => {
    const entries = fixture.entries;
    assert.deepEqual(await verifyEntries(entries, GENESIS_HASH, 1), []);
});

test('the client asks for collections and transfers with their own parameters', async () => {
    const asked = [];
    const stub = async (url) => {
        asked.push(String(url));
        return new Response(JSON.stringify({ collections: [], transfers: [], nextCursor: null }),
            { headers: { 'content-type': 'application/json' } });
    };
    const c = client({ fetch: stub, network: 'signet', api: 'https://index.example' });
    await c.collections();
    await c.collection('a'.repeat(64));
    await c.transfers({ q: 'tb1q…', cursor: '153', limit: 50 });
    assert.ok(asked[0].startsWith('https://index.example/v1/collections?network=signet'));
    assert.ok(asked[1].startsWith(`https://index.example/v1/collections/${'a'.repeat(64)}`));
    const transfers = new URL(asked[2]);
    assert.equal(transfers.pathname, '/v1/transfers');
    assert.equal(transfers.searchParams.get('network'), 'signet');
    assert.equal(transfers.searchParams.get('q'), 'tb1q…');
    assert.equal(transfers.searchParams.get('cursor'), '153');
    assert.equal(transfers.searchParams.get('limit'), '50');
});
