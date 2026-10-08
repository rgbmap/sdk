// Registration packages: one signature over every entry, entries bound to the signer.
// https://rgbmap.org/docs/registering-from-your-app

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signP2WPKH } from '../protocol/bip322.js';
import { batchMessage, batchRoot, checkBatch, checkEntry } from '../protocol/batch.js';
import { signingDigest } from '../protocol/declaration.js';

const KEY = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) % 251 || 1);
const address = signP2WPKH(KEY, '', 'tb').address;

async function entry(overrides = {}) {
    const manifest = {
        standard: 'rgbmap-asset',
        standard_version: '1',
        network: 'signet',
        rgb_protocol_version: '0.11.1',
        contract_id: 'rgb:Example-Contract',
        name: 'test',
        ticker: 'TEST',
        precision: '8',
        media: [],
        links: {},
        previous_sha256: '',
        signature: { scheme: 'bip322-simple', address, value: '' },
        ...overrides,
    };
    return manifest;
}

async function pack(manifests, mutate = (pkg) => pkg) {
    const entries = [];
    for (const m of manifests) entries.push(await signingDigest(m));
    const pkg = mutate({
        standard: 'rgbmap-batch',
        standard_version: '1',
        network: 'signet',
        rgb_protocol_version: '0.11.1',
        entries,
        signature: { scheme: 'bip322-simple', address, value: '' },
    }) ?? undefined;
    const root = await batchRoot(pkg.entries);
    pkg.signature.value = signP2WPKH(KEY, batchMessage(root), 'tb').signature;
    return pkg;
}

test('a package signed over its own entries is accepted, and so is each entry in it', async () => {
    const a = await entry();
    const b = await entry({ contract_id: 'rgb:Another-Contract', ticker: 'OTHER' });
    const pkg = await pack([a, b]);
    const checked = await checkBatch(pkg);
    assert.deepEqual(checked.problems, []);
    assert.equal(checked.ok, true);
    for (const m of [a, b]) {
        const one = await checkEntry(pkg, m);
        assert.deepEqual(one.problems, []);
    }
});

test('adding an entry after signing breaks the package', async () => {
    const pkg = await pack([await entry()]);
    pkg.entries.push('a'.repeat(64));
    const checked = await checkBatch(pkg);
    assert.equal(checked.ok, false);
    assert.match(checked.problems.join(';'), /signature does not verify/);
});

test('an entry the package does not list is refused', async () => {
    const pkg = await pack([await entry()]);
    const stranger = await entry({ contract_id: 'rgb:Stranger' });
    const one = await checkEntry(pkg, stranger);
    assert.equal(one.ok, false);
    assert.match(one.problems.join(';'), /not in the package/);
});

test('an entry signed for by another address is refused', async () => {
    const mine = await entry();
    const other = { ...await entry({ contract_id: 'rgb:Other-Signer' }), signature: { scheme: 'bip322-simple', address: 'tb1qhj5huq6zc47y6yr5x6z6lkj93ajsjq7lc5s6mt', value: '' } };
    const pkg = await pack([mine, other]);
    // The package lists it — the digest is over the bytes, whichever address is named —
    // but the entry names a signer who never signed for it.
    const one = await checkEntry(pkg, other);
    assert.equal(one.ok, false);
    assert.match(one.problems.join(';'), /not the package signer/);
});

test('a package record that is not a package is refused before any entry is opened', async () => {
    assert.equal((await checkBatch({ standard: 'rgbmap-asset' })).ok, false);
    assert.equal((await checkBatch(null)).ok, false);
    const doubled = await pack([await entry()]);
    doubled.entries = [doubled.entries[0], doubled.entries[0]];
    // Re-signing over the doubled list would pass the signature but not the rule.
    const root = await batchRoot(doubled.entries);
    doubled.signature.value = signP2WPKH(KEY, batchMessage(root), 'tb').signature;
    assert.match((await checkBatch(doubled)).problems.join(';'), /twice/);
});

test('an entry that carries its own signature value is refused', async () => {
    const a = await entry();
    const pkg = await pack([a]);
    const smuggled = { ...a, signature: { ...a.signature, value: signP2WPKH(KEY, 'whatever', 'tb').signature } };
    const one = await checkEntry(pkg, smuggled);
    assert.equal(one.ok, false);
    assert.match(one.problems.join(';'), /has to be empty/);
});
