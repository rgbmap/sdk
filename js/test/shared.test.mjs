// The recomputation the whole archive rests on, against a page of the publisher's own
// signet output (test/fixtures). A divergence here means objects would be published that
// nobody can verify.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize, CanonicalError } from '../protocol/canonical.js';
import { anchorCommitment, entryHash, legsBalance, publicCommitment, verifyEntries, GENESIS_HASH } from '../protocol/ledger.js';
import { ledgerObject, restoreEntry, serialize, splitShards } from '../protocol/objects.js';

const read = (name) => JSON.parse(readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'));
const ENTRIES = read('signet-ledger.json').entries;
const SNAPSHOTS = read('signet-snapshots.json').snapshots;
const PUBLISHER = 'signet:' + ENTRIES[0].hash;

test('every record hashes to what the publisher published', async () => {
    for (const e of ENTRIES) assert.equal(await entryHash(e), e.hash, `record #${e.seq}`);
});

test('records opened in full match the commitment the chain carries', async () => {
    const opened = ENTRIES.filter((e) => e.public != null);
    assert.ok(opened.length > 0, 'the fixture should contain at least one opened record');
    for (const e of opened) {
        assert.equal(await publicCommitment(e.public, e.publicSalt), e.publicCommitment, `record #${e.seq}`);
    }
});

test('the chain recomputes without any record being opened', async () => {
    // What the skeleton alone proves: order, links and hashes, with no business data at all.
    const skeleton = ENTRIES.map(({ seq, ts, publicCommitment: pc, privateCommitment, prevHash, hash }) =>
        ({ seq, ts, publicCommitment: pc, privateCommitment, prevHash, hash }));
    assert.deepEqual(await verifyEntries(skeleton, GENESIS_HASH, 1), []);
});

test('the chain recomputes from genesis with balanced legs', async () => {
    assert.deepEqual(await verifyEntries(ENTRIES, GENESIS_HASH, 1), []);
});

test('a changed public segment breaks its commitment', async () => {
    const opened = ENTRIES.find((e) => e.public != null);
    // One byte: the shortest change an archive could carry without anyone noticing.
    const tampered = { ...opened, public: opened.public.replace('{', '{ ') };
    assert.notEqual(await publicCommitment(tampered.public, tampered.publicSalt), tampered.publicCommitment);
    const problems = await verifyEntries([tampered], tampered.prevHash, Number(tampered.seq));
    assert.ok(problems.some((p) => /do not match the commitment/.test(p)), problems.join('; '));
});

test('each snapshot recomputes its own anchor commitment', async () => {
    for (const s of SNAPSHOTS) assert.equal(await anchorCommitment(s), s.commitment, `snapshot ${s.snapshotId}`);
});

test('a snapshot ledgerHash matches the entry it names', async () => {
    const bySeq = new Map(ENTRIES.map((e) => [Number(e.seq), e]));
    for (const s of SNAPSHOTS) {
        if (s.ledgerSeq === 0) continue;
        const entry = bySeq.get(s.ledgerSeq);
        if (!entry) continue;
        assert.equal(entry.hash, s.ledgerHash, `snapshot ${s.snapshotId}`);
    }
});

test('legs sum to zero per asset, and a broken leg is caught', () => {
    for (const e of ENTRIES.filter((x) => x.public != null)) assert.ok(legsBalance(JSON.parse(e.public)), `record #${e.seq}`);
    assert.equal(legsBalance({ legs: [{ assetId: 'sats', delta: '5' }, { assetId: 'sats', delta: '-4' }] }), false);
});

test('canonical form sorts keys, escapes as JSON.stringify does, and rejects what has no fixed form', () => {
    assert.equal(canonicalize({ b: 1, a: 'x', c: [1, 2] }), '{"a":"x","b":1,"c":[1,2]}');
    assert.equal(canonicalize({ s: 'a"b\\c\nde' }), '{"s":"a\\"b\\\\c\\nd\\u0001e"}');
    assert.equal(canonicalize({ s: 'caf\u00e9 \u00b7 \u0e44\u0e17\u0e22' }), '{"s":"caf\u00e9 \u00b7 \u0e44\u0e17\u0e22"}');
    assert.equal(canonicalize({ a: undefined, b: 1 }), '{"b":1}');
    assert.throws(() => canonicalize({ x: 1.5 }), CanonicalError);
    assert.throws(() => canonicalize({ x: 9007199254740993 }), CanonicalError);
    assert.throws(() => canonicalize({ x: 1n }), CanonicalError);
});

test('shards stay continuous and within the size bound, and re-verify from their own bytes', async () => {
    const shards = await splitShards(PUBLISHER, ENTRIES, 8000);
    assert.ok(shards.length > 1, 'the fixture should need more than one shard at this size');

    let expected = 1;
    for (const shard of shards) {
        assert.equal(Number(shard.entries[0].seq), expected, 'a shard starts where the last one ended');
        expected = Number(shard.entries[shard.entries.length - 1].seq) + 1;
        if (shard.entries.length > 1) assert.ok(shard.serialized.size <= 8000, 'a multi-entry shard fits the bound');
    }
    assert.equal(expected - 1, ENTRIES.length, 'the shards cover every entry');

    // Read one shard back the way a verifier would: its entries alone must recompute.
    const object = JSON.parse(shards[1].serialized.text);
    const restored = object.entries.map(restoreEntry);
    const from = Number(object.from_seq);
    const previous = ENTRIES[from - 2].hash;
    assert.deepEqual(await verifyEntries(restored, previous, from), []);
});

test('an object serialises to the same bytes every time', async () => {
    const one = await serialize(ledgerObject(PUBLISHER, ENTRIES.slice(0, 5)));
    const two = await serialize(ledgerObject(PUBLISHER, ENTRIES.slice(0, 5)));
    assert.equal(one.sha256, two.sha256);
    assert.equal(one.size, new TextEncoder().encode(one.text).length);
});
