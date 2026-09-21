// Declaration rules: what counts and what does not.
// https://rgbmap.org/docs/declarations

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signP2WPKH } from '../protocol/bip322.js';
import { checkBinding, checkDeclaration, messageFor, signingDigest } from '../protocol/declaration.js';

const KEY = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) % 251 || 1);

async function signed(overrides = {}) {
    const declaration = {
        standard: 'rgbmap-asset',
        standard_version: '1',
        network: 'signet',
        rgb_protocol_version: '0.11.1',
        contract_id: 'rgb:Example-Contract',
        name: 'test',
        ticker: 'TEST',
        precision: '8',
        media: [],
        links: { website: 'https://example.org' },
        previous_sha256: '',
        issuer: { proof: 'dns' },
        ...overrides,
    };
    const address = signP2WPKH(KEY, '', 'tb').address;
    declaration.signature = { scheme: 'bip322-simple', address, value: '' };
    const digest = await signingDigest(declaration);
    // The message carries the declaration's own version, so a v2 helper signs a v2 message.
    const version = String(declaration.standard_version);
    declaration.signature.value = signP2WPKH(KEY, messageFor(declaration.standard, version, digest), 'tb').signature;
    return declaration;
}

test('a declaration signed over its own contents is accepted', async () => {
    assert.deepEqual((await checkDeclaration(await signed())).problems, []);
});

test('changing one field after signing breaks it', async () => {
    const d = await signed();
    d.ticker = 'OTHER';
    const checked = await checkDeclaration(d);
    assert.equal(checked.ok, false);
    assert.match(checked.problems[0], /signature does not verify/);
});

test('a missing or foreign signature is refused', async () => {
    assert.equal((await checkDeclaration({ standard: 'rgbmap-asset', standard_version: '1' })).ok, false);
    const d = await signed();
    d.signature.scheme = 'ecdsa';
    assert.equal((await checkDeclaration(d)).ok, false);
    const other = await signed();
    d.signature = { ...other.signature, address: 'tb1qhj5huq6zc47y6yr5x6z6lkj93ajsjq7lc5s6mt' };
    assert.equal((await checkDeclaration(d)).ok, false);
});

test('a manifest that disagrees with the ledger is invalid', async () => {
    const d = await signed();
    const good = checkBinding(d, { ledger: { ticker: 'TEST', name: 'test', precision: 8 } });
    assert.deepEqual(good.problems, []);
    const bad = checkBinding(d, { ledger: { ticker: 'REAL', name: 'test', precision: 8 } });
    assert.equal(bad.ok, false);
    assert.match(bad.problems[0], /the ledger records REAL/);
});

test('media has to name an Arweave location and a digest', async () => {
    const d = await signed({ media: [{ role: 'logo', mime: 'image/png', sha256: 'aa', locations: ['https://example.org/logo.png'] }] });
    assert.match(checkBinding(d).problems.join(';'), /Arweave location/);
});

test("only RGBMap's own address may publish a review, dispute or mark", async () => {
    const d = await signed({ standard: 'rgbmap-review', contract_id: 'rgb:Example-Contract' });
    assert.equal(checkBinding(d, { rgbmapAddress: 'tb1qsomeoneelse' }).ok, false);
    assert.equal(checkBinding(d, { rgbmapAddress: d.signature.address }).ok, true);
});

// ---------------------------------------------------------------- NFTs and collections

const AR = ['ar://kBmOMsSk3sIFSt3rXnmt2PEcbVKm_jMnXpc0lCFMA6c'];
const artwork = (bytes) => ({ role: 'artwork', mime: 'image/webp', sha256: 'aa', bytes, locations: AR });

async function nft(overrides = {}) {
    return signed({ standard_version: '2', schema_type: 'UDA', ...overrides });
}

test('a v1 manifest still verifies after v2 exists', async () => {
    const d = await signed();
    assert.equal(d.standard_version, '1');
    assert.deepEqual((await checkDeclaration(d)).problems, []);
});

test('the signed message carries the version the declaration was written as', async () => {
    const one = await signed();
    const two = await nft();
    const [a, b] = await Promise.all([signingDigest(one), signingDigest(two)]);
    assert.equal(messageFor('rgbmap-asset', '1', a).includes(' v1 '), true);
    assert.equal(messageFor('rgbmap-asset', '2', b).includes(' v2 '), true);
    assert.deepEqual((await checkDeclaration(two)).problems, []);
});

test('collection and traits need version 2', async () => {
    const d = await signed({ collection: { id: 'a'.repeat(64), serial: 1 }, traits: [{ type: 'bg', value: 'snow' }] });
    const problems = checkBinding(d).problems.join(';');
    assert.match(problems, /collection needs standard_version 2/);
    assert.match(problems, /traits needs standard_version 2/);
});

test('an artwork role needs version 2', async () => {
    const d = await signed({ media: [artwork(1000)] });
    assert.match(checkBinding(d).problems.join(';'), /artwork needs standard_version 2/);
});

test('a v2 manifest takes a collection, a serial and traits', async () => {
    const d = await nft({ collection: { id: 'b'.repeat(64), serial: 7 }, traits: [{ type: 'bg', value: 'snow' }], media: [artwork(1000)] });
    assert.deepEqual(checkBinding(d).problems, []);
});

test('a collection reference has to be a digest and a whole serial', async () => {
    const bad = await nft({ collection: { id: 'not-a-digest', serial: -1 } });
    const problems = checkBinding(bad).problems.join(';');
    assert.match(problems, /collection.id is not a sha256/);
    assert.match(problems, /collection.serial is not a whole number/);
});

test('media over its role allowance is refused', async () => {
    const over = await nft({ media: [artwork(524_289)] });
    assert.match(checkBinding(over).problems.join(';'), /artwork is 524289 bytes, over 524288/);
    const at = await nft({ media: [artwork(524_288)] });
    assert.deepEqual(checkBinding(at).problems, []);
});

test('an unknown media role is refused', async () => {
    const d = await nft({ media: [{ role: 'whatever', sha256: 'aa', bytes: 10, locations: AR }] });
    assert.match(checkBinding(d).problems.join(';'), /media role whatever is not one of/);
});

test('a collection declaration needs a name, a network and a whole declared size', async () => {
    const ok = await signed({ standard: 'rgbmap-collection', name: 'Hermit', declared_size: 500, media: [] });
    assert.deepEqual(checkBinding(ok).problems, []);
    const bad = await signed({ standard: 'rgbmap-collection', name: '', declared_size: '500', media: [] });
    const problems = checkBinding(bad).problems.join(';');
    assert.match(problems, /no name/);
    assert.match(problems, /declared_size is not a whole number/);
});

test('a collection cover may not use the artwork allowance', async () => {
    const d = await signed({ standard: 'rgbmap-collection', name: 'Hermit', declared_size: 0, media: [artwork(1000)] });
    assert.match(checkBinding(d).problems.join(';'), /media role artwork is not one of logo, preview/);
});
