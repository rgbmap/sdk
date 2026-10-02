// BIP-322 verification, against the same 60 vectors the backend is pinned to.
//
// 🚨 Accepting one signature the reference rejects is an authentication bypass; rejecting
// one it accepts locks out a legitimate issuer. Both directions are checked.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verify } from '../protocol/bip322.js';

const cases = JSON.parse(readFileSync(new URL('../../vectors/bip322.json', import.meta.url), 'utf8')).cases;

test('every vector verifies exactly as the reference does', () => {
    let checked = 0;
    for (const c of cases) {
        if (!c.signature) continue;
        assert.equal(
            verify(c.address, c.message, c.signature),
            c.verifies,
            `${c.network}/${c.kind} message ${JSON.stringify(String(c.message).slice(0, 40))}`,
        );
        checked += 1;
    }
    assert.ok(checked >= 60, `too few vectors: ${checked}`);
});

test('a signature does not verify for another message or another key', () => {
    const good = cases.filter((c) => c.signature && c.verifies);
    for (const c of good.slice(0, 12)) {
        assert.equal(verify(c.address, c.message + ' ', c.signature), false, 'message changed by one space');
        // Compare across keys only: one key's mainnet, testnet and regtest addresses share a
        // witness program, and BIP-322 signs the message, not the network. The same person
        // controls all three, so a signature verifying against all three is correct.
        const otherKey = good.find((o) => o.kind === c.kind && o.key !== c.key);
        if (otherKey) assert.equal(verify(otherKey.address, c.message, c.signature), false, 'another key');
    }
});

test('one key\'s addresses on different networks share a witness program', () => {
    const c = cases.find((x) => x.kind === 'p2wpkh' && x.network === 'mainnet' && x.signature);
    const sameKeyOtherNet = cases.find((x) => x.key === c.key && x.kind === c.kind && x.network === 'testnet');
    assert.equal(verify(sameKeyOtherNet.address, c.message, c.signature), true);
});

test('malformed input is rejected rather than thrown', () => {
    for (const bad of ['', 'not base64', 'AA==', 'AkgwRQIh']) {
        assert.equal(verify(cases[0].address, 'x', bad), false);
    }
    assert.equal(verify('bc1qinvalid', 'x', cases[0].signature), false);
    assert.equal(verify('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'x', cases[0].signature), false, 'legacy addresses are not accepted');
});

test('a signature this code produces verifies with this code', async () => {
    const { signP2WPKH } = await import('../protocol/bip322.js');
    const key = new Uint8Array(32).fill(7);
    key[31] = 9;
    for (const message of ['', 'RGBMap rgbmap-asset v1 ' + 'a'.repeat(64), 'café · \u0e44\u0e17\u0e22 · \ud83d\ude42']) {
        const { address, signature } = signP2WPKH(key, message);
        assert.equal(verify(address, message, signature), true, `round trip for ${JSON.stringify(message)}`);
        assert.equal(verify(address, message + '.', signature), false, 'the same signature for a changed message');
    }
});
