// BIP-322 simple signature verification: P2WPKH and single-key P2TR.
// The one scheme declarations are signed with: https://rgbmap.org/docs/declarations
//
// 🚨 Verification loosened by even a little accepts declarations nobody signed. Every rule
// here is pinned by test/bip322.test.mjs against the 60 vectors the backend already uses
// (`trade-api-rs/tests/bip322-vectors.json`, produced with bip322-js).
//
// The construction side mirrors the wallet extension's `lib/bip322.js`; this file adds the
// sighash computation and the signature check.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';

const enc = new TextEncoder();
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const dsha256 = (b) => sha256(sha256(b));
const hash160 = (b) => ripemd160(sha256(b));

function cat(...arrays) {
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrays) {
        out.set(a, o);
        o += a.length;
    }
    return out;
}

function varint(n) {
    if (n < 0xfd) return new Uint8Array([n]);
    if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
    return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
}
const withLen = (b) => cat(varint(b.length), b);
const u32 = (n) => new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
const u64 = (v) => {
    const out = new Uint8Array(8);
    let n = BigInt(v);
    for (let i = 0; i < 8; i++) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return out;
};

// ---------- bech32 ----------

function polymod(values) {
    let chk = 1;
    for (const v of values) {
        const top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
const hrpExpand = (hrp) => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];

function convertBits(data, from, to, pad) {
    let acc = 0;
    let bits = 0;
    const out = [];
    const max = (1 << to) - 1;
    for (const value of data) {
        if (value < 0 || value >> from !== 0) throw new Error('bad value');
        acc = (acc << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            out.push((acc >> bits) & max);
        }
    }
    if (pad && bits) out.push((acc << (to - bits)) & max);
    else if (!pad && (bits >= from || ((acc << (to - bits)) & max))) throw new Error('bad padding');
    return out;
}

/** A segwit address: its witness version and program. Other address types are refused. */
export function decodeAddress(address) {
    const addr = String(address).trim();
    const lower = addr.toLowerCase();
    if (addr !== lower && addr !== addr.toUpperCase()) throw new Error('mixed-case address');
    const pos = lower.lastIndexOf('1');
    if (pos < 1 || pos + 7 > lower.length) throw new Error('not a bech32 address');
    const hrp = lower.slice(0, pos);
    const data = [];
    for (const c of lower.slice(pos + 1)) {
        const i = CHARSET.indexOf(c);
        if (i < 0) throw new Error('invalid character in address');
        data.push(i);
    }
    const version = data[0];
    const want = version === 0 ? 1 : 0x2bc830a3;
    if (polymod([...hrpExpand(hrp), ...data]) !== want) throw new Error('bad address checksum');
    const program = new Uint8Array(convertBits(data.slice(1, -6), 5, 8, false));
    if (version === 0 && program.length !== 20) throw new Error('only P2WPKH is accepted at witness v0');
    if (version === 1 && program.length !== 32) throw new Error('only single-key P2TR is accepted at witness v1');
    if (version > 1) throw new Error('unsupported witness version');
    return { hrp, version, program };
}

export const scriptPubKeyOf = (address) => {
    const { version, program } = decodeAddress(address);
    return cat(new Uint8Array([version === 0 ? 0x00 : 0x50 + version]), withLen(program));
};

// ---------- the two virtual transactions ----------

function taggedHash(tag, message) {
    const t = sha256(enc.encode(tag));
    return sha256(cat(t, t, message));
}

function serializeTx({ inputs, outputs }) {
    let out = u32(0); // version
    out = cat(out, varint(inputs.length));
    for (const i of inputs) out = cat(out, i.hash, u32(i.index), withLen(i.script), u32(i.sequence));
    out = cat(out, varint(outputs.length));
    for (const o of outputs) out = cat(out, u64(o.value), withLen(o.script));
    return cat(out, u32(0)); // locktime
}

function virtualTxs(address, message) {
    const spk = scriptPubKeyOf(address);
    const msgHash = taggedHash('BIP0322-signed-message', enc.encode(message));
    const toSpend = serializeTx({
        inputs: [{ hash: new Uint8Array(32), index: 0xffffffff, script: cat(new Uint8Array([0x00]), withLen(msgHash)), sequence: 0 }],
        outputs: [{ value: 0n, script: spk }],
    });
    return { toSpendTxid: dsha256(toSpend), scriptPubKey: spk };
}

// ---------- witness ----------

/** The witness stack a BIP-322 simple signature carries, as base64. */
function parseWitness(base64) {
    const raw = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    let o = 0;
    const readVarint = () => {
        const b = raw[o++];
        if (b < 0xfd) return b;
        if (b === 0xfd) {
            const v = raw[o] | (raw[o + 1] << 8);
            o += 2;
            return v;
        }
        throw new Error('oversized varint in witness');
    };
    const count = readVarint();
    if (count < 1 || count > 3) throw new Error('unexpected witness item count');
    const items = [];
    for (let i = 0; i < count; i++) {
        const len = readVarint();
        if (o + len > raw.length) throw new Error('witness item runs past the end');
        items.push(raw.slice(o, o + len));
        o += len;
    }
    if (o !== raw.length) throw new Error('trailing bytes after the witness');
    return items;
}

// ---------- sighashes ----------

/** BIP-143, for the P2WPKH input of the to_sign transaction. */
function sighashP2WPKH(toSpendTxid, pubkeyHash, sighashType) {
    const outpoint = cat(toSpendTxid, u32(0));
    const hashPrevouts = dsha256(outpoint);
    const hashSequence = dsha256(u32(0));
    const hashOutputs = dsha256(cat(u64(0n), withLen(new Uint8Array([0x6a]))));
    const scriptCode = cat(new Uint8Array([0x19, 0x76, 0xa9, 0x14]), pubkeyHash, new Uint8Array([0x88, 0xac]));
    return dsha256(cat(u32(0), hashPrevouts, hashSequence, outpoint, scriptCode, u64(0n), u32(0), hashOutputs, u32(0), u32(sighashType)));
}

/** BIP-341 key-path sighash, for the P2TR input of the to_sign transaction. */
function sighashP2TR(toSpendTxid, scriptPubKey, hashType) {
    const shaPrevouts = sha256(cat(toSpendTxid, u32(0)));
    const shaAmounts = sha256(u64(0n));
    const shaScriptPubKeys = sha256(withLen(scriptPubKey));
    const shaSequences = sha256(u32(0));
    const shaOutputs = sha256(cat(u64(0n), withLen(new Uint8Array([0x6a]))));
    const common = cat(
        new Uint8Array([hashType]),
        u32(0), // nVersion
        u32(0), // nLockTime
        shaPrevouts,
        shaAmounts,
        shaScriptPubKeys,
        shaSequences,
        shaOutputs,
        new Uint8Array([0x00]), // spend type: key path, no annex
        u32(0), // input index
    );
    return taggedHash('TapSighash', cat(new Uint8Array([0x00]), common));
}

// ---------- verification ----------

/**
 * Whether `signature` (base64 witness, BIP-322 simple) signs `message` for `address`.
 *
 * Any malformed input is a rejection, never an exception: a declaration that cannot be
 * parsed is one that does not verify.
 */
export function verify(address, message, signature) {
    try {
        if (!address || !signature) return false;
        const { version, program } = decodeAddress(address);
        const { toSpendTxid, scriptPubKey } = virtualTxs(address, message);
        const witness = parseWitness(signature);

        if (version === 0) {
            if (witness.length !== 2) return false;
            const [sig, pubkey] = witness;
            if (pubkey.length !== 33) return false;
            if (!bytesEqual(hash160(pubkey), program)) return false;
            if (sig.length < 9) return false;
            const sighashType = sig[sig.length - 1];
            if (sighashType !== 0x01) return false; // SIGHASH_ALL only
            const digest = sighashP2WPKH(toSpendTxid, program, sighashType);
            const parsed = secp256k1.Signature.fromBytes(sig.slice(0, -1), 'der');
            // Bitcoin policy requires low-s; a high-s signature is a different encoding of
            // the same signature and is not accepted.
            if (parsed.hasHighS()) return false;
            // 🚨 noble verifies from compact bytes; handing it the parsed object throws,
            // which this function would swallow into a silent rejection.
            return secp256k1.verify(parsed.toBytes('compact'), digest, pubkey, { prehash: false });
        }

        if (witness.length !== 1) return false;
        const sig = witness[0];
        let hashType = 0x00;
        let raw = sig;
        if (sig.length === 65) {
            hashType = sig[64];
            if (hashType === 0x00) return false; // 0x00 must use the 64-byte form
            raw = sig.slice(0, 64);
        } else if (sig.length !== 64) {
            return false;
        }
        if (hashType !== 0x00 && hashType !== 0x01) return false;
        const digest = sighashP2TR(toSpendTxid, scriptPubKey, hashType);
        return schnorr.verify(raw, digest, program);
    } catch {
        return false;
    }
}

/**
 * Sign a message for a P2WPKH address, producing the same base64 witness a wallet would.
 *
 * For the keys RGBMap and its tools hold; a wallet signs in its own process and this is
 * never used on a key that came from elsewhere.
 */
export function signP2WPKH(privateKey, message, hrp = 'bc') {
    const pubkey = secp256k1.getPublicKey(privateKey, true);
    const program = hash160(pubkey);
    const address = encodeSegwit(hrp, 0, program);
    const { toSpendTxid } = virtualTxs(address, message);
    const digest = sighashP2WPKH(toSpendTxid, program, 0x01);
    // noble returns compact bytes; the witness carries DER plus the sighash byte.
    const compact = secp256k1.sign(digest, privateKey, { prehash: false, lowS: true });
    const der = cat(secp256k1.Signature.fromBytes(compact, 'compact').toBytes('der'), new Uint8Array([0x01]));
    const witness = cat(new Uint8Array([2]), withLen(der), withLen(pubkey));
    return { address, signature: btoa(String.fromCharCode(...witness)) };
}

/** bech32 encoding, for turning a key into the address that signs with it. */
export function encodeSegwit(hrp, version, program) {
    const data = [version, ...convertBits([...program], 8, 5, true)];
    const values = [...hrpExpand(hrp), ...data];
    const constant = version === 0 ? 1 : 0x2bc830a3;
    const mod = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ constant;
    const checksum = [];
    for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31);
    return `${hrp}1${[...data, ...checksum].map((d) => CHARSET[d]).join('')}`;
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}
