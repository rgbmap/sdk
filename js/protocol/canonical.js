// Deterministic JSON serialisation. Everything hashed under this protocol is hashed over
// these bytes: https://rgbmap.org/docs/declarations#canonical-form
//
// The rules are the publisher's: object keys sorted by name, no whitespace, floats and
// integers outside the exactly-representable range rejected rather than coerced. A
// divergence produces a different hash with no error anywhere, so every rule here is
// pinned by test/canonical.test.mjs against vectors taken from the publisher's own output.
//
// Reference implementation: backend trade-api-rs/src/canonical.rs.

const SAFE = 9007199254740991;

/** Serialise a value canonically. Throws on anything that has no deterministic form. */
export function canonicalize(value, path = '$') {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'string') return quote(value);
    if (typeof value === 'number') return number(value, path);
    if (typeof value === 'bigint') throw new CanonicalError(path, 'use a decimal string for large integers');
    if (Array.isArray(value)) return '[' + value.map((v, i) => canonicalize(v, `${path}[${i}]`)).join(',') + ']';
    if (typeof value === 'object') {
        const parts = [];
        // Sorted by name: insertion order depends on the code path that built the object.
        for (const k of Object.keys(value).sort()) {
            const v = value[k];
            if (v === undefined) continue;
            parts.push(quote(k) + ':' + canonicalize(v, `${path}.${k}`));
        }
        return '{' + parts.join(',') + '}';
    }
    throw new CanonicalError(path, `${typeof value} has no canonical form`);
}

export class CanonicalError extends Error {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.path = path;
    }
}

function number(n, path) {
    if (!Number.isInteger(n)) throw new CanonicalError(path, 'floating point values are not accepted, use a decimal string');
    if (Math.abs(n) > SAFE) throw new CanonicalError(path, 'integer outside the safe range, use a decimal string');
    return String(n);
}

// Escaping as JSON.stringify does it: quote, backslash and the C0 controls, with the short
// forms where they exist. Characters above 0x7F stay as they are.
function quote(s) {
    let out = '"';
    for (const c of s) {
        const code = c.codePointAt(0);
        if (c === '"') out += '\\"';
        else if (c === '\\') out += '\\\\';
        else if (c === '\b') out += '\\b';
        else if (c === '\t') out += '\\t';
        else if (c === '\n') out += '\\n';
        else if (c === '\f') out += '\\f';
        else if (c === '\r') out += '\\r';
        else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
        else out += c;
    }
    return out + '"';
}
