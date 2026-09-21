# @rgbmap/sdk

Read an RGBMap index, and recompute what it says rather than believe it.

The rules are published at <https://rgbmap.org/docs>. This package implements them, and is not
the only implementation anyone may write.

Plain ES modules, no build step, usable from a browser, a Worker or Node. The only dependencies
are the two the signature check needs.

## There is no verdict function

This package exposes no `isValid`, no `isVerified` and no `isTrusted`. Every status stands on
its own, and none of them says an asset is safe, official or worth anything. What a status does
mean is at <https://rgbmap.org/docs/identity-and-status>; what none of them means is at
<https://rgbmap.org/docs/what-rgbmap-does-not-state>.

## Use

```sh
npm install @rgbmap/sdk
```

```js
import { client, checkDeclaration } from '@rgbmap/sdk'

const rgbmap = client({ network: 'signet' })

// What a wallet needs to show one asset. Each status separately.
const asset = await rgbmap.resolve('rgb:…')
asset.status.issuer_signed
asset.same_ticker.count

// A page of records, recomputed here from the bytes the index returned.
const page = await rgbmap.ledgerChecked({ limit: 200 })
page.problems           // empty when everything recomputes

// A declaration's own consistency and its signature.
const { ok, problems, digest } = await checkDeclaration(declaration)
```

Fetch the whole asset list for a network and compare locally. Asking an index about one asset at
a time tells it what its user holds.

| Export | What it does |
|---|---|
| `client({ api, network, fetch })` | Reads an index: `resolve`, `assets`, `ledger`, `anchors`, `objects`, `manifests`, `search`, `health` |
| `client().ledgerChecked()` | A page of records, plus the problems found recomputing it |
| `verifyEntries(entries, prevHash, firstSeq)` | Recompute a run of records: chain, order, balance |
| `anchorCommitment(snapshot)` | Recompute the commitment a snapshot claims |
| `opReturnFor(commitment)` | The scriptPubKey that commitment appears as on bitcoin |
| `checkDeclaration(declaration)` | A declaration's own consistency and its BIP-322 signature |
| `verifyBip322(address, message, signature)` | A signature on its own |
| `canonicalize(value)` | The one serialisation everything is hashed over |
| `fetchObject(url, sha256)` | Fetch an object and refuse it unless the digest matches |

`fetch` is injectable, so a caller can add caching, a timeout or their own transport.

The protocol modules are importable on their own:

```js
import { canonicalize } from '@rgbmap/sdk/protocol/canonical.js'
```

## Checking another implementation

A second implementation of these rules exists in Rust, sharing no code with this one. Both are
held to the same vectors, and those vectors ship here so that any other implementation can be
held to them too.

```js
import vectors from '@rgbmap/sdk/vectors/bip322.json' with { type: 'json' }
```

| File | Covers |
|---|---|
| `canonical.json` | The one serialisation everything is hashed over |
| `bip322.json` | Signature verification, accepted and refused |
| `signet-ledger.json` | Records from a live ledger: the chain, the commitments, the balance rule |
| `signet-snapshots.json` | Snapshots from the same ledger: anchor commitments |

🚨 The signature vectors are produced by [bip322-js](https://github.com/ACken2/bip322-js), an
outside implementation. A set produced by the code it checks proves only that the code agrees
with itself.

## Licence

MIT.
