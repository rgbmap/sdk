# RGBMap

[![npm](https://img.shields.io/npm/v/@rgbmap/sdk?label=%40rgbmap%2Fsdk)](https://www.npmjs.com/package/@rgbmap/sdk)
[![crates.io](https://img.shields.io/crates/v/rgbmap?label=rgbmap)](https://crates.io/crates/rgbmap)
[![crates.io](https://img.shields.io/crates/v/rgbmap-verify?label=rgbmap-verify)](https://crates.io/crates/rgbmap-verify)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Everything needed to check an RGBMap index rather than believe it: the protocol primitives, a
client that recomputes what it reads, an offline verifier, and the vectors both implementations
are held to.

```sh
npm install @rgbmap/sdk          # JavaScript
cargo add rgbmap                 # Rust
cargo install rgbmap-verify      # the offline checker, as a command
```

The rules are published at <https://rgbmap.org/docs>. This repository implements them, and is
not the only implementation anyone may write.

| | |
|---|---|
| `js/` | [`@rgbmap/sdk`](https://www.npmjs.com/package/@rgbmap/sdk) — the protocol modules and a client, plain ES modules |
| `rust/rgbmap` | [The same rules in Rust](https://crates.io/crates/rgbmap) |
| `rust/rgbmap-verify` | [A command-line verifier](https://crates.io/crates/rgbmap-verify) reading published objects and one bitcoin interface |
| `vectors/` | What both implementations are checked against |

## There is no verdict function

Neither language exposes `isValid`, `isVerified` or `isTrusted`. Every status stands on its own,
and none of them says an asset is safe, official or worth anything. What a status does mean is
at <https://rgbmap.org/docs/identity-and-status>; what none of them means is at
<https://rgbmap.org/docs/what-rgbmap-does-not-state>.

## JavaScript

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

The protocol modules are importable on their own, and have no dependency beyond the two the
signature check needs:

```js
import { canonicalize } from '@rgbmap/sdk/protocol/canonical.js'
```

## Rust

```toml
rgbmap = "0.1"
```

```rust
use rgbmap::{check_signature, entry_hash, verify_bip322};
```

```sh
cargo run -p rgbmap-verify -- --objects https://data.rgbmap.org --index https://api.rgbmap.org
```

## Two implementations

The two share no code, and must not start. A recomputation proves history was not altered only
when the side checking it is not the side that wrote it. Where they disagree, neither result is
correct until the cause is found.

`vectors/` sits above both languages because neither owns it.

| File | Covers |
|---|---|
| `canonical.json` | The one serialisation everything is hashed over |
| `bip322.json` | Signature verification, accepted and refused |
| `signet-ledger.json` | Records from a live ledger: the chain, the commitments, the balance rule |
| `signet-snapshots.json` | Snapshots from the same ledger: anchor commitments |

🚨 The signature vectors are produced by [bip322-js](https://github.com/ACken2/bip322-js), an
outside implementation. Regenerate with `cd js && npm run vectors`; never with the signer in
this repository. A set produced by the code it checks proves only that the code agrees with
itself.

## Checking another implementation

Any implementation of these rules can be held to the same vectors, which ship inside the npm
package for that purpose.

```js
import vectors from '@rgbmap/sdk/vectors/bip322.json' with { type: 'json' }
```

## Tests

```sh
cd js && npm install && npm test
cd rust && cargo test
```

## Licence

MIT. See [LICENSE](LICENSE).
