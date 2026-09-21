# rgbmap

The RGBMap protocol rules in Rust: canonical serialisation, the record hash chain, anchor and
public-segment commitments, and declaration signatures over BIP-322.

The rules are published at <https://rgbmap.org/docs>. This crate implements them so that a
reader can recompute what an index says instead of believing it.

```toml
[dependencies]
rgbmap = "0.1"
```

| Module | What it does |
|---|---|
| `canonical` | The one serialisation every digest is taken over; refuses what has no fixed form |
| `ledger` | Record hashes, the chain from genesis, commitments and the OP_RETURN they appear in |
| `declaration` | The signing digest of a declaration, and its BIP-322 signature |

For a command-line checker built on this crate, see
[`rgbmap-verify`](https://crates.io/crates/rgbmap-verify).

🚨 This crate shares no code with the JavaScript implementation, and must not start. A hash
chain proves history was not altered only when the side recomputing it is not the side that
wrote it. Both are held to the same vectors in
[`vectors/`](https://github.com/rgbmap/sdk/tree/main/vectors); where they disagree, neither is
right until the difference is understood.
