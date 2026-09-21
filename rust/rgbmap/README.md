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

## An independent implementation

This crate is written against the specification, not ported from the code that publishes
RGBMap archives. That is what makes it worth running: recomputing a hash chain with the same
code that wrote it proves nothing about the chain.

It is held to the same
[vectors](https://github.com/rgbmap/sdk/tree/main/vectors) as every other implementation, so a
disagreement is a real one and not a difference in style.
