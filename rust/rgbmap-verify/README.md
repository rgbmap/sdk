# rgbmap-verify

Recomputes a published RGBMap archive from the objects alone. It asks an index for one thing —
which object paths exist — and re-fetches and re-hashes everything that list names.

The checks are specified at <https://rgbmap.org/docs/verification>.

```sh
cargo build --release --locked

rgbmap-verify --objects https://data.rgbmap.org --index https://api.rgbmap.org --publisher <id>
rgbmap-verify --arweave https://turbo-gateway.com --index https://api.rgbmap.org --publisher <id>
rgbmap-verify --objects ./objects --list objects.json --bitcoin https://mempool.space/api
```

Exit code 0 when every check passes, 1 when any does not.

| Check | Question it answers |
|---|---|
| Object digests | Do the bytes match the digest they are published under? |
| Shard ranges | Are the records continuous, with no gap and no overlap? |
| Hash chain | Was any record altered, removed or reordered? |
| Balance | Does every record sum to zero per asset? |
| Commitments | Does each snapshot recompute the commitment it claims? |
| Heads | Does the record a snapshot names hash to the hash it claims? |
| Bitcoin | Is that commitment in a confirmed OP_RETURN? |

An index is never believed: nothing it returns beyond the list of paths is used, and a
tampered index cannot make a check pass.

🚨 This crate shares no code with the JavaScript implementation, and must not start. A hash
chain proves history was not altered only when the side recomputing it is not the side that
wrote it. Where the two disagree, neither is right until the difference is understood.
