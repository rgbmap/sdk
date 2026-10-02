// Regenerate vectors/signet-ledger.json and vectors/signet-snapshots.json.
//
//   cd js && node tools/generate-ledger-vectors.mjs
//
// The chain and the snapshots here are synthetic: every hash is computed from the fields
// below, and no record describes anything that happened. Vectors are public by nature, and
// a fixture copied from a live ledger would publish that ledger's contents to everyone
// reading this repository. What these pin is the wire format and the recomputation rules,
// which the JavaScript and the Rust implementations are both held to.
//
// The preimage rules the hashes follow are the ones in `protocol/ledger.js` (entry hash,
// public commitment, anchor commitment); each implementation recomputes them from the raw
// fields on its own.

import { writeFileSync } from 'node:fs'
import { GENESIS_HASH, entryHash, publicCommitment, anchorCommitment, sha256Hex } from '../protocol/ledger.js'

const NET = 'signet'
const ASSET_A = 'rgb:synth-vector-alpha'
const ASSET_B = 'rgb:synth-vector-beta'

const entries = []
let prevHash = GENESIS_HASH

/** Records opened in full: the platform events a publisher opens, plus one balanced transfer. */
const OPENED = new Map([
  [2, () => ({
    op: 'issue',
    json: {
      assetId: ASSET_A,
      contractFileUri: null,
      issuedSupply: '100000000000',
      name: 'Synth Alpha',
      network: NET,
      precision: 8,
      ticker: 'SYN-A',
      totalSupply: '100000000000',
    },
  })],
  [8, () => ({
    op: 'list_asset',
    json: {
      assetId: ASSET_A,
      listedBy: 'synth-vector-issuer',
      minSats: '100000',
    },
  })],
  [15, () => ({
    op: 'transfer',
    json: {
      legs: [
        { assetId: ASSET_A, delta: '2500000' },
        { assetId: ASSET_A, delta: '-2500000' },
        { assetId: 'sats', delta: '546' },
        { assetId: 'sats', delta: '-546' },
      ],
    },
  })],
  [22, () => ({
    op: 'param_change',
    json: {
      after: '20000',
      before: '10000',
      network: NET,
      param: 'withdrawal_fee_sats',
    },
  })],
  [28, () => ({
    op: 'issue',
    json: {
      assetId: ASSET_B,
      contractFileUri: null,
      issuedSupply: '21000000000',
      name: 'Synth Beta',
      network: NET,
      precision: 8,
      ticker: 'SYN-B',
      totalSupply: '21000000000',
    },
  })],
])

const N = 32
for (let i = 1; i <= N; i++) {
  const seq = String(i)
  const ts = String(1700000000000 + i * 60000)
  const opened = OPENED.get(i)?.()
  const publicBytes = opened ? JSON.stringify(opened.json) : null
  const publicSalt = opened ? await sha256Hex(`synth-vector-salt-${i}`) : null
  const publicCommit = opened
    ? await publicCommitment(publicBytes, publicSalt)
    : await sha256Hex(`synth-vector-closed-${i}`)
  const privateCommit = await sha256Hex(`synth-vector-private-${i}`)
  const entry = {
    seq,
    ts,
    network: NET,
    publicCommitment: publicCommit,
    privateCommitment: privateCommit,
    prevHash,
    hash: await entryHash({ prevHash, seq, ts, publicCommitment: publicCommit, privateCommitment: privateCommit }),
    ...(opened ? { op: opened.op, public: publicBytes, publicSalt } : {}),
  }
  entries.push(entry)
  prevHash = entry.hash
}

const verify = {
  algorithm: 'sha256',
  preimage: 'prev_hash || 0x1F || seq || 0x1F || ts || 0x1F || publicCommitment || 0x1F || privateCommitment',
  encoding: 'UTF-8, fields joined by a single 0x1F byte; output is lowercase hex',
  publicCommitment:
    'SHA256("rgb-ledger-pub-v1" || 0x1F || public || 0x1F || publicSalt); `public` and `publicSalt` are returned for ops published in full, and by /v1/me/ledger for your own records.',
  note: "Every record is recomputable from the fields above alone, so the chain can be mirrored and checked against an anchor without anyone's transaction data. Hash `public` verbatim where it is present: parsing and re-serializing may change the byte sequence and will produce a different digest.",
}

writeFileSync(
  new URL('../../vectors/signet-ledger.json', import.meta.url),
  JSON.stringify({ entries, limit: 500, nextCursor: null, verify }, null, 1) + '\n',
)

/** One snapshot per anchor a checker would want: a mid-run one and one at the head. */
const snapshot = async (snapshotId, ledgerSeq, at, height) => {
  const ledgerHash = ledgerSeq === 0 ? GENESIS_HASH : entries[ledgerSeq - 1].hash
  const liabilities = { [ASSET_A]: '97500000000', [ASSET_B]: '21000000000', sats: '999454' }
  const reserves = { [ASSET_A]: '99800000000', [ASSET_B]: '21000000000', sats: '1200000' }
  const snapshot = {
    snapshotId,
    network: NET,
    at,
    algorithm: 'rgb-anchor-v1',
    ledgerSeq,
    ledgerHash,
    liabilitiesRoot: await sha256Hex(`synth-vector-liabilities-${snapshotId}`),
    assetRoots: Object.fromEntries(
      await Promise.all(
        Object.entries(reserves).map(async ([asset, total]) => [asset, { root: await sha256Hex(`synth-vector-root-${snapshotId}-${asset}`), total }]),
      ),
    ),
    leafCount: ledgerSeq,
    liabilities,
    reserves,
    coverage: Object.fromEntries(
      Object.entries(liabilities).map(([asset, liability]) => [
        asset,
        {
          liability,
          reserve: reserves[asset],
          surplus: String(BigInt(reserves[asset]) - BigInt(liability)),
          ok: BigInt(reserves[asset]) >= BigInt(liability),
        },
      ]),
    ),
    disclaimer:
      'BTC reserves are independently verifiable on-chain. RGB asset reserves are self-attested by this platform and are NOT independently verified: verification would require consignments, which carry the private state.',
    anchorState: 'CONFIRMED',
    anchorTxid: await sha256Hex(`synth-vector-txid-${snapshotId}`),
    confirmedHeight: height,
    commitment: null,
  }
  snapshot.commitment = await anchorCommitment(snapshot)
  return snapshot
}

const snapshots = [
  await snapshot(4, 16, 1700001000000, 10104),
  await snapshot(7, 32, 1700002000000, 10190),
]

writeFileSync(
  new URL('../../vectors/signet-snapshots.json', import.meta.url),
  JSON.stringify({ snapshots, limit: 500, nextCursor: null }, null, 1) + '\n',
)

console.log(`wrote ${entries.length} entries (${OPENED.size} opened) and ${snapshots.length} snapshots`)
