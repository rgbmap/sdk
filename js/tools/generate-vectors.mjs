// Regenerate vectors/bip322.json.
//
//   cd js && npm install && npm run vectors
//
// 🚨 The signatures are produced by bip322-js, an implementation written by someone else.
// That is the entire point of this file: a vector set produced by the implementation it is
// meant to check proves only that the implementation agrees with itself. Do not regenerate
// these with the signer in protocol/bip322.js.
//
// The keys below are written out here rather than kept anywhere. Vectors are public by
// nature, and these sign nothing that exists.

import { writeFileSync } from 'node:fs'
import { Signer, Verifier, Address } from 'bip322-js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import bs58check from 'bs58check'

const KEYS = [
  '0000000000000000000000000000000000000000000000000000000000000001',
  '1111111111111111111111111111111111111111111111111111111111111111',
  'f00dbabe00000000000000000000000000000000000000000000000000000042',
]

const wifFor = (network, keyHex) =>
  bs58check.encode(
    Buffer.concat([Buffer.from([network === 'mainnet' ? 0x80 : 0xef]), Buffer.from(keyHex, 'hex'), Buffer.from([0x01])]),
  )

const digest = 'a'.repeat(64)
const MESSAGES = [
  ['empty', ''],
  ['ascii', 'Hello World'],
  ['asset v1', `RGBMap rgbmap-asset v1 ${digest}`],
  ['asset v2', `RGBMap rgbmap-asset v2 ${digest}`],
  ['collection v1', `RGBMap rgbmap-collection v1 ${digest}`],
  ['publisher v0', `RGBMap rgbmap-publisher v0 ${digest}`],
  // One, two, three and four byte sequences, and a newline in the middle.
  ['multibyte', 'café · ไทย · 🚀\nend'],
  ['long', 'x'.repeat(1000)],
]

const cases = []
for (const [k, keyHex] of KEYS.entries()) {
  const pub = Buffer.from(secp256k1.getPublicKey(Buffer.from(keyHex, 'hex'), true))
  for (const network of ['mainnet', 'testnet']) {
    const wif = wifFor(network, keyHex)
    for (const kind of ['p2wpkh', 'p2tr']) {
      const address = Address.convertPubKeyIntoAddress(pub, kind)[network]
      for (const [name, message] of MESSAGES) {
        const signature = Signer.sign(wif, address, message)
        cases.push({
          key: k,
          network,
          kind,
          name,
          address,
          message,
          signature,
          verifies: Verifier.verifySignature(address, message, signature),
        })
      }
    }
  }
}

// Things a verifier has to refuse. A verifier that accepts one of these is an authentication
// bypass; the shape of the refusal is not pinned, only that it does not accept.
const first = cases[0]
// 🚨 Another key, not another network. The same key encoded for mainnet and for testnet has
// the same script behind it, so a signature made for one verifies against the other — which
// is correct behaviour, not a bypass, and makes a useless negative case.
const other = cases.find((c) => c.key !== first.key && c.kind === first.kind && c.network === first.network)
const negative = [
  { name: 'signature from another key', address: other.address, message: first.message, signature: first.signature },
  { name: 'signature over another message', address: first.address, message: 'not what was signed', signature: first.signature },
  { name: 'one byte of the signature flipped', address: first.address, message: first.message, signature: flip(first.signature) },
  { name: 'empty signature', address: first.address, message: first.message, signature: '' },
  { name: 'not base64', address: first.address, message: first.message, signature: 'not a signature' },
]
for (const n of negative) {
  let accepted = false
  try {
    accepted = Verifier.verifySignature(n.address, n.message, n.signature)
  } catch {
    accepted = false
  }
  if (accepted) throw new Error(`the reference accepted a case meant to be refused: ${n.name}`)
}

function flip(sig) {
  const b = Buffer.from(sig, 'base64')
  b[b.length - 1] ^= 0x01
  return b.toString('base64')
}

writeFileSync(
  new URL('../../vectors/bip322.json', import.meta.url),
  JSON.stringify({ generator: 'bip322-js', cases, negative }, null, 1) + '\n',
)
console.log(`wrote ${cases.length} cases and ${negative.length} negative cases`)
