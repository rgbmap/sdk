// Copy the vectors into the package before it is packed, and take them out afterwards.
//
// 🚨 They live at the top of the repository because both implementations are held to them and
// neither owns them. npm only packs what is inside the package directory, so a published SDK
// that did not carry them would leave a third party with no way to check their own work —
// which is most of what this package is for.
//
// `js/vectors/` is a build artifact and is not committed.

import { cpSync, existsSync, rmSync } from 'node:fs'

const from = new URL('../../vectors/', import.meta.url)
const to = new URL('../vectors/', import.meta.url)

if (process.argv.includes('--clean')) {
  rmSync(to, { recursive: true, force: true })
} else {
  if (!existsSync(from)) throw new Error('vectors/ is missing: this has to run inside the repository')
  rmSync(to, { recursive: true, force: true })
  // The generator is a development tool, not something a consumer needs.
  cpSync(from, to, { recursive: true })
}
