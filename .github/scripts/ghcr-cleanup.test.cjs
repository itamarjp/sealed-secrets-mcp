// Checks the keep/delete plan of ghcr-cleanup.cjs on a made-up package.
// The workflow runs it on pull requests and before every cleanup.
const assert = require('node:assert/strict')
const { plan, options } = require('./ghcr-cleanup.cjs')

const now = Date.parse('2026-10-26T00:00:00Z')
const digest = (n) => `sha256:${n.toString(16).padStart(64, '0')}`
const daysAgo = (k) => new Date(now - k * 24 * 60 * 60 * 1000).toISOString()
const versions = []
const manifests = new Map()
let next = 1

// A tagged index with a platform manifest and an attestation, as buildx pushes it.
function image(age, tags, { index = true } = {}) {
  const root = digest(next++)
  versions.push({ id: next, digest: root, tags, created: daysAgo(age) })
  if (!index) { manifests.set(root, { config: {} }); return root }
  const kids = [digest(next++), digest(next++)]
  for (const k of kids) {
    versions.push({ id: next, digest: k, tags: [], created: daysAgo(age) })
    manifests.set(k, { config: {} })
  }
  manifests.set(root, { manifests: kids.map((d) => ({ digest: d })) })
  return root
}
function extra(age, tags) {
  const d = digest(next++)
  versions.push({ id: next, digest: d, tags, created: daysAgo(age) })
  manifests.set(d, { config: {} })
  return d
}
const childrenOf = (root) => manifests.get(root).manifests.map((m) => m.digest)

const opts = options({
  PROTECT_TAGS: '^latest$',
  EPHEMERAL_TAGS: '^[0-9a-f]{40}$',
  KEEP_LATEST: '3',
  KEEP_DAYS: '30',
})
const latest = image(100, ['latest', '2026.07.18-1'])
const old = [0, 1, 2, 3, 4, 5].map((i) => image(200 + i, [`2026.04.0${i}-${i}`]))
const recent = image(5, ['2026.10.21-9'])
const untagged = image(60, [], { index: false })
const preview = image(3, ['a'.repeat(40)])
const oldPreview = image(40, ['b'.repeat(40)])
const signature = extra(100, [`sha256-${latest.slice(7)}.sig`])
const oldSignature = extra(205, [`sha256-${old[5].slice(7)}.sig`])
const orphan = extra(300, [])
const openPr = image(60, ['c'.repeat(40)])
opts.keepTags.add('c'.repeat(40))

let result = plan(versions, manifests, opts, now)
let kept = new Set(result.keep.map((v) => v.digest))
let removed = new Set(result.remove.map((v) => v.digest))
const isKept = (d, why) => assert.ok(kept.has(d), `kept: ${why}`)
const isRemoved = (d, why) => assert.ok(removed.has(d), `removed: ${why}`)

assert.equal(kept.size + removed.size, versions.length)
for (const [root, why] of [[latest, 'protected tag'], [recent, 'newer than KEEP_DAYS'], [preview, 'recent preview']]) {
  isKept(root, why)
  childrenOf(root).forEach((c) => isKept(c, `child of ${why}`))
}
// Ranked: recent, untagged (an old deployed digest), old[0]; KEEP_LATEST is 3.
isKept(untagged, 'untagged top-level version among the newest')
isKept(old[0], 'among the newest')
childrenOf(old[0]).forEach((c) => isKept(c, 'child of a kept version'))
for (const o of old.slice(1)) {
  isRemoved(o, 'older than the newest KEEP_LATEST')
  childrenOf(o).forEach((c) => isRemoved(c, 'child of a removed version'))
}
isRemoved(oldPreview, 'old preview')
isKept(openPr, 'preview of an open PR')
isKept(signature, 'signature of a kept version')
isRemoved(oldSignature, 'signature of a removed version')
isRemoved(orphan, 'orphan child')
assert.deepEqual(result.remove.map((v) => v.created), [...result.remove.map((v) => v.created)].sort())

// A manifest shared with a kept index stays even if a removed index lists it.
manifests.get(old[5]).manifests.push({ digest: childrenOf(recent)[0] })
result = plan(versions, manifests, opts, now)
kept = new Set(result.keep.map((v) => v.digest))
isKept(childrenOf(recent)[0], 'shared child')

const defaults = options({})
assert.equal(defaults.dryRun, true)
assert.equal(defaults.keepLatest, 15)
assert.equal(defaults.keepDays, 30)
assert.equal(defaults.ephemeral, null)
assert.equal(defaults.keepPrHeads, false)
assert.ok(defaults.protect.test('latest'))
assert.equal(options({ DRY_RUN: 'false' }).dryRun, false)
assert.equal(options({ KEEP_LATEST: '0' }).keepLatest, 1)

console.log('ghcr-cleanup plan: ok')
