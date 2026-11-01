// Deletes old versions of this repository's GHCR container packages.
// Run by .github/workflows/ghcr-cleanup.yml through actions/github-script.
//
// GHCR lists every manifest as a "version": a multi-platform or attested
// image is an index (the tagged version) plus untagged child manifests, and
// deleting a child breaks the image. So the plan reads each manifest from the
// registry and keeps a version together with everything it references:
//
// - a version with a protected tag (PROTECT_TAGS, e.g. latest) is kept, and
//   with KEEP_PR_HEADS=true so is one tagged with the head commit of an open PR;
// - a version whose tags all match EPHEMERAL_TAGS (e.g. PR preview builds) is
//   kept for EPHEMERAL_DAYS;
// - of the other top-level versions, tagged or not, the KEEP_LATEST newest
//   and all those newer than KEEP_DAYS are kept. Untagged top-level versions
//   count too: production pins digests, and a rebuild can move every tag off
//   the digest that is still deployed;
// - children of a kept index and signatures/attestations of a kept version
//   (OCI subject or cosign sha256-<digest>.sig tags) are kept with it.
//
// Everything else is deleted, at most MAX_DELETE per package and run.
// DRY_RUN=true only prints the plan.

const MANIFEST_TYPES = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ')

const DAY = 24 * 60 * 60 * 1000

// versions: [{id, digest, tags, created}]; manifests: Map digest -> manifest
// (absent when the registry has none). Returns {keep, remove} as version lists.
function plan(versions, manifests, opts, now = Date.now()) {
  const byDigest = new Map(versions.map((v) => [v.digest, v]))
  const children = new Map()
  const referenced = new Set()
  const subjectOf = new Map()
  for (const v of versions) {
    const m = manifests.get(v.digest)
    const refs = (m && Array.isArray(m.manifests) ? m.manifests : []).map((c) => c.digest)
    children.set(v.digest, refs)
    refs.forEach((d) => referenced.add(d))
    if (m && m.subject && m.subject.digest) subjectOf.set(v.digest, m.subject.digest)
    for (const t of v.tags) {
      const sig = /^sha256-([0-9a-f]{64})\.(sig|att|sbom)$/.exec(t)
      if (sig) subjectOf.set(v.digest, `sha256:${sig[1]}`)
    }
  }

  const age = (v) => now - Date.parse(v.created)
  const isProtected = (v) => v.tags.some((t) => opts.protect.test(t) || opts.keepTags.has(t))
  const isEphemeral = (v) =>
    opts.ephemeral !== null && v.tags.length > 0 && v.tags.every((t) => opts.ephemeral.test(t))

  const keep = new Set()
  const roots = versions.filter((v) => !referenced.has(v.digest) && !subjectOf.has(v.digest))
  const ranked = roots
    .filter((v) => !isProtected(v) && !isEphemeral(v))
    .sort((a, b) => Date.parse(b.created) - Date.parse(a.created))
  ranked.forEach((v, i) => {
    if (i < opts.keepLatest || age(v) < opts.keepDays * DAY) keep.add(v.digest)
  })
  for (const v of versions) {
    if (isProtected(v)) keep.add(v.digest)
    else if (isEphemeral(v) && !subjectOf.has(v.digest) && age(v) < opts.ephemeralDays * DAY) keep.add(v.digest)
  }

  // Kept versions bring their children and their signatures, transitively.
  let changed = true
  while (changed) {
    changed = false
    for (const d of [...keep]) {
      for (const c of children.get(d) || []) {
        if (!keep.has(c)) { keep.add(c); changed = true }
      }
    }
    for (const [d, subject] of subjectOf) {
      if (keep.has(subject) && !keep.has(d)) { keep.add(d); changed = true }
    }
  }

  const kept = versions.filter((v) => keep.has(v.digest))
  const remove = versions
    .filter((v) => !keep.has(v.digest))
    .sort((a, b) => Date.parse(a.created) - Date.parse(b.created))
  return { keep: kept, remove, byDigest }
}

function options(env) {
  const int = (name, def) => {
    const n = Number.parseInt(env[name] ?? '', 10)
    return Number.isFinite(n) && n >= 0 ? n : def
  }
  return {
    packages: (env.PACKAGES || '').split(/[\s,]+/).filter(Boolean),
    protect: new RegExp(env.PROTECT_TAGS || '^(latest)$'),
    ephemeral: env.EPHEMERAL_TAGS ? new RegExp(env.EPHEMERAL_TAGS) : null,
    ephemeralDays: int('EPHEMERAL_DAYS', 14),
    keepLatest: Math.max(1, int('KEEP_LATEST', 15)),
    keepDays: int('KEEP_DAYS', 30),
    maxDelete: int('MAX_DELETE', 300),
    keepPrHeads: env.KEEP_PR_HEADS === 'true',
    keepTags: new Set(),
    dryRun: env.DRY_RUN !== 'false',
  }
}

async function registryToken(owner, pkg, user, token) {
  const scope = encodeURIComponent(`repository:${owner}/${pkg}:pull`)
  const res = await fetch(`https://ghcr.io/token?scope=${scope}&service=ghcr.io`, {
    headers: { Authorization: `Basic ${Buffer.from(`${user}:${token}`).toString('base64')}` },
  })
  if (!res.ok) throw new Error(`ghcr.io token for ${pkg}: HTTP ${res.status}`)
  return (await res.json()).token
}

// Missing manifests (404) are left out; any other error stops the package,
// because a manifest that is not read could hide children of a kept image.
async function readManifests(owner, pkg, digests, bearer) {
  const manifests = new Map()
  const queue = [...digests]
  async function worker() {
    while (queue.length) {
      const digest = queue.shift()
      const res = await fetch(`https://ghcr.io/v2/${owner}/${pkg}/manifests/${digest}`, {
        headers: { Authorization: `Bearer ${bearer}`, Accept: MANIFEST_TYPES },
      })
      if (res.status === 404) continue
      if (!res.ok) throw new Error(`manifest ${pkg}@${digest}: HTTP ${res.status}`)
      manifests.set(digest, await res.json())
    }
  }
  await Promise.all(Array.from({ length: 8 }, worker))
  return manifests
}

async function cleanPackage({ github, core }, owner, pkg, opts, user, token) {
  const base = `/users/${owner}/packages/container/${encodeURIComponent(pkg)}/versions`
  const raw = await github.paginate(`GET ${base}`, { per_page: 100 })
  const versions = raw.map((v) => ({
    id: v.id,
    digest: v.name,
    tags: (v.metadata && v.metadata.container && v.metadata.container.tags) || [],
    created: v.created_at,
  }))
  const bearer = await registryToken(owner, pkg, user, token)
  const manifests = await readManifests(owner, pkg, versions.map((v) => v.digest), bearer)
  const { keep, remove } = plan(versions, manifests, opts)
  if (keep.length === 0) throw new Error(`${pkg}: plan keeps nothing, refusing to delete`)

  const batch = remove.slice(0, opts.maxDelete)
  core.info(`${pkg}: ${versions.length} versions, keeping ${keep.length}, deleting ${batch.length}` +
    (remove.length > batch.length ? ` (${remove.length - batch.length} left for the next run)` : '') +
    (opts.dryRun ? ' [dry run]' : ''))
  let deleted = 0
  const failed = []
  for (const v of batch) {
    const label = `${v.digest} ${v.tags.length ? v.tags.join(',') : '(untagged)'} ${v.created}`
    if (opts.dryRun) { core.info(`  would delete ${label}`); continue }
    try {
      await github.request(`DELETE ${base}/{id}`, { id: v.id })
      deleted++
      core.info(`  deleted ${label}`)
    } catch (err) {
      // GHCR refuses, for example, public versions with over 5000 downloads.
      failed.push(v.digest)
      core.warning(`${pkg}: could not delete ${label}: ${err.message}`)
    }
  }
  return { pkg, total: versions.length, keep: keep.length, remove: batch.length, deleted, failed: failed.length }
}

module.exports = async function run({ github, context, core }) {
  const opts = options(process.env)
  const token = process.env.GHCR_TOKEN
  if (!opts.packages.length) throw new Error('PACKAGES is empty')
  if (!token) throw new Error('GHCR_TOKEN is not set')
  const user = process.env.GHCR_USER || context.repo.owner
  const owner = context.repo.owner.toLowerCase()
  if (opts.keepPrHeads) {
    const pulls = await github.paginate('GET /repos/{owner}/{repo}/pulls', { ...context.repo, state: 'open', per_page: 100 })
    pulls.forEach((p) => opts.keepTags.add(p.head.sha))
    core.info(`Keeping the images of ${pulls.length} open pull request(s).`)
  }
  const rows = []
  let errors = 0
  for (const pkg of opts.packages) {
    try {
      rows.push(await cleanPackage({ github, core }, owner, pkg.toLowerCase(), opts, user, token))
    } catch (err) {
      errors++
      core.error(`${pkg}: ${err.message}`)
    }
  }
  await core.summary
    .addHeading(`GHCR cleanup${opts.dryRun ? ' (dry run)' : ''}`)
    .addTable([
      [
        { data: 'Package', header: true }, { data: 'Versions', header: true },
        { data: 'Kept', header: true }, { data: opts.dryRun ? 'Would delete' : 'To delete', header: true },
        { data: 'Deleted', header: true }, { data: 'Failed', header: true },
      ],
      ...rows.map((r) => [r.pkg, `${r.total}`, `${r.keep}`, `${r.remove}`, `${r.deleted}`, `${r.failed}`]),
    ])
    .write()
  if (errors) core.setFailed(`${errors} package(s) failed; see the log.`)
}

module.exports.plan = plan
module.exports.options = options
