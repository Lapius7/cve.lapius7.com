import express from 'express'
import { createHash } from 'node:crypto'
import { pool, rowToCve } from './db.ts'
import { ADV_RE, advisory, cached, j, normAdvId } from './sources.ts'

const DAY = 86400_000
const HOUR = 3600_000
const PER = 20
const SELECT = `SELECT c.*, k.cve_id AS kev_added, e.score AS epss_score FROM cves c
  LEFT JOIN kev k ON k.cve_id = c.id LEFT JOIN epss e ON e.cve_id = c.id`
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i

// URL slug -> OSV ecosystem name
const ECO: Record<string, string> = {
  npm: 'npm', pypi: 'PyPI', crates: 'crates.io', cargo: 'crates.io', go: 'Go', maven: 'Maven', nuget: 'NuGet',
  rubygems: 'RubyGems', gem: 'RubyGems', packagist: 'Packagist', composer: 'Packagist', hex: 'Hex', pub: 'Pub',
  actions: 'GitHub Actions', swift: 'SwiftURL', cran: 'CRAN', hackage: 'Hackage', conan: 'ConanCenter',
}
const ECO_NAMES = new Set(Object.values(ECO))
const ecoName = (s: string) => ECO[s.toLowerCase()] ?? (ECO_NAMES.has(s) ? s : null)

const sha = (s: string) => createHash('sha1').update(s).digest('hex')
const key = (prefix: string, s: string) => prefix + sha(s).slice(0, 23 - prefix.length)
const sevOf = (s?: string | null) => {
  const u = String(s ?? '').toUpperCase()
  return u === 'MODERATE' ? 'MEDIUM' : ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(u) ? u : null
}
const scoreSev = (n: number) => (n >= 9 ? 'CRITICAL' : n >= 7 ? 'HIGH' : n >= 4 ? 'MEDIUM' : n > 0 ? 'LOW' : null)

// ---- per-IP rate limit for endpoints that fan out to OSV ----
const hits = new Map<string, { n: number; t: number }>()
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (now - v.t > 60_000) hits.delete(k) }, 60_000).unref()
const limit = (max: number): express.RequestHandler => (req, res, next) => {
  const ip = String(req.headers['cf-connecting-ip'] ?? req.ip ?? '')
  const now = Date.now()
  const k = `${req.path.split('/')[2]}|${ip}`
  const h = hits.get(k)
  if (!h || now - h.t > 60_000) hits.set(k, { n: 1, t: now })
  else if (++h.n > max) return void res.status(429).json({ error: 'rate_limited' })
  next()
}

type Brief = { id: string; summary: string; severity: string | null; aliases: string[]; published: string | null; modified: string | null; withdrawn: boolean; fixed: string[] }

async function osvQuery(body: object) {
  const out: any[] = []
  let token: string | undefined
  for (let i = 0; i < 5; i++) {
    const r = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'vulns.lapius7.com' },
      body: JSON.stringify(token ? { ...body, page_token: token } : body), signal: AbortSignal.timeout(12000),
    })
    if (!r.ok) throw new Error(String(r.status))
    const d: any = await r.json()
    out.push(...(d.vulns ?? []))
    token = d.next_page_token
    if (!token) break
  }
  return out
}

const brief = (v: any, pkg?: { ecosystem: string; name: string }): Brief => {
  const fixed = new Set<string>()
  for (const a of v.affected ?? []) {
    if (pkg && (a.package?.name !== pkg.name || a.package?.ecosystem !== pkg.ecosystem)) continue
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed)
  }
  let sev = sevOf(v.database_specific?.severity)
  if (!sev) for (const s of v.severity ?? []) { const m = /CVSS:[\d.]+\/.*/.test(s.score ?? '') ? null : Number(s.score); if (m) sev = scoreSev(m) }
  return {
    id: v.id, summary: String(v.summary ?? v.details ?? '').split('\n')[0].slice(0, 200), severity: sev,
    aliases: (v.aliases ?? []).slice(0, 8), published: v.published ?? null, modified: v.modified ?? null,
    withdrawn: Boolean(v.withdrawn), fixed: [...fixed].slice(0, 6),
  }
}

/** Fill missing severity from our own NVD data via CVE aliases. */
async function fillSeverity(items: Brief[]) {
  const need = items.filter((b) => !b.severity)
  const ids = [...new Set(need.flatMap((b) => b.aliases.filter((a) => CVE_RE.test(a))))]
  if (!ids.length) return
  const [rows] = await pool.query<any[]>('SELECT id, severity FROM cves WHERE id IN (?)', [ids])
  const m = new Map(rows.map((r) => [r.id, r.severity as string | null]))
  for (const b of need) for (const a of b.aliases) { const s = m.get(a); if (s) { b.severity = s; break } }
}

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
const sevRank = (s: string | null) => (s ? SEV_ORDER[s] : 4)

async function pkgVulns(ecosystem: string, name: string, version?: string) {
  const k = key('p', `${ecosystem}|${name}|${version ?? ''}`)
  return cached(k, 'pkg', 3 * HOUR, async () => {
    const vulns = await osvQuery({ package: { ecosystem, name }, ...(version ? { version } : {}) })
    const items = vulns.map((v) => brief(v, { ecosystem, name }))
    await fillSeverity(items)
    items.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || String(b.published).localeCompare(String(a.published)))
    return items
  })
}

async function osvBrief(id: string): Promise<Brief | null> {
  return cached(key('b', id), 'osvb', 6 * HOUR, async () => {
    const v = await j(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, 8000)
    const b = brief(v)
    await fillSeverity([b])
    return b
  })
}

async function pool8<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>) {
  const out: R[] = new Array(items.length)
  let i = 0
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]) }
  }))
  return out
}

// ---- badge ----
const COLORS: Record<string, string> = { CRITICAL: '#b91c1c', HIGH: '#c2410c', MEDIUM: '#b45309', LOW: '#4d7c0f', NONE: '#15803d', UNKNOWN: '#6b7280' }
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
function badge(label: string, value: string, color: string) {
  const w = (s: string) => Math.round(s.length * 6.4 + 12)
  const lw = w(label), vw = w(value)
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${lw + vw}" height="20" role="img" aria-label="${esc(label)}: ${esc(value)}"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/><g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle"><text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + vw / 2}" y="14">${esc(value)}</text></g></svg>`
}

// ---- JSON / Markdown rendering ----
function cveMd(c: any) {
  return [
    `# ${c.id}`, '',
    `- Severity: ${c.severity ?? 'n/a'}${c.score != null ? ` (${c.score}${c.vector ? `, ${c.vector}` : ''})` : ''}`,
    `- Published: ${c.published}`, `- Modified: ${c.modified}`,
    c.cwes?.length ? `- CWE: ${c.cwes.join(', ')}` : '', c.kev ? '- Known exploited (CISA KEV)' : '',
    c.epss != null ? `- EPSS: ${(c.epss * 100).toFixed(2)}%` : '', '',
    c.description, '',
    ...(c.references?.length ? ['## References', '', ...c.references.slice(0, 30).map((r: any) => `- ${r.url}`)] : []),
  ].filter((x) => x !== '').join('\n') + '\n'
}
function advMd(a: any) {
  return [`# ${a.id}`, '', a.summary, '', a.details ?? ''].join('\n') + '\n'
}

export const OPENAPI = {
  openapi: '3.0.3',
  info: { title: 'Vulnerability.DB API', version: '1.0.0', description: 'Read-only, no authentication. Please keep to a few requests per second.' },
  servers: [{ url: 'https://vulns.lapius7.com' }],
  paths: {
    '/api/cves': { get: { summary: 'Search CVEs', parameters: ['q', 'severity', 'sort', 'year', 'kev', 'page'] } },
    '/api/cves/{id}': { get: { summary: 'CVE detail' } },
    '/api/cves/{id}/related': { get: { summary: 'CVEs sharing a CWE or product' } },
    '/api/advisories/{id}': { get: { summary: 'OSV / GHSA advisory' } },
    '/api/pkg/{ecosystem}/{name}': { get: { summary: 'Vulnerabilities of a package', parameters: ['version'] } },
    '/api/scan': { post: { summary: 'Check a list of packages: {packages:[{ecosystem,name,version}]} (max 3000)' } },
    '/api/products': { get: { summary: 'Vendor / product suggestions', parameters: ['q'] } },
    '/api/vendors/{vendor}': { get: { summary: 'Products of a vendor' } },
    '/api/vendors/{vendor}/{product}': { get: { summary: 'CVEs of a product', parameters: ['page', 'sort'] } },
    '/api/cwe/{id}/cves': { get: { summary: 'CVEs of a CWE', parameters: ['page'] } },
    '/api/stats': { get: { summary: 'Dashboard statistics' } },
    '/badge/{id}.svg': { get: { summary: 'Severity badge (CVE or advisory)' } },
    '/badge/pkg/{ecosystem}/{name}.svg': { get: { summary: 'Vulnerability count badge for a package' } },
    '/embed/{id}': { get: { summary: 'Embeddable card (iframe)', parameters: ['theme=dark|light'] } },
    '/{lang}/{id}.json': { get: { summary: 'JSON form of a CVE or advisory page' } },
    '/{lang}/{id}.md': { get: { summary: 'Markdown form of a CVE or advisory page' } },
  },
}

export function extraRoutes(app: express.Express, deps: { wrap: (fn: (req: express.Request, res: express.Response) => Promise<unknown>) => express.RequestHandler; getCve: (id: string, gone?: () => boolean) => Promise<any> }) {
  const { wrap, getCve } = deps
  app.set('trust proxy', 1)
  app.use('/api', (req, res, next) => {
    if (req.method === 'GET') res.set('access-control-allow-origin', '*')
    next()
  })

  // ---- stats ----
  let statsCache: { t: number; v: unknown } | null = null
  app.get('/api/stats', wrap(async (_req, res) => {
    if (!statsCache || Date.now() - statsCache.t > HOUR) {
      const q = async (sql: string) => (await pool.query<any[]>(sql))[0]
      const [[tot], sev, months, kev, cwes, vendors] = await Promise.all([
        q(`SELECT COUNT(*) AS total, ROUND(AVG(score),2) AS avg, SUM(kev) AS kev FROM cves`),
        q(`SELECT severity, COUNT(*) AS n FROM cves WHERE severity IS NOT NULL GROUP BY severity`),
        q(`SELECT DATE_FORMAT(published,'%Y-%m') AS m, COUNT(*) AS n FROM cves WHERE published >= DATE_SUB(UTC_DATE(), INTERVAL 24 MONTH) GROUP BY m ORDER BY m`),
        q(`SELECT DATE_FORMAT(added,'%Y-%m') AS m, COUNT(*) AS n FROM kev WHERE added >= DATE_SUB(UTC_DATE(), INTERVAL 24 MONTH) GROUP BY m ORDER BY m`),
        q(`SELECT w.cwe, COUNT(*) AS n FROM cve_cwe w JOIN cves c ON c.id = w.cve_id WHERE c.published >= DATE_SUB(UTC_DATE(), INTERVAL 365 DAY) AND w.cwe NOT LIKE 'NVD-CWE-%' GROUP BY w.cwe ORDER BY n DESC LIMIT 10`),
        q(`SELECT p.vendor, COUNT(DISTINCT p.cve_id) AS n FROM cve_product p JOIN cves c ON c.id = p.cve_id WHERE c.published >= DATE_SUB(UTC_DATE(), INTERVAL 365 DAY) GROUP BY p.vendor ORDER BY n DESC LIMIT 10`),
      ] as const).then((r) => [r[0] as any[], r[1], r[2], r[3], r[4], r[5]] as const)
      statsCache = {
        t: Date.now(),
        v: {
          total: Number(tot.total), kev: Number(tot.kev ?? 0), avgScore: tot.avg == null ? null : Number(tot.avg),
          severity: sev.map((r: any) => ({ severity: r.severity, count: Number(r.n) })),
          monthly: months.map((r: any) => ({ month: r.m, count: Number(r.n) })),
          kevMonthly: kev.map((r: any) => ({ month: r.m, count: Number(r.n) })),
          topCwes: cwes.map((r: any) => ({ cwe: r.cwe, count: Number(r.n) })),
          topVendors: vendors.map((r: any) => ({ vendor: r.vendor, count: Number(r.n) })),
        },
      }
    }
    res.set('cache-control', 'public, max-age=600').json(statsCache.v)
  }))

  // ---- products / vendors ----
  app.get('/api/products', wrap(async (req, res) => {
    const q = String(req.query.q ?? '').trim().toLowerCase().slice(0, 60)
    if (q.length < 2) return res.json({ items: [] })
    const like = `${q.replace(/[%_\\]/g, '\\$&')}%`
    const [rows] = await pool.query<any[]>(
      `SELECT vendor, product, COUNT(*) AS n FROM cve_product WHERE product LIKE ? OR vendor LIKE ? GROUP BY vendor, product ORDER BY n DESC LIMIT 12`, [like, like])
    res.set('cache-control', 'public, max-age=300').json({ items: rows.map((r) => ({ vendor: r.vendor, product: r.product, count: Number(r.n) })) })
  }))

  app.get('/api/vendors/:vendor', wrap(async (req, res) => {
    const vendor = String(req.params.vendor).toLowerCase().slice(0, 128)
    const [rows] = await pool.query<any[]>(
      `SELECT product, COUNT(*) AS n FROM cve_product WHERE vendor = ? GROUP BY product ORDER BY n DESC LIMIT 100`, [vendor])
    if (!rows.length) return res.status(404).json({ error: 'not_found' })
    res.json({ vendor, products: rows.map((r) => ({ product: r.product, count: Number(r.n) })) })
  }))

  app.get('/api/vendors/:vendor/:product', wrap(async (req, res) => {
    const vendor = String(req.params.vendor).toLowerCase().slice(0, 128)
    const product = String(req.params.product).toLowerCase().slice(0, 160)
    const page = Math.max(1, Number(req.query.page) || 1)
    const order = req.query.sort === 'score' ? 'c.score DESC, c.published DESC' : req.query.sort === 'epss' ? 'e.score DESC' : 'c.published DESC'
    const from = `FROM cve_product p JOIN cves c ON c.id = p.cve_id LEFT JOIN kev k ON k.cve_id = c.id LEFT JOIN epss e ON e.cve_id = c.id WHERE p.vendor = ? AND p.product = ?`
    const [[tot], [sev], [rows]] = await Promise.all([
      pool.query<any[]>(`SELECT COUNT(*) AS n ${from}`, [vendor, product]),
      pool.query<any[]>(`SELECT c.severity, COUNT(*) AS n ${from} GROUP BY c.severity`, [vendor, product]),
      pool.query<any[]>(`SELECT c.*, k.cve_id AS kev_added, e.score AS epss_score ${from} ORDER BY ${order} LIMIT ? OFFSET ?`, [vendor, product, PER, (page - 1) * PER]),
    ])
    const total = Number(tot[0].n)
    if (!total) return res.status(404).json({ error: 'not_found' })
    res.json({
      vendor, product, total, page, perPage: PER,
      severity: Object.fromEntries(sev.map((r: any) => [r.severity ?? 'NONE', Number(r.n)])),
      items: rows.map(rowToCve),
    })
  }))

  // ---- CWE -> CVEs ----
  app.get('/api/cwe/:id/cves', wrap(async (req, res) => {
    const id = String(req.params.id)
    const cwe = /^\d+$/.test(id) ? `CWE-${id}` : id.toUpperCase()
    if (!/^CWE-\d{1,5}$/.test(cwe)) return res.status(400).json({ error: 'bad_id' })
    const page = Math.max(1, Number(req.query.page) || 1)
    const [[tot], [rows]] = await Promise.all([
      pool.query<any[]>(`SELECT COUNT(*) AS n FROM cve_cwe WHERE cwe = ?`, [cwe]),
      pool.query<any[]>(`${SELECT} JOIN cve_cwe w ON w.cve_id = c.id WHERE w.cwe = ? ORDER BY c.published DESC LIMIT ? OFFSET ?`, [cwe, PER, (page - 1) * PER]),
    ])
    res.json({ cwe, total: Number(tot[0].n), page, perPage: PER, items: rows.map(rowToCve) })
  }))

  // ---- related CVEs ----
  app.get('/api/cves/:id/related', wrap(async (req, res) => {
    const id = String(req.params.id).toUpperCase()
    if (!CVE_RE.test(id)) return res.status(400).json({ error: 'bad_id' })
    const [sameCwe, sameProduct] = await Promise.all([
      pool.query<any[]>(
        `${SELECT} WHERE c.id <> ? AND c.id IN (SELECT w2.cve_id FROM cve_cwe w2 JOIN cve_cwe w1 ON w1.cwe = w2.cwe WHERE w1.cve_id = ? AND w1.cwe NOT LIKE 'NVD-CWE-%')
         ORDER BY (e.score IS NULL), e.score DESC, c.published DESC LIMIT 6`, [id, id]).then(([r]) => r),
      pool.query<any[]>(
        `${SELECT} WHERE c.id <> ? AND c.id IN (SELECT p2.cve_id FROM cve_product p2 JOIN cve_product p1 ON p1.vendor = p2.vendor AND p1.product = p2.product WHERE p1.cve_id = ?)
         ORDER BY c.published DESC LIMIT 6`, [id, id]).then(([r]) => r),
    ])
    res.set('cache-control', 'public, max-age=600').json({ sameCwe: sameCwe.map(rowToCve), sameProduct: sameProduct.map(rowToCve) })
  }))

  // ---- package search ----
  app.get('/api/pkg/:eco/*name', limit(30), wrap(async (req, res) => {
    const ecosystem = ecoName(String(req.params.eco))
    const name = (req.params.name as unknown as string[]).join('/').slice(0, 214)
    const version = String(req.query.version ?? '').trim().slice(0, 64) || undefined
    if (!ecosystem) return res.status(400).json({ error: 'bad_ecosystem', ecosystems: Object.keys(ECO) })
    if (!name) return res.status(400).json({ error: 'bad_name' })
    const items = await pkgVulns(ecosystem, name, version)
    if (!items) return res.status(502).json({ error: 'upstream_error' })
    res.set('cache-control', 'public, max-age=900').json({ ecosystem, name, version: version ?? null, total: items.length, items })
  }))

  // ---- SBOM / lockfile scan ----
  app.post('/api/scan', limit(10), express.json({ limit: '1mb' }), wrap(async (req, res) => {
    const input: any[] = Array.isArray(req.body?.packages) ? req.body.packages : []
    const pkgs = input.slice(0, 3000).map((p) => ({
      ecosystem: ecoName(String(p?.ecosystem ?? '')) ?? '', name: String(p?.name ?? '').slice(0, 214), version: String(p?.version ?? '').slice(0, 64),
    })).filter((p) => p.ecosystem && p.name && p.version)
    if (!pkgs.length) return res.status(400).json({ error: 'no_packages' })
    const uniq = [...new Map(pkgs.map((p) => [`${p.ecosystem}|${p.name}|${p.version}`, p])).values()]

    const hitIds: string[][] = []
    for (let i = 0; i < uniq.length; i += 500) {
      const chunk = uniq.slice(i, i + 500)
      const r = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'vulns.lapius7.com' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })) }),
        signal: AbortSignal.timeout(25000),
      })
      if (!r.ok) return res.status(502).json({ error: 'upstream_error' })
      const d: any = await r.json()
      chunk.forEach((_, k) => hitIds.push((d.results?.[k]?.vulns ?? []).map((v: any) => v.id)))
    }
    const vulnIds = [...new Set(hitIds.flat())]
    const capped = vulnIds.slice(0, 400)
    const briefs = await pool8(capped, 8, osvBrief)
    const vulns: Record<string, Brief | null> = {}
    capped.forEach((id, k) => { vulns[id] = briefs[k] })
    const packages = uniq.map((p, k) => ({ ...p, vulns: hitIds[k] })).filter((p) => p.vulns.length)
    const bySev: Record<string, number> = {}
    for (const id of capped) { const s = vulns[id]?.severity ?? 'UNKNOWN'; bySev[s] = (bySev[s] ?? 0) + 1 }
    res.json({
      summary: { scanned: uniq.length, vulnerablePackages: packages.length, vulnerabilities: vulnIds.length, severity: bySev, truncated: vulnIds.length > capped.length },
      packages, vulns,
    })
  }))

  // ---- badges ----
  const svg = (res: express.Response, body: string) => res.type('image/svg+xml').set('cache-control', 'public, max-age=3600').send(body)
  app.get('/badge/pkg/:eco/*name', limit(30), wrap(async (req, res) => {
    const ecosystem = ecoName(String(req.params.eco))
    let name = (req.params.name as unknown as string[]).join('/')
    name = name.replace(/\.svg$/, '').slice(0, 214)
    if (!ecosystem || !name) return svg(res, badge('vulnerabilities', 'unknown', COLORS.UNKNOWN))
    const items = await pkgVulns(ecosystem, name, String(req.query.version ?? '') || undefined)
    if (!items) return svg(res, badge('vulnerabilities', 'unknown', COLORS.UNKNOWN))
    const open = items.filter((b) => !b.withdrawn)
    const top = open.map((b) => b.severity).sort((a, b) => sevRank(a) - sevRank(b))[0]
    svg(res, badge('vulnerabilities', String(open.length), open.length ? COLORS[top ?? 'UNKNOWN'] : COLORS.NONE))
  }))
  app.get('/badge/:file', wrap(async (req, res) => {
    const raw = String(req.params.file).replace(/\.svg$/, '')
    const id = CVE_RE.test(raw) ? raw.toUpperCase() : normAdvId(raw)
    if (CVE_RE.test(id)) {
      const c = await getCve(id)
      if (!c) return svg(res, badge(id, 'not found', COLORS.UNKNOWN))
      return svg(res, badge(id, c.severity ? `${c.severity}${c.score != null ? ` ${c.score}` : ''}` : 'unrated', COLORS[c.severity ?? 'UNKNOWN']))
    }
    if (ADV_RE.test(id)) {
      try { const a: any = await advisory(id); return svg(res, badge(id, a.severity ?? 'advisory', COLORS[String(a.severity).toUpperCase()] ?? COLORS.UNKNOWN)) } catch { /* fallthrough */ }
    }
    svg(res, badge('advisory', 'not found', COLORS.UNKNOWN))
  }))

  // ---- embed card ----
  app.get('/embed/:id', wrap(async (req, res) => {
    const rid = String(req.params.id)
    const id = CVE_RE.test(rid) ? rid.toUpperCase() : normAdvId(rid)
    const dark = req.query.theme === 'dark'
    const site = process.env.SITE_URL ?? 'https://vulns.lapius7.com'
    let title = id, sev: string | null = null, desc = '', score: number | null = null
    if (CVE_RE.test(id)) {
      const c = await getCve(id)
      if (c) { sev = c.severity; desc = c.description; score = c.score }
    } else if (ADV_RE.test(id)) {
      try { const a: any = await advisory(id); title = a.summary || id; desc = a.details ?? ''; sev = sevOf(a.severity) } catch { /* empty card */ }
    } else return res.status(400).type('text').send('bad id')
    const color = COLORS[sev ?? 'UNKNOWN']
    res.set('cache-control', 'public, max-age=1800').removeHeader('x-frame-options')
    res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(id)}</title>
<style>:root{color-scheme:${dark ? 'dark' : 'light'};--bg:${dark ? '#121212' : '#fff'};--fg:${dark ? '#ededed' : '#171717'};--mut:${dark ? '#a3a3a3' : '#525252'};--bd:${dark ? '#2a2a2a' : '#e5e5e5'}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
a{color:inherit;text-decoration:none;display:block;padding:14px 16px;border:1px solid var(--bd);border-radius:10px}
.h{display:flex;gap:8px;align-items:center;flex-wrap:wrap}b{font-weight:600}.s{background:${color};color:#fff;border-radius:6px;padding:1px 8px;font-size:12px}
p{margin:8px 0 0;color:var(--mut);display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}small{display:block;margin-top:8px;color:var(--mut)}</style>
<a href="${site}/en/${esc(id)}" target="_blank" rel="noopener"><div class="h"><b>${esc(id)}</b>${sev ? `<span class="s">${esc(sev)}${score != null ? ` ${score}` : ''}</span>` : ''}</div>${title !== id ? `<div>${esc(title)}</div>` : ''}<p>${esc(desc.slice(0, 400))}</p><small>Vulnerability.DB</small></a></html>`)
  }))

  // ---- format switch: /{lang}/ID.json|md ----
  app.get(/^\/(?:(?:ja|en)\/)?([A-Za-z]+-[A-Za-z0-9-]{4,40})\.(json|md)$/, wrap(async (req, res) => {
    const rid = String(req.params[0])
    const id = CVE_RE.test(rid) ? rid.toUpperCase() : normAdvId(rid)
    const fmt = req.params[1]
    let data: any
    if (CVE_RE.test(id)) data = await getCve(id)
    else if (ADV_RE.test(id)) data = await advisory(id).catch(() => null)
    if (!data) return res.status(404).type('text').send('not found')
    res.set('cache-control', 'public, max-age=600')
    if (fmt === 'json') return res.json(data)
    res.type('text/markdown').send(CVE_RE.test(id) ? cveMd(data) : advMd(data))
  }))

  app.get('/api/openapi.json', (_req, res) => res.set('cache-control', 'public, max-age=3600').json(OPENAPI))
}
