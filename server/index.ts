import express from 'express'
import path from 'node:path'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { getState, migrate, pool, rowToCve, upsertCves } from './db.ts'
import { normalize, nvdRaw, type Json } from './nvd.ts'
import { cached, cveOrg, cweName, epssSeries, ghsa, jvn, osv, storedJa, translateJa } from './sources.ts'
import { startScheduler } from './sync.ts'

const PORT = Number(process.env.PORT ?? 3100)
const PER_PAGE = 20
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i
const DAY = 86400_000

const app = express()
app.disable('x-powered-by')
await migrate()

const goneFn = (res: express.Response) => { let g = false; res.on('close', () => { if (!res.writableEnded) g = true }); return () => g }
const wrap = (fn: (req: express.Request, res: express.Response) => Promise<unknown>): express.RequestHandler =>
  (req, res) => fn(req, res).catch((e) => {
    if (!res.headersSent) res.status(e.status === 403 || e.status === 429 ? 429 : 502).json({ error: e.status === 429 ? 'rate_limited' : 'upstream_error' })
  })

const SELECT = `SELECT c.*, k.cve_id AS kev_added, e.score AS epss_score FROM cves c
  LEFT JOIN kev k ON k.cve_id = c.id LEFT JOIN epss e ON e.cve_id = c.id`

async function ready() {
  return (await getState('full_done')) === '1'
}

// ---- NVD live fallback (used until the first full sync completes) ----
async function nvdSearch(q: string, sev: string, page: number, year: string, gone: () => boolean) {
  const p = new URLSearchParams({ resultsPerPage: String(PER_PAGE), startIndex: String((page - 1) * PER_PAGE) })
  if (CVE_RE.test(q)) p.set('cveId', q.toUpperCase())
  else if (q) p.set('keywordSearch', q)
  if (SEVERITIES.includes(sev)) p.set('cvssV3Severity', sev)
  if (/^\d{4}$/.test(year)) { p.set('pubStartDate', `${year}-01-01T00:00:00.000`); p.set('pubEndDate', `${year}-12-31T23:59:59.999`) }
  if (!q && !p.has('pubStartDate')) {
    const end = new Date()
    p.set('pubStartDate', new Date(end.getTime() - 30 * DAY).toISOString().replace('Z', ''))
    p.set('pubEndDate', end.toISOString().replace('Z', ''))
  }
  const raw = await nvdRaw(p, gone)
  return { total: raw.totalResults as number, page, perPage: PER_PAGE, items: ((raw.vulnerabilities ?? []) as Json[]).map((v) => normalize(v.cve)), live: true }
}

async function getCve(id: string, gone?: () => boolean) {
  const [rows] = await pool.query<any[]>(`${SELECT} WHERE c.id = ?`, [id])
  if (rows[0]) return rowToCve(rows[0])
  const raw = await nvdRaw(new URLSearchParams({ cveId: id }), gone)
  const c = raw.vulnerabilities?.[0]?.cve
  if (!c) return null
  const n = normalize(c)
  await upsertCves([n])
  return { ...n, epss: null as number | null }
}

// ---- Search ----
app.get('/api/cves', wrap(async (req, res) => {
  const q = String(req.query.q ?? '').trim().slice(0, 200)
  const sev = String(req.query.severity ?? '').toUpperCase()
  const page = Math.max(1, Number(req.query.page) || 1)
  const year = String(req.query.year ?? '')
  const sort = String(req.query.sort ?? '')
  const kevOnly = req.query.kev === '1'

  if (!(await ready())) return res.json(await nvdSearch(q, sev, page, year, goneFn(res)))

  const where: string[] = []
  const args: unknown[] = []
  let orderBy = 'c.published DESC'
  const orderArgs: unknown[] = []
  if (CVE_RE.test(q)) { where.push('c.id = ?'); args.push(q.toUpperCase()) }
  else if (/^CVE-[\d-]*$/i.test(q)) { where.push('c.id LIKE ?'); args.push(q.toUpperCase().replace(/[%_]/g, '') + '%') }
  else if (q) {
    const toks = q.split(/[\s/\\,;:()[\]{}"'<>+\-~*@]+/).filter(Boolean).slice(0, 8)
    if (toks.length && toks.every((t) => t.length >= 3)) {
      const m = toks.map((t) => `+${t}*`).join(' ')
      where.push('MATCH(c.id, c.description) AGAINST (? IN BOOLEAN MODE)')
      args.push(m)
      if (!sort) { orderBy = 'MATCH(c.id, c.description) AGAINST (? IN BOOLEAN MODE) DESC, c.published DESC'; orderArgs.push(m) }
    } else {
      for (const t of toks.length ? toks : [q]) { where.push('c.description LIKE ?'); args.push(`%${t.replace(/[%_\\]/g, '\\$&')}%`) }
    }
  }
  if (SEVERITIES.includes(sev)) { where.push('c.severity = ?'); args.push(sev) }
  if (/^\d{4}$/.test(year)) { where.push('c.published >= ? AND c.published < ?'); args.push(`${year}-01-01`, `${Number(year) + 1}-01-01`) }
  if (kevOnly) where.push('k.cve_id IS NOT NULL')
  if (sort === 'score') orderBy = 'c.score DESC, c.published DESC'
  else if (sort === 'epss') orderBy = 'e.score DESC, c.published DESC'
  else if (sort === 'modified') orderBy = 'c.modified DESC'
  else if (sort === 'new') orderBy = 'c.published DESC'
  const W = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const needJoin = kevOnly || sort === 'epss'
  const [cnt] = await pool.query<any[]>(
    `SELECT COUNT(*) AS n FROM cves c ${needJoin ? 'LEFT JOIN kev k ON k.cve_id = c.id LEFT JOIN epss e ON e.cve_id = c.id' : ''} ${W}`, args)
  const [rows] = await pool.query<any[]>(`${SELECT} ${W} ORDER BY ${orderBy} LIMIT ? OFFSET ?`,
    [...args, ...orderArgs, PER_PAGE, (page - 1) * PER_PAGE])
  res.json({ total: Number(cnt[0].n), page, perPage: PER_PAGE, items: rows.map(rowToCve) })
}))

app.get('/api/status', wrap(async (_req, res) => {
  const [r] = await pool.query<any[]>('SELECT COUNT(*) AS n FROM cves')
  res.json({ count: Number(r[0].n), fullDone: await ready(), lastSync: await getState('last_sync') })
}))

app.get('/api/cves/:id', wrap(async (req, res) => {
  if (!CVE_RE.test(req.params.id)) return res.status(400).json({ error: 'invalid_id' })
  const c = await getCve(req.params.id.toUpperCase(), goneFn(res))
  if (!c) return res.status(404).json({ error: 'not_found' })
  res.json(c)
}))

const TTL = (published: string, base: number) => (Date.now() - new Date(published).getTime() > 365 * DAY ? 30 * DAY : base)

app.get('/api/cves/:id/extra', wrap(async (req, res) => {
  if (!CVE_RE.test(req.params.id)) return res.status(400).json({ error: 'invalid_id' })
  const id = req.params.id.toUpperCase()
  const c = await getCve(id, goneFn(res))
  const pub = c?.published ?? new Date().toISOString()
  const [kr] = await pool.query<any[]>('SELECT * FROM kev WHERE cve_id = ?', [id])
  const [er] = await pool.query<any[]>('SELECT score, percentile FROM epss WHERE cve_id = ?', [id])
  const [series, co, os, gh, jv] = await Promise.all([
    cached(id, 'epss_series', DAY, () => epssSeries(id)),
    cached(id, 'cveorg', TTL(pub, DAY), () => cveOrg(id)),
    cached(id, 'osv', TTL(pub, DAY), () => osv(id)),
    cached(id, 'ghsa', TTL(pub, 6 * 3600_000), () => ghsa(id)),
    cached(id, 'jvn', TTL(pub, DAY), () => jvn(id)),
  ])
  const k = kr[0]
  const epss = er[0] ? { score: Number(er[0].score), percentile: Number(er[0].percentile), date: (series ?? []).at(-1)?.date ?? '', series: series ?? [] } : null
  res.set('Cache-Control', 'public, max-age=300').json({
    epss,
    kev: k ? { vendor: k.vendor, product: k.product, name: k.name, description: k.description, action: k.action, added: k.added, due: k.due, ransomware: k.ransomware === 'Known' || k.ransomware === 1 } : null,
    cveorg: co, osv: os, ghsa: gh ?? [], jvn: jv,
  })
}))

app.get('/api/cwe/:id', wrap(async (req, res) => {
  const id = req.params.id.replace(/\D/g, '')
  if (!id) return res.status(400).json({ error: 'invalid_id' })
  res.set('Cache-Control', 'public, max-age=86400').json({ name: (await cached(`CWE-${id}`, 'cwe', 365 * DAY, () => cweName(id)))?.name ?? null })
}))

// ---- Home feeds ----
app.get('/api/feed/kev', wrap(async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1)
  const [c] = await pool.query<any[]>('SELECT COUNT(*) AS n FROM kev')
  const [rows] = await pool.query<any[]>('SELECT * FROM kev ORDER BY added DESC, cve_id DESC LIMIT ? OFFSET ?', [PER_PAGE, (page - 1) * PER_PAGE])
  res.set('Cache-Control', 'public, max-age=600').json({
    total: Number(c[0].n), page, perPage: PER_PAGE,
    items: rows.map((v) => ({ id: v.cve_id, vendor: v.vendor, product: v.product, name: v.name, description: v.description, added: String(v.added).slice(0, 10), due: String(v.due).slice(0, 10), ransomware: v.ransomware === 'Known' || v.ransomware === 1 })),
  })
}))

app.get('/api/feed/epss', wrap(async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1)
  const [rows] = await pool.query<any[]>('SELECT cve_id, score, percentile FROM epss ORDER BY score DESC LIMIT ? OFFSET ?', [PER_PAGE, (page - 1) * PER_PAGE])
  res.set('Cache-Control', 'public, max-age=600').json({
    total: 1000, page, perPage: PER_PAGE,
    items: rows.map((x) => ({ id: x.cve_id, score: Number(x.score), percentile: Number(x.percentile) })),
  })
}))

// ---- Machine translation fallback (en -> ja) ----
app.get('/api/translate/:id', wrap(async (req, res) => {
  if (!CVE_RE.test(req.params.id)) return res.status(400).json({ error: 'invalid_id' })
  const id = req.params.id.toUpperCase()
  const c = await getCve(id, goneFn(res))
  if (!c) return res.status(404).json({ error: 'not_found' })
  const text = await cached(id, 'tr_ja', 365 * DAY, () => translateJa(c.description.slice(0, 1800)))
  if (!text) return res.status(502).json({ error: 'upstream_error' })
  res.json({ text })
}))

const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist')
const SITE = process.env.SITE_URL ?? 'https://cve.lapius7.com'
const esc = (t: string) => t.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const SEV_JA: Record<string, string> = { CRITICAL: '緊急', HIGH: '重要', MEDIUM: '警告', LOW: '注意' }

// jaText: Japanese description already stored (JVN or machine translation); used for /ja/ pages only.
function metaFor(c: { id: string; severity: string | null; score: number | null; description: string }, ja: boolean, jaText?: { text?: string; title?: string } | null) {
  const sev = c.severity ? ` (${ja ? SEV_JA[c.severity] ?? c.severity : c.severity.toLowerCase()} ${c.score?.toFixed(1)})` : ''
  const title = `${c.id}${sev} | ${(ja && jaText?.title) || 'Vulnerability.DB'}`
  const desc = esc((ja && jaText?.text ? jaText.text : c.description).replace(/\s+/g, ' ').slice(0, ja && jaText?.text ? 120 : 200))
  const t = esc(title), url = `${SITE}/${ja ? 'ja' : 'en'}/vulns/${c.id}`
  return `<title>${t}</title>
    <meta name="description" content="${desc}" />
    <link rel="canonical" href="${url}" />
    <meta property="og:site_name" content="Vulnerability.DB" />
    <meta property="og:type" content="article" />
    <meta property="og:locale" content="${ja ? 'ja_JP' : 'en_US'}" />
    <link rel="alternate" hreflang="en" href="${SITE}/en/vulns/${c.id}" />
    <link rel="alternate" hreflang="ja" href="${SITE}/ja/vulns/${c.id}" />
    <meta property="og:title" content="${t}" />
    <meta property="og:description" content="${desc}" />
    <meta property="og:url" content="${url}" />
    <meta property="og:image" content="${SITE}/og.png?v=2" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${t}" />
    <meta name="twitter:description" content="${desc}" />
    <meta name="twitter:image" content="${SITE}/og.png?v=2" />`
}

app.use(express.static(dist, { index: false }))
app.get(/^\/(?!api\/).*/, async (req, res) => {
  // Short URL: /2026102322 or /ja/2026102322 -> /ja/vulns/CVE-2026-102322 (4-digit year + 4+ digit sequence).
  const sm = req.path.match(/^\/(?:(ja|en)\/)?(\d{4})(\d{4,})\/?$/)
  if (sm) {
    const lang = sm[1] ?? ((req.headers['accept-language'] ?? '').toString().toLowerCase().startsWith('ja') ? 'ja' : 'en')
    return res.redirect(301, `/${lang}/vulns/CVE-${sm[2]}-${sm[3]}`)
  }
  if (!/^\/(ja|en)(\/|$)/.test(req.path)) {
    const lang = (req.headers['accept-language'] ?? '').toString().toLowerCase().startsWith('ja') ? 'ja' : 'en'
    const q = req.url.slice(req.path.length)
    return res.redirect(302, `/${lang}${req.path === '/' ? '' : req.path}${q}`)
  }
  let html = await readFile(path.join(dist, 'index.html'), 'utf8').catch(() => null)
  if (!html) return res.status(404).send('Not built')
  if (/^\/ja(\/|$)/.test(req.path)) html = html.replace('<html lang="en"', '<html lang="ja"')
  const m = req.path.match(/^\/(?:ja|en)\/vulns\/(CVE-\d{4}-\d{4,})\/?$/i)
  if (m) {
    try {
      const c = await getCve(m[1].toUpperCase())
      if (c) {
        const isJa = /^\/ja(\/|$)/.test(req.path)
        const jaText = isJa ? await storedJa(c.id).catch(() => null) : null
        html = html.replace(/<title>[\s\S]*?<\/title>[\s\S]*?<!--\/meta-->/, metaFor(c, isJa, jaText) + '\n    <!--/meta-->')
      }
    } catch {}
  }
  res.type('html').send(html)
})

if (process.env.SYNC !== '0') startScheduler()
app.listen(PORT, '127.0.0.1', () => console.log(`cve api on :${PORT}`))
