import express from 'express'
import path from 'node:path'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { getState, migrate, pool, rowToCve, upsertCves } from './db.ts'
import { normalize, nvdRaw, type Json } from './nvd.ts'
import { ADV_RE, advisory, translateAdvisory, cached, cveOrg, cweName, epssSeries, ghsa, jvn, normAdvId, osv, storedJa, translateJa } from './sources.ts'
import { startScheduler } from './sync.ts'
import { extraRoutes } from './extra.ts'
import { renderOg } from './og.ts'

const PORT = Number(process.env.PORT ?? 3100)
const PER_PAGE = 20
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i
const ADV_PATH = /^\/(?:ja|en)\/([A-Za-z]+-[A-Za-z0-9-]{4,40})\/?$/
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

app.get('/api/advisories/:id', wrap(async (req, res) => {
  if (!ADV_RE.test(req.params.id) || req.params.id.length > 24) return res.status(400).json({ error: 'invalid_id' })
  const id = normAdvId(req.params.id)
  const repo = typeof req.query.repo === 'string' ? req.query.repo : undefined
  const a = await cached(id, 'advisory', 6 * 3600_000, () => advisory(id, repo))
  if (!a) return res.status(404).json({ error: 'not_found' })
  res.json(a)
}))

app.get('/api/advisories/:id/translate', wrap(async (req, res) => {
  if (!ADV_RE.test(req.params.id) || req.params.id.length > 24) return res.status(400).json({ error: 'invalid_id' })
  const id = normAdvId(req.params.id)
  const repo = typeof req.query.repo === 'string' ? req.query.repo : undefined
  const a = await cached(id, 'advisory', 6 * 3600_000, () => advisory(id, repo))
  if (!a) return res.status(404).json({ error: 'not_found' })
  const tr = await cached(id, 'adv_ja', 365 * DAY, () => translateAdvisory(a.summary.slice(0, 400), a.details.slice(0, 6000)))
  if (!tr) return res.status(502).json({ error: 'upstream_error' })
  res.json(tr)
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
const SITE = process.env.SITE_URL ?? 'https://vulns.lapius7.com'
const esc = (t: string) => t.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const SEV_JA: Record<string, string> = { CRITICAL: '緊急', HIGH: '重要', MEDIUM: '警告', LOW: '注意' }

// jaText: Japanese description already stored (JVN or machine translation); used for /ja/ pages only.
function metaFor(c: { id: string; severity: string | null; score: number | null; description: string }, ja: boolean, jaText?: { text?: string; title?: string } | null) {
  const sev = c.severity ? ` (${ja ? SEV_JA[c.severity] ?? c.severity : c.severity.toLowerCase()}${c.score != null ? ` ${c.score.toFixed(1)}` : ''})` : ''
  const title = `${c.id}${sev} | ${(ja && jaText?.title) || 'Vulnerability.DB'}`
  const desc = esc((ja && jaText?.text ? jaText.text : c.description).replace(/\s+/g, ' ').slice(0, ja && jaText?.text ? 120 : 200))
  const t = esc(title), url = `${SITE}/${ja ? 'ja' : 'en'}/${c.id}`
  return `<title>${t}</title>
    <meta name="description" content="${desc}" />
    <link rel="canonical" href="${url}" />
    <meta property="og:site_name" content="Vulnerability.DB" />
    <meta property="og:type" content="article" />
    <meta property="og:locale" content="${ja ? 'ja_JP' : 'en_US'}" />
    <link rel="alternate" hreflang="en" href="${SITE}/en/${c.id}" />
    <link rel="alternate" hreflang="ja" href="${SITE}/ja/${c.id}" />
    <meta property="og:title" content="${t}" />
    <meta property="og:description" content="${desc}" />
    <meta property="og:url" content="${url}" />
    <meta property="og:image" content="${SITE}/og/${ja ? 'ja' : 'en'}/${c.id}.png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${t}" />
    <meta name="twitter:description" content="${desc}" />
    <meta name="twitter:image" content="${SITE}/og/${ja ? 'ja' : 'en'}/${c.id}.png" />`
}

const PAGES: Record<string, { en: [string, string]; ja: [string, string] }> = {
  scan: { en: ['Check dependencies', 'Drop a lockfile or SBOM to list known vulnerabilities in your dependencies. Parsed in your browser.'], ja: ['依存関係の診断', 'ロックファイルや SBOM をドロップすると、依存パッケージの既知の脆弱性を一覧にします。解析はブラウザ内で行います。'] },
  stats: { en: ['Statistics', 'Totals, severity, monthly counts, top CWEs and vendors.'], ja: ['統計', '総数、深刻度別、月ごとの件数、多い CWE とベンダー。'] },
  docs: { en: ['Docs', 'Search formats, URL formats, the public API, badges and embeds.'], ja: ['ドキュメント', '検索の書き方、URL の形式、公開 API、バッジと埋め込み。'] },
  pkg: { en: ['Package search', 'Find known vulnerabilities by package name and version for npm, PyPI, Go, Maven and more.'], ja: ['パッケージ検索', 'npm、PyPI、Go、Maven などのパッケージ名とバージョンから既知の脆弱性を検索します。'] },
}
// Title/OGP for non-CVE pages (package, vendor, CWE, scan, stats, docs).
function pageInfo(rest: string, ja: boolean): { title: string; desc: string } | null {
  const dec = (x: string) => { try { return decodeURIComponent(x) } catch { return x } }
  let title = '', desc = ''
  let m: RegExpMatchArray | null
  const L = ja ? 'ja' : 'en'
  if ((m = rest.match(/^\/(scan|stats|docs)\/?$/))) [title, desc] = PAGES[m[1]][L]
  else if ((m = rest.match(/^\/pkg(?:\/([^/]+)(?:\/(.+?))?)?\/?$/))) {
    if (m[1] && m[2]) { const n = dec(m[2]); title = ja ? `${n} (${m[1]}) の脆弱性` : `${n} (${m[1]}) vulnerabilities`; desc = ja ? `${m[1]} の ${n} に関する既知の脆弱性とその修正バージョン。` : `Known vulnerabilities and fixed versions of ${n} on ${m[1]}.` }
    else [title, desc] = PAGES.pkg[L]
  } else if ((m = rest.match(/^\/vendor\/([^/]+)(?:\/([^/]+))?\/?$/))) {
    const n = m[2] ? `${dec(m[1])} / ${dec(m[2])}` : dec(m[1])
    title = ja ? `${n} の脆弱性` : `${n} vulnerabilities`; desc = ja ? `${n} に関する CVE の一覧。` : `CVEs affecting ${n}.`
  } else if ((m = rest.match(/^\/cwe\/(\d{1,5})\/?$/i))) {
    title = `CWE-${m[1]}`; desc = ja ? `CWE-${m[1]} に分類された CVE の一覧。` : `CVEs classified as CWE-${m[1]}.`
  } else return null
  return { title, desc }
}
function pageMeta(rest: string, ja: boolean): string | null {
  const info = pageInfo(rest, ja)
  if (!info) return null
  const { title, desc } = info, L = ja ? 'ja' : 'en'
  const img = `${SITE}/og/${L}${rest.replace(/\/$/, '')}.png`
  const t = esc(`${title} | Vulnerability.DB`), d = esc(desc), url = esc(`${SITE}/${L}${rest.replace(/\/$/, '')}`)
  return `<title>${t}</title>
    <meta name="description" content="${d}" />
    <link rel="canonical" href="${url}" />
    <meta property="og:site_name" content="Vulnerability.DB" />
    <meta property="og:type" content="website" />
    <meta property="og:locale" content="${ja ? 'ja_JP' : 'en_US'}" />
    <meta property="og:title" content="${t}" />
    <meta property="og:description" content="${d}" />
    <meta property="og:url" content="${url}" />
    <meta property="og:image" content="${img}" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${t}" />
    <meta name="twitter:description" content="${d}" />
    <meta name="twitter:image" content="${img}" />`
}

// Per-page OGP images, drawn from the same text as the page meta. Only known page shapes are rendered.
app.get(/^\/og\/(ja|en)(\/.+)\.png$/, wrap(async (req, res) => {
  const ja = req.params[0] === 'ja', rest = req.params[1] as string
  let key = `${req.params[0]}${rest}`, input: { title: string; desc?: string; severity?: string | null; score?: number | null } | null = null
  const idm = rest.match(/^\/([A-Za-z]+-[A-Za-z0-9-]{4,40})$/)
  if (idm && CVE_RE.test(idm[1])) {
    const c = await getCve(idm[1].toUpperCase())
    if (c) { const j = ja ? await storedJa(c.id).catch(() => null) : null; input = { title: c.id, desc: (ja && j?.text) || c.description, severity: c.severity, score: c.score }; key = `${req.params[0]}/${c.id}:${c.modified}` }
  } else if (idm && ADV_RE.test(idm[1])) {
    const id = normAdvId(idm[1])
    const a = await cached(id, 'advisory', 6 * 3600_000, () => advisory(id)).catch(() => null)
    if (a) input = { title: a.id, desc: a.summary || a.details, severity: a.severity }
  } else {
    const i = pageInfo(rest, ja)
    if (i) input = i
  }
  if (!input) return res.status(404).type('text/plain').send('not found')
  res.set('Cache-Control', 'public, max-age=86400').type('png').send(renderOg(key, input))
}))

extraRoutes(app, { wrap, getCve })
app.use(express.static(dist, { index: false }))
app.get(/^\/(?!api\/).*/, async (req, res) => {
  // Short GHSA URL: /ja/GHSA2464fhr4w9xw?vercel/next.js -> /ja/GHSA-2464-fhr4-w9xw?repo=vercel/next.js
  const gm = req.path.match(/^\/(?:(ja|en)\/)?GHSA([a-z0-9]{4})([a-z0-9]{4})([a-z0-9]{4})\/?$/i)
  if (gm) {
    const lang = gm[1] ?? ((req.headers['accept-language'] ?? '').toString().toLowerCase().startsWith('ja') ? 'ja' : 'en')
    const raw = decodeURIComponent(req.url.slice(req.path.length).replace(/^\?(repo=)?/, ''))
    const repo = /^[\w.-]{1,39}\/[\w.-]{1,100}$/.test(raw) ? `?repo=${raw}` : ''
    return res.redirect(301, `/${lang}/GHSA-${gm.slice(2, 5).join('-').toLowerCase()}${repo}`)
  }
  // Legacy /ja/vulns/ID -> /ja/ID
  const lm = req.path.match(/^\/(ja|en)\/vulns\/([^/]+)\/?$/)
  if (lm) return res.redirect(301, `/${lm[1]}/${lm[2]}${req.url.slice(req.path.length)}`)
  // Bare / non-normalised ID: /PYSEC-2021-123, /ja/cve-2026-1 -> /ja/PYSEC-2021-123
  const dm = req.path.match(/^\/(?:(ja|en)\/)?([A-Za-z]+-[A-Za-z0-9-]{4,40})\/?$/)
  if (dm && (ADV_RE.test(dm[2]) || CVE_RE.test(dm[2]))) {
    const lang = dm[1] ?? ((req.headers['accept-language'] ?? '').toString().toLowerCase().startsWith('ja') ? 'ja' : 'en')
    const raw = decodeURIComponent(req.url.slice(req.path.length).replace(/^\?(repo=)?/, ''))
    const repo = /^[\w.-]{1,39}\/[\w.-]{1,100}$/.test(raw) ? `?repo=${raw}` : ''
    const canon = CVE_RE.test(dm[2]) ? dm[2].toUpperCase() : normAdvId(dm[2])
    if (!dm[1] || canon !== dm[2]) return res.redirect(301, `/${lang}/${canon}${repo}`)
  }
  // Short URL: /2026102322 or /ja/2026102322 -> /ja/CVE-2026-102322 (4-digit year + 4+ digit sequence).
  const sm = req.path.match(/^\/(?:(ja|en)\/)?(\d{4})(\d{4,})\/?$/)
  if (sm) {
    const lang = sm[1] ?? ((req.headers['accept-language'] ?? '').toString().toLowerCase().startsWith('ja') ? 'ja' : 'en')
    return res.redirect(301, `/${lang}/CVE-${sm[2]}-${sm[3]}`)
  }
  if (!/^\/(ja|en)(\/|$)/.test(req.path)) {
    const lang = (req.headers['accept-language'] ?? '').toString().toLowerCase().startsWith('ja') ? 'ja' : 'en'
    const q = req.url.slice(req.path.length)
    return res.redirect(302, `/${lang}${req.path === '/' ? '' : req.path}${q}`)
  }
  let html = await readFile(path.join(dist, 'index.html'), 'utf8').catch(() => null)
  if (!html) return res.status(404).send('Not built')
  if (/^\/ja(\/|$)/.test(req.path)) html = html.replace('<html lang="en"', '<html lang="ja"')
  const pm = pageMeta(req.path.replace(/^\/(ja|en)/, ''), /^\/ja(\/|$)/.test(req.path))
  if (pm) html = html.replace(/<title>[\s\S]*?<\/title>[\s\S]*?<!--\/meta-->/, pm + '\n    <!--/meta-->')
  const m = req.path.match(/^\/(?:ja|en)\/(CVE-\d{4}-\d{4,})\/?$/i)
  const am = req.path.match(ADV_PATH)
  if (am && ADV_RE.test(am[1]) && !CVE_RE.test(am[1])) {
    const id = normAdvId(am[1])
    const isJa = /^\/ja(\/|$)/.test(req.path)
    try {
      const a = await cached(id, 'advisory', 6 * 3600_000, () => advisory(id))
      if (a) html = html.replace(/<title>[\s\S]*?<\/title>[\s\S]*?<!--\/meta-->/, metaFor({ id: a.id, severity: a.severity, score: null, description: a.summary || a.details }, isJa, null) + '\n <!--/meta-->')
    } catch {}
  }
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
