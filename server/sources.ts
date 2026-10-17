import { pool } from './db.ts'
import type { Json } from './nvd.ts'

export async function j(url: string, ms = 8000, headers: Record<string, string> = {}) {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms), headers: { 'user-agent': 'vulns.lapius7.com', ...headers } })
  if (!r.ok) throw new Error(String(r.status))
  return (await r.json()) as Json
}

const tag = (x: string, t: string) => x.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`))?.[1]?.trim()
const unxml = (t?: string) =>
  t?.replace(/<!\[CDATA\[|\]\]>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&')

export async function epssSeries(id: string) {
  const d = (await j(`https://api.first.org/data/v1/epss?cve=${id}&scope=time-series`)).data?.[0]
  return ((d?.['time-series'] ?? []) as Json[]).map((x) => ({ date: x.date as string, score: Number(x.epss) })).reverse()
}

export async function cveOrg(id: string) {
  const d = await j(`https://cveawg.mitre.org/api/cve/${id}`)
  const c = d.containers?.cna ?? {}
  return {
    title: c.title as string | undefined,
    assigner: d.cveMetadata?.assignerShortName as string | undefined,
    state: d.cveMetadata?.state as string | undefined,
    reserved: d.cveMetadata?.dateReserved as string | undefined,
    affected: ((c.affected ?? []) as Json[]).map((a) => ({
      vendor: a.vendor, product: a.product, default: a.defaultStatus,
      versions: ((a.versions ?? []) as Json[]).slice(0, 12).map((v) => ({
        version: v.version, status: v.status, lessThan: v.lessThan ?? v.lessThanOrEqual, orEqual: Boolean(v.lessThanOrEqual),
      })),
    })).slice(0, 20),
    solutions: ((c.solutions ?? []) as Json[]).map((x) => x.value as string).slice(0, 5),
    workarounds: ((c.workarounds ?? []) as Json[]).map((x) => x.value as string).slice(0, 5),
    credits: ((c.credits ?? []) as Json[]).map((x) => x.value as string).slice(0, 10),
  }
}

export async function osv(id: string) {
  const d = await j(`https://api.osv.dev/v1/vulns/${id}`)
  return {
    aliases: (d.aliases ?? []) as string[],
    packages: ((d.affected ?? []) as Json[]).map((a) => ({
      ecosystem: a.package?.ecosystem, name: a.package?.name,
      fixed: [...new Set(((a.ranges ?? []) as Json[]).flatMap((r) => ((r.events ?? []) as Json[]).map((e) => e.fixed).filter(Boolean)))].slice(0, 6),
    })).slice(0, 20),
  }
}

export async function ghsa(id: string) {
  const d = (await j(`https://api.github.com/advisories?cve_id=${id}`, 8000, process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {})) as unknown as Json[]
  return d.slice(0, 5).map((a) => ({
    id: a.ghsa_id as string, url: a.html_url as string, summary: a.summary as string, severity: a.severity as string,
    published: a.published_at as string, updated: a.updated_at as string, reviewed: a.type === 'reviewed',
    vulns: ((a.vulnerabilities ?? []) as Json[]).slice(0, 12).map((v) => ({
      ecosystem: v.package?.ecosystem as string, name: v.package?.name as string,
      range: v.vulnerable_version_range as string, patched: v.first_patched_version as string | null,
    })),
  }))
}

export async function jvn(id: string) {
  const T = { signal: AbortSignal.timeout(10000) }
  const q = 'feed=hnd&lang=ja&rangeDatePublic=n&rangeDatePublished=n&rangeDateFirstPublished=n'
  const list = await (await fetch(`https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&${q}&keyword=${id}`, T)).text()
  const item = list.split('<item ').slice(1).find((it) => it.includes(`id="${id}"`))
  const jvnId = item && tag(item, 'sec:identifier')
  if (!jvnId) return null
  const x = await (await fetch(`https://jvndb.jvn.jp/myjvn?method=getVulnDetailInfo&feed=hnd&lang=ja&vulnId=${jvnId}`, T)).text()
  const impact = unxml(tag(tag(x, 'Impact') ?? '', 'Description'))
  const solution = (x.match(/<SolutionItem>[\s\S]*?<\/SolutionItem>/g) ?? []).map((v) => unxml(tag(v, 'Description'))).filter(Boolean) as string[]
  return {
    id: jvnId, url: `https://jvndb.jvn.jp/ja/contents/${jvnId.split('-')[1]}/${jvnId}.html`,
    title: unxml(tag(x, 'Title')), overview: unxml(tag(x, 'Overview')), impact, solution,
  }
}

export async function cweName(id: string) {
  const n = id.replace(/^CWE-/, '')
  const d = await j(`https://cwe-api.mitre.org/api/v1/cwe/weakness/${n}`)
  const w = d.Weaknesses?.[0]
  return w ? { id: `CWE-${n}`, name: w.Name as string, description: (w.Description as string)?.slice(0, 400) } : null
}

const LIBRE = process.env.LIBRETRANSLATE_URL ?? 'http://127.0.0.1:5000'

/** Self-hosted LibreTranslate (no quota, no key). Throws when unavailable so callers can fall back. */
async function libreJa(text: string) {
  const r = await fetch(`${LIBRE}/translate`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ q: text, source: 'en', target: 'ja', format: 'text' }), signal: AbortSignal.timeout(20000),
  })
  if (!r.ok) throw new Error('libre')
  const out = ((await r.json()) as any).translatedText as string | undefined
  if (!out) throw new Error('libre')
  return out.replace(/\.$/, '。').replace(/\s*;\s*/g, '; ')
}

async function myMemoryJa(c: string) {
  const r = await j(`https://api.mymemory.translated.net/get?langpair=en|ja${process.env.MYMEMORY_EMAIL ? `&de=${encodeURIComponent(process.env.MYMEMORY_EMAIL)}` : ''}&q=${encodeURIComponent(c)}`)
  const out = r.responseData?.translatedText as string | undefined
  // MyMemory reports quota/limit errors as a 200 with a warning text; never cache that.
  if (r.responseStatus !== 200 || !out || /MYMEMORY WARNING|QUERY LENGTH LIMIT|INVALID/i.test(out)) throw new Error('translate')
  return out
}

export async function translateJa(text: string) {
  const chunks: string[] = []
  for (const sent of text.slice(0, 1800).split(/(?<=[.!?])\s+/)) {
    const last = chunks.length - 1
    if (last >= 0 && chunks[last].length + sent.length < 450) chunks[last] += ' ' + sent
    else chunks.push(sent.slice(0, 480))
  }
  const parts = await Promise.all(chunks.map((c) => libreJa(c).catch(() => myMemoryJa(c))))
  return parts.join('')
}

/** Machine-translates English text to Japanese while keeping URLs intact (they are swapped for tokens during translation). */
export async function translateJaKeepUrls(text: string) {
  const urls: string[] = []
  const masked = text.replace(/https?:\/\/[^\s<>"')]+/g, (u) => { urls.push(u); return `URL${urls.length}` })
  let out = await translateJa(masked)
  const missing: string[] = []
  urls.forEach((u, i) => {
    const re = new RegExp(`URL\\s*${i + 1}(?!\\d)`)
    if (re.test(out)) out = out.replace(re, ` ${u} `).replace(/ {2,}/g, ' ')
    else missing.push(u)
  })
  return missing.length ? `${out} ${missing.join(' ')}` : out
}

const inflight = new Map<string, Promise<unknown>>()

/** DB-backed cache with stale-if-error. ttl in ms; null results are cached too. */
export function cached<T>(key: string, source: string, ttl: number, fn: () => Promise<T>): Promise<T | null> {
  const k = `${key}|${source}`
  const ex = inflight.get(k)
  if (ex) return ex as Promise<T | null>
  const run = (async () => {
    const [rows] = await pool.query<any[]>('SELECT data, fetched_at FROM cve_extra WHERE cve_id=? AND source=?', [key, source])
    const row = rows[0]
    const age = row ? Date.now() - new Date(String(row.fetched_at).replace(' ', 'T') + 'Z').getTime() : Infinity
    const val = row ? (typeof row.data === 'string' ? JSON.parse(row.data) : row.data) : undefined
    if (row && age < ttl) return val.v as T | null
    try {
      const v = await fn()
      await pool.query(
        'INSERT INTO cve_extra (cve_id,source,data,fetched_at) VALUES (?,?,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE data=VALUES(data), fetched_at=VALUES(fetched_at)',
        [key, source, JSON.stringify({ v })],
      )
      return v
    } catch {
      return row ? (val.v as T | null) : null
    }
  })().finally(() => inflight.delete(k))
  inflight.set(k, run)
  return run
}

/** Japanese text we already have for a CVE (JVN iPedia first, then stored machine translation). Reads the DB only, never calls an API. */
export async function storedJa(id: string): Promise<{ text?: string; title?: string } | null> {
  const [rows] = await pool.query<any[]>("SELECT source, data FROM cve_extra WHERE cve_id=? AND source IN ('jvn','tr_ja')", [id])
  let jvnV: any, trV: any
  for (const r of rows) {
    const v = (typeof r.data === 'string' ? JSON.parse(r.data) : r.data)?.v
    if (r.source === 'jvn') jvnV = v
    else trV = v
  }
  const text = (jvnV?.overview as string | undefined) || (typeof trV === 'string' && trV ? trV : undefined)
  return text ? { text, title: (jvnV?.title as string | undefined) || undefined } : null
}

// OSV serves GHSA, PYSEC, RUSTSEC, GO-... and other advisory IDs from one endpoint.
export const ADV_RE = /^(GHSA|PYSEC|RUSTSEC|GO|OSV|MAL|GSD|HSEC|DSA|DLA|USN|ALSA|RLSA|MGASA|UVI|BIT|CURL|LBSEC)-[A-Za-z0-9-]{4,40}$/i
export const normAdvId = (id: string) => {
  const [pre, ...rest] = id.split('-')
  return pre.toUpperCase() === 'GHSA' ? `GHSA-${rest.join('-').toLowerCase()}` : id.toUpperCase()
}

// Advisories published on a repository but not yet in OSV / the global database.
async function repoAdvisory(id: string, repo: string) {
  const d = await j(`https://api.github.com/repos/${repo}/security-advisories/${id}`, 10000, process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {})
  const sev = String(d.severity ?? '').toUpperCase()
  return {
    id: String(d.ghsa_id), summary: String(d.summary ?? ''), details: String(d.description ?? ''),
    severity: sev === 'MODERATE' ? 'MEDIUM' : ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sev) ? sev : null,
    cvss: d.cvss?.vector_string ? String(d.cvss.vector_string) : null,
    published: d.published_at ?? null, modified: d.updated_at ?? null, withdrawn: d.withdrawn_at ?? null,
    aliases: d.cve_id ? [String(d.cve_id)] : [],
    cwes: ((d.cwes ?? []) as Json[]).map((c) => String(c.cwe_id)).slice(0, 10),
    packages: ((d.vulnerabilities ?? []) as Json[]).filter((v) => v.package?.name).map((v) => ({
      ecosystem: String(v.package.ecosystem ?? ''), name: String(v.package.name),
      ranges: [String(v.vulnerable_version_range || 'all')], fixed: v.patched_versions ? [String(v.patched_versions)] : [],
    })).slice(0, 30),
    references: [{ type: 'ADVISORY', url: String(d.html_url) }],
  }
}

export const REPO_RE = /^[\w.-]{1,39}\/[\w.-]{1,100}$/

export async function advisory(id: string, repo?: string) {
  let d: Json
  try { d = await j(`https://api.osv.dev/v1/vulns/${id}`, 10000) }
  catch (e) { if (repo && REPO_RE.test(repo)) return repoAdvisory(id, repo); throw e }
  const refs = ((d.references ?? []) as Json[]).filter((r) => /^https?:\/\//.test(r.url ?? '')).map((r) => ({ type: String(r.type ?? 'WEB'), url: String(r.url) }))
  const sev = String(d.database_specific?.severity ?? '').toUpperCase()
  const cvss = ((d.severity ?? []) as Json[]).find((s) => String(s.type).startsWith('CVSS'))
  return {
    id: String(d.id),
    summary: String(d.summary ?? ''),
    details: String(d.details ?? ''),
    severity: ['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW'].includes(sev) ? (sev === 'MODERATE' ? 'MEDIUM' : sev) : null,
    cvss: cvss ? String(cvss.score) : null,
    published: d.published ? String(d.published) : null,
    modified: d.modified ? String(d.modified) : null,
    withdrawn: d.withdrawn ? String(d.withdrawn) : null,
    aliases: ((d.aliases ?? []) as string[]).slice(0, 20),
    cwes: ((d.database_specific?.cwe_ids ?? []) as string[]).slice(0, 10),
    packages: ((d.affected ?? []) as Json[]).map((a) => ({
      ecosystem: String(a.package?.ecosystem ?? ''), name: String(a.package?.name ?? ''),
      ranges: ((a.ranges ?? []) as Json[]).map((r) => {
        const ev = (r.events ?? []) as Json[]
        const from = ev.find((e) => e.introduced !== undefined)?.introduced
        const fixed = ev.find((e) => e.fixed)?.fixed
        return `${from && from !== '0' ? `>= ${from}` : ''}${fixed ? `${from && from !== '0' ? ', ' : ''}< ${fixed}` : ''}` || 'all'
      }).slice(0, 4),
      fixed: [...new Set(((a.ranges ?? []) as Json[]).flatMap((r) => ((r.events ?? []) as Json[]).map((e) => e.fixed).filter(Boolean)))].slice(0, 6) as string[],
    })).filter((p) => p.name).slice(0, 30),
    references: refs.slice(0, 30),
  }
}

/** Machine-translate advisory text line by line so markdown structure (headings, lists, code fences) survives. */
export async function translateAdvisory(summary: string, details: string) {
  const lines = details.replace(/<!--[\s\S]*?-->/g, '').replace(/\r\n?/g, '\n').split('\n')
  let fence = false, budget = 1800, n = 0
  const out = await Promise.all(lines.map(async (l) => {
    if (/^\s*```/.test(l)) { fence = !fence; return l }
    if (fence || !l.trim() || n >= 30 || budget <= 0) return l
    const m = l.match(/^(\s*(?:#{1,6}|[-*+])\s+)?(.*)$/)!
    n++; budget -= m[2].length
    return `${m[1] ?? ''}${await translateJa(m[2])}`
  }))
  return { summary: summary ? await translateJa(summary) : '', details: out.join('\n') }
}
