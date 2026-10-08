import { pool } from './db.ts'
import type { Json } from './nvd.ts'

export async function j(url: string, ms = 8000) {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms), headers: { 'user-agent': 'cve.lapius7.com' } })
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
  const d = (await j(`https://api.github.com/advisories?cve_id=${id}`)) as unknown as Json[]
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

export async function translateJa(text: string) {
  const chunks: string[] = []
  for (const sent of text.slice(0, 1800).split(/(?<=[.!?])\s+/)) {
    const last = chunks.length - 1
    if (last >= 0 && chunks[last].length + sent.length < 450) chunks[last] += ' ' + sent
    else chunks.push(sent.slice(0, 480))
  }
  const parts = await Promise.all(chunks.map(async (c) => {
    const r = await j(`https://api.mymemory.translated.net/get?langpair=en|ja&q=${encodeURIComponent(c)}`)
    const out = r.responseData?.translatedText as string | undefined
    // MyMemory reports quota/limit errors as a 200 with a warning text; never cache that.
    if (r.responseStatus !== 200 || !out || /MYMEMORY WARNING|QUERY LENGTH LIMIT|INVALID/i.test(out)) throw new Error('translate')
    return out
  }))
  return parts.join('')
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
