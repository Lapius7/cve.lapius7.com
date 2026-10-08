export type Json = Record<string, any>

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
export const KEY = process.env.NVD_API_KEY || undefined
const calls: number[] = []

// NVD: 5 req/30s without key, 50 with key. Burst freely, wait only when the window is full.
async function throttle() {
  const limit = KEY ? 45 : 4
  for (;;) {
    const now = Date.now()
    while (calls.length && calls[0] <= now - 30_000) calls.shift()
    if (calls.length < limit) return void calls.push(now)
    await new Promise((r) => setTimeout(r, calls[0] + 30_000 - now + 50))
  }
}

export async function nvdRaw(params: URLSearchParams, gone: () => boolean = () => false): Promise<Json> {
  await throttle()
  if (gone()) throw Object.assign(new Error('aborted'), { status: 499 })
  const res = await fetch(`${NVD}?${params}`, { headers: KEY ? { apiKey: KEY } : {}, signal: AbortSignal.timeout(60_000) })
  if (!res.ok) throw Object.assign(new Error(`NVD ${res.status}`), { status: res.status })
  return (await res.json()) as Json
}

export interface CveRow {
  id: string
  status: string
  published: string
  modified: string
  description: string
  score: number | null
  severity: string | null
  vector: string | null
  cvssVersion: string | null
  cwes: string[]
  references: { url: string; source: string; tags: string[] }[]
  kev: boolean
}

export function normalize(c: Json): CveRow {
  const m = c.metrics ?? {}
  const pick = m.cvssMetricV40 ?? m.cvssMetricV31 ?? m.cvssMetricV30 ?? m.cvssMetricV2 ?? []
  const best = pick.find((x: Json) => x.type === 'Primary') ?? pick[0]
  const d = best?.cvssData
  const desc = (c.descriptions ?? []) as Json[]
  return {
    id: c.id,
    status: c.vulnStatus,
    published: c.published,
    modified: c.lastModified,
    description: (desc.find((x) => x.lang === 'en') ?? desc[0])?.value ?? '',
    score: d?.baseScore ?? null,
    severity: d?.baseSeverity ?? best?.baseSeverity ?? null,
    vector: d?.vectorString ?? null,
    cvssVersion: d?.version ?? null,
    cwes: [...new Set(((c.weaknesses ?? []) as Json[]).flatMap((w) => w.description.map((x: Json) => x.value as string)))],
    references: ((c.references ?? []) as Json[]).map((r) => ({ url: r.url, source: r.source, tags: r.tags ?? [] })),
    kev: Boolean(c.cisaExploitAdd),
  }
}
