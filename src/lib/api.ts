export interface Cve {
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
  products: { vendor: string; product: string }[]
  epss?: number | null
  references: { url: string; source: string; tags: string[] }[]
  kev: boolean
}
export interface CveList {
  total: number
  page: number
  perPage: number
  items: Cve[]
}

export interface Extra {
  epss: { score: number; percentile: number; date: string; series: { date: string; score: number }[] } | null
  kev: { vendor: string; product: string; name: string; added: string; due: string; action: string; ransomware: boolean } | null
  cveorg: {
    title?: string; assigner?: string; state?: string; reserved?: string
    affected: { vendor?: string; product?: string; default?: string; versions: { version: string; status: string; lessThan?: string; orEqual: boolean }[] }[]
    solutions: string[]; workarounds: string[]; credits: string[]
  } | null
  osv: { aliases: string[]; packages: { ecosystem?: string; name?: string; fixed: string[] }[] } | null
  ghsa: { id: string; url: string; summary: string; severity: string; vulns: { ecosystem: string; name: string; range: string; patched: string | null }[] }[]
  jvn: { id: string; url: string; title?: string; overview?: string; impact?: string; solution: string[] } | null
}
export interface KevItem { id: string; vendor: string; product: string; name: string; description: string; added: string; due: string; ransomware: boolean }
export interface EpssItem { id: string; score: number; percentile: number }
export interface Feed<T> { total: number; page: number; perPage: number; items: T[] }
export const getKev = (page: number, signal?: AbortSignal) => get<Feed<KevItem>>(`/api/feed/kev?page=${page}`, signal)
export const getEpssTop = (page: number, signal?: AbortSignal) => get<Feed<EpssItem>>(`/api/feed/epss?page=${page}`, signal)
export const getTranslation = (id: string, signal?: AbortSignal) => get<{ text: string }>(`/api/translate/${id}`, signal)
export const getExtra = (id: string, signal?: AbortSignal) => get<Extra>(`/api/cves/${id}/extra`, signal)

async function get<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? String(res.status))
  return res.json()
}

export const searchCves = (q: string, severity: string, page: number, signal?: AbortSignal) => {
  const p = new URLSearchParams({ page: String(page) })
  if (q) p.set('q', q)
  if (severity) p.set('severity', severity)
  return get<CveList>(`/api/cves?${p}`, signal)
}
export const getCve = (id: string, signal?: AbortSignal) => get<Cve>(`/api/cves/${id}`, signal)

export const tone = (s: string | null) =>
  s === 'CRITICAL' || s === 'HIGH' ? 'danger' : s === 'MEDIUM' ? 'warning' : s === 'LOW' ? 'info' : 'neutral'
export const fmtDate = (s: string) => s.slice(0, 10)
