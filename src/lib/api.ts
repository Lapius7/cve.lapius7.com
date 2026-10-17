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
  live?: boolean
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
export interface ExtraJa { kevName: string | null; kevAction: string | null; solutions: (string | null)[]; workarounds: (string | null)[] }
export const getExtraJa = (id: string, signal?: AbortSignal) => get<ExtraJa>(`/api/cves/${id}/extra-ja`, signal)
export const getExtra = (id: string, signal?: AbortSignal) => get<Extra>(`/api/cves/${id}/extra`, signal)

async function get<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? String(res.status))
  return res.json()
}

export const searchCves = (q: string, severity: string, page: number, signal?: AbortSignal, year = '', sort = '') => {
  const p = new URLSearchParams({ page: String(page) })
  if (q) p.set('q', q)
  if (severity) p.set('severity', severity)
  if (year) p.set('year', year)
  if (sort) p.set('sort', sort)
  return get<CveList>(`/api/cves?${p}`, signal)
}
export const getCve = (id: string, signal?: AbortSignal) => get<Cve>(`/api/cves/${id}`, signal)

export const tone = (s: string | null) =>
  s === 'CRITICAL' || s === 'HIGH' ? 'danger' : s === 'MEDIUM' ? 'warning' : s === 'LOW' ? 'info' : 'neutral'
export const fmtDate = (s: string) => s.slice(0, 10)

/** CVE-2026-102322 -> 2026102322 (the server redirects /{lang}/2026102322 back to the full page). */
export const shortId = (id: string) => id.replace(/^CVE-(\d{4})-(\d+)$/i, '$1$2')

export interface Advisory {
  id: string; summary: string; details: string; severity: string | null; cvss: string | null
  published: string | null; modified: string | null; withdrawn: string | null
  aliases: string[]; cwes: string[]; references: { type: string; url: string }[]
  packages: { ecosystem: string; name: string; ranges: string[]; fixed: string[] }[]
}
/** GHSA / PYSEC / RUSTSEC / GO-... style advisory IDs (served via OSV). */
export const ADV_RE = /^(GHSA|PYSEC|RUSTSEC|GO|OSV|MAL|GSD|HSEC|DSA|DLA|USN|ALSA|RLSA|MGASA|UVI|BIT|CURL|LBSEC)-[A-Za-z0-9-]{4,40}$/i
export const getAdvisory = (id: string, repo?: string, signal?: AbortSignal) => get<Advisory>(`/api/advisories/${id}${repo ? `?repo=${encodeURIComponent(repo)}` : ''}`, signal)
export const getAdvisoryTr = (id: string, repo?: string, signal?: AbortSignal) => get<{ summary: string; details: string }>(`/api/advisories/${id}/translate${repo ? `?repo=${encodeURIComponent(repo)}` : ''}`, signal)

export interface PkgVuln { id: string; summary: string; severity: string | null; aliases: string[]; published: string | null; withdrawn: boolean; fixed: string[] }
export interface PkgResult { ecosystem: string; name: string; version: string | null; total: number; items: PkgVuln[] }
export const getPkg = (eco: string, name: string, version: string, signal?: AbortSignal) =>
  get<PkgResult>(`/api/pkg/${encodeURIComponent(eco)}/${name.split('/').map(encodeURIComponent).join('/')}${version ? `?version=${encodeURIComponent(version)}` : ''}`, signal)
export interface ProductHit { vendor: string; product: string; count: number }
export const getProducts = (q: string, signal?: AbortSignal) => get<{ items: ProductHit[] }>(`/api/products?q=${encodeURIComponent(q)}`, signal)
export const getVendor = (v: string, signal?: AbortSignal) => get<{ vendor: string; products: { product: string; count: number }[] }>(`/api/vendors/${encodeURIComponent(v)}`, signal)
export interface ProductPage extends CveList { vendor: string; product: string; severity: Record<string, number> }
export const getProduct = (v: string, p: string, page: number, sort: string, signal?: AbortSignal) =>
  get<ProductPage>(`/api/vendors/${encodeURIComponent(v)}/${encodeURIComponent(p)}?page=${page}&sort=${sort}`, signal)
export const getCweCves = (id: string, page: number, signal?: AbortSignal) => get<CveList & { cwe: string }>(`/api/cwe/${encodeURIComponent(id)}/cves?page=${page}`, signal)

export interface ScanBrief { id: string; summary: string; severity: string | null; aliases: string[]; fixed: string[]; withdrawn: boolean }
export interface ScanResult {
  summary: { scanned: number; vulnerablePackages: number; vulnerabilities: number; severity: Record<string, number>; truncated: boolean }
  packages: { ecosystem: string; name: string; version: string; vulns: string[] }[]
  vulns: Record<string, ScanBrief | null>
}
export async function scanPackages(packages: { ecosystem: string; name: string; version: string }[], signal?: AbortSignal): Promise<ScanResult> {
  const res = await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ packages }), signal })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? String(res.status))
  return res.json()
}

export const getRelated = (id: string, signal?: AbortSignal) => get<{ sameCwe: Cve[]; sameProduct: Cve[] }>(`/api/cves/${id}/related`, signal)
