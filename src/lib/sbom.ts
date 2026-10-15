/** Browser-side manifest / lockfile / SBOM parsing. Only {ecosystem,name,version} ever leaves the browser. */
export interface Pkg { ecosystem: string; name: string; version: string }
export interface Parsed { format: string; packages: Pkg[] }

const P = (ecosystem: string, name: string, version: string): Pkg => ({ ecosystem, name, version })
const clean = (v: string) => v.replace(/^[v=^~<>\s]+/, '').trim()

const PURL_ECO: Record<string, string> = {
  npm: 'npm', pypi: 'pypi', cargo: 'crates', golang: 'go', maven: 'maven', nuget: 'nuget', gem: 'rubygems', composer: 'packagist', hex: 'hex', pub: 'pub', github: 'actions',
}
function purl(s: string): Pkg | null {
  const m = s.match(/^pkg:([a-z]+)\/(.+?)@([^?#]+)/i)
  const eco = m && PURL_ECO[m[1].toLowerCase()]
  if (!m || !eco) return null
  let name = m[2]
  try { name = decodeURIComponent(name) } catch { /* keep raw */ }
  if (eco === 'maven') name = name.replace('/', ':')
  return P(eco, name, m[3])
}

function npmLock(j: any): Pkg[] {
  const out: Pkg[] = []
  if (j.packages) {
    for (const [path, v] of Object.entries<any>(j.packages)) {
      const name = v.name ?? path.split('node_modules/').pop()
      if (path && name && v.version) out.push(P('npm', name, v.version))
    }
  } else {
    const walk = (deps: any) => { for (const [n, v] of Object.entries<any>(deps ?? {})) { if (v.version) out.push(P('npm', n, v.version)); walk(v.dependencies) } }
    walk(j.dependencies)
  }
  return out
}

function yarnLock(t: string): Pkg[] {
  const out: Pkg[] = []
  for (const block of t.split(/\n\n+/)) {
    const head = block.match(/^"?(@?[^@\s"]+)@/m)
    const ver = block.match(/^\s+version:?\s+"?([^"\s]+)"?/m)
    if (head && ver) out.push(P('npm', head[1], ver[1]))
  }
  return out
}

function pnpmLock(t: string): Pkg[] {
  const out: Pkg[] = []
  for (const m of t.matchAll(/^\s{2,4}'?\/?(@?[^@\s'/][^@\s']*(?:\/[^@\s']+)?)@(\d[^\s:'()]*)'?:/gm)) out.push(P('npm', m[1], m[2]))
  return out
}

function requirements(t: string): Pkg[] {
  const out: Pkg[] = []
  for (const line of t.split('\n')) {
    const m = line.replace(/#.*/, '').trim().match(/^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*==\s*([\w.+!-]+)/)
    if (m) out.push(P('pypi', m[1], m[2]))
  }
  return out
}

function tomlPackages(t: string, eco: string, key = 'package'): Pkg[] {
  const out: Pkg[] = []
  for (const b of t.split(new RegExp(`^\\[\\[${key}\\]\\]`, 'm')).slice(1)) {
    const n = b.match(/^name\s*=\s*"([^"]+)"/m), v = b.match(/^version\s*=\s*"([^"]+)"/m)
    if (n && v) out.push(P(eco, n[1], v[1]))
  }
  return out
}

function goMod(t: string): Pkg[] {
  const out: Pkg[] = []
  for (const m of t.matchAll(/^\s*(?:require\s+)?([\w.-]+\.[\w.-]+\/[^\s]+)\s+v([^\s/]+)/gm)) out.push(P('go', m[1], m[2]))
  return out
}

function gemfileLock(t: string): Pkg[] {
  const out: Pkg[] = []
  for (const m of t.matchAll(/^ {4}([\w.-]+) \(([\d][^)\s]*)\)/gm)) out.push(P('rubygems', m[1], m[2]))
  return out
}

function composerLock(j: any): Pkg[] {
  return [...(j.packages ?? []), ...(j['packages-dev'] ?? [])].filter((p: any) => p.name && p.version).map((p: any) => P('packagist', p.name, clean(p.version)))
}

function cyclonedx(j: any): Pkg[] {
  const out: Pkg[] = []
  const walk = (cs: any[]) => { for (const c of cs ?? []) { const p = c.purl && purl(c.purl); if (p) out.push(p); walk(c.components) } }
  walk(j.components)
  return out
}

function spdx(j: any): Pkg[] {
  const out: Pkg[] = []
  for (const p of j.packages ?? []) for (const r of p.externalRefs ?? []) if (r.referenceType === 'purl') { const x = purl(r.referenceLocator); if (x) out.push(x) }
  return out
}

function purlList(t: string): Pkg[] {
  return t.split('\n').map((l) => purl(l.trim())).filter((x): x is Pkg => !!x)
}

export function parseManifest(text: string, filename = ''): Parsed {
  const f = filename.toLowerCase()
  const t = text.replace(/^﻿/, '')
  let format = '', packages: Pkg[] = []
  const trimmed = t.trimStart()
  if (trimmed.startsWith('{')) {
    let j: any
    try { j = JSON.parse(t) } catch { return { format: '', packages: [] } }
    if (j.bomFormat === 'CycloneDX' || Array.isArray(j.components)) { format = 'CycloneDX'; packages = cyclonedx(j) }
    else if (j.spdxVersion || Array.isArray(j.packages) && j.packages[0]?.SPDXID) { format = 'SPDX'; packages = spdx(j) }
    else if (j.lockfileVersion || j.packages || j.dependencies) {
      if (j.content_hash !== undefined || (Array.isArray(j.packages) && !j.lockfileVersion)) { format = 'composer.lock'; packages = composerLock(j) }
      else { format = 'package-lock.json'; packages = npmLock(j) }
    }
  } else if (f.endsWith('cargo.lock')) { format = 'Cargo.lock'; packages = tomlPackages(t, 'crates') }
  else if (f.endsWith('poetry.lock') || f.endsWith('pdm.lock') || f.endsWith('uv.lock')) { format = f.split('/').pop()!; packages = tomlPackages(t, 'pypi') }
  else if (f.endsWith('go.mod') || /^module\s+\S+/m.test(t) && /^go\s+\d/m.test(t)) { format = 'go.mod'; packages = goMod(t) }
  else if (f.endsWith('gemfile.lock') || /^GEM\n/m.test(t)) { format = 'Gemfile.lock'; packages = gemfileLock(t) }
  else if (f.endsWith('yarn.lock') || /^# yarn lockfile/m.test(t)) { format = 'yarn.lock'; packages = yarnLock(t) }
  else if (f.endsWith('pnpm-lock.yaml') || /^lockfileVersion:/m.test(t)) { format = 'pnpm-lock.yaml'; packages = pnpmLock(t) }
  else if (/^pkg:/m.test(t)) { format = 'purl'; packages = purlList(t) }
  else if (/^[A-Za-z0-9][\w.-]*(\[[^\]]*\])?\s*==/m.test(t)) { format = 'requirements.txt'; packages = requirements(t) }
  const seen = new Set<string>()
  packages = packages.filter((p) => { const k = `${p.ecosystem}|${p.name}|${p.version}`; if (seen.has(k)) return false; seen.add(k); return true })
  return { format, packages }
}
