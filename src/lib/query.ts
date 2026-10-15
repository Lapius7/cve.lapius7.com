/** Recognise non-keyword search input: purl, "eco:name@ver", CPE, CWE, CVE. Returns app paths (without lang). */
export interface Intent { kind: 'pkg' | 'vendor' | 'cwe' | 'cve'; label: string; href: string }

const ECO_ALIAS: Record<string, string> = {
  npm: 'npm', pypi: 'pypi', pip: 'pypi', cargo: 'crates', crates: 'crates', 'crates.io': 'crates', go: 'go', golang: 'go',
  maven: 'maven', nuget: 'nuget', gem: 'rubygems', rubygems: 'rubygems', composer: 'packagist', packagist: 'packagist',
  hex: 'hex', pub: 'pub', actions: 'actions', github: 'actions',
}

const pkgIntent = (eco: string, name: string, version: string): Intent => ({
  kind: 'pkg', label: `${eco} / ${name}${version ? ` @ ${version}` : ''}`,
  href: `/pkg/${eco}/${name.split('/').map(encodeURIComponent).join('/')}${version ? `?version=${encodeURIComponent(version)}` : ''}`,
})

export function classify(raw: string): Intent[] {
  const q = raw.trim()
  if (!q || q.length > 200) return []
  const out: Intent[] = []
  let m: RegExpMatchArray | null

  if ((m = q.match(/^CVE[-\s](\d{4})[-\s](\d{4,})$/i))) out.push({ kind: 'cve', label: `CVE-${m[1]}-${m[2]}`, href: `/CVE-${m[1]}-${m[2]}` })
  if ((m = q.match(/^cwe[-\s:]?(\d{1,5})$/i))) out.push({ kind: 'cwe', label: `CWE-${m[1]}`, href: `/cwe/${m[1]}` })

  // purl: pkg:npm/%40babel/core@7.0.0
  if ((m = q.match(/^pkg:([a-z.]+)\/(.+?)(?:@([^?#@]+))?(?:[?#].*)?$/i))) {
    const eco = ECO_ALIAS[m[1].toLowerCase()]
    let name = ''
    try { name = decodeURIComponent(m[2]) } catch { name = m[2] }
    if (eco && name) out.push(pkgIntent(eco, eco === 'maven' ? name.replace('/', ':') : name, m[3] ?? ''))
  }

  // CPE 2.3: cpe:2.3:a:vendor:product:version:...
  if ((m = q.match(/^cpe:2\.3:[aho]:([^:]+):([^:]+)(?::([^:]+))?/i))) {
    const [v, p] = [m[1].toLowerCase(), m[2].toLowerCase()]
    if (v !== '*' && p !== '*') out.push({ kind: 'vendor', label: `${v} / ${p}`, href: `/vendor/${encodeURIComponent(v)}/${encodeURIComponent(p)}` })
  }

  if ((m = q.match(/^maven[:/]([\w.-]+):([\w.-]+)(?::([\w.\-+]+))?$/i))) out.push(pkgIntent('maven', `${m[1]}:${m[2]}`, m[3] ?? ''))

  // eco:name@version, eco:name==version, eco/name
  if (!out.length && (m = q.match(/^([a-z.]+)[:/\s]\s*(@?[\w.\-/]+?)(?:\s*(?:@|==|=|:)\s*v?([\w.\-+]+))?$/i))) {
    const eco = ECO_ALIAS[m[1].toLowerCase()]
    if (eco && m[2] && !/^\d/.test(m[2])) out.push(pkgIntent(eco, m[2], m[3] ?? ''))
  }

  // name@version with no ecosystem: offer npm and PyPI
  if (!out.length && (m = q.match(/^(@?[a-z][\w.\-]*(?:\/[\w.\-]+)?)@v?(\d[\w.\-+]*)$/i))) out.push(pkgIntent('npm', m[1], m[2]))
  if (!out.length && (m = q.match(/^([a-z][\w.\-]*)==(\d[\w.\-+]*)$/i))) out.push(pkgIntent('pypi', m[1], m[2]))
  return out
}
