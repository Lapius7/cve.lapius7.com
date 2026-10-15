import { useEffect, useState, type ReactNode } from 'react'
import { ArrowLeft } from 'lucide-react'
import { Badge } from '@/components/arc/badge/badge'
import { Button } from '@/components/arc/button/button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Input } from '@/components/arc/input/input'
import { Pagination } from '@/components/arc/pagination/pagination'
import SegmentedControl from '@/components/arc/segmented-control/segmented-control'
import { Select } from '@/components/arc/select/select'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import DataTable from '@/components/data-table'
import { cveColumns } from '@/columns'
import { fmtDate, getCweCves, getPkg, getProduct, getVendor, tone, type CveList, type PkgResult, type ProductPage } from '@/lib/api'
import { Link, navigate, withLang } from '@/lib/router'
import { useLang } from '@/lib/i18n'
import { LangSwitch } from '@/App'

type ThemeProps = { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }

export const ECOSYSTEMS = [
  ['npm', 'npm'], ['pypi', 'PyPI'], ['go', 'Go'], ['crates', 'crates.io'], ['maven', 'Maven'], ['nuget', 'NuGet'],
  ['rubygems', 'RubyGems'], ['packagist', 'Packagist'], ['hex', 'Hex'], ['pub', 'Pub'], ['actions', 'GitHub Actions'],
] as const

export function Shell({ title, crumb, children, theme, onThemeChange }: { title: string; crumb?: string; children: ReactNode } & ThemeProps) {
  const { t } = useLang()
  useEffect(() => { document.title = `${title} | ${t('title')}` }, [title, t])
  return (
    <main className="page">
      <div className="top" style={{ marginBottom: '1rem' }}>
        <Link href="/" className="back" style={{ margin: 0 }}><ArrowLeft size={14} /> {t('title')}</Link>
        <div className="actions"><LangSwitch /><ThemeSwitch theme={theme} onThemeChange={onThemeChange} iconOnly /></div>
      </div>
      <h1 className="dh" style={{ marginBottom: '.25rem', fontVariantNumeric: 'normal' }}>{title}</h1>
      {crumb && <p className="lead" style={{ marginTop: 0 }}>{crumb}</p>}
      {children}
    </main>
  )
}

export function useLoad<T>(fn: (s: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    const ac = new AbortController()
    setLoading(true); setErr(null)
    fn(ac.signal).then((d) => { setData(d); setLoading(false) }).catch((e) => { if (e.name !== 'AbortError') { setErr(e.message); setLoading(false) } })
    return () => ac.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return { data, err, loading }
}

export const Fail = ({ err }: { err: string }) => {
  const { t } = useLang()
  return <EmptyState title={t(err === '404' || err === 'not_found' ? 'notFound' : 'errorTitle')} description={err === 'rate_limited' ? t('rate') : t('loadFail')} />
}

/** /pkg and /pkg/{eco}/{name...}?version= */
export function PkgPage({ eco, name, theme, onThemeChange }: { eco: string; name: string } & ThemeProps) {
  const { t } = useLang()
  const q = new URLSearchParams(location.search)
  const version = q.get('version') ?? ''
  const [fEco, setFEco] = useState(eco || 'npm')
  const [fName, setFName] = useState(name)
  const [fVer, setFVer] = useState(version)
  const ecoLabel = ECOSYSTEMS.find((e) => e[0] === eco)?.[1] ?? eco
  const { data, err, loading } = useLoad<PkgResult | null>((s) => (name ? getPkg(eco, name, version, s) : Promise.resolve(null)), [eco, name, version])

  const go = () => {
    if (!fName.trim()) return
    const path = `/pkg/${fEco}/${fName.trim().split('/').map(encodeURIComponent).join('/')}`
    navigate(withLang(path) + (fVer.trim() ? `?version=${encodeURIComponent(fVer.trim())}` : ''), false)
  }
  const open = data?.items.filter((i) => !i.withdrawn) ?? []
  const badgeUrl = name ? `${location.origin}/badge/pkg/${eco}/${name}.svg${version ? `?version=${version}` : ''}` : ''

  return (
    <Shell title={name ? t('pkgTitle', { name }) : t('navPkg')} crumb={name ? `${ecoLabel}${version ? ` @ ${version}` : ''}` : t('pkgLead', { eco: 'npm, PyPI, Go, Maven …' })} theme={theme} onThemeChange={onThemeChange}>
      <form className="controls" onSubmit={(e) => { e.preventDefault(); go() }} style={{ alignItems: 'flex-end' }}>
        <div style={{ width: '11rem' }}><Select label={t('pkgEco')} value={fEco} onValueChange={setFEco} options={ECOSYSTEMS.map(([v, l]) => ({ value: v, label: l }))} /></div>
        <div className="grow"><Input label={t('pkgName')} value={fName} onChange={(e) => setFName(e.target.value)} autoComplete="off" spellCheck={false} placeholder="lodash, @babel/core, requests" /></div>
        <div style={{ width: '10rem' }}><Input label={t('pkgVer')} value={fVer} onChange={(e) => setFVer(e.target.value)} autoComplete="off" spellCheck={false} placeholder="4.17.15" /></div>
        <Button type="submit">{t('pkgGo')}</Button>
      </form>
      {!name ? <p className="meta">{t('pkgHint')}</p> : err ? <Fail err={err} /> : loading ? <Skeleton label={t('searching')} lines={5} /> : data && (
        <>
          <div className="meta" style={{ display: 'flex', gap: '.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <span aria-live="polite">{t('pkgTotal', { n: data.total })}</span>
            <img src={badgeUrl} alt={t('pkgBadge')} height={20} />
          </div>
          {data.items.length === 0 ? <EmptyState title={t('pkgNone', { v: version ? ` (${version})` : '' })} description="" /> : (
            <div className="list">
              {data.items.map((v) => (
                <Link key={v.id} href={`/${v.id}`} className="row prow" style={{ textDecoration: 'none', opacity: v.withdrawn ? 0.55 : 1 }}>
                  <span className="id">{v.id}</span>
                  <span>
                    <span className="desc" style={{ color: 'var(--foreground)' }}>{v.summary || v.aliases.join(', ')}</span>
                    <span className="tags" style={{ display: 'block', marginTop: '.25rem' }}>
                      {v.aliases.filter((a) => a.startsWith('CVE-')).join(' ')}{v.published ? ` · ${fmtDate(v.published)}` : ''}{v.fixed.length ? ` · ${t('fixedIn')} ${v.fixed.join(', ')}` : ''}
                    </span>
                  </span>
                  <span className="score">
                    {v.withdrawn ? <Badge tone="neutral" size="sm">{t('withdrawn')}</Badge>
                      : v.severity ? <Badge tone={tone(v.severity)} size="sm">{t(v.severity.toLowerCase() as 'critical')}</Badge> : <span className="tags">{t('unknown')}</span>}
                  </span>
                </Link>
              ))}
            </div>
          )}
          {open.length > 0 && <p className="tags" style={{ marginTop: '.75rem' }}>{t('pkgBadge')}: <code>![vulnerabilities]({badgeUrl})</code></p>}
        </>
      )}
    </Shell>
  )
}

function CveTable({ data, page, onPage }: { data: CveList; page: number; onPage: (p: number) => void }) {
  const { t } = useLang()
  const pages = Math.ceil(data.total / data.perPage)
  const narrow = matchMedia('(max-width: 40rem)').matches
  return (
    <>
      <div className="meta">{t('results', { n: data.total.toLocaleString() })}</div>
      <DataTable data={data.items} columns={cveColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} initialVisibility={narrow ? { description: false } : {}} />
      {pages > 1 && <div className="pager"><Pagination page={page} pageCount={Math.min(pages, 500)} onPageChange={(p) => { onPage(p); scrollTo({ top: 0 }) }} /></div>}
    </>
  )
}

function usePageParam() {
  const [page, setPage] = useState(() => Math.max(1, Number(new URLSearchParams(location.search).get('page')) || 1))
  return [page, (p: number) => { setPage(p); const u = new URLSearchParams(location.search); p > 1 ? u.set('page', String(p)) : u.delete('page'); history.replaceState(null, '', u.size ? `?${u}` : location.pathname) }] as const
}

/** /vendor/{vendor} and /vendor/{vendor}/{product} */
export function VendorPage({ vendor, product, theme, onThemeChange }: { vendor: string; product: string } & ThemeProps) {
  const { t } = useLang()
  const [page, setPage] = usePageParam()
  const [sort, setSort] = useState(() => new URLSearchParams(location.search).get('sort') ?? 'new')
  const pr = useLoad<ProductPage | null>((s) => (product ? getProduct(vendor, product, page, sort, s) : Promise.resolve(null)), [vendor, product, page, sort])
  const vd = useLoad((s) => (product ? Promise.resolve(null) : getVendor(vendor, s)), [vendor, product])
  const err = product ? pr.err : vd.err
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  return (
    <Shell title={product ? t('productTitle', { vendor, product }) : t('vendorTitle', { vendor })} theme={theme} onThemeChange={onThemeChange}>
      {err ? <Fail err={err} /> : product ? (
        <>
          <div className="controls">
            <SegmentedControl label="Sort" value={sort} onValueChange={(v) => { setSort(v); setPage(1); const u = new URLSearchParams(location.search); v === 'new' ? u.delete('sort') : u.set('sort', v); history.replaceState(null, '', u.size ? `?${u}` : location.pathname) }}
              options={[{ value: 'new', label: t('sortNew') }, { value: 'score', label: t('sortScore') }, { value: 'epss', label: t('sortEpss') }]} />
            {pr.data && <div className="chips">{sevOrder.filter((s) => pr.data!.severity[s]).map((s) => <Badge key={s} tone={tone(s)} size="sm">{t(s.toLowerCase() as 'critical')} {pr.data!.severity[s]}</Badge>)}</div>}
          </div>
          {pr.loading && !pr.data ? <Skeleton label={t('searching')} lines={6} /> : pr.data && <CveTable data={pr.data} page={page} onPage={setPage} />}
        </>
      ) : vd.loading ? <Skeleton label={t('searching')} lines={6} /> : vd.data && (
        <div className="list">
          {vd.data.products.map((p) => (
            <Link key={p.product} href={`/vendor/${encodeURIComponent(vendor)}/${encodeURIComponent(p.product)}`} className="row prow" style={{ textDecoration: 'none', gridTemplateColumns: '1fr auto' }}>
              <span className="id" style={{ whiteSpace: 'normal' }}>{p.product}</span><span className="score">{p.count.toLocaleString()}</span>
            </Link>
          ))}
        </div>
      )}
    </Shell>
  )
}

/** /cwe/{n} */
export function CwePage({ id, theme, onThemeChange }: { id: string } & ThemeProps) {
  const { t } = useLang()
  const [page, setPage] = usePageParam()
  const cwe = /^\d+$/.test(id) ? `CWE-${id}` : id.toUpperCase()
  const { data, err, loading } = useLoad((s) => getCweCves(cwe, page, s), [cwe, page])
  return (
    <Shell title={t('cweTitle', { id: cwe })} crumb={undefined} theme={theme} onThemeChange={onThemeChange}>
      <p className="lead" style={{ marginTop: 0 }}><a href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`} target="_blank" rel="noopener noreferrer">{t('cweOpen')}</a></p>
      {err ? <Fail err={err} /> : loading && !data ? <Skeleton label={t('searching')} lines={6} /> : data && <CveTable data={data} page={page} onPage={setPage} />}
    </Shell>
  )
}
