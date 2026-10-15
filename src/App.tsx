import { useEffect, useLayoutEffect, useState } from 'react'
import { SearchField } from '@/components/arc/search-field/search-field'
import { Select } from '@/components/arc/select/select'
import SegmentedControl from '@/components/arc/segmented-control/segmented-control'
import { Pagination } from '@/components/arc/pagination/pagination'
import { Button } from '@/components/arc/button/button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { useThemeTransition } from '@/components/transitions/theme-transition'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { ADV_RE, getAdvisory, getEpssTop, type Advisory, getKev, searchCves, type EpssItem, type Feed, type KevItem, type CveList } from '@/lib/api'
import { Link, stripLang, usePath, withLang } from '@/lib/router'
import { useLang, type Lang } from '@/lib/i18n'
import Detail from '@/Detail'
import EmptyArt from '@/EmptyArt'
import AdvisoryDetail from '@/Advisory'
import ScanPage from '@/Scan'
import StatsPage from '@/Stats'
import DocsPage from '@/Docs'
import { classify } from '@/lib/query'
import { ProductSuggest } from '@/ProductSuggest'
import { CwePage, PkgPage, VendorPage } from '@/Explore'
import DataTable from '@/components/data-table'
import { cveColumns, epssColumns, kevColumns } from '@/columns'

function useDebounced<T>(v: T, ms: number) {
  const [d, setD] = useState(v)
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms)
    return () => clearTimeout(t)
  }, [v, ms])
  return d
}

export default function App() {
  const path = usePath()
  const { resolvedTheme: theme, setTheme: applyTheme } = useThemeTransition()
  useLayoutEffect(() => { document.documentElement.dataset.theme = theme }, [theme])
  const setTheme = (next: Theme, _v: unknown, trigger: HTMLElement) => applyTheme(next, { origin: trigger })
  const rest = stripLang(path)
  const dec = (x: string) => { try { return decodeURIComponent(x) } catch { return x } }
  const tp = { theme, onThemeChange: setTheme }
  const pk = rest.match(/^\/pkg(?:\/([^/]+)(?:\/(.+?))?)?\/?$/)
  if (pk) return <PkgPage eco={pk[1] ?? ''} name={dec(pk[2] ?? '')} {...tp} />
  if (/^\/scan\/?$/.test(rest)) return <ScanPage {...tp} />
  if (/^\/stats\/?$/.test(rest)) return <StatsPage {...tp} />
  if (/^\/docs\/?$/.test(rest)) return <DocsPage {...tp} />
  const vd = rest.match(/^\/vendor\/([^/]+)(?:\/([^/]+))?\/?$/)
  if (vd) return <VendorPage vendor={dec(vd[1])} product={dec(vd[2] ?? '')} {...tp} />
  const cw = rest.match(/^\/cwe\/([\w-]+)\/?$/i)
  if (cw) return <CwePage id={cw[1]} {...tp} />
  const m = rest.match(/^\/([A-Za-z]+-[A-Za-z0-9-]{4,40})\/?$/)
  const vid = m && (ADV_RE.test(m[1]) || /^CVE-\d{4}-\d{4,}$/i.test(m[1])) ? decodeURIComponent(m[1]) : ''
  return vid ? (ADV_RE.test(vid) && !/^CVE-/i.test(vid) ? <AdvisoryDetail id={vid} theme={theme} onThemeChange={setTheme} /> : <Detail id={vid} theme={theme} onThemeChange={setTheme} />) : <Home theme={theme} onThemeChange={setTheme} />
}

export function LangSwitch() {
  const { lang, setLang } = useLang()
  return (
    <SegmentedControl label="Language" value={lang} onValueChange={(v) => setLang(v as Lang)}
      options={[{ value: 'en', label: 'EN' }, { value: 'ja', label: '日本語' }]} />
  )
}

type Tab = 'search' | 'kev' | 'epss'


const normAdv = (id: string) => /^ghsa-/i.test(id) ? `GHSA-${id.slice(5).toLowerCase()}` : id.toUpperCase()

function Home({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t } = useLang()
  const init = new URLSearchParams(location.search)
  const [tab, setTab] = useState<Tab>((init.get('tab') as Tab) || 'search')
  const [q, setQ] = useState(init.get('q') ?? '')
  const [severity, setSeverity] = useState(init.get('severity') ?? '')
  const [year, setYear] = useState(init.get('year') ?? '')
  const [sort, setSort] = useState(init.get('sort') ?? '')
  const [page, setPage] = useState(Number(init.get('page')) || 1)
  const [data, setData] = useState<CveList | null>(null)
  const [kev, setKev] = useState<Feed<KevItem> | null>(null)
  const [top, setTop] = useState<Feed<EpssItem> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  const dq = useDebounced(q.trim(), 600)
  // A GHSA / OSV style ID, or a GitHub advisory URL, links straight to its advisory page.
  const gh = q.trim().match(/github\.com\/([\w.-]+\/[\w.-]+)\/security\/advisories\/(GHSA(?:-[a-z0-9]{4}){3})/i)
  const advId = gh ? gh[2].toLowerCase().replace('ghsa', 'GHSA') : ADV_RE.test(q.trim()) && !/^CVE-/i.test(q.trim()) ? normAdv(q.trim()) : null
  const [advInfo, setAdvInfo] = useState<Advisory | null>(null)
  const intents = classify(q)
  const advHref = advId ? `/${advId}${gh ? `?repo=${gh[1]}` : ''}` : null
  const narrow = matchMedia('(max-width: 40rem)').matches

  useEffect(() => {
    setAdvInfo(null)
    if (!advId) return
    const ac = new AbortController()
    const h = setTimeout(() => getAdvisory(advId, gh?.[1], ac.signal).then(setAdvInfo).catch(() => {}), 400)
    return () => { clearTimeout(h); ac.abort() }
  }, [advId, gh?.[1]])

  useEffect(() => {
    const p = new URLSearchParams()
    if (tab !== 'search') p.set('tab', tab)
    if (tab === 'search' && dq) p.set('q', dq)
    if (tab === 'search' && severity) p.set('severity', severity)
    if (tab === 'search' && year) p.set('year', year)
    if (tab === 'search' && sort) p.set('sort', sort)
    if (page > 1) p.set('page', String(page))
    history.replaceState(null, '', p.size ? `?${p}` : location.pathname)
  }, [tab, dq, severity, year, sort, page])

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    const fail = (e: Error) => { if (e.name !== 'AbortError') { setError(e.message === 'rate_limited' ? 'rate' : 'loadFail'); setLoading(false) } }
    if (tab === 'search') searchCves(dq, severity, page, ac.signal, year, sort).then((d) => { setData(d); setLoading(false) }).catch(fail)
    else if (tab === 'kev') getKev(page, ac.signal).then((d) => { setKev(d); setLoading(false) }).catch(fail)
    else getEpssTop(page, ac.signal).then((d) => { setTop(d); setLoading(false) }).catch(fail)
    return () => ac.abort()
  }, [tab, dq, severity, year, sort, page, nonce])

  const feed = tab === 'search' ? data : tab === 'kev' ? kev : top
  const pageCount = feed ? Math.ceil(feed.total / feed.perPage) : 0
  const sevOptions = [
    { value: '', label: t('all') }, { value: 'CRITICAL', label: t('critical') }, { value: 'HIGH', label: t('high') },
    { value: 'MEDIUM', label: t('medium') }, { value: 'LOW', label: t('low') },
  ]

  return (
    <main className="page">
      <div className="top">
        <h1>{t('title')}</h1>
        <div className="actions"><LangSwitch /><ThemeSwitch theme={theme} onThemeChange={onThemeChange} iconOnly /></div>
      </div>
      <p className="lead">{t('lead')}</p>
      <nav className="tags" style={{ display: 'flex', gap: '1rem', margin: '-.5rem 0 1rem', fontSize: '.875rem' }}><Link href="/pkg">{t('navPkg')}</Link><Link href="/scan">{t('navScan')}</Link><Link href="/stats">{t('navStats')}</Link><Link href="/docs">{t('navDocs')}</Link></nav>

      <div className="tabs" style={{ marginBottom: '1rem' }}>
        <SegmentedControl label="View" value={tab} onValueChange={(v) => { setTab(v as Tab); setPage(1) }}
          options={[{ value: 'search', label: t('tabSearch') }, { value: 'kev', label: t('tabKev') }, { value: 'epss', label: t('tabEpss') }]} />
      </div>

      {tab === 'search' ? (
        <div className="controls">
          <div className="grow">
            <SearchField autoComplete="off" spellCheck={false} label={t('searchLabel')} placeholder={t('searchPh')} value={q} onValueChange={(v) => { setQ(v); setPage(1) }} />
          </div>
          <SegmentedControl label={t('severity')} options={sevOptions} value={severity} onValueChange={(v) => { setSeverity(v); setPage(1) }} />
          <Select label={t('year')} value={year || '_'} onValueChange={(v) => { setYear(v === '_' ? '' : v); setPage(1) }} options={[{ value: '_', label: t('anyYear') }, ...Array.from({ length: new Date().getFullYear() - 1998 }, (_, i) => String(new Date().getFullYear() - i)).map((y) => ({ value: y, label: y }))]} />
          <Select label={t('sortBy')} value={sort || '_'} onValueChange={(v) => { setSort(v === '_' ? '' : v); setPage(1) }} options={[{ value: '_', label: t('sortNew') }, { value: 'score', label: t('sortScore') }, { value: 'epss', label: t('sortEpss') }, { value: 'modified', label: t('sortModified') }]} />
        </div>
      ) : (
        <p className="lead" style={{ marginTop: 0 }}>{t(tab === 'kev' ? 'kevLead' : 'epssLead')}</p>
      )}

      {intents.length > 0 && <div className="card" style={{ margin: '0 0 .75rem', display: 'grid', gap: '.25rem' }}>
        {intents.map((it) => <p key={it.href} style={{ margin: 0 }}><Link href={it.href}>{t(it.kind === 'pkg' ? 'openPkg' : it.kind === 'vendor' ? 'openVendor' : it.kind === 'cwe' ? 'openCwe' : 'openCve', { x: it.label })}</Link></p>)}
      </div>}
      {tab === 'search' && !intents.length && !advId && <ProductSuggest q={dq} />}
      {advHref && <div className="card" style={{ margin: '0 0 .75rem' }}>
        <p style={{ margin: 0 }}><Link href={advHref}>{t('openAdv', { id: advId! })}</Link></p>
        <p className="tags" style={{ margin: '.25rem 0 0' }}>{advInfo?.summary || t(gh ? 'advRepoHint' : 'advHint')}{advInfo?.severity && ` (${t(advInfo.severity.toLowerCase() as 'critical')})`}</p>
      </div>}
      <div className="meta" aria-live="polite">
        {error ? '' : loading ? t('searching') : feed && t(tab === 'search' && !dq && data?.live ? 'recent' : 'results', { n: feed.total.toLocaleString() })}
      </div>

      {error ? (
        <EmptyState title={t('errorTitle')} description={t(error as 'rate')} action={<Button onClick={() => setNonce((n) => n + 1)}>{t('retry')}</Button>} />
      ) : loading && !feed ? (
        <Skeleton label={t('searching')} lines={6} />
      ) : feed && feed.items.length === 0 ? (
        <div className="empty-art"><EmptyState icon={<EmptyArt />} title={t('noneTitle')} description={t('none')} /></div>
      ) : (
        <div className="list" style={{ opacity: loading ? 0.6 : 1, transition: 'opacity .15s' }}>
          {tab === 'search' && data && <DataTable key="s" data={data.items} columns={cveColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} initialVisibility={narrow ? { package: false, description: false, epss: false, published: false } : {}} />}
          {tab === 'kev' && kev && <DataTable key="k" data={kev.items} columns={kevColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} initialVisibility={narrow ? { description: false, due: false, vendor: false, added: false, ransomware: false } : { ransomware: false, due: false }} />}
          {tab === 'epss' && top && <DataTable key="e" data={top.items} columns={epssColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} />}
        </div>
      )}

      {pageCount > 1 && (
        <div className="pager">
          <Pagination page={page} pageCount={Math.min(pageCount, 500)} onPageChange={(p) => { setPage(p); scrollTo({ top: 0 }) }} />
        </div>
      )}
    </main>
  )
}
