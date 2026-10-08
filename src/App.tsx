import { useEffect, useState } from 'react'
import { SearchX } from 'lucide-react'
import { SearchField } from '@/components/arc/search-field/search-field'
import SegmentedControl from '@/components/arc/segmented-control/segmented-control'
import { Pagination } from '@/components/arc/pagination/pagination'
import { Button } from '@/components/arc/button/button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { getEpssTop, getKev, searchCves, type EpssItem, type Feed, type KevItem, type CveList } from '@/lib/api'
import { stripLang, usePath, withLang } from '@/lib/router'
import { useLang, type Lang } from '@/lib/i18n'
import Detail from '@/Detail'
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
  const [theme, setTheme] = useState<Theme>(() =>
    (localStorage.getItem('theme') as Theme) ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('theme', theme)
  }, [theme])
  const m = stripLang(path).match(/^\/vulns\/([^/]+)\/?$/)
  return m ? <Detail id={decodeURIComponent(m[1])} theme={theme} onThemeChange={setTheme} /> : <Home theme={theme} onThemeChange={setTheme} />
}

export function LangSwitch() {
  const { lang, setLang } = useLang()
  return (
    <SegmentedControl label="Language" value={lang} onValueChange={(v) => setLang(v as Lang)}
      options={[{ value: 'en', label: 'EN' }, { value: 'ja', label: '日本語' }]} />
  )
}

type Tab = 'search' | 'kev' | 'epss'


function Home({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme) => void }) {
  const { t } = useLang()
  const init = new URLSearchParams(location.search)
  const [tab, setTab] = useState<Tab>((init.get('tab') as Tab) || 'search')
  const [q, setQ] = useState(init.get('q') ?? '')
  const [severity, setSeverity] = useState(init.get('severity') ?? '')
  const [page, setPage] = useState(Number(init.get('page')) || 1)
  const [data, setData] = useState<CveList | null>(null)
  const [kev, setKev] = useState<Feed<KevItem> | null>(null)
  const [top, setTop] = useState<Feed<EpssItem> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  const dq = useDebounced(q.trim(), 600)
  const narrow = matchMedia('(max-width: 40rem)').matches

  useEffect(() => {
    const p = new URLSearchParams()
    if (tab !== 'search') p.set('tab', tab)
    if (tab === 'search' && dq) p.set('q', dq)
    if (tab === 'search' && severity) p.set('severity', severity)
    if (page > 1) p.set('page', String(page))
    history.replaceState(null, '', p.size ? `?${p}` : location.pathname)
  }, [tab, dq, severity, page])

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    const fail = (e: Error) => { if (e.name !== 'AbortError') { setError(e.message === 'rate_limited' ? t('rate') : t('loadFail')); setLoading(false) } }
    if (tab === 'search') searchCves(dq, severity, page, ac.signal).then((d) => { setData(d); setLoading(false) }).catch(fail)
    else if (tab === 'kev') getKev(page, ac.signal).then((d) => { setKev(d); setLoading(false) }).catch(fail)
    else getEpssTop(page, ac.signal).then((d) => { setTop(d); setLoading(false) }).catch(fail)
    return () => ac.abort()
  }, [tab, dq, severity, page, nonce, t])

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

      <div style={{ marginBottom: '1rem' }}>
        <SegmentedControl label="View" value={tab} onValueChange={(v) => { setTab(v as Tab); setPage(1) }}
          options={[{ value: 'search', label: t('tabSearch') }, { value: 'kev', label: t('tabKev') }, { value: 'epss', label: t('tabEpss') }]} />
      </div>

      {tab === 'search' ? (
        <div className="controls">
          <div className="grow">
            <SearchField label={t('searchLabel')} placeholder={t('searchPh')} value={q} onValueChange={(v) => { setQ(v); setPage(1) }} />
          </div>
          <SegmentedControl label={t('severity')} options={sevOptions} value={severity} onValueChange={(v) => { setSeverity(v); setPage(1) }} />
        </div>
      ) : (
        <p className="lead" style={{ marginTop: 0 }}>{t(tab === 'kev' ? 'kevLead' : 'epssLead')}</p>
      )}

      <div className="meta" aria-live="polite">
        {error ? '' : loading ? t('searching') : feed && t(tab === 'search' && !dq ? 'recent' : 'results', { n: feed.total.toLocaleString() })}
      </div>

      {error ? (
        <EmptyState title={t('errorTitle')} description={error} action={<Button onClick={() => setNonce((n) => n + 1)}>{t('retry')}</Button>} />
      ) : loading && !feed ? (
        <Skeleton label={t('searching')} lines={6} />
      ) : feed && feed.items.length === 0 ? (
        <EmptyState icon={<SearchX size={20} />} title={t('noneTitle')} description={t('none')} />
      ) : (
        <div className="list" style={{ opacity: loading ? 0.6 : 1, transition: 'opacity .15s' }}>
          {tab === 'search' && data && <DataTable key="s" data={data.items} columns={cveColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/vulns/${c.id}`)} initialVisibility={narrow ? { description: false, epss: false } : {}} />}
          {tab === 'kev' && kev && <DataTable key="k" data={kev.items} columns={kevColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/vulns/${c.id}`)} initialVisibility={narrow ? { description: false, due: false, vendor: false } : {}} />}
          {tab === 'epss' && top && <DataTable key="e" data={top.items} columns={epssColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/vulns/${c.id}`)} />}
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
