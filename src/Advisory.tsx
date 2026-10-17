import { useEffect, useState } from 'react'
import { ArrowLeft, ExternalLink } from 'lucide-react'
import { Badge } from '@/components/arc/badge/badge'
import { Button } from '@/components/arc/button/button'
import { CopyMenu } from '@/lib/CopyMenu'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { fmtDate, getAdvisory, getAdvisoryTr, tone, type Advisory } from '@/lib/api'
import Markdown from '@/Markdown'
import { Link, withLang } from '@/lib/router'
import { useLang } from '@/lib/i18n'
import { LangSwitch } from '@/App'

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function AdvisoryDetail({ id, theme, onThemeChange }: { id: string; theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t, lang } = useLang()
  const [tr, setTr] = useState<{ summary: string; details: string } | null>(null)
  const [showEn, setShowEn] = useState(false)
  const [a, setA] = useState<Advisory | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    const ac = new AbortController()
    setA(null); setErr(null)
    getAdvisory(id, new URLSearchParams(location.search).get('repo') ?? undefined, ac.signal).then(setA).catch((e) => e.name !== 'AbortError' && setErr(e.message))
    return () => ac.abort()
  }, [id])
  useEffect(() => {
    setTr(null)
    if (lang !== 'ja' || !a) return
    const ac = new AbortController()
    getAdvisoryTr(id, new URLSearchParams(location.search).get('repo') ?? undefined, ac.signal).then(setTr).catch(() => {})
    return () => ac.abort()
  }, [lang, a, id])
  useEffect(() => { document.title = `${id} | ${t('title')}` }, [id, t])

  const top = (
    <div className="top" style={{ marginBottom: '1rem' }}>
      <Link href="/" className="back" style={{ margin: 0 }}><ArrowLeft size={16} /> {t('back')}</Link>
      <div className="actions"><LangSwitch /><ThemeSwitch theme={theme} onThemeChange={onThemeChange} iconOnly /></div>
    </div>
  )

  if (err) {
    const nf = err === 'not_found' || err === 'invalid_id' || err === '404'
    return (
      <main className="page">{top}
        <EmptyState title={nf ? t('notFound') : t('loadCve')} description={nf ? t('notInOsv', { id }) : t('tryLater')}
          action={<Button onClick={() => location.reload()}>{t('retry')}</Button>} />
      </main>
    )
  }
  if (!a) return <main className="page">{top}<Skeleton label={t('aLoading')} lines={6} /></main>

  const sev = a.severity && SEV.includes(a.severity) ? a.severity : null
  const repo = new URLSearchParams(location.search).get('repo')
  const shortUrl = `${location.origin}${withLang(`/${a.id.startsWith('GHSA-') ? a.id.replace(/-/g, '') : a.id}`)}${repo ? `?${repo}` : ''}`
  const ja = lang === 'ja' && !showEn && tr
  const cves = a.aliases.filter((x) => /^CVE-\d{4}-\d{4,}$/i.test(x))
  const others = a.aliases.filter((x) => !cves.includes(x))

  return (
    <main className="page wide">
      <nav className="crumb"><Link href="/">{t('crumb')}</Link><span>/</span><span>{a.id}</span></nav>
      {top}
      <header className="dhead">
        <h1 className="dh">{(ja ? tr.summary : '') || a.summary || a.id}</h1>
        <div className="chips">
          {sev && <Badge tone={tone(sev)}>{t(sev.toLowerCase() as 'critical')}</Badge>}
          {a.withdrawn && <Badge>{t('withdrawn')}</Badge>}
          <span className="tags">{a.id}{a.published && ` · ${t('published')} ${fmtDate(a.published)}`}{a.modified && ` · ${t('updated')} ${fmtDate(a.modified)}`}</span>
        </div>
        <div className="actions"><CopyMenu id={a.id} url={shortUrl} /></div>
      </header>

      <div className="dgrid">
        <div className="dmain detail">
          {a.details && <section className="card"><h3>{t('description')}</h3>
            {lang === 'ja' && tr && <p className="tags">{t('machine')}{' '}<button className="lnk" onClick={() => setShowEn(!showEn)}>{showEn ? '日本語' : t('showOriginal')}</button></p>}
            <div className="md"><Markdown text={ja ? tr.details : a.details} /></div></section>}

          {a.packages.length > 0 && <section className="card">
            <h3>{t('osv')}</h3>
            <ul>{a.packages.map((p, i) => <li key={i}>{p.ecosystem}: <code>{p.name}</code>{' '}
              <span className="tags">{p.ranges.join('; ')}{p.fixed.length > 0 && ` · ${t('patched', { v: p.fixed.join(', ') })}`}</span></li>)}</ul>
          </section>}
        </div>

        <aside className="dside">
          {(cves.length > 0 || others.length > 0) && <section className="card">
            <h3>{t('alias', { a: '' }).trim()}</h3>
            <ul>
              {cves.map((c) => <li key={c}><Link href={`/${c}`}>{c}</Link></li>)}
              {others.map((o) => <li key={o}><Link href={`/${o}`}>{o}</Link></li>)}
            </ul>
          </section>}

          {(a.cvss || a.cwes.length > 0) && <section className="card">
            {a.cvss && <p className="tags"><code>{a.cvss}</code></p>}
            {a.cwes.length > 0 && <p className="tags">{a.cwes.join(', ')}</p>}
          </section>}

          <section className="card">
            <h3>{t('detailPages')}</h3>
            <ul>
              <li><a href={`https://osv.dev/vulnerability/${a.id}`} target="_blank" rel="noopener noreferrer">OSV <ExternalLink size={12} style={{ display: 'inline' }} /></a></li>
              {a.id.startsWith('GHSA-') && <li><a href={`https://github.com/advisories/${a.id}`} target="_blank" rel="noopener noreferrer">GitHub <ExternalLink size={12} style={{ display: 'inline' }} /></a></li>}
            </ul>
          </section>

          {a.references.length > 0 && <section className="card">
            <h3>{t('refs', { n: a.references.length })}</h3>
            <ul>{a.references.map((r, i) => <li key={i} style={{ overflowWrap: 'anywhere' }}><a href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a></li>)}</ul>
          </section>}
        </aside>
      </div>
    </main>
  )
}
