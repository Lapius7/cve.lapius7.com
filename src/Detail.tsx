import { useEffect, useState } from 'react'
import { ArrowLeft, ExternalLink } from 'lucide-react'
import { Badge } from '@/components/arc/badge/badge'
import { Button } from '@/components/arc/button/button'
import { CopyButton } from '@/components/arc/copy-button/copy-button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import Sparkline from '@/components/arc/sparkline/sparkline'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { fmtDate, getCve, getExtra, getTranslation, tone, type Cve, type Extra } from '@/lib/api'
import { Link, withLang } from '@/lib/router'
import { useLang } from '@/lib/i18n'
import { LangSwitch } from '@/App'
import { parseVector } from '@/lib/cvss'

const Ext = ({ href, children }: { href: string; children: React.ReactNode }) => (
  <a href={href} target="_blank" rel="noopener noreferrer">{children} <ExternalLink size={12} style={{ display: 'inline' }} /></a>
)

export default function Detail({ id, theme, onThemeChange }: { id: string; theme: Theme; onThemeChange: (t: Theme) => void }) {
  const { t, lang } = useLang()
  const [cve, setCve] = useState<Cve | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [x, setX] = useState<Extra | null>(null)
  const [xLoaded, setXLoaded] = useState(false)
  const [tr, setTr] = useState<string | null>(null)
  const [trFailed, setTrFailed] = useState(false)
  const [showEn, setShowEn] = useState(false)
  const [cwe, setCwe] = useState<Record<string, string>>({})

  useEffect(() => {
    const ac = new AbortController()
    setCve(null); setErr(null); setX(null); setXLoaded(false); setTr(null); setTrFailed(false)
    document.title = `${id} | ${t('title')}`
    getExtra(id, ac.signal).then(setX).catch(() => {}).finally(() => setXLoaded(true))
    getCve(id, ac.signal).then(setCve).catch((e) => e.name !== 'AbortError' && setErr(e.message))
    return () => ac.abort()
  }, [id, t])

  useEffect(() => {
    setCwe({})
    for (const w of cve?.cwes ?? []) if (/^CWE-\d+$/.test(w)) fetch(`/api/cwe/${w.slice(4)}`).then((r) => r.json()).then((d) => d.name && setCwe((c) => ({ ...c, [w]: d.name }))).catch(() => {})
  }, [cve])

  // Japanese fallback: machine translate only when JVN has no entry.
  const needTr = lang === 'ja' && xLoaded && !x?.jvn?.overview && !!cve
  useEffect(() => {
    if (!needTr) return
    const ac = new AbortController()
    getTranslation(id, ac.signal).then((r) => setTr(r.text)).catch((e) => e.name !== 'AbortError' && setTrFailed(true))
    return () => ac.abort()
  }, [needTr, id])

  const top = (
    <div className="top" style={{ marginBottom: '1rem' }}>
      <Link href="/" className="back" style={{ margin: 0 }}><ArrowLeft size={16} /> {t('back')}</Link>
      <div className="actions"><LangSwitch /><ThemeSwitch theme={theme} onThemeChange={onThemeChange} iconOnly /></div>
    </div>
  )

  if (err) {
    const nf = err === 'not_found' || err === 'invalid_id'
    return (
      <main className="page">{top}
        <EmptyState title={nf ? t('notFound') : t('loadCve')}
          description={nf ? t('notInNvd', { id }) : err === 'rate_limited' ? t('rate') : t('tryLater')}
          action={<Button onClick={() => location.reload()}>{t('retry')}</Button>} />
      </main>
    )
  }
  if (!cve) return <main className="page">{top}<Skeleton label="Loading" lines={6} /></main>

  const sev = (s: string) => t(s.toLowerCase() as 'critical')
  const jvn = x?.jvn
  const jaText = lang === 'ja' && !showEn ? (jvn?.overview ?? tr) : null
  // Japanese view: never flash the English original while the Japanese text is still on its way.
  const jaPending = lang === 'ja' && !showEn && !jaText && !trFailed && (!xLoaded || needTr)
  const origin = location.origin
  const links = [
    { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cve.id}` },
    { label: 'CVE.org', url: `https://www.cve.org/CVERecord?id=${cve.id}` },
    ...(jvn ? [{ label: 'JVN iPedia', url: jvn.url }] : []),
    { label: 'OSV', url: `https://osv.dev/vulnerability/${cve.id}` },
    { label: 'EPSS', url: `https://www.first.org/epss/?cve=${cve.id}` },
    { label: 'MITRE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}` },
    ...(cve.kev ? [{ label: 'CISA KEV', url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve.id}` }] : []),
  ]
  const e = x?.epss
  const metrics = parseVector(cve.vector, lang === 'ja')
  const sevTone = tone(cve.severity)
  const timeline = [
    { d: cve.published, l: t('tlPub') },
    ...(x?.kev ? [{ d: x.kev.added, l: t('tlKev') }] : []),
    { d: cve.modified, l: t('tlMod') },
  ].sort((a, b) => a.d.localeCompare(b.d))
  const pk = [
    ...(x?.ghsa ?? []).flatMap((g) => g.vulns.map((v) => ({ eco: v.ecosystem, name: v.name, range: v.range, fixed: v.patched }))),
    ...(x?.osv?.packages ?? []).filter((p) => p.name).map((p) => ({ eco: p.ecosystem ?? '', name: p.name!, range: '', fixed: p.fixed.join(', ') || null })),
  ].filter((p, i, a) => a.findIndex((q) => q.name === p.name && q.eco === p.eco) === i)

  return (
    <main className="page wide">
      <nav className="crumb">
        <Link href="/">{t('crumb')}</Link><span>/</span><span>{cve.id}</span>
      </nav>
      {top}
      <header className="dhead">
        <h1 className="dh">{lang === 'ja' && jvn?.title ? jvn.title : cve.id}</h1>
        <div className="chips">
          {cve.severity && <Badge tone={sevTone}>{sev(cve.severity)}</Badge>}
          {cve.kev && <Badge tone="danger">{t('knownExploited')}</Badge>}
          <Badge>{cve.status}</Badge>
          <span className="tags">{cve.id} · {t('published')} {fmtDate(cve.published)} · {t('updated')} {fmtDate(cve.modified)}</span>
        </div>
        <div className="actions">
          <CopyButton value={cve.id} label={t('copyId')} />
          <CopyButton value={`${origin}${withLang(`/vulns/${cve.id}`)}`} label={t('copyLink')} />
        </div>
      </header>

      {(pk.length > 0 || (x?.cveorg?.affected.length ?? 0) > 0) && (
        <div className="strip">
          <div><span className="k">{t('pkgs')}</span><span>{pk[0] ? <code>{pk[0].eco ? `${pk[0].eco}/` : ''}{pk[0].name}</code> : `${x!.cveorg!.affected[0].vendor} ${x!.cveorg!.affected[0].product}`}{pk.length > 1 && <span className="tags"> +{pk.length - 1}</span>}</span></div>
          <div><span className="k">{t('affVer')}</span><span>{pk[0]?.range || x?.cveorg?.affected[0]?.versions.map((v) => `${v.version}${v.lessThan ? ` ${t('to')} ${v.lessThan}` : ''}`).slice(0, 2).join(', ') || t('noInfo')}</span></div>
          <div><span className="k">{t('fixVer')}</span><span>{pk.find((p) => p.fixed)?.fixed ?? t('noPatch')}</span></div>
        </div>
      )}

      <div className="dgrid">
        <div className="dmain detail">
          <section className="card">
            <h3>{t('description')}</h3>
            {jaPending ? <p className="tags">{t('translating')}</p> : <p>{jaText ?? cve.description}</p>}
            {jaText && <p className="tags">{jvn?.overview ? t('jvnSource') : t('machine')}{' '}<button className="lnk" onClick={() => setShowEn(true)}>{t('showOriginal')}</button></p>}
            {showEn && <button className="lnk" onClick={() => setShowEn(false)}>日本語</button>}
          </section>

          {lang === 'ja' && jvn && (jvn.impact || jvn.solution.length > 0) && <section className="card">
            <h3>{t('jvn')}</h3>
            {jvn.impact && <><p className="tags">{t('jvnImpact')}</p><p>{jvn.impact}</p></>}
            {jvn.solution.map((s, i) => <div key={i}><p className="tags" style={{ marginTop: '.75rem' }}>{t('jvnSolution')}</p><p>{s}</p></div>)}
          </section>}

          {x?.kev && <section className="card">
            <h3>{t('kev')}</h3>
            <p>{x.kev.vendor} {x.kev.product}: {x.kev.name}{'\n'}{t('kevAdded', { a: x.kev.added, d: x.kev.due })}{x.kev.ransomware ? `, ${t('kevRansom')}` : ''}{'\n'}{x.kev.action}</p>
          </section>}

          {x?.cveorg && x.cveorg.solutions.length > 0 && <section className="card"><h3>{t('solution')}</h3><p>{x.cveorg.solutions.join('\n\n')}</p></section>}
          {x?.cveorg && x.cveorg.workarounds.length > 0 && <section className="card"><h3>{t('workaround')}</h3><p>{x.cveorg.workarounds.join('\n\n')}</p></section>}

          {x?.cveorg && x.cveorg.affected.length > 0 && <section className="card">
            <h3>{t('affected', { a: x.cveorg.assigner ?? '' })}</h3>
            <ul>{x.cveorg.affected.map((a, i) => <li key={i}><strong style={{ fontWeight: 500 }}>{a.vendor} {a.product}</strong> <span className="tags">{a.versions.map((v) => `${v.version}${v.lessThan ? ` ${t('to')} ${v.lessThan}${v.orEqual ? '' : ` ${t('excl')}`}` : ''} ${v.status}`).join('; ')}</span></li>)}</ul>
          </section>}

          {x && x.ghsa.length > 0 && <section className="card">
            <h3>{t('ghsa')}</h3>
            <ul>{x.ghsa.map((g) => <li key={g.id}><Ext href={g.url}>{g.id}</Ext> <span className="tags">{g.summary}</span>
              <ul style={{ margin: '.25rem 0 0 .75rem' }}>{g.vulns.map((v, i) => <li key={i} className="tags">{v.ecosystem}: <code>{v.name}</code> {v.range} {v.patched ? t('patched', { v: v.patched }) : t('noPatch')}</li>)}</ul></li>)}</ul>
          </section>}

          {x?.osv && x.osv.packages.length > 0 && <section className="card">
            <h3>{t('osv')}{x.osv.aliases.length > 0 && `, ${t('alias', { a: x.osv.aliases.join(', ') })}`}</h3>
            <ul>{x.osv.packages.map((p, i) => <li key={i}>{p.ecosystem}: <code>{p.name}</code>{p.fixed.length > 0 && <span className="tags"> {t('patched', { v: p.fixed.join(', ') })}</span>}</li>)}</ul>
          </section>}

          <section className="card">
            <h3>{t('detailPages')}</h3>
            <div className="chips">{links.map((l) => <a key={l.label} href={l.url} target="_blank" rel="noopener noreferrer"><Badge size="sm">{l.label}</Badge></a>)}</div>
          </section>

          <section className="card">
            <h3>{t('refs', { n: String(cve.references.length) })}</h3>
            <ul>{cve.references.map((r, i) => <li key={i}><Ext href={r.url}>{r.url}</Ext>{r.tags.length > 0 && <span className="tags"> {r.tags.join(', ')}</span>}</li>)}</ul>
          </section>
        </div>

        <aside className="dside">
          <section className="card">
            <h3>{t('sevScore')}</h3>
            <div className="score" data-tone={sevTone}><b>{cve.score?.toFixed(1) ?? '-'}</b><span>{t('outOf')}</span>{cve.severity && <Badge tone={sevTone}>{sev(cve.severity)}</Badge>}</div>
            {metrics.length > 0 && <>
              <h3 style={{ marginTop: '1rem' }}>{t('cvssMetrics')} <span className="tags">{cve.cvssVersion}</span></h3>
              <dl className="metrics">{metrics.map((m) => <div key={m.name}><dt>{m.name}</dt><dd data-l={m.level}>{m.value}</dd></div>)}</dl>
            </>}
            {cve.vector && <><h3 style={{ marginTop: '1rem' }}>{t('vec')}</h3><code>{cve.vector}</code></>}
          </section>

          {e && <section className="card">
            <h3>{t('epssTitle')}</h3>
            <div className="score"><b>{(e.score * 100).toFixed(2)}%</b><span>{t('pctl', { p: String(Math.max(1, Math.round((1 - e.percentile) * 100))) })}</span></div>
            {e.series.length > 2 && <div style={{ marginTop: '.5rem' }}><Sparkline label={t('epssTrend')} data={e.series.map((p) => p.score * 100)} labels={e.series.map((p) => p.date)} formatValue={(v) => `${v.toFixed(2)}%`} width={260} height={56} /></div>}
          </section>}

          {cve.cwes.length > 0 && <section className="card">
            <h3>{t('weak')}</h3>
            <ul>{cve.cwes.map((w) => <li key={w}><a href={/^CWE-\d+$/.test(w) ? `https://cwe.mitre.org/data/definitions/${w.slice(4)}.html` : undefined} target="_blank" rel="noopener noreferrer"><Badge size="sm">{w}</Badge></a>{cwe[w] && <span className="tags"> {cwe[w]}</span>}</li>)}</ul>
          </section>}

          <section className="card">
            <h3>{t('timeline')}</h3>
            <ol className="tl">{timeline.map((s, i) => <li key={i}><b>{fmtDate(s.d)}</b><span>{s.l}</span></li>)}{x?.kev?.due && <li><b>{fmtDate(x.kev.due)}</b><span>{t('tlDue')}</span></li>}</ol>
          </section>

          <section className="card">
            <h3>{t('idLabel')}</h3>
            <p><code>{cve.id}</code></p>
            {x?.osv && x.osv.aliases.length > 0 && <p className="tags">{x.osv.aliases.join(', ')}</p>}
            {x?.cveorg && x.cveorg.credits.length > 0 && <><h3 style={{ marginTop: '1rem' }}>{t('credits')}</h3><p>{x.cveorg.credits.join(', ')}</p></>}
          </section>
        </aside>
      </div>
    </main>
  )
}
