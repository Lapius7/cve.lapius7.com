import { useEffect, useRef, useState, type ReactNode } from 'react'
import { ArrowLeft, ExternalLink } from 'lucide-react'
import { Badge } from '@/components/arc/badge/badge'
import { Button } from '@/components/arc/button/button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import Sparkline from '@/components/arc/sparkline/sparkline'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { ADV_RE, fmtDate, getCve, getExtra, getExtraJa, getRelated, getTranslation, shortId, tone, type Cve, type Extra, type ExtraJa } from '@/lib/api'
import { Link, withLang } from '@/lib/router'
import { CopyMenu } from '@/lib/CopyMenu'
import { RichText } from '@/RichText'
import { JaText } from '@/lib/jaText'
import { refTagLabel, statusLabel, versionLabel } from '@/lib/labels'
import { useLang } from '@/lib/i18n'
import { LangSwitch } from '@/App'
import { parseVector } from '@/lib/cvss'

const RefItem = ({ r }: { r: { url: string; tags: string[] } }) => {
  const { t } = useLang()
  let host = '', rest = r.url
  try { const u = new URL(r.url); host = u.hostname.replace(/^www\./, ''); rest = `${u.pathname}${u.search}`.replace(/^\/$/, '') } catch { /* keep raw */ }
  return <li><a href={r.url} target="_blank" rel="noopener noreferrer"><b>{host}</b><span className="rpath">{rest}</span></a>{r.tags.length > 0 && <span className="rtags">{r.tags.map((x) => <Badge key={x} size="sm">{refTagLabel(t, x)}</Badge>)}</span>}</li>
}

const Ext = ({ href, children }: { href: string; children: React.ReactNode }) => (
  <a href={href} target="_blank" rel="noopener noreferrer">{children} <ExternalLink size={12} style={{ display: 'inline' }} /></a>
)

export default function Detail({ id, theme, onThemeChange }: { id: string; theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t, lang } = useLang()
  const [cve, setCve] = useState<Cve | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [x, setX] = useState<Extra | null>(null)
  const [xLoaded, setXLoaded] = useState(false)
  const [tr, setTr] = useState<string | null>(null)
  const [xja, setXja] = useState<ExtraJa | null>(null)
  const [trFailed, setTrFailed] = useState(false)
  const langRef = useRef(lang)
  langRef.current = lang
  const loadedLang = useRef(lang)
  const [showEn, setShowEn] = useState(false)
  const [rel, setRel] = useState<{ sameCwe: Cve[]; sameProduct: Cve[] } | null>(null)
  const [cwe, setCwe] = useState<Record<string, string>>({})

  useEffect(() => {
    const ac = new AbortController()
    setCve(null); setErr(null); setX(null); setXLoaded(false); setTr(null); setTrFailed(false)
    loadedLang.current = langRef.current
    getRelated(id, ac.signal).then(setRel).catch(() => {})
    getExtra(id, ac.signal).then(setX).catch(() => {}).finally(() => setXLoaded(true))
    getCve(id, ac.signal).then(setCve).catch((e) => e.name !== 'AbortError' && setErr(e.message))
    return () => ac.abort()
  }, [id])

  // Switching language only swaps text: no refetch, no skeleton.
  useEffect(() => { document.title = `${id} | ${t('title')}` }, [id, t])

  useEffect(() => {
    setCwe({})
    for (const w of cve?.cwes ?? []) if (/^CWE-\d+$/.test(w)) fetch(`/api/cwe/${w.slice(4)}`).then((r) => r.json()).then((d) => d.name && setCwe((c) => ({ ...c, [w]: d.name }))).catch(() => {})
  }, [cve])

  // Japanese fallback: machine translate only when JVN has no entry.
  useEffect(() => {
    setXja(null)
    if (lang !== 'ja' || !xLoaded || !(x?.kev || x?.cveorg)) return
    const ac = new AbortController()
    getExtraJa(id, ac.signal).then(setXja).catch(() => {})
    return () => ac.abort()
  }, [lang, xLoaded, id])

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
  if (!cve) return <main className="page">{top}<Skeleton label={t('aLoading')} lines={6} /></main>

  const sev = (s: string) => t(s.toLowerCase() as 'critical')
  const jvn = x?.jvn
  const jaText = lang === 'ja' && !showEn ? (jvn?.overview ?? tr) : null
  // Japanese view: never flash the English original while the Japanese text is still on its way.
  const jaPending = lang === 'ja' && loadedLang.current === 'ja' && !showEn && !jaText && !trFailed && (!xLoaded || needTr)
  const origin = location.origin
  const shortUrl = `${origin}${withLang(`/${shortId(cve.id)}`)}`
  const links = [
    { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cve.id}` },
    { label: 'CVE.org', url: `https://www.cve.org/CVERecord?id=${cve.id}` },
    ...(jvn ? [{ label: 'JVN iPedia', url: jvn.url }] : []),
    { label: 'OSV', url: `https://osv.dev/vulnerability/${cve.id}` },
    { label: 'EPSS', url: `https://www.first.org/epss/?cve=${cve.id}` },
    { label: t('searchPoc'), url: `https://github.com/search?q=${cve.id}&type=repositories` },
    { label: t('searchEdb'), url: `https://www.exploit-db.com/search?cve=${cve.id.replace(/^CVE-/, '')}` },
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

  const days = (a: string, b: string) => Math.max(0, Math.round((new Date(b).getTime() - new Date(a).getTime()) / 86400_000))
  const refsBy = (tag: string) => cve.references.filter((r) => r.tags.includes(tag))
  const exploitRefs = refsBy('Exploit')
  const fixGroups = ([['Patch', 'refPatch'], ['Vendor Advisory', 'refVendor'], ['Mitigation', 'refMitigation'], ['Release Notes', 'refRelease'], ['US Government Resource', 'refGov']] as const)
    .map(([tag, key]) => ({ key, items: refsBy(tag) })).filter((g) => g.items.length > 0)
  const hasFix = fixGroups.some((g) => g.key === 'refPatch' || g.key === 'refVendor') || pk.some((p) => p.fixed)
  const reasons: { tone: 'danger' | 'warning' | 'success' | 'neutral'; text: string; pts: number }[] = []
  if (cve.kev) reasons.push({ tone: 'danger', text: t('rKev'), pts: 3 })
  if (x?.kev?.ransomware) reasons.push({ tone: 'danger', text: t('rRansom'), pts: 1 })
  if (e && e.score >= 0.5) reasons.push({ tone: 'danger', text: t('rEpssHigh', { p: (e.score * 100).toFixed(1) }), pts: 2 })
  else if (e && e.score >= 0.1) reasons.push({ tone: 'warning', text: t('rEpssMid', { p: (e.score * 100).toFixed(1) }), pts: 1 })
  if (cve.severity === 'CRITICAL') reasons.push({ tone: 'danger', text: t('rSevCrit'), pts: 2 })
  else if (cve.severity === 'HIGH') reasons.push({ tone: 'warning', text: t('rSevHigh'), pts: 1 })
  if (exploitRefs.length > 0) reasons.push({ tone: 'warning', text: t('rExploit', { n: exploitRefs.length }), pts: 1 })
  const pts = reasons.reduce((n, r) => n + r.pts, 0)
  if (pts === 0) reasons.unshift({ tone: 'neutral', text: t('rNone'), pts: 0 })
  reasons.push(hasFix ? { tone: 'success', text: t('rPatch'), pts: 0 } : { tone: 'neutral', text: t('rNoPatch'), pts: 0 })
  const prio = pts >= 5 ? { k: 'prioUrgent', tone: 'danger' } as const : pts >= 3 ? { k: 'prioHigh', tone: 'warning' } as const : pts >= 1 ? { k: 'prioMid', tone: 'info' } as const : { k: 'prioLow', tone: 'neutral' } as const
  const kevGap = x?.kev ? days(cve.published, x.kev.added) : null

  const enc = encodeURIComponent
  const vendors = [...new Set(cve.products.map((p) => p.vendor))].slice(0, 3)
  type Topic = { href: string; label: ReactNode; kev?: boolean }
  const topicGroups: { key: 'tgGeneral' | 'tgWeak' | 'tgVendor' | 'tgPkg'; items: Topic[] }[] = [
    { key: 'tgGeneral' as const, items: [
      ...(cve.severity ? [{ href: `/?severity=${cve.severity}`, label: sev(cve.severity) }] : []),
      ...(cve.kev ? [{ href: '/?tab=kev', label: 'KEV', kev: true }] : []),
      { href: `/?year=${cve.published.slice(0, 4)}`, label: cve.published.slice(0, 4) },
    ] },
    { key: 'tgWeak' as const, items: cve.cwes.filter((w) => /^CWE-\d+$/.test(w)).map((w) => ({ href: `/cwe/${w}`, label: cwe[w] ? <>{w} <JaText text={cwe[w]} /></> : w })) },
    { key: 'tgVendor' as const, items: vendors.map((v) => ({ href: `/vendor/${enc(v)}`, label: v })) },
    { key: 'tgPkg' as const, items: pk.slice(0, 3).map((p) => ({ href: `/pkg/${enc(p.eco)}/${enc(p.name)}`, label: `${p.eco ? `${p.eco}/` : ''}${p.name}` })) },
  ].filter((g) => g.items.length > 0)

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
          <Badge>{statusLabel(t, cve.status)}</Badge>
          <span className="tags">{cve.id} · {t('published')} {fmtDate(cve.published)} · {t('updated')} {fmtDate(cve.modified)}</span>
        </div>
        <div className="topics">{topicGroups.map((g) => <div key={g.key} className="trow"><span className="tlabel">{t(g.key)}</span><div className="tscroll">{g.items.map((x) => <Link key={x.href} href={x.href} className={x.kev ? 'topic kev' : 'topic'}>{x.label}</Link>)}</div></div>)}</div>
        <div className="actions"><CopyMenu id={cve.id} url={shortUrl} /></div>
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
          <section className="card prio">
            <h3>{t('prio')}</h3>
            <p className="prio-level"><Badge tone={prio.tone}>{t(prio.k)}</Badge></p>
            <p className="tags">{t('prioWhy')}</p>
            <ul className="prio-why">{reasons.map((r, i) => <li key={i}><Badge tone={r.tone} size="sm">{r.text}</Badge></li>)}</ul>
          </section>
          <section className="card">
            <h3>{t('description')}</h3>
            {jaPending ? <p className="tags">{t('translating')}</p> : <RichText text={jaText ?? cve.description} lead />}
            {jaText && <p className="rt-src"><Badge size="sm">{jvn?.overview ? t('jvnSource') : t('machine')}</Badge><button className="lnk" onClick={() => setShowEn(true)}>{t('showOriginal')}</button></p>}
            {showEn && <button className="lnk" onClick={() => setShowEn(false)}>日本語</button>}
          </section>

          {lang === 'ja' && jvn && (jvn.impact || jvn.solution.length > 0) && <section className="card">
            <h3>{t('jvn')}</h3>
            {jvn.impact && <><p className="tags">{t('jvnImpact')}</p><RichText text={jvn.impact} /></>}
            {jvn.solution.map((s, i) => <div key={i}><p className="tags" style={{ marginTop: '.75rem' }}>{t('jvnSolution')}</p><RichText text={s} /></div>)}
          </section>}

          {x?.kev && <section className="card">
            <h3>{t('kev')}</h3>
            <p className="kev-title"><strong>{x.kev.vendor} {x.kev.product}</strong>: {(lang === 'ja' && xja?.kevName) || x.kev.name}</p>
            <div className="kev-meta">
              <span className="kv"><b>{t('kevAddedL')}</b>{x.kev.added}</span>
              <span className="kv"><b>{t('kevDueL')}</b>{x.kev.due}</span>
              {x.kev.ransomware && <Badge tone="warning" size="sm">{t('kevRansom')}</Badge>}
            </div>
            <RichText text={(lang === 'ja' && xja?.kevAction) || x.kev.action} />
          </section>}

          {x?.cveorg && x.cveorg.solutions.length > 0 && <section className="card"><h3>{t('solution')}</h3><RichText text={x.cveorg.solutions.map((v, i) => (lang === 'ja' && xja?.solutions[i]) || v).join('\n')} /></section>}
          {x?.cveorg && x.cveorg.workarounds.length > 0 && <section className="card"><h3>{t('workaround')}</h3><RichText text={x.cveorg.workarounds.map((v, i) => (lang === 'ja' && xja?.workarounds[i]) || v).join('\n')} /></section>}

          {x?.cveorg && x.cveorg.affected.length > 0 && <section className="card">
            <h3>{t('affected', { a: x.cveorg.assigner ?? '' })}</h3>
            <ul className="aff">{x.cveorg.affected.slice(0, 10).map((a, i) => <li key={i}>
              <strong>{a.vendor} {a.product}</strong>
              <div className="vchips">{a.versions.slice(0, 8).map((v, j) => <span key={j} className="vchip" data-s={v.status}>{v.version}{v.lessThan ? ` ${t('to')} ${v.lessThan}${v.orEqual ? '' : ` ${t('excl')}`}` : ''}<i>{versionLabel(t, v.status)}</i></span>)}{a.versions.length > 8 && <span className="tags">+{a.versions.length - 8}</span>}</div>
            </li>)}</ul>
            {x.cveorg.affected.length > 10 && <details className="more"><summary>+{x.cveorg.affected.length - 10}</summary>
              <ul className="aff">{x.cveorg.affected.slice(10).map((a, i) => <li key={i}>
                <strong>{a.vendor} {a.product}</strong>
                <div className="vchips">{a.versions.slice(0, 8).map((v, j) => <span key={j} className="vchip" data-s={v.status}>{v.version}{v.lessThan ? ` ${t('to')} ${v.lessThan}${v.orEqual ? '' : ` ${t('excl')}`}` : ''}<i>{versionLabel(t, v.status)}</i></span>)}</div>
              </li>)}</ul></details>}
          </section>}

          {x && x.ghsa.length > 0 && <section className="card">
            <h3>{t('ghsa')}</h3>
            <ul>{x.ghsa.map((g) => <li key={g.id}><Ext href={g.url}>{g.id}</Ext> <span className="tags"><JaText text={g.summary} /></span>
              <ul style={{ margin: '.25rem 0 0 .75rem' }}>{g.vulns.map((v, i) => <li key={i} className="tags"><Badge size="sm">{v.ecosystem}</Badge> <code>{v.name}</code> {v.range && <span>{v.range}</span>} · {v.patched ? t('patched', { v: v.patched }) : t('noPatch')}</li>)}</ul></li>)}</ul>
          </section>}

          {x?.osv && x.osv.packages.length > 0 && <section className="card">
            <h3>{t('osv')}{x.osv.aliases.length > 0 && `, ${t('alias', { a: x.osv.aliases.join(', ') })}`}</h3>
            <ul>{x.osv.packages.map((p, i) => <li key={i}>{p.ecosystem}: <code>{p.name}</code>{p.fixed.length > 0 && <span className="tags"> {t('patched', { v: p.fixed.join(', ') })}</span>}</li>)}</ul>
          </section>}

          {exploitRefs.length > 0 && <section className="card">
            <h3>{t('exploitTitle')} <span className="tags">{exploitRefs.length}</span></h3>
            <p className="tags">{t('exploitLead')}</p>
            <ul className="refs">{exploitRefs.slice(0, 5).map((r, i) => <RefItem key={i} r={r} />)}</ul>
            {exploitRefs.length > 5 && <details className="more"><summary>+{exploitRefs.length - 5}</summary><ul className="refs">{exploitRefs.slice(5).map((r, i) => <RefItem key={i} r={r} />)}</ul></details>}
          </section>}

          {fixGroups.length > 0 && <section className="card">
            <h3>{t('fixTitle')}</h3>
            {fixGroups.map((g) => <div key={g.key} className="fixg">
              <p className="tags">{t(g.key)} · {g.items.length}</p>
              <ul className="refs">{g.items.slice(0, 4).map((r, i) => <RefItem key={i} r={{ ...r, tags: [] }} />)}</ul>
              {g.items.length > 4 && <details className="more"><summary>+{g.items.length - 4}</summary><ul className="refs">{g.items.slice(4).map((r, i) => <RefItem key={i} r={{ ...r, tags: [] }} />)}</ul></details>}
            </div>)}
          </section>}

          <section className="card">
            <h3>{t('detailPages')}</h3>
            <div className="chips">{links.map((l) => <a key={l.label} href={l.url} target="_blank" rel="noopener noreferrer"><Badge size="sm">{l.label}</Badge></a>)}</div>
          </section>

          <section className="card">
            <h3>{t('refs', { n: String(cve.references.length) })}</h3>
            <ul className="refs">{cve.references.slice(0, 8).map((r, i) => <RefItem key={i} r={r} />)}</ul>
            {cve.references.length > 8 && <details className="more"><summary>+{cve.references.length - 8}</summary><ul className="refs">{cve.references.slice(8).map((r, i) => <RefItem key={i} r={r} />)}</ul></details>}
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
            <ul>{cve.cwes.map((w) => <li key={w}><a href={/^CWE-\d+$/.test(w) ? `https://cwe.mitre.org/data/definitions/${w.slice(4)}.html` : undefined} target="_blank" rel="noopener noreferrer"><Badge size="sm">{w}</Badge></a>{cwe[w] && <span className="tags"> <JaText text={cwe[w]} /></span>}</li>)}</ul>
          </section>}

          <section className="card">
            <h3>{t('timeline')}</h3>
            <ol className="tl">{timeline.map((s, i) => <li key={i}><b>{fmtDate(s.d)}</b><span>{s.l}</span></li>)}{x?.kev?.due && <li><b>{fmtDate(x.kev.due)}</b><span>{t('tlDue')}</span></li>}</ol>
            <p className="tags tl-sum">{t('tlAge', { n: days(cve.published, new Date().toISOString()) })}{kevGap != null && <><br />{t('tlKevGap', { n: kevGap })}</>}</p>
          </section>

          <section className="card">
            <h3>{t('idLabel')}</h3>
            <p><Ext href={`https://www.cve.org/CVERecord?id=${cve.id}`}><code>{cve.id}</code></Ext></p>
            {x?.osv && x.osv.aliases.length > 0 && <ul className="aliases">{x.osv.aliases.map((al) => <li key={al}>{al === cve.id || !(ADV_RE.test(al) || /^CVE-\d{4}-\d{4,}$/i.test(al)) ? al : <Link href={`/${al}`}>{al}</Link>}</li>)}</ul>}
            {x?.cveorg && x.cveorg.credits.length > 0 && <><h3 style={{ marginTop: '1rem' }}>{t('credits')}</h3><ul>{x.cveorg.credits.map((c, i) => <li key={i}>{c}</li>)}</ul></>}
          </section>
          {rel && (rel.sameProduct.length > 0 || rel.sameCwe.length > 0) && <section className="card">
            <h3>{t('related')}</h3>
            {([['relProduct', rel.sameProduct], ['relCwe', rel.sameCwe]] as const).filter(([, l]) => l.length > 0).map(([k, l]) => <div key={k}>
              <p className="tags" style={{ margin: '.5rem 0 .25rem' }}>{t(k)}</p>
              <ul>{l.slice(0, 5).map((c) => <li key={c.id}><Link href={`/${c.id}`}>{c.id}</Link>{c.severity && <> <Badge tone={tone(c.severity)} size="sm">{t(c.severity.toLowerCase() as 'critical')}</Badge></>}</li>)}</ul>
            </div>)}
          </section>}
          <section className="card">
            <h3>{t('formats')}</h3>
            <p className="tags"><a href={`/${lang}/${cve.id}.json`}>JSON</a> · <a href={`/${lang}/${cve.id}.md`}>Markdown</a> · <a href={`/badge/${cve.id}.svg`}>{t('badge')}</a> · <a href={`/embedbuilder/${lang}/${cve.id}`}>{t('embed')}</a></p>
          </section>
        </aside>
      </div>
    </main>
  )
}
