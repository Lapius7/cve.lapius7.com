import { useMemo, useRef, useState } from 'react'
import { ArrowLeft, Upload } from 'lucide-react'
import { Badge } from '@/components/arc/badge/badge'
import { Button } from '@/components/arc/button/button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { scanPackages, tone, type ScanResult } from '@/lib/api'
import { parseManifest } from '@/lib/sbom'
import { Link } from '@/lib/router'
import { useLang } from '@/lib/i18n'
import { LangSwitch } from '@/App'

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const rank = (s?: string | null) => { const i = SEV.indexOf(s ?? 'UNKNOWN'); return i < 0 ? 4 : i }

export default function ScanPage({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t } = useLang()
  const [text, setText] = useState('')
  const [file, setFile] = useState('')
  const [res, setRes] = useState<ScanResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [drag, setDrag] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const parsed = useMemo(() => parseManifest(text, file), [text, file])

  const load = async (f: File) => {
    if (f.size > 20_000_000) { setErr('tooBig'); return }
    setFile(f.name); setText(await f.text()); setRes(null); setErr(null)
  }
  const run = async () => {
    setBusy(true); setErr(null); setRes(null)
    try { setRes(await scanPackages(parsed.packages)) } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const rows = useMemo(() => res && [...res.packages]
    .map((p) => ({ ...p, top: Math.min(...p.vulns.map((v) => rank(res.vulns[v]?.severity))) }))
    .sort((a, b) => a.top - b.top || b.vulns.length - a.vulns.length), [res])

  return (
    <main className="page">
      <div className="top" style={{ marginBottom: '1rem' }}>
        <Link href="/" className="back" style={{ margin: 0 }}><ArrowLeft size={14} /> {t('title')}</Link>
        <div className="actions"><LangSwitch /><ThemeSwitch theme={theme} onThemeChange={onThemeChange} iconOnly /></div>
      </div>
      <h1 className="dh" style={{ fontVariantNumeric: 'normal' }}>{t('scanTitle')}</h1>
      <p className="lead">{t('scanLead')}</p>

      <div className="scanbox" data-drag={drag} onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) void load(f) }}>
        <textarea aria-label={t('scanLabel')} value={text} spellCheck={false} placeholder={t('scanPh')}
          onChange={(e) => { setText(e.target.value); setFile(''); setRes(null) }} />
        <div className="scanbar">
          <Button variant="secondary" type="button" onClick={() => input.current?.click()}><Upload data-icon="inline-start" size={14} /> {t('scanFile')}</Button>
          <input ref={input} type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) void load(f); e.target.value = '' }} />
          <span className="tags" style={{ flex: 1 }} aria-live="polite">
            {text.trim() ? (parsed.packages.length ? t('scanDetected', { f: parsed.format, n: parsed.packages.length.toLocaleString() }) : t('scanUnknown')) : t('scanFormats')}
          </span>
          <Button type="button" disabled={!parsed.packages.length || busy} onClick={run}>{busy ? t('searching') : t('scanRun')}</Button>
        </div>
      </div>
      <p className="tags" style={{ marginTop: '.5rem' }}>{t('scanPrivacy')}{parsed.packages.length > 3000 && ` ${t('scanCap')}`}</p>

      {err ? <EmptyState title={t('errorTitle')} description={err === 'rate_limited' ? t('rate') : t('loadFail')} />
        : busy ? <Skeleton label={t('searching')} lines={5} />
        : res && rows && (
          <section style={{ marginTop: '1.25rem' }} aria-live="polite">
            <div className="strip">
              <div><span className="k">{t('scanScanned')}</span><b>{res.summary.scanned.toLocaleString()}</b></div>
              <div><span className="k">{t('scanVulnPkgs')}</span><b>{res.summary.vulnerablePackages.toLocaleString()}</b></div>
              <div><span className="k">{t('scanVulns')}</span><b>{res.summary.vulnerabilities.toLocaleString()}</b></div>
            </div>
            <div className="chips" style={{ margin: '.75rem 0' }}>
              {SEV.filter((s) => res.summary.severity[s]).map((s) => <Badge key={s} tone={tone(s)} size="sm">{s === 'UNKNOWN' ? t('unknown') : t(s.toLowerCase() as 'critical')} {res.summary.severity[s]}</Badge>)}
            </div>
            {res.summary.truncated && <p className="tags">{t('scanTrunc')}</p>}
            {rows.length === 0 ? <EmptyState title={t('scanClean')} description="" /> : (
              <div className="list">
                {rows.map((p) => (
                  <details key={`${p.ecosystem}${p.name}${p.version}`} className="scanrow">
                    <summary>
                      <span className="id">{p.name}<span className="tags"> {p.version}</span></span>
                      <span className="score"><Badge tone={tone(SEV[p.top] ?? null)} size="sm">{p.top >= 4 ? t('unknown') : t(SEV[p.top].toLowerCase() as 'critical')}</Badge> {p.vulns.length}</span>
                    </summary>
                    <ul>
                      {[...p.vulns].sort((a, b) => rank(res.vulns[a]?.severity) - rank(res.vulns[b]?.severity)).map((id) => {
                        const v = res.vulns[id]
                        return <li key={id}><Link href={`/${id}`}>{id}</Link>{v?.severity && <> <Badge tone={tone(v.severity)} size="sm">{t(v.severity.toLowerCase() as 'critical')}</Badge></>} <span className="tags">{v?.summary}{v?.fixed.length ? ` · ${t('fixedIn')} ${v.fixed.join(', ')}` : ''}</span></li>
                      })}
                    </ul>
                  </details>
                ))}
              </div>
            )}
          </section>
        )}
    </main>
  )
}
