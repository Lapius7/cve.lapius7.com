import { Skeleton } from '@/components/arc/skeleton/skeleton'
import type { Theme } from '@/components/arc/theme-switch/theme-switch'
import { Link } from '@/lib/router'
import { useLang } from '@/lib/i18n'
import { Fail, Shell, useLoad } from '@/Explore'

type Row = { severity?: string; month?: string; cwe?: string; vendor?: string; count: number }
interface Stats { total: number; kev: number; avgScore: number | null; severity: Row[]; monthly: Row[]; kevMonthly: Row[]; topCwes: Row[]; topVendors: Row[] }

function Bars({ rows, label, href }: { rows: { key: string; count: number; to?: string }[]; label: string; href?: boolean }) {
  const max = Math.max(1, ...rows.map((r) => r.count))
  return (
    <div className="bars" role="list" aria-label={label}>
      {rows.map((r) => (
        <div className="bar" role="listitem" key={r.key}>
          <span className="bl">{href && r.to ? <Link href={r.to}>{r.key}</Link> : r.key}</span>
          <span className="bt"><i style={{ width: `${(r.count / max) * 100}%` }} /></span>
          <span className="bn">{r.count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}

export default function StatsPage({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t } = useLang()
  const { data, err, loading } = useLoad<Stats>((s) => fetch('/api/stats', { signal: s }).then((r) => { if (!r.ok) throw new Error(String(r.status)); return r.json() }), [])
  return (
    <Shell title={t('statsTitle')} crumb={t('statsLead')} theme={theme} onThemeChange={onThemeChange}>
      {err ? <Fail err={err} /> : loading || !data ? <Skeleton label={t('searching')} lines={6} /> : (
        <>
          <div className="strip">
            <div><span className="k">{t('statsTotal')}</span><b>{data.total.toLocaleString()}</b></div>
            <div><span className="k">{t('statsKev')}</span><b>{data.kev.toLocaleString()}</b></div>
            <div><span className="k">{t('statsAvg')}</span><b>{data.avgScore ?? '-'}</b></div>
          </div>
          <div className="statgrid">
            <section><h2 className="sh">{t('statsSeverity')}</h2>
              <Bars label={t('statsSeverity')} rows={['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => ({ key: t(s.toLowerCase() as 'critical'), count: data.severity.find((r) => r.severity === s)?.count ?? 0 }))} /></section>
            <section><h2 className="sh">{t('statsTopCwe')}</h2>
              <Bars href label={t('statsTopCwe')} rows={data.topCwes.slice(0, 10).map((r) => ({ key: r.cwe!, count: r.count, to: `/cwe/${r.cwe!.replace(/\D/g, '')}` }))} /></section>
            <section><h2 className="sh">{t('statsTopVendor')}</h2>
              <Bars href label={t('statsTopVendor')} rows={data.topVendors.slice(0, 10).map((r) => ({ key: r.vendor!, count: r.count, to: `/vendor/${encodeURIComponent(r.vendor!)}` }))} /></section>
            <section><h2 className="sh">{t('statsMonthly')}</h2>
              <Bars label={t('statsMonthly')} rows={data.monthly.slice(-12).map((r) => ({ key: r.month!, count: r.count }))} /></section>
            <section><h2 className="sh">{t('statsKevMonthly')}</h2>
              <Bars label={t('statsKevMonthly')} rows={data.kevMonthly.slice(-12).map((r) => ({ key: r.month!, count: r.count }))} /></section>
          </div>
        </>
      )}
    </Shell>
  )
}
