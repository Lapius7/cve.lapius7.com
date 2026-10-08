import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react'
import { isJaPath, navigate, stripLang, usePath, withLang } from '@/lib/router'

export type Lang = 'en' | 'ja'

const dict = {
  en: {
    title: 'Vulnerability.DB',
    lead: 'Search vulnerabilities by CVE ID or keyword. Aggregated from NVD, CISA KEV, EPSS, CVE.org, OSV, GitHub Advisories and JVN.',
    tabSearch: 'Search', tabKev: 'Known exploited', tabEpss: 'Most likely exploited',
    searchLabel: 'Search CVEs', searchPh: 'CVE-2021-44228 or a keyword such as openssl',
    severity: 'Severity', all: 'All', critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
    searching: 'Searching…', results: '{n} results', recent: '{n} results published in the last 30 days',
    kevLead: 'Vulnerabilities confirmed as exploited in the wild (CISA KEV), newest first.',
    epssLead: 'CVEs with the highest chance of exploitation in the next 30 days (EPSS).',
    errorTitle: 'Something went wrong', retry: 'Retry', rate: 'NVD is rate limiting requests. Try again in a moment.', loadFail: 'Could not load data.',
    noneTitle: 'No matching CVEs', none: 'Try a different keyword, or clear the severity filter.',
    exploited: 'Exploited', colId: 'CVE', colPackage: 'Package', colSeverity: 'Severity', colScore: 'CVSS', colEpss: 'EPSS', colPublished: 'Published', colAdded: 'Added', colDue: 'Due', colDesc: 'Description', colVendor: 'Vendor', colProduct: 'Product', columns: 'Columns', noPackage: 'Not listed yet', ransomware: 'Ransomware', prob: 'Exploit probability',
    back: 'All vulnerabilities', notFound: 'CVE not found', notInNvd: '{id} is not in the NVD.', loadCve: 'Could not load this CVE', tryLater: 'Try again in a moment.',
    knownExploited: 'Known exploited', description: 'Description', machine: 'Machine translated', jvnSource: 'Japanese description from JVN iPedia',
    translating: 'Translating…', showOriginal: 'Show English original',
    dates: 'Dates', datesText: 'Published {p}, last modified {m}', cvss: 'CVSS {v}', weak: 'Weaknesses',
    epss: 'Exploit prediction (EPSS, {d})', epssText: '{s}% chance of exploitation in the next 30 days, higher than {p}% of all CVEs.', epssTrend: '30 day trend',
    kev: 'CISA known exploited', kevAdded: 'Added {a}, due {d}', kevRansom: 'used in ransomware campaigns',
    jvn: 'JVN iPedia (Japanese)', jvnImpact: 'Impact', jvnSolution: 'Solution',
    affected: 'Affected products (CVE.org, {a})', solution: 'Solution', workaround: 'Workaround', credits: 'Credits',
    ghsa: 'GitHub Security Advisories', patched: 'fixed in {v}', noPatch: 'no fix listed',
    osv: 'Affected packages (OSV)', alias: 'also known as {a}',
    sevScore: 'Severity', outOf: 'out of 10', cvssMetrics: 'CVSS base metrics', vec: 'Vector', epssTitle: 'EPSS score', pctl: '{p}th percentile', timeline: 'Timeline', tlPub: 'Published to the NVD', tlKev: 'Added to CISA KEV', tlMod: 'Last modified', tlDue: 'KEV remediation due', pkgs: 'Package', affVer: 'Affected versions', fixVer: 'Patched versions', noInfo: 'Not available', idLabel: 'CVE ID', sources: 'Sources', crumb: 'Vulnerabilities', published: 'Published', updated: 'Updated',
    detailPages: 'Detail pages', refs: 'References ({n})', copyId: 'Copy ID', copyLink: 'Copy link', shortUrl: 'Short URL', json: 'View JSON',
    excl: '(excl.)', to: 'to',
  },
  ja: {
    title: 'Vulnerability.DB',
    lead: 'CVE番号やキーワードで脆弱性を検索できます。NVD、CISA KEV、EPSS、CVE.org、OSV、GitHub Advisories、JVN の情報をまとめて表示します。',
    tabSearch: '検索', tabKev: '悪用確認済み', tabEpss: '悪用されやすい順',
    searchLabel: 'CVEを検索', searchPh: 'CVE-2021-44228 または openssl などのキーワード',
    severity: '深刻度', all: 'すべて', critical: '緊急', high: '重要', medium: '警告', low: '注意',
    searching: '検索中…', results: '{n} 件', recent: '直近30日に公開された {n} 件',
    kevLead: '実際に悪用が確認された脆弱性 (CISA KEV)。追加日の新しい順です。',
    epssLead: '今後30日以内に悪用される確率が高い CVE (EPSS)。',
    errorTitle: 'エラーが発生しました', retry: '再試行', rate: 'NVD のレート制限に達しました。少し待ってから再試行してください。', loadFail: 'データを取得できませんでした。',
    noneTitle: '該当する CVE がありません', none: 'キーワードを変えるか、深刻度の絞り込みを解除してください。',
    exploited: '悪用確認', colId: 'CVE', colPackage: 'パッケージ', colSeverity: '深刻度', colScore: 'CVSS', colEpss: 'EPSS', colPublished: '公開日', colAdded: '追加日', colDue: '期限', colDesc: '説明', colVendor: 'ベンダー', colProduct: '製品', columns: '列', noPackage: '未掲載', ransomware: 'ランサム', prob: '悪用確率',
    back: '脆弱性一覧へ', notFound: 'CVE が見つかりません', notInNvd: '{id} は NVD にありません。', loadCve: 'この CVE を取得できませんでした', tryLater: '少し待ってから再試行してください。',
    knownExploited: '悪用確認済み', description: '概要', machine: '機械翻訳', jvnSource: 'JVN iPedia の日本語情報',
    translating: '翻訳中…', showOriginal: '英語の原文を表示',
    dates: '日付', datesText: '公開 {p}、最終更新 {m}', cvss: 'CVSS {v}', weak: '脆弱性の種類 (CWE)',
    epss: '悪用予測 (EPSS、{d})', epssText: '今後30日以内に悪用される確率は {s}% で、全 CVE の {p}% より高い値です。', epssTrend: '30日間の推移',
    kev: 'CISA 悪用確認済み', kevAdded: '追加 {a}、対応期限 {d}', kevRansom: 'ランサムウェア攻撃での使用あり',
    jvn: 'JVN iPedia (日本語)', jvnImpact: '想定される影響', jvnSolution: '対策',
    affected: '影響を受ける製品 (CVE.org, {a})', solution: '解決策', workaround: '回避策', credits: '謝辞',
    ghsa: 'GitHub セキュリティアドバイザリ', patched: '{v} で修正', noPatch: '修正版の記載なし',
    osv: '影響を受けるパッケージ (OSV)', alias: '別名 {a}',
    sevScore: '深刻度', outOf: '/ 10', cvssMetrics: 'CVSS 基本評価基準', vec: 'ベクター', epssTitle: 'EPSS スコア', pctl: '上位 {p}% 目', timeline: 'タイムライン', tlPub: 'NVD に公開', tlKev: 'CISA KEV に追加', tlMod: '最終更新', tlDue: 'KEV 対応期限', pkgs: 'パッケージ', affVer: '影響を受けるバージョン', fixVer: '修正済みバージョン', noInfo: '情報なし', idLabel: 'CVE ID', sources: '情報源', crumb: '脆弱性', published: '公開', updated: '更新',
    detailPages: '詳細ページ', refs: '参考リンク ({n})', copyId: 'IDをコピー', copyLink: 'リンクをコピー', shortUrl: '短縮URL', json: 'JSONを表示',
    excl: '(未満)', to: '〜',
  },
} as const

export type Key = keyof typeof dict.en
type Ctx = { lang: Lang; setLang: (l: Lang) => void; t: (k: Key, v?: Record<string, string | number>) => string }
const C = createContext<Ctx>(null!)

export function LangProvider({ children }: { children: ReactNode }) {
  const path = usePath()
  const lang: Lang = isJaPath(path) ? 'ja' : 'en'
  useEffect(() => { localStorage.setItem('lang', lang); document.documentElement.lang = lang }, [lang])
  const setLang = useCallback((l: Lang) => {
    const base = stripLang(location.pathname)
    navigate(withLang(base, l) + location.search, false)
  }, [])
  const t = useCallback<Ctx['t']>((k, v) => dict[lang][k].replace(/\{(\w+)\}/g, (_, n) => String(v?.[n] ?? '')), [lang])
  const value = useMemo(() => ({ lang, setLang, t }), [lang, t])
  return <C.Provider value={value}>{children}</C.Provider>
}
export const useLang = () => useContext(C)
