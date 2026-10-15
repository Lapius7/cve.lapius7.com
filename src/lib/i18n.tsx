import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react'
import { isJaPath, navigate, stripLang, usePath, withLang } from '@/lib/router'

export type Lang = 'en' | 'ja'

const dict = {
  en: {
    title: 'Vulnerability.DB',
    lead: 'Search vulnerabilities by CVE ID or keyword. Aggregated from NVD, CISA KEV, EPSS, CVE.org, OSV, GitHub Advisories and JVN.',
    tabSearch: 'Search', tabKev: 'Known exploited', tabEpss: 'Most likely exploited',
    searchLabel: 'Search vulnerabilities', searchPh: 'CVE-2021-44228, GHSA-…, CWE-79, npm:lodash@4.17.15, pkg:pypi/django, cpe:2.3:a:…, or a keyword',
    severity: 'Severity', all: 'All', critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
    searching: 'Searching…', results: '{n} results', recent: '{n} results published in the last 30 days',
    kevLead: 'Vulnerabilities confirmed as exploited in the wild (CISA KEV), newest first.',
    epssLead: 'CVEs with the highest chance of exploitation in the next 30 days (EPSS).',
    errorTitle: 'Something went wrong', retry: 'Retry', rate: 'NVD is rate limiting requests. Try again in a moment.', loadFail: 'Could not load data.',
    noneTitle: 'No matching vulnerabilities', none: 'Try a different keyword, or clear the severity filter.',
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
    openAdv: 'Open advisory {id}', advHint: 'Advisory ID. Open it to see the details, affected packages and fixed versions.', advRepoHint: 'Repository advisory. Opens the advisory published on that GitHub repository.', withdrawn: 'Withdrawn', notInOsv: '{id} is not in OSV or GitHub Advisories yet. For an advisory published only on a repository, paste its github.com/…/security/advisories/… URL into the search box.',
    fixedIn: 'Fixed in', unknown: 'Unrated', openPkg: 'Check package vulnerabilities: {x}', openVendor: 'Open product: {x}', openCwe: 'Open weakness: {x}', openCve: 'Open {x}', suggestProducts: 'Products', scanTitle: 'Check dependencies', scanLead: 'Paste or drop a lockfile or SBOM to list known vulnerabilities in your dependencies.', scanLabel: 'Lockfile or SBOM', scanPh: 'Paste package-lock.json, requirements.txt, Cargo.lock, go.mod, Gemfile.lock, CycloneDX, SPDX or a list of purls', scanFile: 'Choose file', scanDetected: '{f}: {n} packages', scanUnknown: 'Format not recognised', scanFormats: 'package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Cargo.lock, go.mod, Gemfile.lock, composer.lock, CycloneDX, SPDX, purl', scanRun: 'Check', scanPrivacy: 'Files are parsed in your browser. Only package names and versions are sent.', scanCap: 'Only the first 3,000 packages are checked.', scanScanned: 'Packages checked', scanVulnPkgs: 'Vulnerable packages', scanVulns: 'Vulnerabilities', scanTrunc: 'Some vulnerabilities are not shown in detail.', scanClean: 'No known vulnerabilities found.', navScan: 'Check dependencies', statsTitle: 'Statistics', statsLead: 'An overview of the vulnerabilities in this database.', statsTotal: 'Total CVEs', statsKev: 'Known exploited (KEV)', statsAvg: 'Average CVSS', statsSeverity: 'By severity', statsTopCwe: 'Top CWEs', statsTopVendor: 'Top vendors', statsMonthly: 'Published per month', statsKevMonthly: 'KEV added per month', navStats: 'Statistics', navDocs: 'Docs', year: 'Year', anyYear: 'Any year', sortBy: 'Sort', sortModified: 'Recently updated', related: 'Related', relProduct: 'Same product', relCwe: 'Same weakness', formats: 'Other formats', badge: 'Badge', embed: 'Embed', navPkg: 'Packages', pkgTitle: '{name} vulnerabilities', pkgLead: 'Known vulnerabilities for {eco} packages, from OSV and GitHub Advisories.', pkgEco: 'Ecosystem', pkgName: 'Package name', pkgVer: 'Version (optional)', pkgGo: 'Check', pkgNone: 'No known vulnerabilities{v}.', pkgTotal: '{n} advisories', pkgBadge: 'Badge', pkgHint: 'Enter a package name to check it.',
    vendorTitle: '{vendor} products', productTitle: '{vendor} / {product}', sortNew: 'Newest', sortScore: 'Highest score', sortEpss: 'Most likely exploited', cweTitle: '{id} vulnerabilities', cweOpen: 'About this weakness', prodMore: 'Products',
  },
  ja: {
    title: 'Vulnerability.DB',
    lead: 'CVE番号やキーワードで脆弱性を検索できます。NVD、CISA KEV、EPSS、CVE.org、OSV、GitHub Advisories、JVN の情報をまとめて表示します。',
    tabSearch: '検索', tabKev: '悪用確認済み', tabEpss: '悪用されやすい順',
    searchLabel: '脆弱性を検索', searchPh: 'CVE-2021-44228、GHSA-…、CWE-79、npm:lodash@4.17.15、pkg:pypi/django、cpe:2.3:a:…、またはキーワード',
    severity: '深刻度', all: 'すべて', critical: '緊急', high: '重要', medium: '警告', low: '注意',
    searching: '検索中…', results: '{n} 件', recent: '直近30日に公開された {n} 件',
    kevLead: '実際に悪用が確認された脆弱性 (CISA KEV)。追加日の新しい順です。',
    epssLead: '今後30日以内に悪用される確率が高い CVE (EPSS)。',
    errorTitle: 'エラーが発生しました', retry: '再試行', rate: 'NVD のレート制限に達しました。少し待ってから再試行してください。', loadFail: 'データを取得できませんでした。',
    noneTitle: '該当する脆弱性がありません', none: 'キーワードを変えるか、深刻度の絞り込みを解除してください。',
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
    openAdv: 'アドバイザリ {id} を開く', advHint: 'アドバイザリの ID です。開くと詳細、影響を受けるパッケージ、修正版を確認できます。', advRepoHint: 'リポジトリのアドバイザリです。そのGitHubリポジトリで公開されている内容を表示します。', withdrawn: '取り下げ済み', notInOsv: '{id} はまだ OSV / GitHub Advisories にありません。リポジトリだけで公開されたものは、github.com/…/security/advisories/… の URL を検索欄に貼ると表示できます。',
    fixedIn: '修正版', unknown: '未評価', openPkg: 'パッケージの脆弱性を調べる: {x}', openVendor: '製品を開く: {x}', openCwe: '弱点を開く: {x}', openCve: '{x} を開く', suggestProducts: '製品', scanTitle: '依存関係の診断', scanLead: 'ロックファイルや SBOM を貼り付けるかドロップすると、依存パッケージの既知の脆弱性を一覧にします。', scanLabel: 'ロックファイルまたは SBOM', scanPh: 'package-lock.json、requirements.txt、Cargo.lock、go.mod、Gemfile.lock、CycloneDX、SPDX、purl の一覧を貼り付けます', scanFile: 'ファイルを選択', scanDetected: '{f}: {n} 個のパッケージ', scanUnknown: '形式を認識できません', scanFormats: 'package-lock.json、yarn.lock、pnpm-lock.yaml、requirements.txt、Cargo.lock、go.mod、Gemfile.lock、composer.lock、CycloneDX、SPDX、purl', scanRun: '診断する', scanPrivacy: 'ファイルはブラウザ内で解析します。送信するのはパッケージ名とバージョンだけです。', scanCap: '先頭の 3,000 個だけ診断します。', scanScanned: '診断したパッケージ', scanVulnPkgs: '脆弱なパッケージ', scanVulns: '脆弱性', scanTrunc: '一部の脆弱性は詳細を表示していません。', scanClean: '既知の脆弱性は見つかりませんでした。', navScan: '依存関係の診断', statsTitle: '統計', statsLead: 'このデータベースにある脆弱性の概要です。', statsTotal: 'CVE の総数', statsKev: '悪用が確認された脆弱性 (KEV)', statsAvg: '平均 CVSS', statsSeverity: '深刻度別', statsTopCwe: '多い CWE', statsTopVendor: '多いベンダー', statsMonthly: '月ごとの公開数', statsKevMonthly: '月ごとの KEV 追加数', navStats: '統計', navDocs: 'ドキュメント', year: '公開年', anyYear: 'すべての年', sortBy: '並び順', sortModified: '更新が新しい順', related: '関連', relProduct: '同じ製品', relCwe: '同じ弱点', formats: '他の形式', badge: 'バッジ', embed: '埋め込み', navPkg: 'パッケージ', pkgTitle: '{name} の脆弱性', pkgLead: '{eco} パッケージの既知の脆弱性です。OSV と GitHub Advisory から取得しています。', pkgEco: 'エコシステム', pkgName: 'パッケージ名', pkgVer: 'バージョン（任意）', pkgGo: '調べる', pkgNone: '既知の脆弱性はありません{v}。', pkgTotal: '{n} 件のアドバイザリ', pkgBadge: 'バッジ', pkgHint: 'パッケージ名を入力して調べます。',
    vendorTitle: '{vendor} の製品', productTitle: '{vendor} / {product}', sortNew: '新しい順', sortScore: 'スコア順', sortEpss: '悪用されやすい順', cweTitle: '{id} の脆弱性', cweOpen: 'この弱点について', prodMore: '製品',
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
