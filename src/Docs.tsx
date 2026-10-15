import type { Theme } from '@/components/arc/theme-switch/theme-switch'
import { useLang } from '@/lib/i18n'
import { Link } from '@/lib/router'
import { Shell } from '@/Explore'

const SEARCH: [string, string, string][] = [
  ['CVE-2021-44228', 'CVE', '/CVE-2021-44228'],
  ['GHSA-jfh8-c2jp-5v3q', 'GitHub Advisory', '/GHSA-jfh8-c2jp-5v3q'],
  ['CWE-79', 'CWE', '/cwe/79'],
  ['lodash@4.17.15', 'npm', '/pkg/npm/lodash?version=4.17.15'],
  ['pypi:django==3.2', 'PyPI', '/pkg/pypi/django?version=3.2'],
  ['org.apache.logging.log4j:log4j-core:2.14.1', 'Maven', '/pkg/maven/org.apache.logging.log4j:log4j-core?version=2.14.1'],
  ['cargo:serde', 'crates.io', '/pkg/crates/serde'],
  ['pkg:npm/%40babel/core@7.0.0', 'purl', '/pkg/npm/@babel/core?version=7.0.0'],
  ['cpe:2.3:a:apache:log4j:*', 'CPE 2.3', '/vendor/apache/log4j'],
]
const FILES = ['package-lock.json (v1/v2/v3)', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt (==)', 'Cargo.lock', 'poetry.lock / pdm.lock / uv.lock', 'go.mod', 'Gemfile.lock', 'composer.lock', 'CycloneDX JSON', 'SPDX JSON', 'purl']
const ECO = 'npm, pypi, go, crates, maven, nuget, rubygems, packagist, hex, pub, actions'

const T = {
  ja: {
    title: 'ドキュメント', lead: '検索の書き方、URL の形式、API、埋め込みの使い方です。認証は不要です。',
    s1: '検索できる入力', s1p: '検索欄に次のような文字列を入れると、該当ページへの候補を表示します。',
    inp: '入力例', kind: '種類', s2: '診断できるファイル', s2p: '/scan にファイルを貼り付けるかドロップします。解析はブラウザ内で行い、送信するのはパッケージ名とバージョンだけです。1 回あたり最大 3,000 個です。',
    s3: 'URL の形式', s4: 'API', s4p: '読み取り専用で認証は不要です。連続して送らず、1 秒に数回までにしてください。仕様は /api/openapi.json で取得できます。',
    s5: 'バッジと埋め込み', s5p: 'README やサイトに貼り付けられます。ダークテーマは ?theme=dark を付けます。', ep: 'エンドポイント', desc: '内容',
    d: { cves: 'CVE の検索 (q, severity, sort, year, kev, page)', cve: 'CVE の詳細', rel: '同じ CWE・製品の CVE', pkg: 'パッケージの脆弱性 (?version=、毎分 30 回まで)', scan: 'パッケージ一覧を一括診断 (POST、毎分 10 回まで)', ven: 'ベンダーと製品', cwe: 'CWE ごとの CVE', st: '統計', pr: '製品の候補 (?q=)' },
  },
  en: {
    title: 'Docs', lead: 'How to search, URL formats, the API and embeds. No authentication needed.',
    s1: 'What you can search', s1p: 'Type any of these into the search box to get a link to the matching page.',
    inp: 'Input', kind: 'Type', s2: 'Files you can check', s2p: 'Paste or drop a file on /scan. Files are parsed in your browser and only package names and versions are sent. Up to 3,000 packages per run.',
    s3: 'URL formats', s4: 'API', s4p: 'Read-only, no authentication. Keep to a few requests per second. The spec is at /api/openapi.json.',
    s5: 'Badges and embeds', s5p: 'Paste into a README or a site. Add ?theme=dark for dark mode.', ep: 'Endpoint', desc: 'Description',
    d: { cves: 'Search CVEs (q, severity, sort, year, kev, page)', cve: 'CVE detail', rel: 'CVEs with the same CWE or product', pkg: 'Vulnerabilities of a package (?version=, 30/min)', scan: 'Check a list of packages (POST, 10/min)', ven: 'Vendors and products', cwe: 'CVEs by CWE', st: 'Statistics', pr: 'Product suggestions (?q=)' },
  },
} as const

export default function DocsPage({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { lang } = useLang()
  const x = T[lang === 'ja' ? 'ja' : 'en']
  const api: [string, string][] = [
    ['GET /api/cves', x.d.cves], ['GET /api/cves/{id}', x.d.cve], ['GET /api/cves/{id}/related', x.d.rel],
    ['GET /api/pkg/{ecosystem}/{name}', x.d.pkg], ['POST /api/scan', x.d.scan], ['GET /api/vendors/{vendor}[/{product}]', x.d.ven],
    ['GET /api/cwe/{id}/cves', x.d.cwe], ['GET /api/stats', x.d.st], ['GET /api/products', x.d.pr],
    ['GET /api/advisories', lang === 'ja' ? '保存済みのアドバイザリを検索' : 'Search stored advisories'],
    ['GET /api/trending', lang === 'ja' ? 'よく見られた項目と検索語（集計のみ）' : 'Most viewed items and searches (aggregates only)'],
  ]
  return (
    <Shell title={x.title} crumb={x.lead} theme={theme} onThemeChange={onThemeChange}>
      <div className="doc">
        <h2>{x.s1}</h2><p>{x.s1p}</p>
        <div className="tw"><table><thead><tr><th>{x.inp}</th><th>{x.kind}</th></tr></thead><tbody>
          {SEARCH.map(([q, k, to]) => <tr key={q}><td><code>{q}</code></td><td><Link href={to}>{k}</Link></td></tr>)}
        </tbody></table></div>
        <p>ecosystem: <code>{ECO}</code></p>

        <h2>{x.s2}</h2><p>{x.s2p} <Link href="/scan">/scan</Link></p>
        <ul>{FILES.map((f) => <li key={f}><code>{f}</code></li>)}</ul>

        <h2>{x.s3}</h2>
        <pre><code>{`/CVE-2021-44228          CVE
/GHSA-jfh8-c2jp-5v3q     GitHub Advisory
/pkg/npm/lodash?version=4.17.15
/pkg/maven/group:artifact
/vendor/apache/log4j
/cwe/79
/scan   /stats   /docs
/ja/CVE-2021-44228.json   /ja/CVE-2021-44228.md`}</code></pre>

        <h2>{x.s4}</h2><p>{x.s4p}</p>
        <div className="tw"><table><thead><tr><th>{x.ep}</th><th>{x.desc}</th></tr></thead><tbody>
          {api.map(([e, d]) => <tr key={e}><td><code>{e}</code></td><td>{d}</td></tr>)}
        </tbody></table></div>
        <pre><code>{`curl 'https://vulns.lapius7.com/api/pkg/npm/lodash?version=4.17.15'

curl -X POST https://vulns.lapius7.com/api/scan \\
  -H 'content-type: application/json' \\
  -d '{"packages":[{"ecosystem":"npm","name":"lodash","version":"4.17.15"}]}'`}</code></pre>

        <h2>{x.s5}</h2>
        <pre><code>{`![CVE](https://vulns.lapius7.com/badge/CVE-2021-44228.svg)
![lodash](https://vulns.lapius7.com/badge/pkg/npm/lodash.svg)
<iframe src="https://vulns.lapius7.com/embed/CVE-2021-44228" width="480" height="180"></iframe>`}</code></pre>
      </div>
    </Shell>
  )
}
