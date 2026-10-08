# Vulnerability.DB (cve.lapius7.com)

[English](README.md) | **日本語** · 公開サイト: <https://cve.lapius7.com>

英語と日本語に対応した、高速な CVE 検索サービスです。CVE ID やキーワードで検索でき、`/{lang}/vulns/{id}` の詳細ページでは、複数の公開情報源をまとめて確認できます。

## 機能

- CVE ID やキーワードで検索。深刻度と年で絞り込み、公開日・スコア・EPSS で並べ替え
- 詳細ページに、CVSS 基本評価、EPSS スコアと推移、CISA KEV の状況、脆弱性の種類(CWE)、タイムライン、影響を受けるパッケージ、その脆弱性を解説している各ページへのリンクを表示
- 日本語対応: 説明文は JVN iPedia から取得し、なければ機械翻訳で補う
- URL に言語を含める(`/en/...`、`/ja/...`)。`Accept-Language` によるリダイレクトと hreflang に対応
- ライト/ダークテーマ(再読み込みしても保持)
- ページごとの OGP タグをサーバーで生成(`/ja/` のページは、日本語の説明があればそれを使う)
- 並べ替えと列の表示切替ができる一覧テーブル。影響を受けるパッケージ(NVD の CPE データから取得したベンダー/製品)も表示
- 短縮 URL: `/{lang}/2026102322` は `/{lang}/vulns/CVE-2026-102322` にリダイレクト。各詳細ページにコピー欄あり
- すべての CVE を MySQL にキャッシュ(全件同期のあと差分同期)。初回の同期が終わるまでは NVD を直接呼ぶ

## データソース

| ソース | 用途 |
| --- | --- |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE レコード、CVSS、参考リンク |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 悪用が確認された脆弱性 |
| [FIRST EPSS](https://www.first.org/epss/) | 悪用される確率とその推移 |
| [CVE.org](https://www.cve.org/) | 影響を受ける製品、対策、謝辞 |
| [OSV](https://osv.dev/) | 影響を受けるパッケージと修正済みバージョン |
| [GitHub Advisories](https://github.com/advisories) | パッケージ向けアドバイザリ |
| [JVN iPedia](https://jvndb.jvn.jp/) | 日本語の説明文 |
| [MITRE CWE](https://cwe.mitre.org/) | 脆弱性の種類の名前 |
| [MyMemory](https://mymemory.translated.net/) | 機械翻訳(代替) |

データの権利は各提供元に帰属します。再配布する場合は、各提供元の利用規約を確認してください。

## 技術スタック

Vite、React、TypeScript、Tailwind CSS v4、[shadcn/ui](https://ui.shadcn.com/)、[TanStack Table](https://tanstack.com/table)、[Arc](https://uiarc.dev/)、Express、MySQL 8。

## はじめかた

必要なもの: Node.js 22 以上、MySQL 8(または Docker)。

```bash
npm install
cp .env.example .env        # 作成後に編集する
docker compose up -d        # 任意: 127.0.0.1:3307 でローカル MySQL を起動
npm run sync:daily          # KEV と EPSS
npm run sync:full           # NVD から全 CVE を取得(再開可能)
npm run dev                 # :5173 で Vite を起動し、/api を :3100 に中継
npm run server              # 127.0.0.1:3100 で API を起動
```

テーブルは起動時に自動で作成されます。`sync:full` が終わるまでは、検索は NVD API を直接呼びます。

## 設定

| 変数 | 説明 |
| --- | --- |
| `PORT` | API のポート(既定値 `3100`) |
| `SITE_URL` | canonical と OGP の URL に使う公開オリジン |
| `NVD_API_KEY` | 任意。[無料のキー](https://nvd.nist.gov/developers/request-an-api-key)で、レート制限が 30 秒あたり 5 回から 50 回に上がる |
| `MYSQL_HOST` `MYSQL_PORT` `MYSQL_USER` `MYSQL_PASSWORD` `MYSQL_DATABASE` | MySQL への接続情報 |
| `SYNC` | `0` にすると、アプリ内の同期スケジューラを無効にする |
| `MYMEMORY_EMAIL` | 任意。MyMemory の `de` パラメータとして送られ、無料の翻訳枠が 1 日 5,000 文字から 50,000 文字に増える |
| `GITHUB_TOKEN` | 任意。権限(スコープ)なしのトークンで、GitHub Advisories の上限が 1 時間あたり 60 回から 5,000 回に上がる |

## 同期

| コマンド | 内容 |
| --- | --- |
| `npm run sync:full` | NVD からすべての CVE を取得する。止まった位置から再開できる。キーありで約 16 分、なしだと 1 時間以上かかる |
| `npm run sync:inc` | 前回の同期以降に更新された CVE を取得する |
| `npm run sync:daily` | CISA KEV と EPSS を更新する |

本番では、サーバーが 2 時間ごとに差分同期、24 時間ごとに日次同期を実行します。古い CVE はほとんど変わらないため、CVE ごとの追加情報(CVE.org、OSV、JVN)は 30 日、新しいものは 1 日キャッシュします。

## 本番運用

```bash
npm run build
npm start                   # dist/ と /api を 127.0.0.1:3100 で配信
```

前段にリバースプロキシ(nginx、Caddy など)を置き、`SITE_URL` を設定してください。

## API

| エンドポイント | 説明 |
| --- | --- |
| `GET /api/cves?q=&severity=&year=&kev=1&sort=&page=` | 検索。`sort` は `new`、`score`、`epss`、`modified` |
| `GET /api/cves/:id` | CVE 1 件 |
| `GET /api/cves/:id/extra` | EPSS、KEV、CVE.org、OSV、GitHub Advisories、JVN |
| `GET /api/cwe/:n` | CWE の名前 |
| `GET /api/feed/kev?page=` | 悪用が確認された脆弱性 |
| `GET /api/feed/epss?page=` | EPSS スコアが高い順 |
| `GET /api/translate/:id` | 日本語への機械翻訳 |
| `GET /api/status` | キャッシュ済みの CVE 件数と同期の状態 |
