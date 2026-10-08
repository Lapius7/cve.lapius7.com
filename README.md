# Vulnerability.DB (cve.lapius7.com)

A fast, bilingual (English / 日本語) CVE search service. Search by CVE ID or keyword, and open any vulnerability at `/{lang}/vulns/{id}` for a detailed page that aggregates several public sources.

## Features

- Search by CVE ID or keyword, filter by severity and year, sort by date, score or EPSS
- Detail page with CVSS base metrics, EPSS score and trend, CISA KEV status, weaknesses (CWE), timeline, affected packages and links to every page that describes the vulnerability
- Japanese support: descriptions from JVN iPedia, with machine translation as a fallback
- Language in the URL (`/en/...`, `/ja/...`), `Accept-Language` redirect, hreflang
- Light / dark theme that survives reload
- Per-page OGP tags rendered on the server
- All CVEs cached in MySQL (full sync, then incremental sync), with a live NVD fallback until the first sync finishes

## Data sources

| Source | Used for |
| --- | --- |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE records, CVSS, references |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability and trend |
| [CVE.org](https://www.cve.org/) | Affected products, solutions, credits |
| [OSV](https://osv.dev/) | Affected packages and fixed versions |
| [GitHub Advisories](https://github.com/advisories) | Package advisories |
| [JVN iPedia](https://jvndb.jvn.jp/) | Japanese descriptions |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness names |
| [MyMemory](https://mymemory.translated.net/) | Machine translation fallback |

Data belongs to the respective providers. Check each provider's terms before redistributing it.

## Stack

Vite, React, TypeScript, Tailwind CSS v4, [shadcn/ui](https://ui.shadcn.com/), [Arc](https://uiarc.dev/), Express, MySQL 8.

## Getting started

Requirements: Node.js 22+, MySQL 8 (or Docker).

```bash
npm install
cp .env.example .env        # then edit it
docker compose up -d        # optional: local MySQL on 127.0.0.1:3307
npm run sync:daily          # KEV + EPSS
npm run sync:full           # all CVEs from NVD (resumable)
npm run dev                 # Vite on :5173, proxies /api to :3100
npm run server              # API on 127.0.0.1:3100
```

Tables are created automatically on startup. Until `sync:full` finishes, search falls back to the NVD API directly.

## Configuration

| Variable | Description |
| --- | --- |
| `PORT` | API port (default `3100`) |
| `SITE_URL` | Public origin used for canonical and OGP URLs |
| `NVD_API_KEY` | Optional. [Free key](https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit from 5 to 50 requests per 30 s |
| `MYSQL_HOST` `MYSQL_PORT` `MYSQL_USER` `MYSQL_PASSWORD` `MYSQL_DATABASE` | MySQL connection |
| `SYNC` | Set to `0` to disable the in-process sync scheduler |

## Sync

| Command | What it does |
| --- | --- |
| `npm run sync:full` | Imports every CVE from NVD. Resumes where it stopped. About 16 minutes with a key to over an hour without |
| `npm run sync:inc` | Imports CVEs modified since the last sync |
| `npm run sync:daily` | Refreshes CISA KEV and EPSS |

In production the server runs incremental sync every 2 hours and the daily sync every 24 hours. Older CVEs rarely change, so per-CVE extras (CVE.org, OSV, JVN) are cached for 30 days, newer ones for 1 day.

## Production

```bash
npm run build
npm start                   # serves dist/ and /api on 127.0.0.1:3100
```

Put a reverse proxy (nginx, Caddy) in front and set `SITE_URL`.

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/cves?q=&severity=&year=&kev=1&sort=&page=` | Search. `sort` is `new`, `score`, `epss` or `modified` |
| `GET /api/cves/:id` | One CVE |
| `GET /api/cves/:id/extra` | EPSS, KEV, CVE.org, OSV, GitHub Advisories, JVN |
| `GET /api/cwe/:n` | CWE name |
| `GET /api/feed/kev?page=` | Known exploited vulnerabilities |
| `GET /api/feed/epss?page=` | Highest EPSS scores |
| `GET /api/translate/:id` | Japanese machine translation |
| `GET /api/status` | Cached CVE count and sync state |
