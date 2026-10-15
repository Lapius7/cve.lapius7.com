import type express from 'express'
import { pool } from './db.ts'
import { advisory, cached } from './sources.ts'

type Wrap = (fn: (req: express.Request, res: express.Response) => Promise<unknown>) => express.RequestHandler

export async function migrateStore() {
  await pool.query(`CREATE TABLE IF NOT EXISTS advisories (
    id VARCHAR(40) NOT NULL PRIMARY KEY, summary VARCHAR(512) NOT NULL, severity VARCHAR(10) NULL, cvss VARCHAR(255) NULL,
    published DATETIME NULL, modified DATETIME NULL, aliases JSON NOT NULL, packages JSON NOT NULL, saved_at DATETIME NOT NULL,
    INDEX i_pub (published), INDEX i_sev (severity, published), FULLTEXT KEY ft_sum (id, summary)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
  await pool.query(`CREATE TABLE IF NOT EXISTS advisory_pkg (
    ecosystem VARCHAR(40) NOT NULL, name VARCHAR(214) NOT NULL, adv_id VARCHAR(40) NOT NULL,
    PRIMARY KEY (ecosystem, name, adv_id), INDEX i_adv (adv_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`)
  // Aggregate counters only: no IP, no user agent, no per-request rows.
  await pool.query(`CREATE TABLE IF NOT EXISTS usage_daily (
    day DATE NOT NULL, kind VARCHAR(12) NOT NULL, k VARCHAR(80) NOT NULL, n INT NOT NULL DEFAULT 0,
    PRIMARY KEY (day, kind, k), INDEX i_kind (kind, day)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`)
  await pool.query(`CREATE TABLE IF NOT EXISTS stats_snapshot (
    day DATE NOT NULL PRIMARY KEY, total INT NOT NULL, critical INT NOT NULL, high INT NOT NULL, kev INT NOT NULL, data JSON NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
}

// ---- advisories ----
const dt = (s: unknown) => { const d = s ? new Date(String(s)) : null; return d && !isNaN(+d) ? d.toISOString().slice(0, 19).replace('T', ' ') : null }

async function saveAdvisory(a: any) {
  if (!a?.id) return
  const pk: { ecosystem: string; name: string }[] = a.packages ?? []
  await pool.query(
    `INSERT INTO advisories (id,summary,severity,cvss,published,modified,aliases,packages,saved_at) VALUES (?,?,?,?,?,?,?,?,UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE summary=VALUES(summary), severity=VALUES(severity), cvss=VALUES(cvss), published=VALUES(published),
     modified=VALUES(modified), aliases=VALUES(aliases), packages=VALUES(packages), saved_at=VALUES(saved_at)`,
    [a.id, String(a.summary || a.details || '').split('\n')[0].slice(0, 500), a.severity ?? null, a.cvss ?? null, dt(a.published), dt(a.modified),
      JSON.stringify((a.aliases ?? []).slice(0, 20)), JSON.stringify(pk.slice(0, 30))])
  const rows = pk.filter((p) => p.ecosystem && p.name).slice(0, 30).map((p) => [String(p.ecosystem).slice(0, 40), String(p.name).slice(0, 214), a.id])
  if (rows.length) await pool.query('INSERT IGNORE INTO advisory_pkg (ecosystem,name,adv_id) VALUES ?', [rows])
}

/** Same cache as before, and every advisory we fetch is also kept in a searchable table. */
export async function cachedAdvisory(id: string, repo?: string) {
  const a = await cached(id, 'advisory', 6 * 3600_000, () => advisory(id, repo))
  if (a) void saveAdvisory(a).catch(() => {})
  return a
}

// ---- usage counters ----
const buf = new Map<string, number>()
export function hit(kind: 'view' | 'search' | 'scan' | 'pkg', k: string, n = 1) {
  k = k.trim().toLowerCase().slice(0, 80)
  if (!k) return
  const key = `${kind}\u0000${k}`
  buf.set(key, (buf.get(key) ?? 0) + n)
}
async function flush() {
  if (!buf.size) return
  const rows = [...buf].map(([key, n]) => { const [kind, k] = key.split('\u0000'); return [kind, k, n] })
  buf.clear()
  try {
    await pool.query(`INSERT INTO usage_daily (day,kind,k,n) VALUES ${rows.map(() => '(UTC_DATE(),?,?,?)').join(',')} ON DUPLICATE KEY UPDATE n=n+VALUES(n)`, rows.flat())
  } catch { for (const [kind, k, n] of rows) buf.set(`${kind}\u0000${k}`, (buf.get(`${kind}\u0000${k}`) ?? 0) + (n as number)) }
}
async function prune() {
  await pool.query("DELETE FROM usage_daily WHERE day < DATE_SUB(UTC_DATE(), INTERVAL 90 DAY)").catch(() => {})
}

// ---- stats snapshots ----
export async function saveSnapshot(v: any) {
  const c = (s: string) => Number(v.severity?.find((x: any) => x.severity === s)?.count ?? 0)
  await pool.query(
    `INSERT INTO stats_snapshot (day,total,critical,high,kev,data) VALUES (UTC_DATE(),?,?,?,?,?)
     ON DUPLICATE KEY UPDATE total=VALUES(total), critical=VALUES(critical), high=VALUES(high), kev=VALUES(kev), data=VALUES(data)`,
    [v.total, c('CRITICAL'), c('HIGH'), v.kev, JSON.stringify(v)]).catch(() => {})
}
export async function latestSnapshot(maxAgeMs: number) {
  const [r] = await pool.query<any[]>('SELECT data, UNIX_TIMESTAMP(day)*1000 AS t FROM stats_snapshot ORDER BY day DESC LIMIT 1')
  return r[0] && Date.now() - Number(r[0].t) < maxAgeMs ? (typeof r[0].data === 'string' ? JSON.parse(r[0].data) : r[0].data) : null
}
export async function history() {
  const [r] = await pool.query<any[]>("SELECT DATE_FORMAT(day,'%Y-%m-%d') AS d, total, critical, high, kev FROM stats_snapshot WHERE day >= DATE_SUB(UTC_DATE(), INTERVAL 90 DAY) ORDER BY day")
  return r.map((x) => ({ day: x.d, total: x.total, critical: x.critical, high: x.high, kev: x.kev }))
}

export function storeRoutes(app: express.Express, wrap: Wrap) {
  setInterval(flush, 30_000).unref()
  setInterval(prune, 24 * 3600_000).unref()
  void prune()

  app.get('/api/advisories', wrap(async (req, res) => {
    const q = String(req.query.q ?? '').trim().slice(0, 100)
    const pkg = String(req.query.package ?? '').trim().slice(0, 214)
    const page = Math.max(1, Number(req.query.page) || 1)
    const where: string[] = []; const args: unknown[] = []
    if (/^[A-Za-z0-9-]{3,40}$/.test(q) && q.length >= 3) { where.push('(MATCH(a.id, a.summary) AGAINST (? IN BOOLEAN MODE) OR a.id LIKE ?)'); args.push(`+${q}*`, `${q.replace(/[%_]/g, '')}%`) }
    else if (q) { where.push('a.summary LIKE ?'); args.push(`%${q.replace(/[%_\\]/g, '\\$&')}%`) }
    if (pkg) { where.push('a.id IN (SELECT adv_id FROM advisory_pkg WHERE name = ?)'); args.push(pkg) }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : ''
    const [[cnt], [rows]] = await Promise.all([
      pool.query<any[]>(`SELECT COUNT(*) AS n FROM advisories a ${w}`, args),
      pool.query<any[]>(`SELECT id,summary,severity,cvss,published,modified,aliases,packages FROM advisories a ${w} ORDER BY published DESC LIMIT 20 OFFSET ?`, [...args, (page - 1) * 20]),
    ])
    res.json({ total: Number(cnt[0].n), page, perPage: 20, items: rows })
  }))

  app.get('/api/trending', wrap(async (_req, res) => {
    const top = async (kind: string, days: number) => (await pool.query<any[]>(
      'SELECT k, SUM(n) AS n FROM usage_daily WHERE kind=? AND day >= DATE_SUB(UTC_DATE(), INTERVAL ? DAY) GROUP BY k ORDER BY n DESC LIMIT 10', [kind, days]))[0]
        .map((r) => ({ key: r.k, count: Number(r.n) }))
    const [views, searches, pkgs, scans] = await Promise.all([top('view', 7), top('search', 7), top('pkg', 7), top('scan', 30)])
    const scanTotal = scans.reduce((s, x) => s + x.count, 0)
    res.set('cache-control', 'public, max-age=300').json({ views, searches, packages: pkgs, scans30d: scanTotal })
  }))
}
