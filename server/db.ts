import mysql from 'mysql2/promise'
import type { CveRow } from './nvd.ts'

export const pool = mysql.createPool({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT ?? 3306),
  user: process.env.MYSQL_USER ?? 'cve',
  password: process.env.MYSQL_PASSWORD ?? '',
  database: process.env.MYSQL_DATABASE ?? 'cve',
  connectionLimit: 10,
  charset: 'utf8mb4',
  dateStrings: true,
  timezone: 'Z',
})

export async function migrate() {
  await pool.query(`CREATE TABLE IF NOT EXISTS cves (
    id VARCHAR(24) NOT NULL PRIMARY KEY,
    year SMALLINT NOT NULL,
    status VARCHAR(32),
    published DATETIME NOT NULL,
    modified DATETIME NOT NULL,
    description MEDIUMTEXT NOT NULL,
    score DECIMAL(3,1) NULL,
    severity VARCHAR(10) NULL,
    vector VARCHAR(255) NULL,
    cvss_version VARCHAR(8) NULL,
    cwes JSON NOT NULL,
    refs JSON NOT NULL,
    kev TINYINT(1) NOT NULL DEFAULT 0,
    INDEX i_pub (published),
    INDEX i_sev_pub (severity, published),
    INDEX i_score (score),
    INDEX i_year_pub (year, published),
    FULLTEXT KEY ft_desc (id, description)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
  await pool.query(`CREATE TABLE IF NOT EXISTS cve_extra (
    cve_id VARCHAR(24) NOT NULL, source VARCHAR(16) NOT NULL, data JSON NOT NULL, fetched_at DATETIME NOT NULL,
    PRIMARY KEY (cve_id, source)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
  await pool.query(`CREATE TABLE IF NOT EXISTS kev (
    cve_id VARCHAR(24) NOT NULL PRIMARY KEY, added DATE NOT NULL, due DATE NULL, vendor VARCHAR(255), product VARCHAR(255),
    name VARCHAR(512), description TEXT, action TEXT, ransomware TINYINT(1) NOT NULL DEFAULT 0, INDEX i_added (added)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
  await pool.query(`CREATE TABLE IF NOT EXISTS epss (
    cve_id VARCHAR(24) NOT NULL PRIMARY KEY, score DECIMAL(6,5) NOT NULL, percentile DECIMAL(6,5) NOT NULL, INDEX i_score (score)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
  await pool.query(`CREATE TABLE IF NOT EXISTS sync_state (k VARCHAR(32) NOT NULL PRIMARY KEY, v VARCHAR(255) NOT NULL)
    ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
  // products column: backfill needs a fresh full sync, so rewind it once when the column is added.
  const [col] = await pool.query<any[]>("SHOW COLUMNS FROM cves LIKE 'products'")
  if (!col.length) {
    await pool.query('ALTER TABLE cves ADD COLUMN products JSON NULL')
    await pool.query("DELETE FROM sync_state WHERE k IN ('full_index','full_done','full_started')")
  }
}

export async function getState(k: string) {
  const [r] = await pool.query<any[]>('SELECT v FROM sync_state WHERE k=?', [k])
  return (r[0]?.v as string | undefined) ?? null
}
export const setState = (k: string, v: string) =>
  pool.query('INSERT INTO sync_state (k,v) VALUES (?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)', [k, v])

const dt = (s: string) => s.replace('T', ' ').replace(/(\.\d+)?Z?$/, '').slice(0, 19)

export async function upsertCves(rows: CveRow[]) {
  if (!rows.length) return
  const vals = rows.map((c) => [
    c.id, Number(c.id.split('-')[1]), c.status, dt(c.published), dt(c.modified), c.description, c.score, c.severity,
    c.vector, c.cvssVersion, JSON.stringify(c.cwes), JSON.stringify(c.references), c.kev ? 1 : 0, JSON.stringify(c.products),
  ])
  await pool.query(
    `INSERT INTO cves (id,year,status,published,modified,description,score,severity,vector,cvss_version,cwes,refs,kev,products) VALUES ?
     ON DUPLICATE KEY UPDATE status=VALUES(status), published=VALUES(published), modified=VALUES(modified), description=VALUES(description),
       score=VALUES(score), severity=VALUES(severity), vector=VALUES(vector), cvss_version=VALUES(cvss_version),
       cwes=VALUES(cwes), refs=VALUES(refs), kev=VALUES(kev), products=VALUES(products)`,
    [vals],
  )
}

export function rowToCve(r: any) {
  const j = (v: unknown) => (typeof v === 'string' ? JSON.parse(v) : v)
  return {
    id: r.id as string, status: r.status as string,
    published: String(r.published).replace(' ', 'T') + 'Z', modified: String(r.modified).replace(' ', 'T') + 'Z',
    description: r.description as string,
    score: r.score === null ? null : Number(r.score), severity: r.severity as string | null,
    vector: r.vector as string | null, cvssVersion: r.cvss_version as string | null,
    cwes: j(r.cwes) as string[], products: (j(r.products) ?? []) as { vendor: string; product: string }[], references: j(r.refs) as { url: string; source: string; tags: string[] }[],
    kev: Boolean(r.kev) || Boolean(r.kev_added),
    epss: r.epss_score == null ? null : Number(r.epss_score),
  }
}
