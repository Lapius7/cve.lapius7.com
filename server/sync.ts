import { gunzipSync } from 'node:zlib'
import { getState, migrate, pool, setState, upsertCves } from './db.ts'
import { KEY, normalize, nvdRaw, type Json } from './nvd.ts'

const PAGE = 2000
const log = (...a: unknown[]) => console.log('[sync]', ...a)
const nvdDate = (d: Date) => d.toISOString().replace('Z', '')

async function pages(base: Record<string, string>, startIndex: number, onPage: (idx: number, total: number) => Promise<void>) {
  let idx = startIndex
  for (;;) {
    const raw = await nvdRaw(new URLSearchParams({ ...base, resultsPerPage: String(PAGE), startIndex: String(idx) }))
    await upsertCves(((raw.vulnerabilities ?? []) as Json[]).map((v) => normalize(v.cve)))
    idx += PAGE
    await onPage(idx, raw.totalResults)
    if (idx >= raw.totalResults) return raw.totalResults as number
  }
}

export async function fullSync() {
  const started = (await getState('full_started')) ?? nvdDate(new Date())
  await setState('full_started', started)
  const from = Number((await getState('full_index')) ?? 0)
  log(`full sync from index ${from}${KEY ? '' : ' (no API key: slow)'}`)
  await pages({}, from, async (i, total) => {
    await setState('full_index', String(i))
    log(`${Math.min(i, total)}/${total}`)
  })
  await setState('last_sync', started)
  await setState('full_done', '1')
  log('full sync done')
}

export async function incrementalSync() {
  let from = new Date((await getState('last_sync'))! + 'Z')
  const now = new Date()
  let n = 0
  while (from < now) {
    const to = new Date(Math.min(from.getTime() + 100 * 864e5, now.getTime()))
    n += await pages({ lastModStartDate: nvdDate(from), lastModEndDate: nvdDate(to) }, 0, async () => {})
    from = to
  }
  await setState('last_sync', nvdDate(now))
  log(`incremental: ${n} updated`)
}

async function syncKev() {
  const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: AbortSignal.timeout(30_000) })
  const d = (await r.json()) as Json
  const vals = (d.vulnerabilities as Json[]).map((v) => [
    v.cveID, v.dateAdded, v.dueDate || null, v.vendorProject, v.product, v.vulnerabilityName, v.shortDescription, v.requiredAction,
    v.knownRansomwareCampaignUse === 'Known' ? 1 : 0,
  ])
  if (vals.length)
    await pool.query(
      `INSERT INTO kev (cve_id,added,due,vendor,product,name,description,action,ransomware) VALUES ?
       ON DUPLICATE KEY UPDATE added=VALUES(added), due=VALUES(due), vendor=VALUES(vendor), product=VALUES(product), name=VALUES(name),
         description=VALUES(description), action=VALUES(action), ransomware=VALUES(ransomware)`,
      [vals],
    )
  log(`kev: ${vals.length}`)
}

async function syncEpss() {
  const r = await fetch('https://epss.cyentia.com/epss_scores-current.csv.gz', { signal: AbortSignal.timeout(120_000) })
  if (!r.ok) throw new Error(`epss ${r.status}`)
  const lines = gunzipSync(Buffer.from(await r.arrayBuffer())).toString('utf8').split('\n')
  let batch: [string, number, number][] = []
  let n = 0
  const flush = async () => {
    if (!batch.length) return
    await pool.query('INSERT INTO epss (cve_id,score,percentile) VALUES ? ON DUPLICATE KEY UPDATE score=VALUES(score), percentile=VALUES(percentile)', [batch])
    n += batch.length
    batch = []
  }
  for (const l of lines) {
    if (!l.startsWith('CVE-')) continue
    const [id, s, p] = l.trim().split(',')
    batch.push([id, Number(s), Number(p)])
    if (batch.length >= 5000) await flush()
  }
  await flush()
  log(`epss: ${n}`)
}

export async function dailySync() {
  await Promise.allSettled([syncKev().catch((e) => log('kev failed', e.message)), syncEpss().catch((e) => log('epss failed', e.message))])
  await setState('daily_at', String(Date.now()))
}

let running = false
export async function tick() {
  if (running) return
  running = true
  try {
    if ((await getState('full_done')) !== '1') await fullSync()
    else if (Date.now() - new Date((await getState('last_sync'))! + 'Z').getTime() > 2 * 3600_000) await incrementalSync()
    if (Date.now() - Number((await getState('daily_at')) ?? 0) > 24 * 3600_000) await dailySync()
  } catch (e: any) {
    log('error', e.message)
  } finally {
    running = false
  }
}

export function startScheduler() {
  setTimeout(tick, 2000)
  setInterval(tick, 10 * 60_000)
}

// CLI: tsx server/sync.ts [full|inc|daily]
if (process.argv[1]?.endsWith('sync.ts')) {
  await migrate()
  const cmd = process.argv[2]
  if (cmd === 'full') await fullSync()
  else if (cmd === 'inc') await incrementalSync()
  else if (cmd === 'daily') await dailySync()
  else console.log('usage: sync.ts full|inc|daily')
  await pool.end()
}
