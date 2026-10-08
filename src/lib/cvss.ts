type L = [string, string]
type Def = Record<string, { name: L; vals: Record<string, L> }>

const imp: Record<string, L> = { N: ['None', 'なし'], L: ['Low', '低'], H: ['High', '高'], P: ['Partial', '部分的'], C: ['Complete', '全面的'] }
const lh: Record<string, L> = { L: imp.L, H: imp.H }
const nlh: Record<string, L> = { N: imp.N, L: imp.L, H: imp.H }

const V3: Def = {
  AV: { name: ['Attack vector', '攻撃元区分'], vals: { N: ['Network', 'ネットワーク'], A: ['Adjacent', '隣接'], L: ['Local', 'ローカル'], P: ['Physical', '物理'] } },
  AC: { name: ['Attack complexity', '攻撃条件の複雑さ'], vals: lh },
  PR: { name: ['Privileges required', '必要な特権'], vals: nlh },
  UI: { name: ['User interaction', 'ユーザー関与'], vals: { N: ['None', '不要'], R: ['Required', '必要'] } },
  S: { name: ['Scope', '影響の想定範囲'], vals: { U: ['Unchanged', '変更なし'], C: ['Changed', '変更あり'] } },
  C: { name: ['Confidentiality', '機密性'], vals: nlh },
  I: { name: ['Integrity', '完全性'], vals: nlh },
  A: { name: ['Availability', '可用性'], vals: nlh },
}
const V4: Def = {
  AV: V3.AV, AC: V3.AC,
  AT: { name: ['Attack requirements', '攻撃要件'], vals: { N: ['None', 'なし'], P: ['Present', 'あり'] } },
  PR: V3.PR, UI: { name: ['User interaction', 'ユーザー関与'], vals: { N: ['None', 'なし'], P: ['Passive', '受動的'], A: ['Active', '能動的'] } },
  VC: { name: ['Vulnerable system confidentiality', '脆弱なシステムの機密性'], vals: nlh },
  VI: { name: ['Vulnerable system integrity', '脆弱なシステムの完全性'], vals: nlh },
  VA: { name: ['Vulnerable system availability', '脆弱なシステムの可用性'], vals: nlh },
  SC: { name: ['Subsequent system confidentiality', '後続システムの機密性'], vals: nlh },
  SI: { name: ['Subsequent system integrity', '後続システムの完全性'], vals: nlh },
  SA: { name: ['Subsequent system availability', '後続システムの可用性'], vals: nlh },
}
const V2: Def = {
  AV: { name: ['Access vector', '攻撃元区分'], vals: { L: ['Local', 'ローカル'], A: ['Adjacent', '隣接'], N: ['Network', 'ネットワーク'] } },
  AC: { name: ['Access complexity', '攻撃条件の複雑さ'], vals: { H: imp.H, M: ['Medium', '中'], L: imp.L } },
  Au: { name: ['Authentication', '認証'], vals: { M: ['Multiple', '複数'], S: ['Single', '単一'], N: ['None', '不要'] } },
  C: { name: ['Confidentiality', '機密性'], vals: { N: imp.N, P: imp.P, C: imp.C } },
  I: { name: ['Integrity', '完全性'], vals: { N: imp.N, P: imp.P, C: imp.C } },
  A: { name: ['Availability', '可用性'], vals: { N: imp.N, P: imp.P, C: imp.C } },
}

/** 0 = good (none/low), 1 = mid, 2 = bad. Used to colour the value. */
const level = (v: string) => (/^(None|Not|Unchanged|Physical|なし|不要|変更なし|物理)/.test(v) ? 0 : /^(Low|Local|Partial|Passive|Single|Adjacent|低|部分|ローカル|受動|単一|隣接|Medium|中)/.test(v) ? 1 : 2)

export interface Metric { name: string; value: string; level: 0 | 1 | 2 }

export function parseVector(vector: string | null, ja: boolean): Metric[] {
  if (!vector) return []
  const parts = vector.split('/')
  const def = vector.startsWith('CVSS:4') ? V4 : vector.startsWith('CVSS:3') ? V3 : V2
  const i = ja ? 1 : 0
  const out: Metric[] = []
  for (const p of parts) {
    const [k, v] = p.split(':')
    const d = def[k]
    if (!d || !d.vals[v]) continue
    const value = d.vals[v][i]
    out.push({ name: d.name[i], value, level: level(d.vals[v][0] === 'None' || d.vals[v][0] === 'Not' ? d.vals[v][0] : d.vals[v][0]) as 0 | 1 | 2 })
  }
  return out
}
