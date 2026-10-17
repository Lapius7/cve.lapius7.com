import { Fragment, type ReactNode } from 'react'
import { Link } from '@/lib/router'

type Block =
  | { k: 'h'; text: string }
  | { k: 'p'; text: string; sentences?: number }
  | { k: 'li'; text: string; level: number }
  | { k: 'ol'; text: string; n: string }

/** Splits flat advisory prose (JVN, NVD, vendor text) into headings, paragraphs and nested bullets. */
export function parseRich(raw: string): Block[] {
  const t0 = raw.replace(/\r\n?/g, '\n')
    .replace(/([ 　]+|^)\* /gm, (_m, ws: string) => `\n${ws.replace(/ /g, '')}* `)
    .replace(/([。.!?！？])[ 　]{2,}(?=\S)/g, '$1\n')
    .replace(/ {2,}(?=\S)/g, '\n')
  const listy = /(^|[\s。:：])1\s*[)）][\s\S]*[^\w-]2\s*[)）]/.test(raw)
  let next = 2
  const t = listy
    ? t0
      .replace(/(\d{1,2})\s*[)）]\s*/g, (m, n, off, str) => (/[\w-]/.test(str[off - 1] ?? ' ') ? m : `${n}) `))
      .replace(/(?:または|および|OR|AND)\s*(?=\d{1,2}\) )/g, '')
      .replace(/(^|[\s。:：])(?=1\) )/, '$1\n')
      .replace(/(?<=\S)\s*(\d{1,2})\) (?=\S)/g, (m, n, off, str) => (+n === next && (/^\s/.test(m) || !/[\w-]/.test(str[off - 1] ?? ' ')) ? (next++, `\n${n}) `) : m))
    : t0
  const out: Block[] = []
  for (const line of t.split('\n')) {
    const l = line.replace(/[ \t]+$/, '')
    if (!l.trim()) continue
    const b = l.match(/^([ 　]*)\* (.*)$/)
    if (b) {
      out.push({ k: 'li', text: b[2].trim(), level: Math.min(3, (b[1].match(/　/g)?.length ?? 1) || 1) })
      continue
    }
    const o = l.trim().match(/^(\d{1,2})\) (.*)$/)
    if (o) {
      const [first, ...rest] = o[2].split(/(?<=。)(?=\S)|(?<=[.])\s+(?=[A-Z0-9])/)
      out.push({ k: 'ol', n: o[1], text: first.replace(/[;；]?\s*(OR|or|AND|and|または|および)?\s*$/, '').trim() })
      if (rest.length) out.push({ k: 'p', text: rest.join(' ') })
      continue
    }
    const h = l.trim().match(/^\[([^\]]{1,30})\]\s*(.*)$/)
    if (h) {
      out.push({ k: 'h', text: h[1] })
      if (h[2]) out.push({ k: 'p', text: h[2] })
      continue
    }
    out.push({ k: 'p', text: l.trim() })
  }
  return out.flatMap((b): Block[] => b.k === 'p' ? splitSentences(b.text).map((text) => ({ k: 'p' as const, text, sentences: countSentences(text) })) : [b])
}

const SENT = /(?<=[。！？!?])\s*(?=\S)|(?<=[a-z0-9)][.])\s+(?=[A-Z])/
const countSentences = (t: string) => t.split(SENT).filter(Boolean).length

/** Breaks a long paragraph into short groups of sentences so a wall of text becomes a few readable blocks. */
function splitSentences(text: string): string[] {
  const ja = /[぀-ヿ一-鿿]/.test(text)
  const limit = ja ? 110 : 240
  if (text.length <= limit * 1.3) return [text]
  const groups: string[] = []
  let cur = ''
  for (const sent of text.split(SENT).filter(Boolean)) {
    cur = cur ? `${cur}${ja ? '' : ' '}${sent}` : sent
    if (cur.length >= limit) { groups.push(cur); cur = '' }
  }
  if (cur) groups.push(cur)
  return groups
}

const TOKEN = /(CVE-\d{4}-\d{4,}|CWE-\d+|https?:\/\/[A-Za-z0-9\-._~:/?#@!$&*+,;=%()[\]]*[A-Za-z0-9\-_~/#=%+])/g

function inline(text: string): ReactNode {
  return text.split(TOKEN).map((s, i) => {
    if (i % 2 === 0) return s
    if (s.startsWith('http')) return <a key={i} href={s} target="_blank" rel="noopener noreferrer" style={{ overflowWrap: 'anywhere' }}>{s}</a>
    return <Link key={i} href={s.startsWith('CVE') ? `/${s}` : `/cwe/${s}`}>{s}</Link>
  })
}

export function RichText({ text, lead = false }: { text: string; lead?: boolean }) {
  const blocks = parseRich(text)
  const leadAt = lead && blocks.length > 1 && blocks[0].k === 'p' && blocks[0].sentences === 1 ? 0 : -1
  const nodes: ReactNode[] = []
  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i]
    if (b.k === 'h') nodes.push(<h4 key={i} className="rt-h">{b.text}</h4>)
    else if (b.k === 'p') nodes.push(<p key={i} className={i === leadAt ? 'rt-p rt-lead' : 'rt-p'}>{inline(b.text)}</p>)
    else if (b.k === 'ol') {
      const items: Extract<Block, { k: 'ol' }>[] = []
      let j = i
      while (j < blocks.length && blocks[j].k === 'ol') items.push(blocks[j++] as Extract<Block, { k: 'ol' }>)
      nodes.push(<ol key={i} className="rt-ol">{items.map((it, n) => <li key={n} value={+it.n}>{inline(it.text)}</li>)}</ol>)
      i = j - 1
    } else {
      const items: Extract<Block, { k: 'li' }>[] = []
      let j = i
      while (j < blocks.length && blocks[j].k === 'li') items.push(blocks[j++] as Extract<Block, { k: 'li' }>)
      nodes.push(<ul key={i} className="rt-ul">{items.map((it, n) => <li key={n} style={{ marginLeft: `${(it.level - 1) * 1.25}rem` }} className={it.level > 1 ? 'rt-sub' : undefined}>{inline(it.text)}</li>)}</ul>)
      i = j - 1
    }
  }
  return <Fragment>{nodes}</Fragment>
}
