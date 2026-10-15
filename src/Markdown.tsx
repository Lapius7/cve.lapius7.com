import { Fragment, type ReactNode } from 'react'

// Small markdown subset for advisory text: headings, lists, fenced code, inline code, bold, links.
// Built from React nodes only (no HTML injection); HTML comments are dropped and only http(s) links are kept.
const inline = (s: string): ReactNode[] =>
  s.split(/(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)\s]+\))/g).map((p, i) => {
    if (/^`[^`]+`$/.test(p)) return <code key={i}>{p.slice(1, -1)}</code>
    if (/^\*\*[^*]+\*\*$/.test(p)) return <strong key={i} style={{ fontWeight: 500 }}>{p.slice(2, -2)}</strong>
    const l = p.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/)
    if (l) return <a key={i} href={l[2]} target="_blank" rel="noopener noreferrer">{l[1]}</a>
    return <Fragment key={i}>{p}</Fragment>
  })

export default function Markdown({ text }: { text: string }) {
  const lines = text.replace(/<!--[\s\S]*?-->/g, '').replace(/\r\n?/g, '\n').split('\n')
  const out: ReactNode[] = []
  let para: string[] = [], list: string[] = [], code: string[] | null = null
  const flush = () => {
    if (para.length) out.push(<p key={out.length}>{para.flatMap((l, i) => (i ? [<br key={`b${i}`} />, ...inline(l)] : inline(l)))}</p>)
    if (list.length) out.push(<ul key={out.length}>{list.map((l, i) => <li key={i}>{inline(l)}</li>)}</ul>)
    para = []; list = []
  }
  for (const raw of lines) {
    if (/^\s*```/.test(raw)) {
      if (code) { out.push(<pre key={out.length}><code>{code.join('\n')}</code></pre>); code = null } else { flush(); code = [] }
      continue
    }
    if (code) { code.push(raw); continue }
    const h = raw.match(/^#{1,6}\s+(.*)$/), li = raw.match(/^\s*[-*+]\s+(.*)$/)
    if (h) { flush(); out.push(<h4 key={out.length} style={{ margin: '1rem 0 .25rem', fontWeight: 500 }}>{inline(h[1])}</h4>) }
    else if (li) { if (para.length) flush(); list.push(li[1]) }
    else if (!raw.trim()) flush()
    else { if (list.length) flush(); para.push(raw.trim()) }
  }
  if (code) out.push(<pre key={out.length}><code>{code.join('\n')}</code></pre>)
  flush()
  return <>{out}</>
}
