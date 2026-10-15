import { Resvg } from '@resvg/resvg-js'

const esc = (t: string) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const SEV_COLOR: Record<string, string> = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }
const FONT = 'Noto Sans CJK JP, Noto Sans JP, WenQuanYi Zen Hei, Inter, Helvetica, Arial, sans-serif'

// Wrap by display width (CJK counts as 2). Latin text breaks at spaces; CJK can break anywhere.
const cjk = (ch: string) => /[\u1100-\u115f\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe30-\ufe6f\uff00-\uff60\uffe0-\uffe6]/.test(ch)
function wrap(text: string, max: number, lines: number): string[] {
  const chars = [...text.replace(/\s+/g, ' ').trim()]
  const out: string[] = []
  let start = 0
  while (start < chars.length) {
    let w = 0, i = start, lastSpace = -1
    while (i < chars.length) {
      const cw = cjk(chars[i]) ? 2 : 1
      if (w + cw > max) break
      if (chars[i] === ' ') lastSpace = i
      w += cw; i++
    }
    if (i >= chars.length) { out.push(chars.slice(start).join('')); break }
    if (out.length === lines - 1) {
      let e = i
      while (e > start && w + 1 > max) { e--; w -= cjk(chars[e]) ? 2 : 1 }
      return [...out, chars.slice(start, e).join('').trimEnd() + '…']
    }
    const brk = !cjk(chars[i]) && chars[i] !== ' ' && lastSpace > start ? lastSpace : i
    out.push(chars.slice(start, brk).join('').trimEnd())
    start = brk + (chars[brk] === ' ' ? 1 : 0)
  }
  return out
}

export interface OgInput { title: string; desc?: string; severity?: string | null; score?: number | null }

const cache = new Map<string, Buffer>()

export function renderOg(key: string, i: OgInput): Buffer {
  const hit = cache.get(key)
  if (hit) { cache.delete(key); cache.set(key, hit); return hit }
  const accent = (i.severity && SEV_COLOR[i.severity]) || '#fafafa'
  const tl = wrap(i.title, 34, 2)
  const dl = i.desc ? wrap(i.desc, 66, tl.length > 1 ? 2 : 3) : []
  const ty = 250
  const dy = ty + tl.length * 84 + 20
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#171717"/>
  <rect x="0" y="0" width="14" height="630" fill="${accent}"/>
  <rect x="80" y="70" width="64" height="64" rx="16" fill="#fafafa"/>
  <g transform="translate(80 70) scale(2)"><path d="M16 6.5 23.5 9.5v6c0 4.6-3.1 8.2-7.5 10-4.4-1.8-7.5-5.4-7.5-10v-6z" fill="none" stroke="#171717" stroke-width="2" stroke-linejoin="round"/><path d="M16 12v5" fill="none" stroke="#171717" stroke-width="2" stroke-linecap="round"/><circle cx="16" cy="20.5" r="1.2" fill="#ef4444"/></g>
  <text x="164" y="116" font-family="${FONT}" font-size="34" fill="#a3a3a3">Vulnerability.DB</text>
  ${i.severity ? `<text x="1120" y="116" text-anchor="end" font-family="${FONT}" font-size="34" font-weight="700" fill="${accent}">${esc(i.severity)}${i.score != null ? ` ${i.score.toFixed(1)}` : ''}</text>` : ''}
  ${tl.map((l, n) => `<text x="80" y="${ty + n * 84}" font-family="${FONT}" font-size="68" font-weight="700" fill="#fafafa">${esc(l)}</text>`).join('\n  ')}
  ${dl.map((l, n) => `<text x="80" y="${dy + n * 46}" font-family="${FONT}" font-size="30" fill="#a3a3a3">${esc(l)}</text>`).join('\n  ')}
  <text x="80" y="580" font-family="${FONT}" font-size="28" fill="#737373">vulns.lapius7.com</text>
</svg>`
  const png = new Resvg(svg, { font: { loadSystemFonts: true, defaultFontFamily: 'Noto Sans CJK JP' } }).render().asPng()
  cache.set(key, png)
  if (cache.size > 300) cache.delete(cache.keys().next().value!)
  return png
}
