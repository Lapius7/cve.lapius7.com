import { useEffect, useRef, useSyncExternalStore } from 'react'
import { useLang } from '@/lib/i18n'

/** Shared client store: list descriptions are queued, sent to the server in small batches, and shown as they arrive. */
const done = new Map<string, string>()
const wanted = new Set<string>()
const subs = new Set<() => void>()
let timer: ReturnType<typeof setTimeout> | undefined
let running = 0

const notify = () => subs.forEach((f) => f())
const subscribe = (f: () => void) => { subs.add(f); return () => { subs.delete(f) } }

async function pump() {
  timer = undefined
  while (running < 2 && wanted.size > 0) {
    const batch = [...wanted].slice(0, 20)
    batch.forEach((x) => wanted.delete(x))
    running++
    fetch('/api/translate/batch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ texts: batch }) })
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { texts: (string | null)[] } | null) => {
        batch.forEach((src, i) => done.set(src, d?.texts[i] || src))
        notify()
      })
      .catch(() => { batch.forEach((src) => done.set(src, src)); notify() })
      .finally(() => { running--; if (wanted.size > 0) pump() })
  }
}

function request(text: string) {
  if (done.has(text) || wanted.has(text)) return
  wanted.add(text)
  timer ??= setTimeout(pump, 60)
}

const clip = (s: string) => s.replace(/\s+/g, ' ').trim().slice(0, 300)

/** Renders `text` in Japanese on /ja pages (machine translated, cached); English text is shown until the translation arrives. */
export function JaText({ text }: { text: string }) {
  const { lang } = useLang()
  const src = clip(text)
  const ja = useSyncExternalStore(subscribe, () => (lang === 'ja' ? done.get(src) : undefined))
  const ref = useRef<HTMLSpanElement>(null)
  // Only rows near the viewport are translated, so a 500-row list does not fire 500 requests.
  useEffect(() => {
    const el = ref.current
    if (lang !== 'ja' || !el || !src || /[぀-ヿ一-鿿]/.test(src) || done.has(src)) return
    const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { request(src); io.disconnect() } }, { rootMargin: '400px' })
    io.observe(el)
    return () => io.disconnect()
  }, [lang, src])
  return <span ref={ref}>{lang === 'ja' && ja ? ja : text}</span>
}
