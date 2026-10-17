import { useEffect, useRef, useState } from 'react'
import { Check, ChevronDown, Copy } from 'lucide-react'
import { useCopyFeedback } from '@/components/arc/lib/use-copy-feedback'
import { useLang } from '@/lib/i18n'

/** One "Copy" button; clicking it opens a small menu to pick what to copy (ID, short URL or Markdown link). */
export function CopyMenu({ id, url }: { id: string; url: string }) {
  const { t } = useLang()
  const [open, setOpen] = useState(false)
  const { state, activeKey, copy } = useCopyFeedback()
  const root = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const off = (e: MouseEvent) => { if (!root.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', off)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', off); document.removeEventListener('keydown', esc) }
  }, [open])

  const items = [
    { key: 'id', label: t('copyAsId'), value: id },
    { key: 'url', label: t('copyAsUrl'), value: url },
    { key: 'md', label: t('copyAsMd'), value: `[${id}](${url})` },
  ]
  const done = state === 'copied'

  return (
    <div className="copymenu" ref={root}>
      <button type="button" className="copymenu-btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {done ? <Check size={14} /> : <Copy size={14} />}
        <span>{done ? t('copiedMsg') : t('copyMenu')}</span>
        <ChevronDown size={14} className="copymenu-chev" />
      </button>
      {open && <ul className="copymenu-list" role="menu">
        {items.map((it) => <li key={it.key} role="none">
          <button type="button" role="menuitem" onClick={async () => { await copy(it.value, it.key); setOpen(false) }}>
            <b>{it.label}</b><code>{it.value}</code>{activeKey === it.key && done && <Check size={14} />}
          </button>
        </li>)}
      </ul>}
    </div>
  )
}
