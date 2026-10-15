import { useEffect, useState } from 'react'
import { getProducts, type ProductHit } from '@/lib/api'
import { Link } from '@/lib/router'
import { useLang } from '@/lib/i18n'

export function ProductSuggest({ q }: { q: string }) {
  const { t } = useLang()
  const [items, setItems] = useState<ProductHit[]>([])
  useEffect(() => {
    if (q.length < 2 || /\s{2,}|^CVE-/i.test(q)) { setItems([]); return }
    const ac = new AbortController()
    getProducts(q, ac.signal).then((d) => setItems(d.items.slice(0, 6))).catch(() => {})
    return () => ac.abort()
  }, [q])
  if (!items.length) return null
  return (
    <div className="meta" style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
      <span>{t('suggestProducts')}:</span>
      {items.map((p) => <Link key={`${p.vendor}/${p.product}`} href={`/vendor/${encodeURIComponent(p.vendor)}/${encodeURIComponent(p.product)}`}>{p.vendor === p.product ? p.product : `${p.vendor} / ${p.product}`}</Link>)}
    </div>
  )
}
