import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/arc/badge/badge'
import { fmtDate, tone, type Cve, type EpssItem, type KevItem } from '@/lib/api'
import { Link } from '@/lib/router'

type T = (k: any, v?: Record<string, string>) => string

const idCell = (id: string) => <Link className="dt-id" href={`/vulns/${id}`} onClick={(e) => e.stopPropagation()}>{id}</Link>
const pct = (v: number | null | undefined) => (v == null ? '–' : `${(v * 100).toFixed(v >= 0.1 ? 1 : 2)}%`)

function packages(c: Cve, t: T) {
  const list = c.products ?? []
  if (!list.length) return <span className="tags">{t('noPackage')}</span>
  return (
    <span className="dt-pk">
      {list.slice(0, 2).map((p) => <code key={p.vendor + p.product} title={`${p.vendor} / ${p.product}`}>{p.product}</code>)}
      {list.length > 2 && <span className="tags">+{list.length - 2}</span>}
    </span>
  )
}

const sevRank = (s: string | null) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as Record<string, number>)[s ?? ''] ?? 0

export const cveColumns = (t: T): ColumnDef<Cve, any>[] => [
  { id: 'id', accessorKey: 'id', header: t('colId'), enableHiding: false,
    cell: ({ row }) => <span className="dt-idwrap">{idCell(row.original.id)}{row.original.kev && <Badge tone="danger" size="sm">{t('exploited')}</Badge>}</span> },
  { id: 'package', header: t('colPackage'), accessorFn: (c) => c.products?.[0]?.product ?? '', cell: ({ row }) => packages(row.original, t) },
  { id: 'severity', header: t('colSeverity'), accessorFn: (c) => sevRank(c.severity), sortDescFirst: true,
    cell: ({ row }) => row.original.severity ? <Badge tone={tone(row.original.severity)} size="sm">{t(row.original.severity.toLowerCase())}</Badge> : <span className="tags">–</span> },
  { id: 'score', header: t('colScore'), accessorFn: (c) => c.score ?? -1, sortDescFirst: true, meta: { align: 'right' },
    cell: ({ row }) => row.original.score?.toFixed(1) ?? '–' },
  { id: 'epss', header: t('colEpss'), accessorFn: (c) => c.epss ?? -1, sortDescFirst: true, meta: { align: 'right' },
    cell: ({ row }) => pct(row.original.epss) },
  { id: 'published', header: t('colPublished'), accessorFn: (c) => c.published, sortDescFirst: true, cell: ({ row }) => fmtDate(row.original.published) },
  { id: 'description', header: t('colDesc'), enableSorting: false, meta: { className: 'dt-desc' },
    cell: ({ row }) => <span className="dt-clamp">{row.original.description}</span> },
]

export const kevColumns = (t: T): ColumnDef<KevItem, any>[] => [
  { id: 'id', accessorKey: 'id', header: t('colId'), enableHiding: false, cell: ({ row }) => idCell(row.original.id) },
  { id: 'vendor', accessorKey: 'vendor', header: t('colVendor') },
  { id: 'product', accessorKey: 'product', header: t('colProduct'), cell: ({ row }) => <code>{row.original.product}</code> },
  { id: 'ransomware', header: t('ransomware'), accessorFn: (c) => Number(c.ransomware), sortDescFirst: true,
    cell: ({ row }) => row.original.ransomware ? <Badge tone="warning" size="sm">{t('ransomware')}</Badge> : <span className="tags">–</span> },
  { id: 'added', accessorKey: 'added', header: t('colAdded'), sortDescFirst: true },
  { id: 'due', accessorKey: 'due', header: t('colDue'), sortDescFirst: true },
  { id: 'description', header: t('colDesc'), enableSorting: false, meta: { className: 'dt-desc' },
    cell: ({ row }) => <span className="dt-clamp">{row.original.name}. {row.original.description}</span> },
]

export const epssColumns = (t: T): ColumnDef<EpssItem, any>[] => [
  { id: 'id', accessorKey: 'id', header: t('colId'), enableHiding: false, cell: ({ row }) => idCell(row.original.id) },
  { id: 'score', header: t('prob'), accessorFn: (c) => c.score, sortDescFirst: true, meta: { align: 'right' }, cell: ({ row }) => pct(row.original.score) },
  { id: 'percentile', header: 'Percentile', accessorFn: (c) => c.percentile, sortDescFirst: true, meta: { align: 'right' }, cell: ({ row }) => pct(row.original.percentile) },
]
