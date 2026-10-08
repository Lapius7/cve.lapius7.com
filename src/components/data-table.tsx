import { useState } from 'react'
import { flexRender, getCoreRowModel, getSortedRowModel, useReactTable, type ColumnDef, type SortingState, type VisibilityState } from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ArrowUpDown, Columns3 } from 'lucide-react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { navigate } from '@/lib/router'

type Meta = { align?: 'right'; className?: string }

/** Sortable, column-toggle data table (TanStack Table + shadcn table primitives). Rows open `rowHref`. */
export default function DataTable<T>({ columns, data, columnsLabel, rowHref, initialVisibility = {} }: {
  columns: ColumnDef<T, any>[]; data: T[]; columnsLabel: string; rowHref: (row: T) => string; initialVisibility?: VisibilityState
}) {
  const [sorting, setSorting] = useState<SortingState>([])
  const [visibility, setVisibility] = useState<VisibilityState>(initialVisibility)
  const [menu, setMenu] = useState(false)
  const table = useReactTable({
    data, columns, state: { sorting, columnVisibility: visibility },
    onSortingChange: setSorting, onColumnVisibilityChange: setVisibility,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(),
  })
  return (
    <div className="dt">
      <div className="dt-bar">
        <div className="dt-menu">
          <button type="button" className="dt-btn" aria-expanded={menu} onClick={() => setMenu((v) => !v)}>
            <Columns3 size={16} />{columnsLabel}
          </button>
          {menu && (
            <div className="dt-pop" role="menu" onMouseLeave={() => setMenu(false)}>
              {table.getAllColumns().filter((c) => c.getCanHide()).map((c) => (
                <label key={c.id}>
                  <input type="checkbox" checked={c.getIsVisible()} onChange={(e) => c.toggleVisibility(e.target.checked)} />
                  {typeof c.columnDef.header === 'string' ? c.columnDef.header : c.id}
                </label>
              ))}
            </div>
          )}
        </div>
      </div>
      <Table>
        <TableHeader className="dt-head">
          {table.getHeaderGroups().map((g) => (
            <TableRow key={g.id}>
              {g.headers.map((h) => {
                const dir = h.column.getIsSorted()
                const meta = (h.column.columnDef.meta ?? {}) as Meta
                return (
                  <TableHead key={h.id} className={`${meta.align === 'right' ? 'text-right' : ''} ${meta.className ?? ''}`} aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}>
                    <button type="button" className={`dt-sort ${meta.align === 'right' ? 'rev' : ''}`} onClick={h.column.getToggleSortingHandler()}>
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {dir === 'asc' ? <ArrowUp size={14} /> : dir === 'desc' ? <ArrowDown size={14} /> : <ArrowUpDown size={14} style={{ opacity: .4 }} />}
                    </button>
                  </TableHead>
                )
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((r) => (
            <TableRow key={r.id} className="dt-row" tabIndex={0}
              onClick={() => navigate(rowHref(r.original))}
              onKeyDown={(e) => { if (e.key === 'Enter') navigate(rowHref(r.original)) }}>
              {r.getVisibleCells().map((c) => {
                const meta = (c.column.columnDef.meta ?? {}) as Meta
                return <TableCell key={c.id} className={`tabular-nums ${meta.align === 'right' ? 'text-right' : ''} ${meta.className ?? ''}`}>{flexRender(c.column.columnDef.cell, c.getContext())}</TableCell>
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
