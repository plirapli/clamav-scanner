import Select from './Select'

interface PaginationProps {
  page: number
  pageSize: number
  total: number
  pageSizeOptions?: number[]
  onPageChange: (page: number) => void
  onPageSizeChange: (pageSize: number) => void
}

const windowSlots = 7

// pageWindow returns zero-based page indexes to render, with null marking a gap.
// Past windowSlots pages it always returns exactly windowSlots entries, so the
// buttons keep their positions while the user pages through.
function pageWindow(page: number, pageCount: number): (number | null)[] {
  if (pageCount <= windowSlots) return Array.from({ length: pageCount }, (_, i) => i)

  const last = pageCount - 1
  const range = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => from + i)

  if (page < 4) return [...range(0, 4), null, last]
  if (page > last - 4) return [0, null, ...range(last - 4, last)]
  return [0, null, page - 1, page, page + 1, null, last]
}

const buttonBase =
  'min-w-9 rounded-md border px-3 py-1.5 text-sm font-medium tabular-nums disabled:cursor-not-allowed disabled:opacity-40'

export default function Pagination({
  page,
  pageSize,
  total,
  pageSizeOptions = [10, 20, 50, 100],
  onPageChange,
  onPageSizeChange,
}: PaginationProps) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : page * pageSize + 1
  const to = Math.min(total, (page + 1) * pageSize)

  return (
    <div className="flex flex-col gap-3 border-t border-slate-200 px-5 py-4 text-sm text-slate-600 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        <span>
          Showing <span className="font-semibold text-slate-800">{from}</span>–
          <span className="font-semibold text-slate-800">{to}</span> of{' '}
          <span className="font-semibold text-slate-800">{total}</span>
        </span>
        <div className="flex items-center gap-2">
          <span id="page-size-label" className="text-xs text-slate-500">Rows</span>
          <Select
            value={pageSize}
            options={pageSizeOptions.map((option) => ({ value: option, label: String(option) }))}
            onChange={onPageSizeChange}
            placement="top"
            size="sm"
            aria-labelledby="page-size-label"
            className="w-20"
          />
        </div>
      </div>

      <nav className="flex flex-wrap items-center gap-1" aria-label="Pagination">
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={page === 0}
          className={`${buttonBase} border-slate-300 bg-white hover:bg-slate-50`}
        >
          Prev
        </button>
        {pageWindow(page, pageCount).map((p, i) =>
          p === null ? (
            <span key={i < 3 ? 'gap-start' : 'gap-end'} className="min-w-9 px-2 text-center text-slate-400">
              …
            </span>
          ) : (
            <button
              key={p}
              type="button"
              onClick={() => onPageChange(p)}
              aria-current={p === page ? 'page' : undefined}
              className={`${buttonBase} ${p === page ? 'border-indigo-600 bg-indigo-600 text-white' : 'border-slate-300 bg-white hover:bg-slate-50'}`}
            >
              {p + 1}
            </button>
          ),
        )}
        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= pageCount - 1}
          className={`${buttonBase} border-slate-300 bg-white hover:bg-slate-50`}
        >
          Next
        </button>
      </nav>
    </div>
  )
}
