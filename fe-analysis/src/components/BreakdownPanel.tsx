import type { ScanLogGroup } from '../types'

interface BreakdownPanelProps {
  title: string
  description: string
  groups: ScanLogGroup[]
  // The filter value currently applied for this breakdown, if any.
  selected: string
  emptyText: string
  onSelect: (value: string) => void
  onClose: () => void
}

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString('en-US', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function BreakdownPanel({
  title,
  description,
  groups,
  selected,
  emptyText,
  onSelect,
  onClose,
}: BreakdownPanelProps) {
  const max = Math.max(1, ...groups.map((group) => group.count))

  return (
    <section className="rounded-xl border border-indigo-200 bg-white shadow-sm">
      <div className="flex items-start justify-between gap-4 border-b border-slate-200 p-5">
        <div>
          <h2 className="font-semibold text-slate-900">{title}</h2>
          <p className="mt-1 max-w-3xl text-sm text-slate-500">{description}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close breakdown"
          className="rounded-md px-2 py-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700"
        >
          ✕
        </button>
      </div>

      {groups.length === 0 ? (
        <p className="p-6 text-center text-sm text-slate-400">{emptyText}</p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {groups.map((group) => {
            const active = group.value === selected
            return (
              <li key={group.value}>
                <button
                  type="button"
                  onClick={() => onSelect(active ? '' : group.value)}
                  aria-pressed={active}
                  className={`grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 px-5 py-3 text-left transition sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_auto_auto] ${active ? 'bg-indigo-50' : 'hover:bg-slate-50'}`}
                >
                  <span className="truncate font-mono text-sm text-slate-800">{group.value}</span>
                  <span className="text-right text-sm font-semibold text-slate-900 sm:order-3">
                    {group.count} {group.count === 1 ? 'log' : 'logs'}
                  </span>
                  <span className="col-span-2 h-1.5 rounded-full bg-slate-100 sm:order-2 sm:col-span-1">
                    <span
                      className="block h-full rounded-full bg-indigo-500"
                      style={{ width: `${(group.count / max) * 100}%` }}
                    />
                  </span>
                  <span className="col-span-2 text-xs text-slate-400 sm:order-4 sm:col-span-1 sm:w-32 sm:text-right">
                    {active ? 'filter on · click to clear' : `last ${formatDate(group.last_seen)}`}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
