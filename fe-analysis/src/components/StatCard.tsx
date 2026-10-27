interface StatCardProps {
  label: string
  value: string | number
  hint?: string
  accent?: string
  // When set, the card becomes a toggle button; active marks it as expanded.
  onClick?: () => void
  active?: boolean
}

export default function StatCard({ label, value, hint, accent, onClick, active }: StatCardProps) {
  const body = (
    <>
      <p className="flex items-center justify-between text-sm font-medium text-slate-500">
        {label}
        {onClick ? (
          <span aria-hidden="true" className={`text-xs transition ${active ? 'rotate-180 text-indigo-600' : 'text-slate-400'}`}>
            ▼
          </span>
        ) : null}
      </p>
      <p className={`mt-2 text-3xl font-bold ${accent ?? 'text-slate-900'}`}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-400">{hint}</p> : null}
    </>
  )

  if (!onClick) {
    return <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">{body}</div>
  }

  return (
    <button
      type="button"
      onClick={onClick}
      aria-expanded={active}
      className={`rounded-xl border bg-white p-5 text-left shadow-sm transition hover:border-indigo-300 hover:shadow focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${active ? 'border-indigo-400 ring-1 ring-indigo-400' : 'border-slate-200'}`}
    >
      {body}
    </button>
  )
}
