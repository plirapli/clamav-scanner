interface StatCardProps {
  label: string
  value: string | number
  hint?: string
  accent?: string
}

export default function StatCard({ label, value, hint, accent }: StatCardProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-bold ${accent ?? 'text-slate-900'}`}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-400">{hint}</p> : null}
    </div>
  )
}