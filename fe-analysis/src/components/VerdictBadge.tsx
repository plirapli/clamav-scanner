import type { Verdict } from '../types'

const STYLES: Record<Verdict, string> = {
  ALLOW: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  QUARANTINE: 'bg-amber-50 text-amber-700 ring-amber-200',
  BLOCK: 'bg-red-50 text-red-700 ring-red-200',
}

const ICONS: Record<Verdict, string> = {
  ALLOW: '✓',
  QUARANTINE: '⚠',
  BLOCK: '⛔',
}

interface VerdictBadgeProps {
  verdict?: Verdict
  size?: 'sm' | 'md'
}

export default function VerdictBadge({ verdict, size = 'md' }: VerdictBadgeProps) {
  if (!verdict) {
    return <span className="text-xs text-slate-400">—</span>
  }

  const sizing = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full font-semibold ring-1 ${STYLES[verdict]} ${sizing}`}
    >
      <span aria-hidden>{ICONS[verdict]}</span>
      {verdict}
    </span>
  )
}
