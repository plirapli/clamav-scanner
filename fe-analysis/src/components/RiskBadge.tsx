import type { RiskLevel } from '../types'

const styles: Record<RiskLevel, string> = {
  low: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  medium: 'bg-yellow-50 text-yellow-700 ring-yellow-200',
  high: 'bg-orange-50 text-orange-700 ring-orange-200',
  critical: 'bg-red-50 text-red-700 ring-red-200',
}

export default function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ${styles[level] ?? styles.medium}`}
    >
      {level}
    </span>
  )
}