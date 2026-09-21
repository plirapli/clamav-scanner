const LABEL_ORDER = ['benign', 'suspicious', 'malicious', 'insufficient-evidence']

const BAR_STYLES: Record<string, string> = {
  benign: 'bg-emerald-500',
  suspicious: 'bg-amber-500',
  malicious: 'bg-red-500',
  'insufficient-evidence': 'bg-slate-400',
}

const LABEL_TEXT: Record<string, string> = {
  'insufficient-evidence': 'insufficient-ev.',
}

interface ClassifierBarsProps {
  scores?: Record<string, number> | null
  activeLabel?: string
}

export default function ClassifierBars({ scores, activeLabel }: ClassifierBarsProps) {
  if (!scores || Object.keys(scores).length === 0) {
    return <p className="text-xs text-slate-400">—</p>
  }

  const known = LABEL_ORDER.filter((label) => label in scores)
  const extra = Object.keys(scores)
    .filter((label) => !LABEL_ORDER.includes(label))
    .sort()
  const labels = [...known, ...extra]

  return (
    <div className="space-y-1">
      {labels.map((label) => {
        const score = scores[label] ?? 0
        const percent = Math.round(score * 100)
        const active = label === activeLabel

        return (
          <div
            key={label}
            className="flex items-center gap-2"
            aria-label={`${label} ${percent}%`}
          >
            <span
              className={`w-28 shrink-0 truncate text-xs ${active ? 'font-semibold text-slate-800' : 'text-slate-500'}`}
            >
              {LABEL_TEXT[label] ?? label}
            </span>
            <div
              className={`h-2 flex-1 overflow-hidden rounded bg-slate-100 ${active ? 'ring-1 ring-slate-300' : ''}`}
            >
              <div
                className={`h-full rounded ${BAR_STYLES[label] ?? 'bg-indigo-400'}`}
                style={{ width: `${percent}%` }}
              />
            </div>
            <span
              className={`w-9 shrink-0 text-right text-xs tabular-nums ${active ? 'font-semibold text-slate-800' : 'text-slate-500'}`}
            >
              {percent}%
            </span>
          </div>
        )
      })}
    </div>
  )
}
