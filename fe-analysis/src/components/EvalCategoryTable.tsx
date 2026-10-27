import { useMemo } from 'react'
import { category, isCorrect, outcome } from '../evalStats'
import type { EvalSample, Verdict } from '../types'

const VERDICT_BARS: Record<Verdict, string> = {
  ALLOW: 'bg-emerald-500',
  QUARANTINE: 'bg-amber-400',
  BLOCK: 'bg-red-500',
}

const LABEL_STYLES: Record<string, string> = {
  benign: 'bg-emerald-50 text-emerald-700',
  suspicious: 'bg-amber-50 text-amber-700',
  malicious: 'bg-red-50 text-red-700',
  'insufficient-evidence': 'bg-slate-100 text-slate-600',
}

interface CategoryRow {
  name: string
  total: number
  correct: number
  scored: number
  verdicts: Record<Verdict, number>
  labels: Record<string, number>
}

interface EvalCategoryTableProps {
  samples: EvalSample[]
  selected: string
  onSelect: (category: string) => void
}

export default function EvalCategoryTable({ samples, selected, onSelect }: EvalCategoryTableProps) {
  const rows = useMemo(() => {
    const byName = new Map<string, CategoryRow>()
    for (const sample of samples) {
      const name = category(sample)
      const row = byName.get(name) ?? {
        name,
        total: 0,
        correct: 0,
        scored: 0,
        verdicts: { ALLOW: 0, QUARANTINE: 0, BLOCK: 0 },
        labels: {},
      }
      row.total++
      if (sample.verdict) row.verdicts[sample.verdict]++
      if (sample.label) row.labels[sample.label] = (row.labels[sample.label] ?? 0) + 1
      const correct = isCorrect(outcome(sample))
      if (correct !== null) {
        row.scored++
        if (correct) row.correct++
      }
      byName.set(name, row)
    }
    return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name))
  }, [samples])

  return (
    <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 p-5">
        <h2 className="font-semibold text-slate-900">By category</h2>
        <p className="mt-1 text-sm text-slate-500">
          Correct means malware was not allowed and benign files were allowed. Click a row to filter the samples below.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-200 text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3 text-right">Files</th>
              <th className="px-4 py-3">Correct</th>
              <th className="px-4 py-3">Verdicts</th>
              <th className="px-4 py-3">Clef labels</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((row) => {
              const active = row.name === selected
              const share = row.scored === 0 ? null : row.correct / row.scored
              return (
                <tr
                  key={row.name}
                  onClick={() => onSelect(active ? '' : row.name)}
                  aria-selected={active}
                  className={`cursor-pointer transition ${active ? 'bg-indigo-50' : 'hover:bg-slate-50'}`}
                >
                  <td className="px-4 py-2.5 font-medium text-slate-800">{row.name}</td>
                  <td className="px-4 py-2.5 text-right tabular-nums text-slate-600">{row.total}</td>
                  <td className="px-4 py-2.5">
                    {share === null ? (
                      <span className="text-xs text-slate-400">not scored</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="h-1.5 w-20 overflow-hidden rounded-full bg-red-100">
                          <span
                            className="block h-full rounded-full bg-emerald-500"
                            style={{ width: `${share * 100}%` }}
                          />
                        </span>
                        <span className="text-xs tabular-nums text-slate-600">
                          {row.correct}/{row.scored}
                        </span>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <div
                      className="flex h-2 w-28 overflow-hidden rounded-full bg-slate-100"
                      title={`ALLOW ${row.verdicts.ALLOW} · QUARANTINE ${row.verdicts.QUARANTINE} · BLOCK ${row.verdicts.BLOCK}`}
                    >
                      {(['ALLOW', 'QUARANTINE', 'BLOCK'] as Verdict[]).map((verdict) =>
                        row.verdicts[verdict] ? (
                          <span
                            key={verdict}
                            className={VERDICT_BARS[verdict]}
                            style={{ width: `${(row.verdicts[verdict] / row.total) * 100}%` }}
                          />
                        ) : null,
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(row.labels)
                        .sort(([a], [b]) => a.localeCompare(b))
                        .map(([label, count]) => (
                          <span
                            key={label}
                            className={`rounded px-1.5 py-0.5 text-[11px] ${LABEL_STYLES[label] ?? 'bg-slate-100 text-slate-600'}`}
                          >
                            {label === 'insufficient-evidence' ? 'insufficient' : label} {count}
                          </span>
                        ))}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}
