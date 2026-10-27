import type { EvalEvaluation, EvalSummary } from '../types'

const percent = (value: number) => `${Math.round(value * 100)}%`

const VARIANT_TEXT: Record<string, { title: string; description: string }> = {
  'rule-only': { title: 'Rules only', description: 'ClamAV + static rules, no classifier' },
  'classifier-only': { title: 'Classifier only', description: 'ClamAV + Clef, no static rules' },
  combined: { title: 'Combined', description: 'ClamAV + static rules + Clef (production)' },
}

interface EvalSummaryTablesProps {
  summary: EvalSummary
  policy: { block_confidence: number; suspicious_imports_min: number }
}

function isCurrent(evaluation: EvalEvaluation, policy: EvalSummaryTablesProps['policy']) {
  return (
    Math.abs(evaluation.block_confidence - policy.block_confidence) < 1e-9 &&
    evaluation.imports_min === policy.suspicious_imports_min
  )
}

// EvalSummaryTables renders the two tables cmd/eval analyze computes: the
// variant comparison and the combined-policy threshold grid.
export default function EvalSummaryTables({ summary, policy }: EvalSummaryTablesProps) {
  const combined = summary.evaluations.filter((evaluation) => evaluation.variant === 'combined')
  const currentCombined = combined.find((evaluation) => isCurrent(evaluation, policy))
  const variants = [
    ...summary.evaluations.filter((evaluation) => evaluation.variant !== 'combined'),
    ...(currentCombined ? [currentCombined] : []),
  ]

  const blockValues = [...new Set(combined.map((evaluation) => evaluation.block_confidence))].sort((a, b) => a - b)
  const importValues = [...new Set(combined.map((evaluation) => evaluation.imports_min))].sort((a, b) => a - b)
  const cell = (block: number, imports: number) =>
    combined.find((evaluation) => evaluation.block_confidence === block && evaluation.imports_min === imports)

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 p-5">
          <h2 className="font-semibold text-slate-900">Variants</h2>
          <p className="mt-1 text-sm text-slate-500">
            Same samples, different signal sets. Variants use block confidence {policy.block_confidence} and suspicious
            imports ≥ {policy.suspicious_imports_min}.
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3">Variant</th>
                <th className="px-4 py-3 text-right">Malware caught</th>
                <th className="px-4 py-3 text-right">Benign FP</th>
                <th className="px-4 py-3 text-right">Precision</th>
                <th className="px-4 py-3 text-right">F1</th>
                <th className="whitespace-nowrap px-4 py-3 text-right">A / Q / B</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {variants.map((evaluation) => {
                const text = VARIANT_TEXT[evaluation.variant] ?? { title: evaluation.variant, description: '' }
                return (
                  <tr key={evaluation.variant} className={evaluation.variant === 'combined' ? 'bg-indigo-50/50' : ''}>
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-800">{text.title}</p>
                      <p className="text-xs text-slate-400">{text.description}</p>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      <span className="font-semibold text-slate-900">{percent(evaluation.recall)}</span>
                      <span className="block text-xs text-slate-400">
                        {evaluation.malware_detected}/{evaluation.malware_total}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      <span className="font-semibold text-slate-900">{percent(evaluation.false_positive_rate)}</span>
                      <span className="block text-xs text-slate-400">
                        {evaluation.benign_flagged}/{evaluation.benign_total}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-slate-700">{percent(evaluation.precision)}</td>
                    <td className="px-4 py-3 text-right tabular-nums text-slate-700">{evaluation.f1.toFixed(2)}</td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono text-xs text-slate-600">
                      <span className="text-emerald-600">{evaluation.verdicts.ALLOW ?? 0}</span> /{' '}
                      <span className="text-amber-600">{evaluation.verdicts.QUARANTINE ?? 0}</span> /{' '}
                      <span className="text-red-600">{evaluation.verdicts.BLOCK ?? 0}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 p-5">
          <h2 className="font-semibold text-slate-900">Threshold grid (combined)</h2>
          <p className="mt-1 text-sm text-slate-500">
            Malware caught / benign false positives for each <span className="font-mono">VERDICT_BLOCK_CONFIDENCE</span>{' '}
            × <span className="font-mono">SUSPICIOUS_IMPORTS_MIN</span>. The cell marked “current” is the scanner's
            setting; identical cells mean that threshold does not change any verdict in this run.
          </p>
        </div>
        {combined.length === 0 ? (
          <p className="p-6 text-center text-sm text-slate-400">No threshold grid in this run.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3 text-left">Block ≥</th>
                  {importValues.map((imports) => (
                    <th key={imports} className="px-4 py-3 text-center">
                      imports ≥ {imports}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {blockValues.map((block) => (
                  <tr key={block}>
                    <td className="px-4 py-2 font-mono text-slate-700">{block.toFixed(2)}</td>
                    {importValues.map((imports) => {
                      const evaluation = cell(block, imports)
                      const current = evaluation ? isCurrent(evaluation, policy) : false
                      return (
                        <td key={imports} className="px-2 py-1.5 text-center">
                          {evaluation ? (
                            <span
                              className={`inline-block rounded-md px-2 py-1 tabular-nums ${current ? 'bg-indigo-50' : ''}`}
                              title={`F1 ${evaluation.f1.toFixed(2)} · BLOCK ${evaluation.verdicts.BLOCK ?? 0}`}
                            >
                              <span className="font-semibold text-slate-900">{percent(evaluation.recall)}</span>
                              <span className="text-slate-400"> / </span>
                              <span className="text-amber-700">{percent(evaluation.false_positive_rate)}</span>
                              {current ? (
                                <span className="block text-[10px] font-semibold uppercase tracking-wide text-indigo-600">
                                  current
                                </span>
                              ) : null}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
