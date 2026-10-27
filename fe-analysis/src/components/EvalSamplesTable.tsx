import { Fragment, useMemo, useState } from 'react'
import { category, fileName, outcome, type Outcome } from '../evalStats'
import type { EvalSample } from '../types'
import ClassifierBars from './ClassifierBars'
import Pagination from './Pagination'
import Select, { type SelectOption } from './Select'
import VerdictBadge from './VerdictBadge'

type OutcomeFilter = '' | 'problems' | Outcome

const outcomeOptions: SelectOption<OutcomeFilter>[] = [
  { value: '', label: 'All outcomes' },
  { value: 'problems', label: 'Errors only (missed + FP)' },
  { value: 'missed', label: 'Missed malware' },
  { value: 'false-positive', label: 'Benign false positives' },
  { value: 'caught', label: 'Malware caught' },
  { value: 'allowed', label: 'Benign allowed' },
  { value: 'unscored', label: 'Not scored' },
]

const OUTCOME_STYLES: Record<Outcome, { text: string; className: string }> = {
  caught: { text: 'caught', className: 'bg-emerald-50 text-emerald-700' },
  allowed: { text: 'allowed', className: 'bg-emerald-50 text-emerald-700' },
  missed: { text: 'missed', className: 'bg-red-100 text-red-700' },
  'false-positive': { text: 'false positive', className: 'bg-amber-100 text-amber-800' },
  unscored: { text: '—', className: 'text-slate-400' },
}

const SIGNATURE_STYLES: Record<string, string> = {
  valid: 'text-emerald-700',
  invalid: 'text-red-700',
  unverified: 'text-slate-500',
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

interface EvalSamplesTableProps {
  samples: EvalSample[]
  category: string
  onCategoryChange: (category: string) => void
}

export default function EvalSamplesTable({ samples, category: categoryFilter, onCategoryChange }: EvalSamplesTableProps) {
  const [outcomeFilter, setOutcomeFilter] = useState<OutcomeFilter>('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(20)
  const [expanded, setExpanded] = useState<string | null>(null)

  const categoryOptions = useMemo<SelectOption<string>[]>(() => {
    const names = [...new Set(samples.map(category))].sort()
    return [{ value: '', label: 'All categories' }, ...names.map((name) => ({ value: name, label: name }))]
  }, [samples])

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return samples.filter((sample) => {
      if (categoryFilter && category(sample) !== categoryFilter) return false
      const value = outcome(sample)
      if (outcomeFilter === 'problems' && value !== 'missed' && value !== 'false-positive') return false
      if (outcomeFilter && outcomeFilter !== 'problems' && value !== outcomeFilter) return false
      if (query && !sample.path.toLowerCase().includes(query) && !(sample.signer ?? '').toLowerCase().includes(query)) {
        return false
      }
      return true
    })
  }, [samples, categoryFilter, outcomeFilter, search])

  const lastPage = Math.max(0, Math.ceil(filtered.length / pageSize) - 1)
  const currentPage = Math.min(page, lastPage)
  const visible = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize)

  return (
    <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="space-y-3 border-b border-slate-200 p-5">
        <div>
          <h2 className="font-semibold text-slate-900">Samples</h2>
          <p className="mt-1 text-sm text-slate-500">
            Verdicts are recomputed with the scanner's current policy. Click a row for Clef's scores and the policy
            reasons.
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="block">
            <span className="text-xs font-medium text-slate-500">Search</span>
            <input
              type="text"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value)
                setPage(0)
              }}
              placeholder="file name, hash or signer"
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </label>
          <div>
            <span id="eval-category-label" className="text-xs font-medium text-slate-500">
              Category
            </span>
            <Select
              value={categoryFilter}
              options={categoryOptions}
              onChange={(next) => {
                onCategoryChange(next)
                setPage(0)
              }}
              aria-labelledby="eval-category-label"
              className="mt-1"
            />
          </div>
          <div>
            <span id="eval-outcome-label" className="text-xs font-medium text-slate-500">
              Outcome
            </span>
            <Select
              value={outcomeFilter}
              options={outcomeOptions}
              onChange={(next) => {
                setOutcomeFilter(next)
                setPage(0)
              }}
              aria-labelledby="eval-outcome-label"
              className="mt-1"
            />
          </div>
        </div>
      </div>

      {filtered.length === 0 ? (
        <p className="py-16 text-center text-sm text-slate-400">No samples match the current filters.</p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">File</th>
                  <th className="px-4 py-3">Expected</th>
                  <th className="px-4 py-3">ClamAV</th>
                  <th className="px-4 py-3">Clef</th>
                  <th className="px-4 py-3">Signature</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Outcome</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {visible.map((sample) => {
                  const value = outcome(sample)
                  const open = expanded === sample.path
                  return (
                    <Fragment key={sample.path}>
                      <tr
                        onClick={() => setExpanded(open ? null : sample.path)}
                        className={`cursor-pointer ${open ? 'bg-slate-50' : 'hover:bg-slate-50'}`}
                      >
                        <td className="max-w-[260px] px-4 py-3">
                          <p className="truncate font-medium text-slate-800" title={sample.path}>
                            {fileName(sample)}
                          </p>
                          <p className="text-xs text-slate-400">
                            {category(sample)} · {formatBytes(sample.size)}
                          </p>
                        </td>
                        <td className="px-4 py-3 text-slate-600">{sample.expected}</td>
                        <td className="px-4 py-3">
                          {sample.clamav_detected ? (
                            <span className="rounded bg-red-50 px-2 py-0.5 font-mono text-xs text-red-700">
                              {sample.clamav_signature || 'detected'}
                            </span>
                          ) : (
                            <span className="text-xs text-slate-400">not detected</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-600">
                          {sample.classifier_error ? (
                            <span className="text-red-600">error</span>
                          ) : sample.label ? (
                            `${sample.label}${typeof sample.confidence === 'number' ? ` · ${Math.round(sample.confidence * 100)}%` : ''}`
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="max-w-[180px] px-4 py-3 text-xs">
                          {sample.signature_status ? (
                            <span className={SIGNATURE_STYLES[sample.signature_status]} title={sample.signer}>
                              <span className="block truncate">{sample.signer || 'unknown signer'}</span>
                              <span className="text-[11px]">{sample.signature_status}</span>
                            </span>
                          ) : sample.kind === 'pe' ? (
                            <span className="text-slate-400">unsigned</span>
                          ) : (
                            <span className="text-slate-300">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <VerdictBadge verdict={sample.verdict} size="sm" />
                        </td>
                        <td className="px-4 py-3">
                          <span className={`rounded px-2 py-0.5 text-xs font-medium ${OUTCOME_STYLES[value].className}`}>
                            {OUTCOME_STYLES[value].text}
                          </span>
                        </td>
                      </tr>
                      {open ? (
                        <tr>
                          <td colSpan={7} className="bg-slate-50 px-6 py-4">
                            <div className="grid gap-6 md:grid-cols-2">
                              <div className="space-y-2">
                                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Clef scores</p>
                                {sample.classifier_error ? (
                                  <p className="text-xs text-red-600">{sample.classifier_error}</p>
                                ) : (
                                  <ClassifierBars scores={sample.scores} activeLabel={sample.label} />
                                )}
                              </div>
                              <div className="space-y-2 text-xs text-slate-600">
                                <p className="font-semibold uppercase tracking-wide text-slate-500">Policy reasons</p>
                                <ul className="list-inside list-disc space-y-0.5">
                                  {(sample.reasons ?? []).map((reason) => (
                                    <li key={reason}>{reason}</li>
                                  ))}
                                </ul>
                                <p className="break-all font-mono text-[11px] text-slate-400">{sample.path}</p>
                                {sample.tags?.length ? <p className="text-slate-500">tags: {sample.tags.join(', ')}</p> : null}
                                {sample.error ? <p className="text-red-600">{sample.error}</p> : null}
                              </div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
          <Pagination
            page={currentPage}
            pageSize={pageSize}
            total={filtered.length}
            onPageChange={setPage}
            onPageSizeChange={(nextSize) => {
              setPageSize(nextSize)
              setPage(0)
            }}
          />
        </>
      )}
    </section>
  )
}
