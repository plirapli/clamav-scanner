import { useEffect, useMemo, useRef, useState } from 'react'
import { getEvalRun, listEvalRuns } from '../api'
import { headline, rate } from '../evalStats'
import type { EvalRun, EvalRunDetail } from '../types'
import EvalCategoryTable from './EvalCategoryTable'
import EvalSamplesTable from './EvalSamplesTable'
import EvalSummaryTables from './EvalSummaryTables'
import Select, { type SelectOption } from './Select'
import StatCard from './StatCard'

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString('en-US', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function EvaluationPage() {
  const [runs, setRuns] = useState<EvalRun[] | null>(null)
  const [runName, setRunName] = useState('')
  const [detail, setDetail] = useState<EvalRunDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [categoryFilter, setCategoryFilter] = useState('')
  const detailRequest = useRef(0)

  useEffect(() => {
    let cancelled = false
    listEvalRuns()
      .then((response) => {
        if (cancelled) return
        setRuns(response.data)
        setRunName((current) => current || response.data[0]?.name || '')
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setRuns([])
        setError(err instanceof Error ? err.message : 'Failed to load eval runs')
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!runName) return
    const requestId = ++detailRequest.current
    // oxlint-disable-next-line react/set-state-in-effect
    setLoading(true)
    getEvalRun(runName)
      .then((response) => {
        if (requestId !== detailRequest.current) return
        setDetail(response.data)
        setError(null)
      })
      .catch((err: unknown) => {
        if (requestId !== detailRequest.current) return
        setDetail(null)
        setError(err instanceof Error ? err.message : 'Failed to load eval run')
      })
      .finally(() => {
        if (requestId === detailRequest.current) setLoading(false)
      })
  }, [runName])

  const runOptions = useMemo<SelectOption<string>[]>(
    () =>
      (runs ?? []).map((run) => ({
        value: run.name,
        label: `${run.name} · ${formatDate(run.created_at)}`,
      })),
    [runs],
  )

  const stats = useMemo(() => (detail ? headline(detail.samples) : null), [detail])
  const latency = detail?.summary?.latency

  if (runs === null) {
    return <div className="flex justify-center py-16 text-slate-400">Loading eval runs…</div>
  }

  if (runs.length === 0) {
    return (
      <section className="rounded-xl border border-slate-200 bg-white p-8 text-sm text-slate-600 shadow-sm">
        <h2 className="font-semibold text-slate-900">No evaluation results yet</h2>
        {error ? <p className="mt-2 text-red-600">{error}</p> : null}
        <p className="mt-2">Run the eval harness from <span className="font-mono">scanner-service/</span>:</p>
        <pre className="mt-3 overflow-x-auto rounded-lg bg-slate-900 p-4 text-xs text-slate-100">
          {'go run ./cmd/eval collect -out ../eval/results/my-run\ngo run ./cmd/eval analyze -in ../eval/results/my-run'}
        </pre>
      </section>
    )
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm sm:flex-row sm:items-end sm:justify-between">
        <div className="w-full sm:max-w-md">
          <span id="eval-run-label" className="text-xs font-medium text-slate-500">
            Eval run
          </span>
          <Select
            value={runName}
            options={runOptions}
            onChange={(next) => {
              setRunName(next)
              setCategoryFilter('')
            }}
            aria-labelledby="eval-run-label"
            className="mt-1"
          />
        </div>
        {detail ? (
          <p className="text-sm text-slate-500">
            {detail.samples.length} samples · model {detail.summary?.models?.join(', ') || '—'} · policy block ≥{' '}
            {detail.policy.block_confidence}, suspicious imports ≥ {detail.policy.suspicious_imports_min}
          </p>
        ) : null}
      </section>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      {loading && !detail ? <div className="flex justify-center py-16 text-slate-400">Loading run…</div> : null}

      {detail && stats ? (
        <div className={`space-y-6 transition-opacity ${loading ? 'opacity-50' : ''}`}>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="Malware caught"
              value={rate(stats.malware)}
              hint={`${stats.malware.hit} of ${stats.malware.total} malware samples not allowed`}
              accent="text-emerald-600"
            />
            <StatCard
              label="ClamAV misses caught"
              value={rate(stats.clamavMisses)}
              hint={`${stats.clamavMisses.hit} of ${stats.clamavMisses.total} malware ClamAV did not detect`}
              accent="text-indigo-600"
            />
            <StatCard
              label="Benign false positives"
              value={rate(stats.benign)}
              hint={`${stats.benign.hit} of ${stats.benign.total} benign files quarantined or blocked`}
              accent="text-amber-600"
            />
            <StatCard
              label="Latency p50 / p95"
              value={latency?.total ? `${latency.total.p50} / ${latency.total.p95} ms` : '—'}
              hint={latency?.classifier ? `Clef ${latency.classifier.p50} / ${latency.classifier.p95} ms` : 'run analyze for latency'}
            />
          </div>

          {detail.summary ? (
            <EvalSummaryTables summary={detail.summary} policy={detail.policy} />
          ) : (
            <p className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
              This run has no summary.json. Run{' '}
              <span className="font-mono">go run ./cmd/eval analyze -in ../eval/results/{detail.name}</span> to add the
              variant comparison and threshold grid.
            </p>
          )}

          <EvalCategoryTable samples={detail.samples} selected={categoryFilter} onSelect={setCategoryFilter} />
          <EvalSamplesTable
            key={detail.name}
            samples={detail.samples}
            category={categoryFilter}
            onCategoryChange={setCategoryFilter}
          />
        </div>
      ) : null}
    </div>
  )
}
