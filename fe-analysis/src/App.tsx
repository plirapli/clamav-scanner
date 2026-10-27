import { useCallback, useEffect, useRef, useState } from 'react'
import { getScanLogSummary, listScanLogs } from './api'
import BreakdownPanel from './components/BreakdownPanel'
import EvaluationPage from './components/EvaluationPage'
import FileUploadPanel from './components/FileUploadPanel'
import Pagination from './components/Pagination'
import Select, { type SelectOption } from './components/Select'
import ScanLogsTable, { type ScanLogSort } from './components/ScanLogsTable'
import StatCard from './components/StatCard'
import type { ScanLog, ScanLogSummary, Verdict } from './types'

type Page = 'dashboard' | 'upload' | 'evaluation'
type Breakdown = 'virus' | 'application'

const verdictDot = (color: string) => <span aria-hidden="true" className={`h-2 w-2 rounded-full ${color}`} />

const verdictOptions: SelectOption<Verdict | ''>[] = [
  { value: '', label: 'All verdicts', icon: verdictDot('bg-slate-300') },
  { value: 'BLOCK', label: 'BLOCK', icon: verdictDot('bg-red-500') },
  { value: 'QUARANTINE', label: 'QUARANTINE', icon: verdictDot('bg-amber-500') },
  { value: 'ALLOW', label: 'ALLOW', icon: verdictDot('bg-emerald-500') },
]

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [logs, setLogs] = useState<ScanLog[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [virusName, setVirusName] = useState('')
  const [application, setApplication] = useState('')
  const [verdict, setVerdict] = useState<Verdict | ''>('')

  const [sort, setSort] = useState<ScanLogSort>({ key: 'created_at', order: 'desc' })
  const [pageIndex, setPageIndex] = useState(0)
  const [pageSize, setPageSize] = useState(20)

  const [summary, setSummary] = useState<ScanLogSummary | null>(null)
  const [breakdown, setBreakdown] = useState<Breakdown | null>(null)

  // Request ids let a slow, superseded response be dropped instead of
  // overwriting the page the user has already moved to.
  const logsRequest = useRef(0)
  const summaryRequest = useRef(0)

  const fetchLogs = useCallback(async () => {
    const requestId = ++logsRequest.current
    try {
      const response = await listScanLogs({
        virus_name: virusName || undefined,
        application: application || undefined,
        verdict: verdict || undefined,
        sort: sort.key,
        order: sort.order,
        limit: pageSize,
        skip: pageIndex * pageSize,
      })
      if (requestId !== logsRequest.current) return
      const { items, total: count } = response.data
      // The current page can fall past the end when rows disappear; jump to the last one.
      if (items.length === 0 && count > 0 && pageIndex > 0) {
        setPageIndex(Math.ceil(count / pageSize) - 1)
        return
      }
      setError(null)
      setLogs(items)
      setTotal(count)
    } catch (err) {
      if (requestId !== logsRequest.current) return
      setError(err instanceof Error ? err.message : 'Failed to load data')
      setLogs([])
      setTotal(0)
    } finally {
      if (requestId === logsRequest.current) setLoading(false)
    }
  }, [virusName, application, verdict, sort, pageIndex, pageSize])

  useEffect(() => {
    // fetchLogs only sets state after await (async), not synchronously
    // oxlint-disable-next-line react/set-state-in-effect
    void fetchLogs()
  }, [fetchLogs])

  // The summary covers every log matching the filters, not just the visible page,
  // so it only refetches when a filter changes.
  const fetchSummary = useCallback(async () => {
    const requestId = ++summaryRequest.current
    try {
      const response = await getScanLogSummary({
        virus_name: virusName || undefined,
        application: application || undefined,
        verdict: verdict || undefined,
      })
      if (requestId === summaryRequest.current) setSummary(response.data)
    } catch {
      if (requestId === summaryRequest.current) setSummary(null)
    }
  }, [virusName, application, verdict])

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
    void fetchSummary()
  }, [fetchSummary])

  const toggleBreakdown = (next: Breakdown) => {
    setBreakdown((current) => (current === next ? null : next))
  }

  const navigate = (nextPage: Page) => {
    setPage(nextPage)
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold">Security Analysis</h1>
            <p className="text-sm text-slate-500">
              {page === 'dashboard'
                ? 'ClamAV virus detection log'
                : page === 'upload'
                  ? 'Scan files before opening or sharing them'
                  : 'How well the pipeline separates malware from benign files'}
            </p>
          </div>
          <nav className="flex rounded-lg bg-slate-100 p-1" aria-label="Page navigation">
            <button
              type="button"
              onClick={() => navigate('dashboard')}
              className={`rounded-md px-3 py-2 text-sm font-semibold transition ${page === 'dashboard' ? 'bg-white text-indigo-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Dashboard
            </button>
            <button
              type="button"
              onClick={() => navigate('upload')}
              className={`rounded-md px-3 py-2 text-sm font-semibold transition ${page === 'upload' ? 'bg-white text-indigo-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Upload
            </button>
            <button
              type="button"
              onClick={() => navigate('evaluation')}
              className={`rounded-md px-3 py-2 text-sm font-semibold transition ${page === 'evaluation' ? 'bg-white text-indigo-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Evaluation
            </button>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {page === 'dashboard' ? (
          <>
            <div className="grid gap-4 sm:grid-cols-3">
              <StatCard label="Total Logs" value={total} hint="matching the current filters" accent="text-red-600" />
              <StatCard
                label="Virus Types"
                value={summary?.virus_names.length ?? '—'}
                hint="distinct ClamAV signatures · click for details"
                onClick={() => toggleBreakdown('virus')}
                active={breakdown === 'virus'}
              />
              <StatCard
                label="Affected Applications"
                value={summary?.applications.length ?? '—'}
                hint="apps that received these files · click for details"
                onClick={() => toggleBreakdown('application')}
                active={breakdown === 'application'}
              />
            </div>

            {breakdown === 'virus' ? (
              <BreakdownPanel
                title="Virus types"
                description="Each row is a distinct malware name reported by ClamAV, like a species label for a known threat (e.g. Eicar-Test-Signature, Win.Trojan.Agent). One virus found in 5 files counts once here and shows 5 logs. Files flagged only by static analysis or the classifier have no virus name, so they are not listed. Click a row to filter the table."
                groups={summary?.virus_names ?? []}
                selected={virusName}
                emptyText="No ClamAV signatures among the logs matching the current filters."
                onSelect={(value) => {
                  setVirusName(value)
                  setPageIndex(0)
                }}
                onClose={() => setBreakdown(null)}
              />
            ) : null}
            {breakdown === 'application' ? (
              <BreakdownPanel
                title="Affected applications"
                description="Each row is the application (scanner instance, set by APP_NAME) that received the uploaded files, i.e. which system the risky files were sent to. Click a row to filter the table."
                groups={summary?.applications ?? []}
                selected={application}
                emptyText="No applications among the logs matching the current filters."
                onSelect={(value) => {
                  setApplication(value)
                  setPageIndex(0)
                }}
                onClose={() => setBreakdown(null)}
              />
            ) : null}

            <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
              <div className="border-b border-slate-200 p-5">
                <div className="grid gap-3 sm:grid-cols-3">
                  <label className="block">
                    <span className="text-xs font-medium text-slate-500">Virus name</span>
                    <input
                      type="text"
                      value={virusName}
                      onChange={(event) => {
                        setVirusName(event.target.value)
                        setPageIndex(0)
                      }}
                      placeholder="e.g. Eicar"
                      className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    />
                  </label>
                  <label className="block">
                    <span className="text-xs font-medium text-slate-500">Application</span>
                    <input
                      type="text"
                      value={application}
                      onChange={(event) => {
                        setApplication(event.target.value)
                        setPageIndex(0)
                      }}
                      placeholder="e.g. app-a"
                      className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    />
                  </label>
                  <div>
                    <span id="verdict-filter-label" className="text-xs font-medium text-slate-500">Verdict</span>
                    <Select
                      value={verdict}
                      options={verdictOptions}
                      onChange={(next) => {
                        setVerdict(next)
                        setPageIndex(0)
                      }}
                      aria-labelledby="verdict-filter-label"
                      className="mt-1"
                    />
                  </div>
                </div>
              </div>

              {error ? (
                <p className="p-6 text-sm text-red-600">{error}</p>
              ) : (
                <>
                  <ScanLogsTable
                    logs={logs}
                    loading={loading}
                    sort={sort}
                    onSortChange={(nextSort) => {
                      setSort(nextSort)
                      setPageIndex(0)
                    }}
                  />
                  {total > 0 ? (
                    <Pagination
                      page={pageIndex}
                      pageSize={pageSize}
                      total={total}
                      onPageChange={setPageIndex}
                      onPageSizeChange={(nextSize) => {
                        setPageSize(nextSize)
                        setPageIndex(0)
                      }}
                    />
                  ) : null}
                </>
              )}
            </section>
          </>
        ) : page === 'upload' ? (
          <FileUploadPanel />
        ) : (
          <EvaluationPage />
        )}
      </main>
    </div>
  )
}
