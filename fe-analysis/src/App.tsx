import { useCallback, useEffect, useMemo, useState } from 'react'
import { analyzeLog, listScanLogs, summarizeLogs } from './api'
import AnalysisModal from './components/AnalysisModal'
import ScanLogsTable from './components/ScanLogsTable'
import StatCard from './components/StatCard'
import SummaryPanel from './components/SummaryPanel'
import type { AnalysisResult, ScanLog, SummaryResult } from './types'

export default function App() {
  const [logs, setLogs] = useState<ScanLog[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [virusName, setVirusName] = useState('')
  const [application, setApplication] = useState('')

  const [selectedLog, setSelectedLog] = useState<ScanLog | null>(null)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [analyzingId, setAnalyzingId] = useState<string | null>(null)
  const [analysisError, setAnalysisError] = useState<string | null>(null)

  const [summary, setSummary] = useState<SummaryResult | null>(null)
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [summaryError, setSummaryError] = useState<string | null>(null)

  const fetchLogs = useCallback(async () => {
    try {
      const response = await listScanLogs({
        virus_name: virusName || undefined,
        application: application || undefined,
        limit: 50,
      })
      setError(null)
      setLogs(response.data.items)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Gagal memuat data')
      setLogs([])
    } finally {
      setLoading(false)
    }
  }, [virusName, application])

  useEffect(() => {
    // fetchLogs hanya melakukan setState setelah await (async), bukan sinkron
    // oxlint-disable-next-line react/set-state-in-effect
    void fetchLogs()
  }, [fetchLogs])

  const stats = useMemo(() => {
    const viruses = new Set(logs.map((log) => log.virus_name))
    const apps = new Set(logs.map((log) => log.application).filter(Boolean))
    return { total: logs.length, viruses: viruses.size, apps: apps.size }
  }, [logs])

  const handleAnalyze = async (log: ScanLog) => {
    setSelectedLog(log)
    setAnalysis(null)
    setAnalysisError(null)
    setAnalyzingId(log._id)
    try {
      const response = await analyzeLog(log._id)
      setAnalysis(response.data)
    } catch (err) {
      setAnalysisError(err instanceof Error ? err.message : 'Analisis gagal')
    } finally {
      setAnalyzingId(null)
    }
  }

  const handleGenerateSummary = async () => {
    setSummaryLoading(true)
    setSummaryError(null)
    try {
      const response = await summarizeLogs(20)
      setSummary(response.data)
    } catch (err) {
      setSummaryError(err instanceof Error ? err.message : 'Ringkasan gagal')
    } finally {
      setSummaryLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div>
            <h1 className="text-xl font-bold">Dashboard Analisis Keamanan</h1>
            <p className="text-sm text-slate-500">
              Log deteksi virus ClamAV + analisis AI
            </p>
          </div>
          <span className="rounded-full bg-red-50 px-3 py-1 text-xs font-semibold text-red-700 ring-1 ring-red-200">
            Infected Logs
          </span>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        <div className="grid gap-4 sm:grid-cols-3">
          <StatCard label="Total Log Terinfeksi" value={stats.total} hint="dari data saat ini" accent="text-red-600" />
          <StatCard label="Jenis Virus" value={stats.viruses} hint="virus unik terdeteksi" />
          <StatCard label="Aplikasi Terdampak" value={stats.apps} hint="aplikasi client" />
        </div>

        <SummaryPanel
          result={summary}
          loading={summaryLoading}
          error={summaryError}
          onGenerate={handleGenerateSummary}
        />

        <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-col gap-3 border-b border-slate-200 p-5 sm:flex-row sm:items-end sm:justify-between">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="text-xs font-medium text-slate-500">Nama Virus</span>
                <input
                  type="text"
                  value={virusName}
                  onChange={(event) => setVirusName(event.target.value)}
                  placeholder="cth: Eicar"
                  className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-500">Aplikasi</span>
                <input
                  type="text"
                  value={application}
                  onChange={(event) => setApplication(event.target.value)}
                  placeholder="cth: app-a"
                  className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
              </label>
            </div>
            <button
              type="button"
              onClick={() => {
                setLoading(true)
                void fetchLogs()
              }}
              disabled={loading}
              className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:opacity-50"
            >
              {loading ? 'Memuat…' : 'Terapkan Filter'}
            </button>
          </div>

          {error ? (
            <p className="p-6 text-sm text-red-600">{error}</p>
          ) : (
            <ScanLogsTable
              logs={logs}
              loading={loading}
              analyzingId={analyzingId}
              onAnalyze={handleAnalyze}
            />
          )}
        </section>
      </main>

      {selectedLog ? (
        <AnalysisModal
          log={selectedLog}
          result={analysis}
          loading={analyzingId !== null}
          error={analysisError}
          onClose={() => setSelectedLog(null)}
        />
      ) : null}
    </div>
  )
}