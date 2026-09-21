import { useCallback, useEffect, useMemo, useState } from 'react'
import { listScanLogs } from './api'
import FileUploadPanel from './components/FileUploadPanel'
import ScanLogsTable from './components/ScanLogsTable'
import StatCard from './components/StatCard'
import type { ScanLog } from './types'

type Page = 'dashboard' | 'upload'

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [logs, setLogs] = useState<ScanLog[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [virusName, setVirusName] = useState('')
  const [application, setApplication] = useState('')

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

  const navigate = (nextPage: Page) => {
    setPage(nextPage)
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold">Analisis Keamanan</h1>
            <p className="text-sm text-slate-500">
              {page === 'dashboard' ? 'Log deteksi virus ClamAV' : 'Pindai file sebelum digunakan atau dibagikan'}
            </p>
          </div>
          <nav className="flex rounded-lg bg-slate-100 p-1" aria-label="Navigasi halaman">
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
              Upload File
            </button>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {page === 'dashboard' ? (
          <>
            <div className="grid gap-4 sm:grid-cols-3">
              <StatCard label="Total Log Terinfeksi" value={stats.total} hint="dari data saat ini" accent="text-red-600" />
              <StatCard label="Jenis Virus" value={stats.viruses} hint="virus unik terdeteksi" />
              <StatCard label="Aplikasi Terdampak" value={stats.apps} hint="aplikasi client" />
            </div>

            <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
              <div className="border-b border-slate-200 p-5">
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
              </div>

              {error ? (
                <p className="p-6 text-sm text-red-600">{error}</p>
              ) : (
                <ScanLogsTable logs={logs} loading={loading} />
              )}
            </section>
          </>
        ) : <FileUploadPanel />}
      </main>
    </div>
  )
}
