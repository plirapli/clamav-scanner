import type { SummaryResult } from '../types'

interface SummaryPanelProps {
  result: SummaryResult | null
  loading: boolean
  error: string | null
  onGenerate: () => void
}

export default function SummaryPanel({
  result,
  loading,
  error,
  onGenerate,
}: SummaryPanelProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-slate-900">Ringkasan AI</h2>
          <p className="text-sm text-slate-500">
            Analisis tren dari log infeksi terbaru
          </p>
        </div>
        <button
          type="button"
          onClick={onGenerate}
          disabled={loading}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? 'Menghasilkan…' : 'Generate Ringkasan'}
        </button>
      </div>

      <div className="mt-4">
        {loading ? (
          <p className="py-8 text-center text-slate-400">AI sedang merangkum…</p>
        ) : error ? (
          <p className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</p>
        ) : result ? (
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-lg bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Total Terinfeksi</p>
              <p className="mt-1 text-2xl font-bold text-slate-900">
                {result.total_infected}
              </p>
            </div>
            <div className="rounded-lg bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Virus Teratas</p>
              <p className="mt-1 truncate font-mono text-sm font-semibold text-red-700">
                {result.top_virus}
              </p>
            </div>
            <div className="rounded-lg bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-500">Tren</p>
              <p className="mt-1 text-sm text-slate-700">{result.trends}</p>
            </div>
            <div className="sm:col-span-3">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                Rekomendasi
              </h3>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-slate-700">
                {result.recommendations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        ) : (
          <p className="py-8 text-center text-slate-400">
            Klik "Generate Ringkasan" untuk melihat analisis AI dari log terinfeksi.
          </p>
        )}
      </div>
    </div>
  )
}