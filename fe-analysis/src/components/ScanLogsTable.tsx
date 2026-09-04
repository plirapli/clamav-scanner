import type { ScanLog } from '../types'

interface ScanLogsTableProps {
  logs: ScanLog[]
  loading: boolean
  analyzingId: string | null
  onAnalyze: (log: ScanLog) => void
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('id-ID', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function ScanLogsTable({
  logs,
  loading,
  analyzingId,
  onAnalyze,
}: ScanLogsTableProps) {
  if (loading) {
    return (
      <div className="flex justify-center py-16 text-slate-400">Memuat data…</div>
    )
  }

  if (logs.length === 0) {
    return (
      <div className="py-16 text-center text-slate-400">
        Tidak ada log terinfeksi yang cocok dengan filter.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-3">File</th>
            <th className="px-4 py-3">Virus</th>
            <th className="px-4 py-3">Aplikasi</th>
            <th className="px-4 py-3">Sumber IP</th>
            <th className="px-4 py-3">Ukuran</th>
            <th className="px-4 py-3">Durasi</th>
            <th className="px-4 py-3">Waktu</th>
            <th className="px-4 py-3 text-right">Aksi</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 bg-white">
          {logs.map((log) => (
            <tr key={log._id} className="hover:bg-slate-50">
              <td className="max-w-[220px] truncate px-4 py-3 font-medium text-slate-800">
                {log.filename || '(body)'}
              </td>
              <td className="px-4 py-3">
                <span className="rounded bg-red-50 px-2 py-0.5 font-mono text-xs text-red-700">
                  {log.virus_name}
                </span>
              </td>
              <td className="px-4 py-3 text-slate-600">{log.application || '—'}</td>
              <td className="px-4 py-3 font-mono text-slate-600">
                {log.source_ip || '—'}
              </td>
              <td className="px-4 py-3 text-slate-600">{formatBytes(log.size)}</td>
              <td className="px-4 py-3 text-slate-600">{log.duration_ms} ms</td>
              <td className="px-4 py-3 text-slate-500">{formatDate(log.created_at)}</td>
              <td className="px-4 py-3 text-right">
                <button
                  type="button"
                  disabled={analyzingId === log._id}
                  onClick={() => onAnalyze(log)}
                  className="rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {analyzingId === log._id ? 'Menganalisis…' : 'Analisis AI'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}