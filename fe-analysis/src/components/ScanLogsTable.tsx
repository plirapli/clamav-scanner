import { Fragment, useState } from 'react'
import ScanLogDetail from './ScanLogDetail'
import VerdictBadge from './VerdictBadge'
import type { ScanLog } from '../types'

interface ScanLogsTableProps {
  logs: ScanLog[]
  loading: boolean
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

function classifierSummary(log: ScanLog): string {
  if (log.classifier_label) {
    const confidence = log.classifier_confidence
    const percent =
      confidence === null || confidence === undefined
        ? '—'
        : `${Math.round(confidence * 100)}%`
    return `${log.classifier_label} · ${percent}`
  }
  if (log.analysis_supported === false) return 'skipped (non-PE)'
  if (log.clamav_detected) return '—'
  return 'assessment unavailable'
}

export default function ScanLogsTable({ logs, loading }: ScanLogsTableProps) {
  const [expanded, setExpanded] = useState<number | null>(null)

  if (loading) {
    return (
      <div className="flex justify-center py-16 text-slate-400">Memuat data…</div>
    )
  }

  if (logs.length === 0) {
    return (
      <div className="py-16 text-center text-slate-400">
        Tidak ada log yang cocok dengan filter.
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
            <th className="px-4 py-3">Verdict</th>
            <th className="px-4 py-3">Classifier</th>
            <th className="px-4 py-3">Aplikasi</th>
            <th className="px-4 py-3">Sumber IP</th>
            <th className="px-4 py-3">Ukuran</th>
            <th className="px-4 py-3">Waktu</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 bg-white">
          {logs.map((log) => (
            <Fragment key={log.id}>
              <tr
                onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                className="cursor-pointer hover:bg-slate-50"
              >
                <td className="max-w-[220px] truncate px-4 py-3 font-medium text-slate-800">
                  {log.filename || '(body)'}
                </td>
                <td className="px-4 py-3">
                  {log.virus_name ? (
                    <span className="rounded bg-red-50 px-2 py-0.5 font-mono text-xs text-red-700">
                      {log.virus_name}
                    </span>
                  ) : (
                    <span className="text-slate-400">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <VerdictBadge verdict={log.verdict} size="sm" />
                </td>
                <td className="px-4 py-3 text-xs text-slate-600">{classifierSummary(log)}</td>
                <td className="px-4 py-3 text-slate-600">{log.application || '—'}</td>
                <td className="px-4 py-3 font-mono text-slate-600">{log.source_ip || '—'}</td>
                <td className="px-4 py-3 text-slate-600">{formatBytes(log.size)}</td>
                <td className="px-4 py-3 text-slate-500">{formatDate(log.created_at)}</td>
              </tr>
              {expanded === log.id ? (
                <tr>
                  <td colSpan={8} className="p-0">
                    <ScanLogDetail log={log} />
                  </td>
                </tr>
              ) : null}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
