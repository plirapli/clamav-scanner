import { Fragment, useState } from 'react'
import ScanLogDetail from './ScanLogDetail'
import VerdictBadge from './VerdictBadge'
import type { ScanLog, ScanLogSortKey, SortOrder } from '../types'

export interface ScanLogSort {
  key: ScanLogSortKey
  order: SortOrder
}

interface ScanLogsTableProps {
  logs: ScanLog[]
  loading: boolean
  sort: ScanLogSort
  onSortChange: (sort: ScanLogSort) => void
}

const columns: { key: ScanLogSortKey; label: string; firstOrder: SortOrder }[] = [
  { key: 'filename', label: 'File', firstOrder: 'asc' },
  { key: 'virus_name', label: 'Virus', firstOrder: 'asc' },
  { key: 'verdict', label: 'Verdict', firstOrder: 'desc' },
  { key: 'classifier', label: 'Classifier', firstOrder: 'desc' },
  { key: 'application', label: 'Application', firstOrder: 'asc' },
  { key: 'source_ip', label: 'Source IP', firstOrder: 'asc' },
  { key: 'size', label: 'Size', firstOrder: 'desc' },
  { key: 'created_at', label: 'Time', firstOrder: 'desc' },
]

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('en-US', {
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

export default function ScanLogsTable({ logs, loading, sort, onSortChange }: ScanLogsTableProps) {
  const [expanded, setExpanded] = useState<number | null>(null)

  const toggleSort = (key: ScanLogSortKey, firstOrder: SortOrder) => {
    if (sort.key === key) {
      onSortChange({ key, order: sort.order === 'asc' ? 'desc' : 'asc' })
    } else {
      onSortChange({ key, order: firstOrder })
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-16 text-slate-400">Loading data…</div>
    )
  }

  if (logs.length === 0) {
    return (
      <div className="py-16 text-center text-slate-400">
        No logs match the current filters.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            {columns.map(({ key, label, firstOrder }) => {
              const active = sort.key === key
              return (
                <th
                  key={key}
                  className="px-4 py-3"
                  aria-sort={active ? (sort.order === 'asc' ? 'ascending' : 'descending') : 'none'}
                >
                  <button
                    type="button"
                    onClick={() => toggleSort(key, firstOrder)}
                    className={`group inline-flex items-center gap-1 uppercase tracking-wide transition hover:text-slate-900 ${active ? 'text-indigo-700' : ''}`}
                  >
                    {label}
                    <span
                      aria-hidden="true"
                      className={active ? '' : 'text-slate-300 group-hover:text-slate-400'}
                    >
                      {active ? (sort.order === 'asc' ? '▲' : '▼') : '↕'}
                    </span>
                  </button>
                </th>
              )
            })}
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
