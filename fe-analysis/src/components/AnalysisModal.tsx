import type { AnalysisResult, ScanLog } from '../types'
import RiskBadge from './RiskBadge'

interface AnalysisModalProps {
  log: ScanLog
  result: AnalysisResult | null
  loading: boolean
  error: string | null
  onClose: () => void
}

export default function AnalysisModal({
  log,
  result,
  loading,
  error,
  onClose,
}: AnalysisModalProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white p-6 shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-slate-900">Analisis AI</h2>
            <p className="mt-1 break-all font-mono text-xs text-red-700">
              {log.virus_name}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
            aria-label="Tutup"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="mt-4">
          {loading ? (
            <p className="py-8 text-center text-slate-400">
              AI sedang menganalisis…
            </p>
          ) : error ? (
            <p className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</p>
          ) : result ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="text-sm font-medium text-slate-500">Tingkat risiko:</span>
                <RiskBadge level={result.risk_level} />
              </div>

              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Ringkasan
                </h3>
                <p className="mt-1 text-sm leading-relaxed text-slate-700">
                  {result.summary}
                </p>
              </div>

              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Mitigasi
                </h3>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-slate-700">
                  {result.remediation.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </div>

              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Rekomendasi
                </h3>
                <p className="mt-1 text-sm leading-relaxed text-slate-700">
                  {result.recommendation}
                </p>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}