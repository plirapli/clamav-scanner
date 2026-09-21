import ClassifierBars from './ClassifierBars'
import EvidenceList from './EvidenceList'
import VerdictBadge from './VerdictBadge'
import type { ScannerFileResult } from '../types'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function classifierStatus(file: ScannerFileResult): string {
  if (file.clamav.detected) return 'not needed (blocked by ClamAV)'
  if (!file.static_analysis) return 'assessment unavailable'
  if (!file.static_analysis.supported) return 'analysis skipped (unsupported type)'
  if (file.classifier) return ''
  return 'assessment unavailable'
}

export default function ScanResultCard({ file }: { file: ScannerFileResult }) {
  const classifier = file.classifier
  const confidence =
    classifier?.confidence === null || classifier?.confidence === undefined
      ? '—'
      : classifier.confidence.toFixed(2)

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-semibold text-slate-800">{file.name || '(request body)'}</p>
          <p className="mt-0.5 text-xs text-slate-500">
            {formatBytes(file.size)} · {file.mime || 'unknown type'}
            {file.sha256 ? ` · sha256 ${file.sha256.slice(0, 12)}…` : ''}
          </p>
        </div>
        <VerdictBadge verdict={file.verdict} />
      </div>

      <dl className="mt-3 space-y-2">
        <div className="flex gap-3">
          <dt className="w-28 shrink-0 text-xs font-medium text-slate-500">ClamAV</dt>
          <dd className="text-xs text-slate-700">
            {file.clamav.detected
              ? `Detected: ${file.clamav.signature}`
              : file.clamav.error
                ? `Error: ${file.clamav.error}`
                : '✓ Not detected'}
          </dd>
        </div>

        <div className="flex gap-3">
          <dt className="w-28 shrink-0 text-xs font-medium text-slate-500">Static analysis</dt>
          <dd className="min-w-0 flex-1">
            {file.static_analysis ? (
              <EvidenceList analysis={file.static_analysis} />
            ) : (
              <span className="text-xs text-slate-500">not run</span>
            )}
          </dd>
        </div>

        <div className="flex gap-3">
          <dt className="w-28 shrink-0 text-xs font-medium text-slate-500">Classifier</dt>
          <dd className="min-w-0 flex-1">
            {classifier ? (
              <>
                <p className="text-xs text-slate-700">
                  {classifier.label} · confidence {confidence}
                  {classifier.model ? ` · ${classifier.model}` : ''}
                </p>
                <div className="mt-1.5 max-w-md">
                  <ClassifierBars scores={classifier.scores} activeLabel={classifier.label} />
                </div>
              </>
            ) : (
              <span className="text-xs text-slate-500">{classifierStatus(file)}</span>
            )}
          </dd>
        </div>
      </dl>

      {file.verdict_reasons?.length ? (
        <div className="mt-3 border-t border-slate-100 pt-2">
          <p className="text-xs font-medium text-slate-500">Reasons</p>
          <ul className="mt-1 list-disc pl-4 text-xs text-slate-600">
            {file.verdict_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {file.quarantined ? (
        <p className="mt-2 text-xs font-medium text-amber-700">Quarantined</p>
      ) : null}
    </div>
  )
}
