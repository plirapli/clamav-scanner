import ClassifierBars from './ClassifierBars'
import EvidenceList from './EvidenceList'
import type { ScanLog } from '../types'

export default function ScanLogDetail({ log }: { log: ScanLog }) {
  const analysis = log.evidence?.static_analysis

  return (
    <div className="grid gap-4 bg-slate-50 px-4 py-3 sm:grid-cols-2">
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence</p>
        {analysis ? (
          <EvidenceList analysis={analysis} />
        ) : (
          <p className="text-xs text-slate-500">No static analysis stored</p>
        )}
        <p className="text-xs text-slate-500">
          ClamAV: {log.clamav_detected ? log.clamav_signature || 'detected' : 'not detected'}
        </p>
        {log.sha256 ? (
          <p className="break-all font-mono text-[11px] text-slate-500">sha256 {log.sha256}</p>
        ) : null}
      </div>

      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Classifier</p>
        {log.classifier_label ? (
          <>
            <p className="text-xs text-slate-700">
              {log.classifier_label} · confidence{' '}
              {log.classifier_confidence === null || log.classifier_confidence === undefined
                ? '—'
                : log.classifier_confidence.toFixed(2)}
              {log.classifier_model ? ` · ${log.classifier_model}` : ''}
            </p>
            <ClassifierBars scores={log.classifier_scores} activeLabel={log.classifier_label} />
          </>
        ) : (
          <p className="text-xs text-slate-500">
            {log.analysis_supported === false
              ? 'analysis skipped (non-PE)'
              : 'assessment unavailable'}
          </p>
        )}
        {log.classifier_error ? (
          <p className="text-xs text-red-600">{log.classifier_error}</p>
        ) : null}
        {log.verdict_reasons?.length ? (
          <ul className="list-disc pl-4 text-xs text-slate-600">
            {log.verdict_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        ) : null}
        {log.quarantined ? (
          <p className="text-xs font-medium text-amber-700">Quarantined</p>
        ) : null}
      </div>
    </div>
  )
}
