import type { StaticAnalysis } from '../types'

interface EvidenceListProps {
  analysis: StaticAnalysis
}

export default function EvidenceList({ analysis }: EvidenceListProps) {
  if (!analysis.supported) {
    return (
      <p className="text-xs text-slate-500">
        Analysis skipped (unsupported type)
        {analysis.error ? `: ${analysis.error}` : ''}
      </p>
    )
  }

  const indicators: string[] = []
  if (analysis.file_type) {
    indicators.push(
      analysis.architecture
        ? `${analysis.file_type} · ${analysis.architecture}`
        : analysis.file_type,
    )
  }
  if (analysis.is_dll) indicators.push('DLL')
  if (analysis.has_packed_section) indicators.push('packed')
  indicators.push(analysis.has_digital_signature ? 'digitally signed' : 'unsigned')
  if (typeof analysis.max_entropy === 'number') {
    indicators.push(`max entropy ${analysis.max_entropy.toFixed(2)}`)
  }
  if (analysis.suspicious_imports?.length) {
    indicators.push(`${analysis.suspicious_imports.length} suspicious imports`)
  }
  if (analysis.imports_count) indicators.push(`${analysis.imports_count} imports`)
  if (analysis.error) indicators.push(`error: ${analysis.error}`)

  return (
    <div className="space-y-1">
      <p className="text-xs text-slate-600">{indicators.join(' · ')}</p>
      {analysis.packer_hints?.length ? (
        <p className="text-[11px] text-slate-500">{analysis.packer_hints.join(' · ')}</p>
      ) : null}
      {analysis.suspicious_imports?.length ? (
        <p className="break-words font-mono text-[11px] text-slate-500">
          {analysis.suspicious_imports.join(', ')}
        </p>
      ) : null}
    </div>
  )
}
