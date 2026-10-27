import type { GenericEvidence, StaticAnalysis } from '../types'

const KIND_LABELS: Record<string, string> = {
  pe: 'PE',
  pdf: 'PDF',
  office: 'Office',
  archive: 'Archive',
  script: 'Script',
  text: 'Text',
  binary: 'Binary',
  generic: 'Unclassified',
}

function genericIndicators(g: GenericEvidence): string[] {
  const indicators: string[] = []
  if (g.embedded_pe) indicators.push('embedded executable')
  if (g.encrypted) indicators.push('encrypted / password-protected')
  if (g.has_macros) indicators.push('macros')
  if (g.has_javascript) indicators.push('javascript')
  if (g.auto_exec) indicators.push('auto-exec')
  if (g.external_targets?.length) indicators.push(`${g.external_targets.length} external targets`)
  if (g.nested_executables?.length) indicators.push(`${g.nested_executables.length} nested executables`)
  if (g.urls?.length) indicators.push(`${g.urls.length} URLs`)
  if (g.obfuscation_hints?.length) indicators.push(...g.obfuscation_hints)
  return indicators
}

export default function EvidenceList({ analysis }: { analysis: StaticAnalysis }) {
  const generic = analysis.generic
  const genericHints = generic ? genericIndicators(generic) : []

  if (!analysis.supported) {
    return (
      <div className="space-y-1">
        <p className="text-xs text-slate-500">
          Analysis skipped (unsupported type)
          {analysis.error ? `: ${analysis.error}` : ''}
        </p>
        {genericHints.length ? (
          <p className="text-[11px] text-amber-700">{genericHints.join(' · ')}</p>
        ) : null}
      </div>
    )
  }

  const indicators: string[] = []
  if (analysis.kind) indicators.push(KIND_LABELS[analysis.kind] ?? analysis.kind)
  if (analysis.file_type) {
    indicators.push(
      analysis.architecture
        ? `${analysis.file_type} · ${analysis.architecture}`
        : analysis.file_type,
    )
  }
  if (analysis.is_dll) indicators.push('DLL')
  if (analysis.is_dotnet) indicators.push('.NET')
  if (analysis.has_packed_section) indicators.push('packed')
  if (analysis.kind === 'pe') {
    if (analysis.signature_status === 'invalid') {
      indicators.push(`signature does not match file (claims ${analysis.signer_subject ?? 'unknown signer'})`)
    } else if (analysis.signer_subject) {
      indicators.push(
        `signed by ${analysis.signer_subject}${analysis.signature_status === 'valid' ? ' (valid)' : ' (unverified)'}`,
      )
    } else {
      indicators.push(analysis.has_digital_signature ? 'digitally signed' : 'unsigned')
    }
  }
  if (typeof analysis.max_entropy === 'number') {
    indicators.push(`max entropy ${analysis.max_entropy.toFixed(2)}`)
  }
  if (analysis.suspicious_imports?.length) {
    indicators.push(`${analysis.suspicious_imports.length} suspicious imports`)
  }
  if (analysis.imports_count) indicators.push(`${analysis.imports_count} imports`)
  indicators.push(...genericHints)
  if (analysis.error) indicators.push(`error: ${analysis.error}`)

  return (
    <div className="space-y-1">
      <p className="text-xs text-slate-600">{indicators.join(' · ')}</p>
      {analysis.packer_hints?.length ? (
        <p className="text-[11px] text-slate-500">{analysis.packer_hints.join(' · ')}</p>
      ) : null}
      {generic?.suspicious_strings?.length ? (
        <p className="break-words font-mono text-[11px] text-slate-500">
          {generic.suspicious_strings.join(', ')}
        </p>
      ) : null}
      {analysis.suspicious_imports?.length ? (
        <p className="break-words font-mono text-[11px] text-slate-500">
          {analysis.suspicious_imports.join(', ')}
        </p>
      ) : null}
    </div>
  )
}
