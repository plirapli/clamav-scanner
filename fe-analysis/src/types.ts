export type Verdict = 'ALLOW' | 'QUARANTINE' | 'BLOCK'

export type ScanLogSortKey =
  | 'filename'
  | 'virus_name'
  | 'verdict'
  | 'classifier'
  | 'application'
  | 'source_ip'
  | 'size'
  | 'created_at'

export type SortOrder = 'asc' | 'desc'

export interface ClamAVResult {
  detected: boolean
  signature?: string | null
  error?: string
}

export interface GenericEvidence {
  magic_type?: string
  file_entropy?: number
  embedded_pe?: boolean
  embedded_types?: string[]
  nested_executables?: string[]
  urls?: string[]
  has_javascript?: boolean
  has_macros?: boolean
  encrypted?: boolean
  external_targets?: string[]
  auto_exec?: boolean
  suspicious_strings?: string[]
  obfuscation_hints?: string[]
}

export interface StaticAnalysis {
  supported: boolean
  kind?: string
  file_type?: string
  architecture?: string
  is_dll?: boolean
  is_dotnet?: boolean
  entry_point_section?: string
  max_entropy?: number
  overlay_size?: number
  overlay_entropy?: number
  has_packed_section?: boolean
  has_digital_signature?: boolean
  signer_subject?: string
  signer_issuer?: string
  signature_status?: 'valid' | 'invalid' | 'unverified'
  packer_hints?: string[]
  suspicious_imports?: string[]
  imports_count?: number
  generic?: GenericEvidence
  error?: string
}

export interface ClassifierResult {
  label: string
  confidence: number | null
  model?: string
  scores?: Record<string, number> | null
}

export interface FileInfo {
  name: string
  size: number
  mime: string
  sha256: string
}

export interface FileEvidence {
  file: FileInfo
  clamav: ClamAVResult
  static_analysis: StaticAnalysis
}

export interface ScanLog {
  id: number
  request_id: string
  application: string
  source_ip: string
  filename: string
  sha256: string
  mime_type: string
  size: number
  status: string
  virus_name: string
  scan_engine: string
  db_version: number
  duration_ms: number
  created_at: string
  verdict?: Verdict
  verdict_reasons?: string[]
  clamav_detected?: boolean
  clamav_signature?: string
  analysis_supported?: boolean
  evidence?: FileEvidence | null
  classifier_label?: string
  classifier_confidence?: number | null
  classifier_scores?: Record<string, number> | null
  classifier_model?: string
  classifier_error?: string
  quarantined?: boolean
  cached?: boolean
}

export interface ScanLogGroup {
  value: string
  count: number
  last_seen: string
}

export interface ScanLogSummary {
  total: number
  virus_names: ScanLogGroup[]
  applications: ScanLogGroup[]
}

export interface ScanLogsData {
  total: number
  items: ScanLog[]
}

export interface ApiResponse<T> {
  code: number
  status: string
  message: string
  data: T
}

export type ScannerFileStatus = 'clean' | 'infected' | 'quarantined' | 'blocked' | 'failed'

export interface ScannerFileResult {
  name: string
  size: number
  mime: string
  sha256: string
  status: ScannerFileStatus
  scan?: string
  error?: string
  verdict?: Verdict
  verdict_reasons?: string[]
  quarantined?: boolean
  cached?: boolean
  clamav: ClamAVResult
  static_analysis?: StaticAnalysis
  classifier?: ClassifierResult
}

export interface ScannerResult {
  files: ScannerFileResult[]
}

export interface ScannerResponse {
  code: number
  status: string
  message: string
  request_id?: string
  data?: ScannerResult
}

export interface EvalRun {
  name: string
  created_at: string
  samples: number
  models?: string[]
  has_summary: boolean
}

export type EvalVariant = 'combined' | 'rule-only' | 'classifier-only'

export interface EvalEvaluation {
  variant: EvalVariant
  block_confidence: number
  imports_min: number
  samples: number
  verdicts: Record<Verdict, number>
  malware_total: number
  malware_detected: number
  benign_total: number
  benign_flagged: number
  clamav_misses: number
  clamav_misses_escalated: number
  true_positive: number
  false_positive: number
  false_negative: number
  precision: number
  recall: number
  f1: number
  false_positive_rate: number
  null_confidence: number
  labels: Record<string, number>
}

export interface EvalSummary {
  samples: number
  models: string[]
  latency: Record<string, { p50: number; p95: number }>
  evaluations: EvalEvaluation[]
}

export interface EvalSample {
  path: string
  expected: string
  tags?: string[]
  sha256?: string
  size: number
  error?: string
  clamav_detected: boolean
  clamav_signature?: string
  kind?: string
  signer?: string
  signature_status?: 'valid' | 'invalid' | 'unverified'
  label?: string
  confidence?: number | null
  scores?: Record<string, number> | null
  classifier_error?: string
  verdict?: Verdict
  reasons?: string[]
  duration_ms: number
}

export interface EvalRunDetail {
  name: string
  created_at: string
  summary: EvalSummary | null
  policy: { block_confidence: number; suspicious_imports_min: number }
  samples: EvalSample[]
}
