export type Verdict = 'ALLOW' | 'QUARANTINE' | 'BLOCK'

export interface ClamAVResult {
  detected: boolean
  signature?: string | null
  error?: string
}

export interface StaticAnalysis {
  supported: boolean
  file_type?: string
  architecture?: string
  is_dll?: boolean
  entry_point_section?: string
  max_entropy?: number
  has_packed_section?: boolean
  has_digital_signature?: boolean
  packer_hints?: string[]
  suspicious_imports?: string[]
  imports_count?: number
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
