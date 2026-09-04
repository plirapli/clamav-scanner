export interface ScanLog {
  _id: string
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
}

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface AnalysisResult {
  risk_level: RiskLevel
  summary: string
  remediation: string[]
  recommendation: string
}

export interface SummaryResult {
  total_infected: string
  top_virus: string
  trends: string
  recommendations: string[]
}

export interface ScanLogsData {
  total: number
  items: ScanLog[]
}

export interface ApiResponse<T> {
  success: boolean
  message: string
  data: T
}

export type ScannerFileStatus = 'clean' | 'infected' | 'failed'

export interface ScannerFileResult {
  name: string
  status: ScannerFileStatus
  scan?: string
  error?: string
}

export interface ScannerResult {
  files: ScannerFileResult[]
}

export interface ScannerResponse {
  code: number
  status: string
  message: string
  data?: ScannerResult
}
