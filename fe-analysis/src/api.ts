import type {
  AnalysisResult,
  ApiResponse,
  ScanLogsData,
  ScannerResponse,
  SummaryResult,
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE ?? ''
const SCANNER_API_BASE = import.meta.env.VITE_SCANNER_API_BASE ?? ''
const SCANNER_CLIENT_ID = import.meta.env.VITE_SCANNER_CLIENT_ID ?? ''
const SCANNER_TOKEN = import.meta.env.VITE_SCANNER_TOKEN ?? ''

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init)
  if (!response.ok) {
    let message = response.statusText
    try {
      const body = await response.json()
      message = body.detail ?? body.message ?? message
    } catch {
      // ignore parse error, keep statusText
    }
    throw new Error(message)
  }
  return response.json() as Promise<T>
}

export interface ListScanLogsParams {
  virus_name?: string
  application?: string
  limit?: number
  skip?: number
}

export async function listScanLogs(
  params: ListScanLogsParams = {},
): Promise<ApiResponse<ScanLogsData>> {
  const query = new URLSearchParams()
  if (params.virus_name) query.set('virus_name', params.virus_name)
  if (params.application) query.set('application', params.application)
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.skip !== undefined) query.set('skip', String(params.skip))
  const qs = query.toString()
  return request(`/analysis/scan-logs${qs ? `?${qs}` : ''}`)
}

export async function analyzeLog(
  logId: string,
): Promise<ApiResponse<AnalysisResult>> {
  return request(`/analysis/scan-logs/${encodeURIComponent(logId)}/analyze`, {
    method: 'POST',
  })
}

export async function summarizeLogs(
  limit = 20,
): Promise<ApiResponse<SummaryResult>> {
  return request(`/analysis/scan-logs/summary?limit=${limit}`, {
    method: 'POST',
  })
}

export async function scanFiles(files: File[]): Promise<ScannerResponse> {
  if (!SCANNER_CLIENT_ID || !SCANNER_TOKEN) {
    throw new Error('VITE_SCANNER_CLIENT_ID dan VITE_SCANNER_TOKEN belum dikonfigurasi')
  }

  const formData = new FormData()
  files.forEach((file) => formData.append('files', file))

  const token = SCANNER_TOKEN.startsWith('Bearer ')
    ? SCANNER_TOKEN
    : `Bearer ${SCANNER_TOKEN}`
  const response = await fetch(`${SCANNER_API_BASE}/api/scanner/scan`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'X-Client-ID': SCANNER_CLIENT_ID,
      Authorization: token,
    },
    body: formData,
  })

  let body: ScannerResponse | undefined
  try {
    body = (await response.json()) as ScannerResponse
  } catch {
    throw new Error(response.statusText || 'Respons scanner tidak valid')
  }

  if (!response.ok && !body.data) {
    throw new Error(body.message || response.statusText)
  }

  return body
}
