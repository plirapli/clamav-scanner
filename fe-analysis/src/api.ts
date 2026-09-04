import type {
  AnalysisResult,
  ApiResponse,
  ScanLogsData,
  SummaryResult,
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE ?? ''

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