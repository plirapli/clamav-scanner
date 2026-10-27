import type { ApiResponse, EvalRun, EvalRunDetail, ScanLogSortKey, ScanLogSummary, ScanLogsData, ScannerResponse, SortOrder, Verdict } from './types'

const SCANNER_API_BASE = import.meta.env.VITE_SCANNER_API_BASE ?? ''

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${SCANNER_API_BASE}${path}`, init)
  if (!response.ok) {
    let message = response.statusText
    try {
      const body = await response.json()
      message = body.message ?? body.detail ?? message
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
  verdict?: Verdict
  sort?: ScanLogSortKey
  order?: SortOrder
  limit?: number
  skip?: number
}

export async function listScanLogs(
  params: ListScanLogsParams = {},
): Promise<ApiResponse<ScanLogsData>> {
  const query = new URLSearchParams()
  if (params.virus_name) query.set('virus_name', params.virus_name)
  if (params.application) query.set('application', params.application)
  if (params.verdict) query.set('verdict', params.verdict)
  if (params.sort) query.set('sort', params.sort)
  if (params.order) query.set('order', params.order)
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.skip !== undefined) query.set('skip', String(params.skip))
  const qs = query.toString()
  return request(`/api/scanner/logs${qs ? `?${qs}` : ''}`)
}

export type ScanLogSummaryParams = Pick<ListScanLogsParams, 'virus_name' | 'application' | 'verdict'>

export async function getScanLogSummary(
  params: ScanLogSummaryParams = {},
): Promise<ApiResponse<ScanLogSummary>> {
  const query = new URLSearchParams()
  if (params.virus_name) query.set('virus_name', params.virus_name)
  if (params.application) query.set('application', params.application)
  if (params.verdict) query.set('verdict', params.verdict)
  const qs = query.toString()
  return request(`/api/scanner/logs/summary${qs ? `?${qs}` : ''}`)
}

export async function scanFiles(files: File[]): Promise<ScannerResponse> {
  const formData = new FormData()
  files.forEach((file) => formData.append('files', file))

  const response = await fetch(`${SCANNER_API_BASE}/api/scanner/scan`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
    },
    body: formData,
  })

  let body: ScannerResponse | undefined
  try {
    body = (await response.json()) as ScannerResponse
  } catch {
    throw new Error(response.statusText || 'Invalid scanner response')
  }

  if (!response.ok && !body.data) {
    throw new Error(body.message || response.statusText)
  }

  return body
}

export async function listEvalRuns(): Promise<ApiResponse<EvalRun[]>> {
  return request('/api/eval/runs')
}

export async function getEvalRun(name: string): Promise<ApiResponse<EvalRunDetail>> {
  return request(`/api/eval/runs/${encodeURIComponent(name)}`)
}
