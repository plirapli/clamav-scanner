import { useRef, useState } from 'react'
import type { DragEvent } from 'react'
import { scanFiles } from '../api'
import ScanResultCard from './ScanResultCard'
import type { ScannerResponse } from '../types'

export default function FileUploadPanel() {
  const inputRef = useRef<HTMLInputElement>(null)
  const dragDepth = useRef(0)
  const [files, setFiles] = useState<File[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScannerResponse | null>(null)

  const chooseFiles = (nextFiles: FileList | File[] | null) => {
    setFiles(nextFiles ? Array.from(nextFiles) : [])
    setResult(null)
    setError(null)
  }

  const handleDragEnter = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    if (loading) return
    dragDepth.current += 1
    setIsDragging(true)
  }

  const handleDragOver = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = loading ? 'none' : 'copy'
  }

  const handleDragLeave = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    dragDepth.current = Math.max(0, dragDepth.current - 1)
    if (dragDepth.current === 0) {
      setIsDragging(false)
    }
  }

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    dragDepth.current = 0
    setIsDragging(false)
    if (loading) return

    const dropped = event.dataTransfer?.files
    if (dropped?.length) {
      chooseFiles(dropped)
    }
  }

  const upload = async () => {
    if (!files.length) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await scanFiles(files))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload and scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 p-5">
        <h2 className="text-base font-bold text-slate-900">Upload Files for Scanning</h2>
        <p className="mt-1 text-sm text-slate-500">
          Check files before opening, using, or sharing them. You can select multiple files at once.
        </p>
      </div>

      <div className="p-5">
        <div className="mb-5 grid gap-3 rounded-lg bg-indigo-50 p-4 text-sm text-indigo-950 sm:grid-cols-3">
          <div>
            <p className="font-semibold">1. Choose files</p>
            <p className="mt-1 text-xs leading-5 text-indigo-800">Click “Choose Files” or drag and drop files onto the upload area.</p>
          </div>
          <div>
            <p className="font-semibold">2. Start the scan</p>
            <p className="mt-1 text-xs leading-5 text-indigo-800">Click “Upload & Scan”. ClamAV, static analysis, and the classifier run in sequence.</p>
          </div>
          <div>
            <p className="font-semibold">3. Act on the result</p>
            <p className="mt-1 text-xs leading-5 text-indigo-800">Follow the verdict: ALLOW can be used, QUARANTINE is held for review, BLOCK must not be opened.</p>
          </div>
        </div>

        <p className="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">
          The verdict is layered: ClamAV signatures, static-analysis evidence, and the classifier
          assessment. Non-PE files and low-confidence assessments may still be unsafe — an ALLOW verdict is not a guarantee.
        </p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="sr-only"
          onChange={(event) => chooseFiles(event.target.files)}
        />
        <div
          onDragEnter={handleDragEnter}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`flex flex-col gap-4 rounded-lg border-2 border-dashed p-5 transition sm:flex-row sm:items-center sm:justify-between ${
            isDragging ? 'border-indigo-400 bg-indigo-50' : 'border-slate-300 bg-slate-50'
          }`}
        >
          <div>
            <p className="text-sm font-medium text-slate-700">
              {files.length ? `${files.length} file(s) selected` : 'No files selected'}
            </p>
            {files.length ? (
              <ul className="mt-1 max-w-xl space-y-1 text-xs text-slate-500">
                {files.map((file) => <li key={`${file.name}-${file.lastModified}`}>{file.name}</li>)}
              </ul>
            ) : (
              <p className="mt-1 text-xs text-slate-500">
                {isDragging
                  ? 'Drop the files here…'
                  : 'Drag and drop one or more files here, or click “Choose Files”.'}
              </p>
            )}
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              onClick={() => inputRef.current?.click()}
              className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition hover:bg-slate-100"
            >
              Choose Files
            </button>
            <button
              type="button"
              onClick={() => void upload()}
              disabled={!files.length || loading}
              className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Scanning…' : 'Upload & Scan'}
            </button>
          </div>
        </div>

        {error ? <p className="mt-4 text-sm text-red-600">{error}</p> : null}

        {result ? (
          <div className="mt-4 space-y-3">
            <p className="text-sm text-slate-700">
              {result.message}
              {result.request_id ? ` · request ${result.request_id.slice(0, 8)}…` : ''}
            </p>
            {(result.data?.files ?? []).map((file, index) => (
              <ScanResultCard key={`${file.name || 'body'}-${index}`} file={file} />
            ))}
          </div>
        ) : null}
      </div>
    </section>
  )
}
