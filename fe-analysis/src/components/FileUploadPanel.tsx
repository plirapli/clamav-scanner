import { useRef, useState } from 'react'
import { scanFiles } from '../api'
import type { ScannerResponse } from '../types'

function resultStyle(status: string) {
  if (status === 'clean') return 'bg-emerald-50 text-emerald-700 ring-emerald-200'
  if (status === 'infected') return 'bg-red-50 text-red-700 ring-red-200'
  return 'bg-amber-50 text-amber-700 ring-amber-200'
}

function resultLabel(status: string) {
  if (status === 'clean') return 'Aman'
  if (status === 'infected') return 'Terinfeksi'
  return 'Gagal dipindai'
}

export default function FileUploadPanel() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [files, setFiles] = useState<File[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScannerResponse | null>(null)

  const chooseFiles = (nextFiles: FileList | null) => {
    setFiles(nextFiles ? Array.from(nextFiles) : [])
    setResult(null)
    setError(null)
  }

  const upload = async () => {
    if (!files.length) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await scanFiles(files))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload dan scan gagal')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 p-5">
        <h2 className="text-base font-bold text-slate-900">Upload File untuk Dipindai</h2>
        <p className="mt-1 text-sm text-slate-500">
          Periksa file sebelum dibuka, digunakan, atau dibagikan. Anda dapat memilih beberapa file sekaligus.
        </p>
      </div>

      <div className="p-5">
        <div className="mb-5 grid gap-3 rounded-lg bg-indigo-50 p-4 text-sm text-indigo-950 sm:grid-cols-3">
          <div>
            <p className="font-semibold">1. Pilih file</p>
            <p className="mt-1 text-xs leading-5 text-indigo-800">Klik “Pilih File”, lalu pilih satu atau beberapa file dari perangkat Anda.</p>
          </div>
          <div>
            <p className="font-semibold">2. Mulai pemindaian</p>
            <p className="mt-1 text-xs leading-5 text-indigo-800">Klik “Upload & Scan” dan tunggu hingga hasil setiap file ditampilkan.</p>
          </div>
          <div>
            <p className="font-semibold">3. Tindak lanjuti hasil</p>
            <p className="mt-1 text-xs leading-5 text-indigo-800">Jangan buka atau jalankan file berstatus “Terinfeksi”. Hapus atau karantina file tersebut sesuai prosedur keamanan.</p>
          </div>
        </div>

        <p className="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">
          Pemindaian mendeteksi ancaman yang sudah dikenal oleh database ClamAV. Hasil “Aman” bukan jaminan mutlak bahwa file bebas risiko.
        </p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="sr-only"
          onChange={(event) => chooseFiles(event.target.files)}
        />
        <div className="flex flex-col gap-4 rounded-lg border-2 border-dashed border-slate-300 bg-slate-50 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-700">
              {files.length ? `${files.length} file dipilih` : 'Belum ada file dipilih'}
            </p>
            {files.length ? (
              <ul className="mt-1 max-w-xl space-y-1 text-xs text-slate-500">
                {files.map((file) => <li key={`${file.name}-${file.lastModified}`}>{file.name}</li>)}
              </ul>
            ) : null}
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              onClick={() => inputRef.current?.click()}
              className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition hover:bg-slate-100"
            >
              Pilih File
            </button>
            <button
              type="button"
              onClick={() => void upload()}
              disabled={!files.length || loading}
              className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Memindai…' : 'Upload & Scan'}
            </button>
          </div>
        </div>

        {error ? <p className="mt-4 text-sm text-red-600">{error}</p> : null}

        {result ? (
          <div className="mt-4 overflow-hidden rounded-lg border border-slate-200">
            <p className="border-b border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              {result.message}
            </p>
            <ul className="divide-y divide-slate-200">
              {result.data?.files.map((file) => (
                <li key={file.name} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm">
                  <div>
                    <p className="font-medium text-slate-800">{file.name || 'Request body'}</p>
                    {file.scan || file.error ? (
                      <p className="mt-0.5 text-xs text-slate-500">{file.scan ?? file.error}</p>
                    ) : null}
                  </div>
                  <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${resultStyle(file.status)}`}>
                    {resultLabel(file.status)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </section>
  )
}
