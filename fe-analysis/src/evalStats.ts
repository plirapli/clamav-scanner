import type { EvalSample, Verdict } from './types'

export type Outcome = 'caught' | 'missed' | 'allowed' | 'false-positive' | 'unscored'

// outcome scores a sample the way cmd/eval analyze does: malware must not be
// ALLOWed, benign files must be. Other expectations are informational only.
export function outcome(sample: EvalSample): Outcome {
  if (!sample.verdict) return 'unscored'
  if (sample.expected === 'malware') return sample.verdict === 'ALLOW' ? 'missed' : 'caught'
  if (sample.expected === 'benign') return sample.verdict === 'ALLOW' ? 'allowed' : 'false-positive'
  return 'unscored'
}

export function isCorrect(value: Outcome): boolean | null {
  if (value === 'caught' || value === 'allowed') return true
  if (value === 'missed' || value === 'false-positive') return false
  return null
}

// category groups samples by corpus folder: benign/pe/x.exe → "benign · pe",
// malware/bazaar/exe/<sha>.exe → "malware · exe", benign/note.txt → "benign".
export function category(sample: EvalSample): string {
  const parts = sample.path.split('/')
  if (parts[0] === 'malware' && parts[1] === 'bazaar' && parts.length > 3) return `malware · ${parts[2]}`
  if (parts.length > 2) return `${parts[0]} · ${parts[1]}`
  return parts[0]
}

export function fileName(sample: EvalSample): string {
  const name = sample.path.split('/').pop() ?? sample.path
  // MalwareBazaar samples are named by SHA-256; shorten them for the table.
  return /^[0-9a-f]{64}\./.test(name) ? `${name.slice(0, 12)}….${name.split('.').pop()}` : name
}

export interface Rate {
  hit: number
  total: number
}

export function rate({ hit, total }: Rate): string {
  return total === 0 ? '—' : `${Math.round((hit / total) * 100)}%`
}

export interface Headline {
  malware: Rate
  benign: Rate
  clamavMisses: Rate
  verdicts: Record<Verdict, number>
}

export function headline(samples: EvalSample[]): Headline {
  const result: Headline = {
    malware: { hit: 0, total: 0 },
    benign: { hit: 0, total: 0 },
    clamavMisses: { hit: 0, total: 0 },
    verdicts: { ALLOW: 0, QUARANTINE: 0, BLOCK: 0 },
  }
  for (const sample of samples) {
    if (sample.verdict) result.verdicts[sample.verdict]++
    const value = outcome(sample)
    if (sample.expected === 'malware' && value !== 'unscored') {
      result.malware.total++
      if (value === 'caught') result.malware.hit++
      if (!sample.clamav_detected) {
        result.clamavMisses.total++
        if (value === 'caught') result.clamavMisses.hit++
      }
    }
    if (sample.expected === 'benign' && value !== 'unscored') {
      result.benign.total++
      if (value === 'false-positive') result.benign.hit++
    }
  }
  return result
}
