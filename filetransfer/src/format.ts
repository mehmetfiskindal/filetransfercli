const UNITS = ['B', 'KB', 'MB', 'GB', 'TB']

/** Compact byte size, e.g. `1.4 GB`. Mirrors the CLI's humanBytes output. */
export function humanBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value = value / 1024
    unit++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${UNITS[unit]}`
}

export function humanRate(bytesPerSecond: number): string {
  if (bytesPerSecond <= 0) return '—'
  return `${humanBytes(bytesPerSecond)}/s`
}

/** Seconds remaining at the current rate, rendered as `m:ss` or `—`. */
export function humanEta(remaining: number, bytesPerSecond: number): string {
  if (bytesPerSecond <= 0 || remaining <= 0) return '—'
  const seconds = Math.round(remaining / bytesPerSecond)
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  return `${minutes}:${rest < 10 ? '0' : ''}${rest}`
}

/** Whole-percent completion, clamped so a stale counter cannot overflow a bar. */
export function percent(done: number, total: number): number {
  if (total <= 0) return 0
  const pct = Math.round((done / total) * 100)
  return pct < 0 ? 0 : pct > 100 ? 100 : pct
}

/** Trailing path segment, for a row label that must fit a phone's width. */
export function baseName(path: string): string {
  const cut = path.lastIndexOf('/')
  return cut < 0 ? path : path.slice(cut + 1)
}
