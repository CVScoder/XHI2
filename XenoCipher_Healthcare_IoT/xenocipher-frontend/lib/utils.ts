// lib/utils.ts
export function parsePrometheusPlainText(text: string): Record<string, number> {
    const out: Record<string, number> = {}
    text.split('\n').forEach((line) => {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) return
      const parts = trimmed.split(/\s+/)
      if (parts.length >= 2) {
        const val = Number(parts[1])
        if (!isNaN(val)) out[parts[0]] = val
      }
    })
    return out
  }
  
  export function formatHex(data: string, maxLength: number = 32): string {
    if (!data) return ''
    if (data.length > maxLength) {
      return data.substring(0, maxLength) + '...'
    }
    return data
  }
  
  export function generateMockPacket(): string {
    const chars = '0123456789ABCDEF'
    let result = 'ENC_DATA:'
    for (let i = 0; i < 64; i++) {
      result += chars[Math.floor(Math.random() * 16)]
    }
    return result
  }