// Strip Go/PCRE inline flags like (?i) that JavaScript regex does not support.
// Returns a RegExp with `gi` flags, or null if the pattern can't be compiled.
export function toJSRegex(pattern) {
  if (!pattern) return null
  const cleaned = pattern.replace(/\(\?[ismUux]+\)/g, '')
  if (!cleaned) return null
  try {
    return new RegExp(cleaned, 'gi')
  } catch {
    try {
      return new RegExp(cleaned.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
    } catch {
      return null
    }
  }
}

// Pretty-print a string as JSON when it looks like JSON; otherwise return it unchanged.
export function tryFormatJSON(str) {
  if (!str) return { text: str, isJSON: false }
  const trimmed = str.trim()
  if ((trimmed[0] === '{' && trimmed[trimmed.length - 1] === '}') ||
      (trimmed[0] === '[' && trimmed[trimmed.length - 1] === ']')) {
    try {
      return { text: JSON.stringify(JSON.parse(trimmed), null, 2), isJSON: true }
    } catch { /* not valid JSON; return the original text below */ }
  }
  return { text: str, isJSON: false }
}
