import { memo, useMemo } from 'react'
import { toJSRegex } from '../utils/formatting'

// Single-pattern highlighter used by Alerts (orange) and Blocks (red).
// Traffic uses its own multi-pattern variant — keep them separate by design.
const HighlightedBody = memo(function HighlightedBody({ text, pattern, colorClass = 'bg-orange-500/40 text-orange-200' }) {
  const ranges = useMemo(() => {
    if (!text || !pattern) return null
    try {
      const re = toJSRegex(pattern)
      if (!re) return null
      const ranges = []
      let m
      while ((m = re.exec(text)) !== null) {
        ranges.push({ start: m.index, end: m.index + m[0].length, text: m[0] })
        if (m[0].length === 0) re.lastIndex++
      }
      if (ranges.length === 0) return null
      return ranges
    } catch {
      return null
    }
  }, [text, pattern])

  if (!text) return <>{text}</>
  if (!ranges) return <>{text}</>

  const parts = []
  let pos = 0
  for (const range of ranges) {
    if (range.start > pos) parts.push(<span key={`t${pos}`}>{text.slice(pos, range.start)}</span>)
    parts.push(<mark key={`m${range.start}`} className={`${colorClass} rounded px-0.5`}>{range.text}</mark>)
    pos = range.end
  }
  if (pos < text.length) parts.push(<span key={`t${pos}`}>{text.slice(pos)}</span>)
  return <>{parts}</>
})

export default HighlightedBody
