import { useState, useEffect, useCallback, useRef, useMemo, memo } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, subscribePacketStream } from '../api'
import { getBindings } from '../trafficNavKeys'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { getDisplayName } from '../api'
import { hideParams, addHiddenIds, setClearCursor, getHiddenIds, getClearCursor, resetClearCursor, clearHiddenIds } from '../userHidden'
import QuickRulePanel from '../components/QuickRulePanel'
import FilterExpression from '../components/FilterExpression'
import ExploitButton from '../components/ExploitButton'
import { tryFormatJSON } from '../utils/formatting'
import { copyText } from '../utils/clipboard'
import { decodeProtobuf, looksLikeProtobuf, hasGRPCFraming } from '../utils/protobufDecode'
import { useServiceMap } from '../hooks/useServiceMap'
import { parse as parseFilter, evaluate as evaluateFilter } from '../utils/filterAst'

const ROW_H = 32
const OVERSCAN = 10

function base64ToBytes(b64) {
  if (!b64) return new Uint8Array()
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  } catch {
    return new Uint8Array()
  }
}

function bytesToHex(bytes, maxBytes = 1024 * 64) {
  const n = Math.min(bytes.length, maxBytes)
  let out = ''
  for (let i = 0; i < n; i++) out += bytes[i].toString(16).padStart(2, '0')
  if (bytes.length > n) out += `...(+${bytes.length - n} bytes)`
  return out
}

async function copyRawBytesFromBase64(b64) {
  const bytes = base64ToBytes(b64)
  if (!bytes || bytes.length === 0) return false

  // Prefer true binary clipboard when supported; fall back to hex text.
  try {
    if (navigator.clipboard?.write && typeof ClipboardItem !== 'undefined' && window.isSecureContext) {
      const blob = new Blob([bytes], { type: 'application/octet-stream' })
      await navigator.clipboard.write([new ClipboardItem({ 'application/octet-stream': blob })])
      return true
    }
  } catch {
    // ignore; fallback below
  }
  return copyText(bytesToHex(bytes))
}

// Highlight matching text with support for multiple patterns (flags=yellow, flagIDs=cyan)
const HighlightedText = memo(function HighlightedText({ text, contains, regex, flagidRegex }) {
  if (!text || (!contains && !regex && !flagidRegex)) return <>{text}</>

  try {
    const ranges = []

    const addMatches = (pattern, flags, cls) => {
      if (!pattern) return
      const re = new RegExp(pattern, flags)
      let m
      while ((m = re.exec(text)) !== null) {
        ranges.push({ start: m.index, end: m.index + m[0].length, cls, text: m[0] })
        if (m[0].length === 0) re.lastIndex++
      }
    }

    // Search highlights: contains (orange) and regex (yellow) — both apply independently
    if (contains) addMatches(contains.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi', 'bg-orange-500/40 text-orange-200')
    if (regex) addMatches(regex, 'gi', 'bg-yellow-500/40 text-yellow-200')

    // FlagID highlights (cyan) — regex built from backend-provided matched values (tiny, 1-3 values)
    if (flagidRegex) addMatches(flagidRegex, 'g', 'bg-teal-500/30 text-teal-200 border-b border-teal-400/50')

    if (ranges.length === 0) return <>{text}</>

    ranges.sort((a, b) => a.start - b.start)
    const merged = []
    for (const r of ranges) {
      if (merged.length === 0 || r.start >= merged[merged.length - 1].end) {
        merged.push(r)
      }
    }

    const parts = []
    let pos = 0
    for (const r of merged) {
      if (r.start > pos) parts.push(<span key={`t${pos}`}>{text.slice(pos, r.start)}</span>)
      parts.push(<mark key={`m${r.start}`} className={`${r.cls} rounded px-0.5`}>{r.text}</mark>)
      pos = r.end
    }
    if (pos < text.length) parts.push(<span key={`t${pos}`}>{text.slice(pos)}</span>)

    return <>{parts}</>
  } catch {
    return <>{text}</>
  }
})

// Get the peer (external) IP from a packet
function getPeerIP(pkt) {
  return pkt.direction === 'request' ? pkt.src_ip : pkt.dst_ip
}

// Render a decoded protobuf field tree.
function ProtobufFields({ fields, depth = 0 }) {
  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 12 }}>
      {fields.map((f, i) => {
        const tagColor = 'text-purple-400'
        const typeColor = 'text-gray-500'
        if (f.type === 'message') {
          return (
            <div key={i}>
              <span className={tagColor}>{f.field}</span>
              <span className={typeColor}> ({'message'}, {f.raw.length}B)</span>
              <ProtobufFields fields={f.value} depth={depth + 1} />
            </div>
          )
        }
        let valueEl
        if (f.type === 'string') {
          valueEl = <span className="text-green-300">{JSON.stringify(f.value)}</span>
        } else if (f.type === 'bytes') {
          valueEl = <span className="text-yellow-300">0x{f.value} <span className="text-gray-500">({f.length}B)</span></span>
        } else if (f.type === 'varint' || f.type === 'i64' || f.type === 'i32') {
          valueEl = <span className="text-cyan-300">{String(f.value)}</span>
        } else {
          valueEl = <span>{String(f.value)}</span>
        }
        return (
          <div key={i}>
            <span className={tagColor}>{f.field}</span>
            <span className={typeColor}> ({f.type}): </span>
            {valueEl}
          </div>
        )
      })}
    </div>
  )
}

// CustomDecodedFields renders a tree decoded by the user-defined custom
// protocol decoder (Step 14). It mirrors ProtobufFields visually but the
// shape comes from internal/customdecode.DecodedField (name, type, value,
// hex, enum, sub, error). Dispatch results carry an `enum` label and a
// nested `sub` array; byte-shaped fields put their content in `hex`.
function CustomDecodedFields({ fields, depth = 0 }) {
  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 12 }}>
      {fields.map((f, i) => {
        const nameCls = 'text-purple-400'
        const typeCls = 'text-gray-500'
        if (f.error) {
          return (
            <div key={i}>
              <span className={nameCls}>{f.name}</span>
              <span className={typeCls}> ({f.type}): </span>
              <span className="text-red-400">{f.error}</span>
            </div>
          )
        }
        if (f.sub && f.sub.length) {
          return (
            <div key={i}>
              <span className={nameCls}>{f.name}</span>
              <span className={typeCls}> ({f.type}{f.enum ? ` → ${f.enum}` : ''})</span>
              <CustomDecodedFields fields={f.sub} depth={depth + 1} />
            </div>
          )
        }
        let valueEl
        if (f.hex !== undefined && f.hex !== '') {
          valueEl = <span className="text-yellow-300 break-all">0x{f.hex}</span>
        } else if (f.enum) {
          valueEl = (
            <>
              <span className="text-green-300">{f.enum}</span>
              <span className="text-gray-500"> ({String(f.value)})</span>
            </>
          )
        } else if (typeof f.value === 'string') {
          valueEl = <span className="text-green-300">{JSON.stringify(f.value)}</span>
        } else if (typeof f.value === 'number' || typeof f.value === 'boolean') {
          valueEl = <span className="text-cyan-300">{String(f.value)}</span>
        } else if (f.value === undefined || f.value === null) {
          valueEl = <span className="text-gray-500">∅</span>
        } else {
          valueEl = <span>{String(f.value)}</span>
        }
        return (
          <div key={i}>
            <span className={nameCls}>{f.name}</span>
            <span className={typeCls}> ({f.type}): </span>
            {valueEl}
          </div>
        )
      })}
    </div>
  )
}

// Build a single-quoted, escaped service-id literal for filter expressions.
function quoteForFilter(s) {
  return `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

// Escape an arbitrary byte slice for use inside a `raw contains "..."`
// expression (FILTERS.md syntax: printable ASCII verbatim, everything else
// as `\xHH`). Same logic as the backend's bytesToFilterEscape — keep them
// in sync.
function escapeBytesForRaw(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i]
    if (c === 0x22 /* " */) out += '\\"'
    else if (c === 0x5c /* \ */) out += '\\\\'
    else if (c >= 0x20 && c <= 0x7e) out += String.fromCharCode(c)
    else out += '\\x' + c.toString(16).padStart(2, '0')
  }
  return out
}

// Escape a UTF-8 string for use inside a `body contains "..."` expression.
// Newlines stay as their `\n` escape so the predicate fits on one line and
// is copy-pasteable between Traffic search and a rule.
function escapeStringForFilter(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
}

// Render a captured body as a hex+ASCII dump with byte-range selection. The
// user clicks a byte to start, drags (or click+shift-click) to extend; the
// "Filter on selection" button next to the dump uses the same action menu
// as the Decoded panel so behavior is identical (Copy / Add / New rule).
function HexView({ bytes, onSelectionAction }) {
  const [start, setStart] = useState(null)
  const [end, setEnd] = useState(null)
  const dragging = useRef(false)

  const sel = useMemo(() => {
    if (start == null || end == null) return null
    const a = Math.min(start, end)
    const b = Math.max(start, end)
    return { a, b }
  }, [start, end])

  const onByteDown = (i) => {
    dragging.current = true
    setStart(i)
    setEnd(i)
  }
  const onByteEnter = (i) => {
    if (dragging.current) setEnd(i)
  }
  useEffect(() => {
    const stop = () => { dragging.current = false }
    window.addEventListener('mouseup', stop)
    return () => window.removeEventListener('mouseup', stop)
  }, [])

  // Render in 16-byte rows. For very large bodies we cap the dump to keep
  // the panel responsive — the user can still copy full bytes via "Copy bytes".
  const MAX_RENDER = 4096
  const render = bytes.subarray(0, Math.min(bytes.length, MAX_RENDER))
  const rows = []
  for (let i = 0; i < render.length; i += 16) {
    rows.push({ offset: i, slice: render.subarray(i, Math.min(render.length, i + 16)) })
  }

  const isSelected = (i) => sel != null && i >= sel.a && i <= sel.b
  const selectionLen = sel ? sel.b - sel.a + 1 : 0

  return (
    <div className="text-[11px] font-mono">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-gray-500">Hex</span>
        <span className="text-gray-600">{bytes.length} bytes{render.length < bytes.length ? ` (showing ${render.length})` : ''}</span>
        {sel && (
          <span className="text-gray-500">
            sel {sel.a}–{sel.b} ({selectionLen}B)
          </span>
        )}
        <RawSelectionActionButton
          disabled={!sel}
          onAction={(kind) => {
            if (!sel) return
            const slice = bytes.subarray(sel.a, sel.b + 1)
            const escaped = escapeBytesForRaw(slice)
            const predicate = `raw contains "${escaped}"`
            const labelHex = bytesToHex(slice, 8)
            onSelectionAction(kind, predicate, `raw[${sel.a}:${sel.b + 1}]=${labelHex}`)
          }}
        />
        {sel && (
          <button
            type="button"
            onClick={() => { setStart(null); setEnd(null) }}
            className="text-[10px] text-gray-500 hover:text-gray-300 underline cursor-pointer"
          >
            clear
          </button>
        )}
      </div>
      <div className="bg-gray-800 rounded p-2 overflow-auto" style={{ maxHeight: '40vh' }}>
        {rows.map((row) => (
          <div key={row.offset} className="flex gap-3 leading-5">
            <span className="text-gray-600 select-none">{row.offset.toString(16).padStart(6, '0')}</span>
            <span className="flex-1 flex flex-wrap">
              {Array.from(row.slice).map((b, j) => {
                const idx = row.offset + j
                const sel = isSelected(idx)
                return (
                  <span
                    key={j}
                    onMouseDown={(e) => { e.preventDefault(); onByteDown(idx) }}
                    onMouseEnter={() => onByteEnter(idx)}
                    className={`px-0.5 cursor-pointer ${sel ? 'bg-cyan-700/60 text-cyan-100' : 'text-gray-300 hover:bg-gray-700'}`}
                    title={`byte ${idx}: 0x${b.toString(16).padStart(2, '0')} (${b})`}
                  >
                    {b.toString(16).padStart(2, '0')}
                  </span>
                )
              })}
            </span>
            <span className="text-gray-400">
              {Array.from(row.slice).map((b, j) => {
                const idx = row.offset + j
                const sel = isSelected(idx)
                const ch = (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.'
                return (
                  <span
                    key={j}
                    onMouseDown={(e) => { e.preventDefault(); onByteDown(idx) }}
                    onMouseEnter={() => onByteEnter(idx)}
                    className={`cursor-pointer ${sel ? 'bg-cyan-700/60 text-cyan-100' : ''}`}
                  >
                    {ch}
                  </span>
                )
              })}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Compact "filter ▾" button + dropdown menu for raw-byte / body-text
// selections. Same three actions as the Decoded panel; the parent supplies
// the already-built predicate string so this component is generic.
function RawSelectionActionButton({ disabled, onAction }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        className={`text-[10px] px-2 py-0.5 rounded border cursor-pointer ${
          disabled
            ? 'border-gray-800 text-gray-600 cursor-not-allowed'
            : 'border-gray-700 bg-gray-900 text-gray-300 hover:text-cyan-300 hover:border-cyan-700'
        }`}
        title={disabled ? 'Select bytes (or text) first' : 'Use selection as filter'}
      >
        Filter on selection ▾
      </button>
      {open && !disabled && (
        <div className="absolute right-0 top-full mt-1 z-30 w-48 bg-gray-900 border border-gray-700 rounded shadow-lg text-[11px]">
          <button type="button" onMouseDown={(e) => { e.preventDefault(); setOpen(false); onAction('copy') }}
            className="block w-full text-left px-2 py-1.5 hover:bg-gray-800 text-gray-200 cursor-pointer">
            Copy filter
          </button>
          <button type="button" onMouseDown={(e) => { e.preventDefault(); setOpen(false); onAction('add') }}
            className="block w-full text-left px-2 py-1.5 hover:bg-gray-800 text-gray-200 cursor-pointer">
            Add to current filter
          </button>
          <button type="button" onMouseDown={(e) => { e.preventDefault(); setOpen(false); onAction('rule') }}
            className="block w-full text-left px-2 py-1.5 hover:bg-gray-800 text-red-200 cursor-pointer">
            New drop rule
          </button>
        </div>
      )}
    </div>
  )
}

// Render a server-decoded protobuf frame (whose body is a parsed JSON object)
// as an interactive tree where each leaf field exposes an action menu:
//   - Copy raw filter   → puts `raw contains "\xHH..."` on the clipboard
//   - Add to filter     → appends the predicate to the Traffic expression
//   - New drop rule     → navigates to /rules with the form pre-filled
// Nested objects/arrays are rendered without action buttons because the
// backend encoder needs a top-level field of the request message; clicking
// a leaf nested inside a sub-message would require encoding a parent path
// that the simple click-to-filter flow doesn't support yet.
function DecodedJSONTree({ value, onLeafAction, depth = 0, parentKey = '' }) {
  const pad = depth === 0 ? 0 : 12
  if (value === null) return <span className="text-gray-500">null</span>
  if (Array.isArray(value)) {
    return (
      <span>
        <span className="text-gray-500">[</span>
        {value.length === 0 ? null : (
          <div style={{ marginLeft: pad }}>
            {value.map((v, i) => (
              <div key={i}>
                <DecodedJSONTree value={v} onLeafAction={onLeafAction} depth={depth + 1} parentKey={parentKey} />
                {i < value.length - 1 ? <span className="text-gray-500">,</span> : null}
              </div>
            ))}
          </div>
        )}
        <span className="text-gray-500">]</span>
      </span>
    )
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value)
    return (
      <span>
        <span className="text-gray-500">{'{'}</span>
        {entries.length === 0 ? null : (
          <div style={{ marginLeft: pad }}>
            {entries.map(([k, v], i) => {
              const isLeaf = v === null || typeof v !== 'object'
              return (
                <div key={k} className="group flex items-start gap-1">
                  <div className="flex-1">
                    <span className="text-cyan-400">"{k}"</span>
                    <span className="text-gray-500">: </span>
                    {isLeaf ? <DecodedLeafValue value={v} /> : <DecodedJSONTree value={v} onLeafAction={onLeafAction} depth={depth + 1} parentKey={k} />}
                    {i < entries.length - 1 ? <span className="text-gray-500">,</span> : null}
                  </div>
                  {/* Action button only for top-level leaves: that's what the
                      backend encoder can map back to a single field of the
                      request/response message type. */}
                  {isLeaf && depth === 0 && (
                    <DecodedFieldActionButton field={k} value={v} onAction={onLeafAction} />
                  )}
                </div>
              )
            })}
          </div>
        )}
        <span className="text-gray-500">{'}'}</span>
      </span>
    )
  }
  return <DecodedLeafValue value={value} />
}

// DecodedNamedFrameView renders a single server-decoded protobuf frame:
// the interactive tree when the JSON parses, the original pretty-printed
// text otherwise. Splitting it out keeps the try/catch out of the parent
// component's JSX (eslint react-hooks/error-boundaries flags JSX inside
// try/catch because rendering errors there don't propagate to boundaries).
function DecodedNamedFrameView({ frameJSON, onLeafAction, fallbackHighlight }) {
  const parsed = useMemo(() => {
    try {
      const v = JSON.parse(frameJSON)
      return v && typeof v === 'object' ? v : null
    } catch {
      return null
    }
  }, [frameJSON])
  if (parsed) {
    return (
      <div className="text-green-300 whitespace-pre-wrap break-all">
        <DecodedJSONTree value={parsed} onLeafAction={onLeafAction} />
      </div>
    )
  }
  return (
    <pre className="text-green-300 whitespace-pre-wrap break-all">
      {fallbackHighlight}
    </pre>
  )
}

function DecodedLeafValue({ value }) {
  if (typeof value === 'string') return <span className="text-green-300">{JSON.stringify(value)}</span>
  if (typeof value === 'number') return <span className="text-cyan-300">{String(value)}</span>
  if (typeof value === 'boolean') return <span className="text-purple-300">{String(value)}</span>
  if (value === null) return <span className="text-gray-500">null</span>
  return <span>{String(value)}</span>
}

function DecodedFieldActionButton({ field, value, onAction }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        className="opacity-0 group-hover:opacity-100 focus:opacity-100 text-[10px] px-1.5 py-0.5 rounded border border-gray-700 bg-gray-900 text-gray-400 hover:text-cyan-300 hover:border-cyan-700 cursor-pointer"
        title={`Use "${field}" = ${JSON.stringify(value)} as a filter`}
      >
        filter ▾
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-20 w-48 bg-gray-900 border border-gray-700 rounded shadow-lg text-[11px]">
          <button
            type="button"
            onMouseDown={(e) => { e.preventDefault(); setOpen(false); onAction('copy', field, value) }}
            className="block w-full text-left px-2 py-1.5 hover:bg-gray-800 text-gray-200 cursor-pointer"
          >
            Copy raw filter
          </button>
          <button
            type="button"
            onMouseDown={(e) => { e.preventDefault(); setOpen(false); onAction('add', field, value) }}
            className="block w-full text-left px-2 py-1.5 hover:bg-gray-800 text-gray-200 cursor-pointer"
          >
            Add to current filter
          </button>
          <button
            type="button"
            onMouseDown={(e) => { e.preventDefault(); setOpen(false); onAction('rule', field, value) }}
            className="block w-full text-left px-2 py-1.5 hover:bg-gray-800 text-red-200 cursor-pointer"
          >
            New drop rule
          </button>
        </div>
      )}
    </div>
  )
}

// SSE packets carry only metadata — no body, no headers. If a parsed
// expression touches any of those fields, client-side evaluation is
// unreliable and we fall back to periodic server polling.
function treeNeedsServerFilter(node) {
  if (!node) return false
  if (node.kind === 'predicate') {
    const f = node.field
    if (f === 'body' || f === 'raw' || f === 'header') return true
    return false
  }
  for (const c of (node.children || [])) {
    if (treeNeedsServerFilter(c)) return true
  }
  return false
}

// Pull contains/icontains/startswith/endswith literals out of the parsed
// expression tree so the table and detail panel can highlight matched
// substrings inline. Negated branches are skipped. Each output field is a
// regex-ready alternation of escaped literals (and any `matches` patterns
// for the same target, included raw so they keep regex semantics).
function extractHighlights(tree) {
  const out = { body: '', url: '', headerAny: '' }
  if (!tree) return out
  const body = []
  const url = []
  const headerAny = []

  const visit = (node, negated) => {
    if (!node) return
    if (node.kind === 'predicate') {
      if (negated) return
      const v = String(node.value ?? '')
      if (!v) return
      const literal = node.op === 'contains' || node.op === 'icontains' ||
                      node.op === 'startswith' || node.op === 'endswith'
      const isRegex = node.op === 'matches'
      if (!literal && !isRegex) return
      const value = literal ? escapeForRegex(v) : v
      if (node.field === 'body' || node.field === 'raw') body.push(value)
      else if (node.field === 'url') url.push(value)
      else if (node.field === 'header' && !node.headerName) headerAny.push(value)
      return
    }
    // group
    const childNeg = negated !== node.not
    for (const c of node.children) visit(c, childNeg)
  }
  visit(tree, false)

  out.body = body.join('|')
  out.url = url.join('|')
  out.headerAny = headerAny.join('|')
  return out
}

function escapeForRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function hasDropAction(pkt) {
  if (!pkt?.matched_rules?.length) return false
  return pkt.matched_rules.some((r) => r.action === 'drop' || r.action === 'both')
}

function hasAlertAction(pkt) {
  if (!pkt?.matched_rules?.length) return false
  return pkt.matched_rules.some((r) => r.action === 'alert' || r.action === 'both')
}

// ---- Main Traffic component ----

export default function Traffic() {
  const navigate = useNavigate()
  const location = useLocation()
  const [services, setServices] = useState([])
  const [customProtocols, setCustomProtocols] = useState([])
  const [decodedCustom, setDecodedCustom] = useState(null) // { protocol, direction, fields, trailing_hex } or null
  const [decodedCustomError, setDecodedCustomError] = useState('')
  const [customProtocolOverride, setCustomProtocolOverride] = useState('') // empty = use service-bound
  const [customPickerOpen, setCustomPickerOpen] = useState(false) // opt-in picker for services with no bound protocol
  const [activeSessions, setActiveSessions] = useState([])
  const [selected, setSelected] = useState(null)
  const [flowMode, setFlowMode] = useState(null) // { packetId, packets, total }
  /** Packet id used when entering flow (API or session fallback); restored on Clear flow */
  const flowEntryPacketIdRef = useRef(null)
  /** When opening flow from another view, Clear flow navigates back and restores context */
  const flowReturnContextRef = useRef(null)
  const packetTableScrollRef = useRef(null)
  const [filtersCollapsed, setFiltersCollapsed] = useState(false)
  const [flagFilter, setFlagFilter] = useState(false)
  const [flagRegex, setFlagRegex] = useState('')
  const [flagIDFilter, setFlagIDFilter] = useState(false)
  const [flagIDEnabled, setFlagIDEnabled] = useState(false)
  const [blockedFilter, setBlockedFilter] = useState(false)
  const [paused, setPaused] = useState(false)
  const [trafficMode, setTrafficMode] = useState('live')
  const [captureStatus, setCaptureStatus] = useState(null)
  const [captureBusy, setCaptureBusy] = useState(false)
  const [applyBusy, setApplyBusy] = useState(false)
  const [clearBusy, setClearBusy] = useState(false)
  const pausedRef = useRef(false)
  const [showQuickRule, setShowQuickRule] = useState(false)
  const [pinDialog, setPinDialog] = useState(null) // null | { anchorId, name, notes, saving, error }
  const [pinToast, setPinToast] = useState(null)
  const [pcapDialog, setPcapDialog] = useState(false)
  const [pcapResult, setPcapResult] = useState(null) // { filename } after export
  const [pcapExporting, setPcapExporting] = useState(false)
  // Unified filter expression — replaces the previous filter grid.
  // The legacy `session_id`, `sort` and `limit` are kept as separate state
  // because they are either set programmatically (session_id during flow
  // mode) or are UI-only controls (sort/limit) that don't belong in the DSL.
  const [expression, setExpression] = useState('')
  // Service quick-filter: chips above the expression input. Kept as a separate
  // state so the user's typed expression isn't rewritten when toggling chips;
  // we merge the two into `effectiveExpression` only when querying / parsing.
  const [selectedServiceIDs, setSelectedServiceIDs] = useState(() => new Set())
  const [sessionFilter, setSessionFilter] = useState('')
  const [sortOrder, setSortOrder] = useState('desc')
  const [pageLimit] = useState(50)

  // Resizable detail panel
  const [detailWidth, setDetailWidth] = useState(450)
  const dragging = useRef(false)
  const dragStartX = useRef(0)
  const dragStartW = useRef(0)

  useEffect(() => {
    function onMouseMove(e) {
      if (!dragging.current) return
      const delta = dragStartX.current - e.clientX
      setDetailWidth(Math.max(300, Math.min(900, dragStartW.current + delta)))
    }
    function onMouseUp() {
      dragging.current = false
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }
  }, [])

  function startDrag(e) {
    dragging.current = true
    dragStartX.current = e.clientX
    dragStartW.current = detailWidth
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }

  useEffect(() => {
    api.getSessionActive().then((d) => setActiveSessions(d?.sessions || [])).catch(() => {})
  }, [])

  // Support linking from other pages (e.g. Config PCAP import) with ?service_id=...
  // This is a one-shot init: if the user edits the expression later, we don't override it.
  useEffect(() => {
    const sp = new URLSearchParams(location.search || '')
    const svc = sp.get('service_id')
    if (!svc) return
    if (expression.trim()) return
    setExpression(`service == "${String(svc).replace(/"/g, '\\"')}"`)
    // Remove query param to avoid re-applying on navigation within the app.
    navigate(location.pathname, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Flag ID poller status (current_round, round_duration, competition_start).
  // Used to surface "Round N" next to the flow banner so the operator knows
  // which scoreboard round the flow they're inspecting belongs to.
  const [flagIDStatus, setFlagIDStatus] = useState(null)

  useEffect(() => {
    api.listServices().then((data) => setServices(data || []))
    api.listProtocols().then((data) => setCustomProtocols(data || [])).catch(() => {})
    api.getConfig().then((cfg) => {
      if (cfg?.flag_regex) setFlagRegex(cfg.flag_regex)
      setFlagIDEnabled(!!cfg?.flagid_enabled)
      setTrafficMode(cfg?.traffic_mode || 'live')
    }).catch(() => {})
    api.getCaptureStatus().then(setCaptureStatus).catch(() => {})
    api.getFlagIDStatus().then(setFlagIDStatus).catch(() => {})
  }, [])

  // Compute the round number for a given timestamp using the poller's
  // competition_start + round_duration_seconds. Only used to derive the
  // "live now" current-round badge during idle periods — the per-packet
  // round always comes from the backend (pkt.round).
  const roundForTimestamp = useCallback((iso) => {
    if (iso == null || iso === '') return null
    const startStr = flagIDStatus?.competition_start
    const dur = flagIDStatus?.round_duration_seconds
    if (!startStr || !dur) return null
    const start = Date.parse(startStr)
    const t = typeof iso === 'number' ? iso : Date.parse(iso)
    if (Number.isNaN(start) || Number.isNaN(t)) return null
    if (t < start) return null
    return Math.floor((t - start) / (dur * 1000)) + 1
  }, [flagIDStatus])

  const [currentRound, setCurrentRound] = useState(null)

  useEffect(() => {
    if (trafficMode !== 'static') return
    setPaused(false)
    pausedRef.current = false
    const t = setInterval(async () => {
      try {
        const status = await api.getCaptureStatus()
        setCaptureStatus(status)
      } catch {}
    }, 3000)
    return () => clearInterval(t)
  }, [trafficMode])


  // Force refetch when user hides/unhides packets. Bumping this key re-runs the
  // hook's effect via fetchPage's dep list.
  const [hideVersion, setHideVersion] = useState(0)

  // Combine the user's typed expression with the chip-selected services.
  // The chips append `service in (...)` (or `service == ...` for one) so the
  // user can keep editing their text expression without losing the chip state.
  const effectiveExpression = useMemo(() => {
    const e = expression.trim()
    if (selectedServiceIDs.size === 0) return e
    const ids = Array.from(selectedServiceIDs)
    const list = ids.map((id) => `"${String(id).replace(/"/g, '\\"')}"`).join(', ')
    const svcExpr = ids.length === 1 ? `service == ${list}` : `service in (${list})`
    return e ? `(${e}) AND ${svcExpr}` : svcExpr
  }, [expression, selectedServiceIDs])

  // fetchPage: called by the hook for each page load
  const fetchPage = useCallback(async (offset, limit) => {
    const params = { ...hideParams() }
    params.limit = limit
    params.offset = offset
    params.sort = sortOrder
    if (effectiveExpression) params.q = effectiveExpression
    if (sessionFilter) params.session_id = sessionFilter
    if (flagFilter) params.flagged = 'true'
    if (flagIDFilter) params.contains_flagid = 'true'
    if (blockedFilter) params.dropped = 'true'
    params.summary = '1'
    const data = await api.getPackets(params)
    return { items: data.packets || [], total: data.total }
  }, [effectiveExpression, sessionFilter, sortOrder, flagFilter, flagIDFilter, blockedFilter, hideVersion])

  const {
    items: packets,
    total,
    loading,
    hasMore,
    sentinelRef: packetSentinelRef,
    prepend: prependPackets,
    refresh: refreshPackets,
    reset: resetPackets,
  } = useInfiniteList({ fetchPage, pageSize: pageLimit })

  // Live current-round badge. This must run after useInfiniteList initializes
  // `packets`; otherwise a hard refresh renders the component while `packets`
  // is still in the temporal dead zone and the Traffic page goes blank.
  useEffect(() => {
    const compute = () => {
      const latestPktRound = packets[0]?.round
      if (latestPktRound && latestPktRound > 0) {
        const startStr = flagIDStatus?.competition_start
        const dur = flagIDStatus?.round_duration_seconds
        let r = latestPktRound
        if (startStr && dur) {
          const start = Date.parse(startStr)
          if (!Number.isNaN(start)) {
            const liveR = Math.floor((Date.now() - start) / (dur * 1000)) + 1
            if (liveR > r) r = liveR
          }
        }
        setCurrentRound((prev) => (prev === r ? prev : r))
        return
      }
      const startStr = flagIDStatus?.competition_start
      const dur = flagIDStatus?.round_duration_seconds
      if (startStr && dur) {
        const start = Date.parse(startStr)
        const now = Date.now()
        if (!Number.isNaN(start) && now >= start) {
          const r = Math.floor((now - start) / (dur * 1000)) + 1
          setCurrentRound((prev) => (prev === r ? prev : r))
          return
        }
      }
      const fallbackRound = flagIDStatus?.clock_round || flagIDStatus?.current_round
      const fallback = (fallbackRound && fallbackRound > 0)
        ? fallbackRound
        : null
      setCurrentRound((prev) => (prev === fallback ? prev : fallback))
    }
    compute()
    const t = setInterval(compute, 1000)
    return () => clearInterval(t)
  }, [flagIDStatus?.competition_start, flagIDStatus?.round_duration_seconds, flagIDStatus?.clock_round, flagIDStatus?.current_round, packets])

  // Parse the user expression once per change. Memoized so the SSE filter
  // doesn't reparse per packet. Uses the merged expression so chip selections
  // are also respected by the client-side SSE filter.
  const parsedExpression = useMemo(() => {
    if (!effectiveExpression) return { tree: null, residual: false }
    const r = parseFilter(effectiveExpression)
    if (!r.ok) return { tree: null, residual: true } // syntax errors → fall back to server
    return { tree: r.tree, residual: treeNeedsServerFilter(r.tree) }
  }, [effectiveExpression])

  // Whenever any predicate touches a field SSE doesn't carry (body/raw/header),
  // we fall back to periodic server polling instead of client-side eval.
  const hasTextFilters = parsedExpression.residual

  // Refs for SSE client-side filtering (stale-closure-safe).
  const expressionTreeRef = useRef(parsedExpression.tree)
  const sessionFilterRef = useRef(sessionFilter)
  const sortOrderRef = useRef(sortOrder)
  const flagFilterRef = useRef(flagFilter)
  const flagIDFilterRef = useRef(flagIDFilter)
  const blockedFilterRef = useRef(blockedFilter)
  useEffect(() => { expressionTreeRef.current = parsedExpression.tree }, [parsedExpression.tree])
  useEffect(() => { sessionFilterRef.current = sessionFilter }, [sessionFilter])
  useEffect(() => { sortOrderRef.current = sortOrder }, [sortOrder])
  useEffect(() => { flagFilterRef.current = flagFilter }, [flagFilter])
  useEffect(() => { flagIDFilterRef.current = flagIDFilter }, [flagIDFilter])
  useEffect(() => { blockedFilterRef.current = blockedFilter }, [blockedFilter])

  // SSE new-packet handler: evaluate the expression tree client-side, then
  // apply the auxiliary toggles and per-user hide filters.
  const handleNewPackets = useCallback((newPkts) => {
    if (pausedRef.current || newPkts.length === 0) return
    const tree = expressionTreeRef.current
    const sessionId = sessionFilterRef.current
    const hiddenSet = new Set(getHiddenIds())
    const cursor = getClearCursor()
    const filtered = newPkts.filter((p) => {
      if (hiddenSet.has(Number(p.id))) return false
      if (cursor && p.timestamp && p.timestamp < cursor) return false
      if (sessionId && p.session_id !== sessionId) return false
      if (flagFilterRef.current && !p.flagged) return false
      if (flagIDFilterRef.current && !p.contains_flagid) return false
      if (blockedFilterRef.current && !hasDropAction(p)) return false
      if (tree && !evaluateFilter(tree, p)) return false
      return true
    })
    if (filtered.length > 0) prependPackets(filtered, sortOrderRef.current !== 'asc')
  }, [prependPackets])

  // Reset + re-fetch when filters change (debounced 300ms). Runs regardless of
  // pause state so filter edits apply to the frozen view. `fetchPage` identity
  // changes whenever any filter/negation/flag toggle changes, which is the
  // cheapest reliable trigger.
  useEffect(() => {
    const timer = setTimeout(() => { resetPackets() }, 300)
    return () => clearTimeout(timer)
  }, [fetchPage, resetPackets])

  // SSE: stream new packets + refresh on metadata changes.
  // When text filters are active, fall back to periodic full refresh.
  useEffect(() => {
    const streamEnabled = trafficMode === 'live' || (trafficMode === 'static' && !!captureStatus?.capturing)
    if (!streamEnabled) return
    if (paused) return
    const unsub = subscribePacketStream(
      hasTextFilters ? () => {} : handleNewPackets,
      () => { if (!pausedRef.current) refreshPackets() },
    )
    let poll
    if (hasTextFilters) {
      poll = setInterval(() => { if (!pausedRef.current) refreshPackets() }, 2000)
    }
    return () => {
      unsub()
      if (poll) clearInterval(poll)
    }
  }, [handleNewPackets, refreshPackets, paused, hasTextFilters, trafficMode, captureStatus?.capturing])


  const [flowLoading, setFlowLoading] = useState(false)

  // Flow: reconstruct multi-connection flow via auth token correlation.
  // Per-user hides intentionally do NOT apply here — a flow is an investigation
  // tool, and dropping hidden packets (or anything before the clear cursor)
  // would leave gaps in the correlated sequence.
  const showFlow = useCallback(async (pkt, opts = {}) => {
    if (pkt?.id == null) return
    if (!opts.preserveFlowReturn) flowReturnContextRef.current = null
    flowEntryPacketIdRef.current = pkt.id
    setFlowLoading(true)
    try {
      const data = await api.getPacketFlow(pkt.id)
      const pkts = data.packets || []
      setFlowMode({
        packetId: pkt.id,
        packets: pkts,
        total: pkts.length,
      })
    } catch (err) {
      console.error('Flow query failed, falling back to session_id:', err)
      setSessionFilter(pkt.session_id || '')
      setSortOrder('asc')
    } finally {
      setFlowLoading(false)
    }
  }, [])

  function toggleFlagFilter() {
    setFlagFilter((v) => !v)
  }

  function toggleFlagIDFilter() {
    setFlagIDFilter((prev) => !prev)
  }

  function toggleBlockedFilter() {
    setBlockedFilter((prev) => !prev)
  }

  function addQuickFilter(predicate) {
    if (!predicate) return
    setExpression((prev) => {
      const e = (prev || '').trim()
      const norm = e.replace(/\s+/g, ' ')
      if (norm.includes(predicate)) return e
      return e ? `(${e}) AND ${predicate}` : predicate
    })
  }

  function togglePause() {
    if (trafficMode !== 'live') return
    setPaused((prev) => {
      const next = !prev
      pausedRef.current = next
      if (!next) resetPackets()
      return next
    })
  }

  // Build a confirmation message that warns about active teammates
  function destructiveConfirm(action) {
    const myName = getDisplayName()
    const others = activeSessions.filter((s) => s.name !== myName)
    const warning = others.length > 0
      ? `\n\nActive teammates: ${others.map((s) => s.name).join(', ')} — this will affect their view.`
      : ''
    return confirm(action + warning)
  }

  // ---- Bulk selection & deletion ----
  const [selectedPkts, setSelectedPkts] = useState(new Set())
  // Anchor for shift-click range selection. Set by any single-select click (row
  // or checkbox). Range selection works from anchor → target.
  const selectionAnchorRef = useRef(null)

  function toggleSingleSelect(id) {
    setSelectedPkts((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
    selectionAnchorRef.current = id
  }

  // Extend (or remove) selection from anchor → target. Used by shift+click on
  // both checkbox and row. Returns true if the action was handled.
  function selectRange(pkt) {
    const anchorId = selectionAnchorRef.current
    if (anchorId == null) return false
    const list = displayPackets
    const anchorIdx = list.findIndex((p) => p.id === anchorId)
    const targetIdx = list.findIndex((p) => p.id === pkt.id)
    if (anchorIdx === -1 || targetIdx === -1) return false
    const [from, to] = [Math.min(anchorIdx, targetIdx), Math.max(anchorIdx, targetIdx)]
    const rangeIds = list.slice(from, to + 1).map((p) => p.id)
    setSelectedPkts((prev) => {
      const next = new Set(prev)
      // If anchor is already selected, treat this as "extend"; otherwise treat
      // as "fresh range". This matches file-manager / mail-client conventions.
      const anchorSelected = prev.has(anchorId)
      if (anchorSelected) rangeIds.forEach((rid) => next.add(rid))
      else {
        next.clear()
        rangeIds.forEach((rid) => next.add(rid))
      }
      return next
    })
    return true
  }

  function handleCheckboxClick(pkt, e) {
    e.stopPropagation()
    if (e.shiftKey && selectRange(pkt)) return
    toggleSingleSelect(pkt.id)
  }

  // Row click: normal = open detail, Shift = range-select, Cmd/Ctrl = toggle.
  function handleRowClick(pkt, e) {
    if (e.shiftKey) {
      e.preventDefault()
      window.getSelection()?.removeAllRanges() // shift+click adds text selection otherwise
      if (selectRange(pkt)) return
      // No anchor yet → fall back to single toggle, acts as the first anchor
      toggleSingleSelect(pkt.id)
      return
    }
    if (e.metaKey || e.ctrlKey) {
      e.preventDefault()
      toggleSingleSelect(pkt.id)
      return
    }
    // Plain click: open detail panel AND update the range anchor so a
    // subsequent shift+click can extend from here.
    selectionAnchorRef.current = pkt.id
    selectPacket(pkt)
  }

  async function bulkDelete() {
    const ids = Array.from(selectedPkts)
    if (ids.length === 0) return
    // Per-user hide: doesn't affect teammates. Data stays in the DB; only this
    // user's view excludes the IDs via the exclude_ids query param.
    if (!confirm(`Hide ${ids.length} selected packet${ids.length !== 1 ? 's' : ''} from your view? (Teammates will still see them.)`)) return
    addHiddenIds(ids)
    if (selected && ids.includes(selected.id)) setSelected(null)
    setSelectedPkts(new Set())
    selectionAnchorRef.current = null
    setHideVersion((v) => v + 1)
    resetPackets()
  }

  async function switchMode(newMode) {
    if (newMode === trafficMode) return
    // Traffic mode is global (one proxy, one capture behavior). Warn the user
    // that every logged-in teammate will be affected.
    const base = newMode === 'static'
      ? 'Switch proxy to Static mode? Live streaming will stop for everyone. Captures must then be started/stopped manually from this page.'
      : 'Switch proxy back to Live mode? Any ongoing Static capture will stop.'
    if (!destructiveConfirm(base)) return
    try {
      const cfg = await api.updateConfig({ traffic_mode: newMode })
      setTrafficMode(cfg?.traffic_mode || newMode)
      api.getCaptureStatus().then(setCaptureStatus).catch(() => {})
      if (newMode === 'live') resetPackets()
    } catch (err) {
      console.error('Failed to switch traffic mode:', err)
    }
  }

  async function handleStartCapture() {
    setCaptureBusy(true)
    try {
      const status = await api.startCapture()
      setCaptureStatus(status)
      resetPackets()
    } finally {
      setCaptureBusy(false)
    }
  }

  async function handleStopCapture() {
    setCaptureBusy(true)
    try {
      const status = await api.stopCapture()
      setCaptureStatus(status)
      resetPackets()
    } finally {
      setCaptureBusy(false)
    }
  }

  async function handleApplyFlagIDs() {
    setApplyBusy(true)
    try {
      await api.applyCaptureFlagIDs()
      resetPackets()
    } finally {
      setApplyBusy(false)
    }
  }

  async function handleClearPackets() {
    // Per-user clear: sets a local cursor; packets older than "now" are hidden
    // from this user only. Teammates are unaffected; DB rows remain intact.
    if (!confirm('Clear all packets from your view? Teammates keep their view; this is reversible with "Show all hidden".')) return
    setClearBusy(true)
    try {
      setClearCursor(new Date().toISOString())
      setSelected(null)
      setFlowMode(null)
      flowEntryPacketIdRef.current = null
      flowReturnContextRef.current = null
      setSessionFilter('')
      setHideVersion((v) => v + 1)
      resetPackets()
    } finally {
      setClearBusy(false)
    }
  }

  // Undo per-user hiding (useful if the user cleared by mistake).
  function handleUnhideAll() {
    if (!confirm('Show all hidden packets again in your view?')) return
    clearHiddenIds()
    resetClearCursor()
    setHideVersion((v) => v + 1)
    resetPackets()
  }

  // Select a packet — fetch full detail if it's a lite/summary packet or
  // came from SSE (no body_string). Lite packets carry a `lite: true` flag.
  // The selectionTokenRef counter race-protects against a slow getPacket from
  // an earlier click overwriting a newer selection (also: if the user clicks
  // the SAME packet again, the older inflight fetch is invalidated so it
  // can't land after the second fetch and clobber the newer body).
  const selectionTokenRef = useRef(0)
  const selectPacket = useCallback(async (pkt) => {
    if (!pkt) return
    const token = ++selectionTokenRef.current
    const needsRefetch = pkt.lite || pkt.body_string === undefined
    setSelected(pkt)
    if (!needsRefetch) return
    try {
      const full = await api.getPacket(pkt.id)
      if (selectionTokenRef.current !== token) return
      setSelected(full)
    } catch {}
  }, [])

  const clearFlow = useCallback(() => {
    const anchorId = flowEntryPacketIdRef.current
    const ret = flowReturnContextRef.current
    flowEntryPacketIdRef.current = null
    flowReturnContextRef.current = null
    setFlowMode(null)
    setSessionFilter('')
    setSortOrder('desc')
    if (ret?.path === '/alerts' && ret.alertId != null) {
      navigate('/alerts', { state: { restoreAlertId: ret.alertId } })
      return
    }
    if (ret?.path === '/blocks' && ret.packetId != null) {
      navigate('/blocks', { state: { restoreBlockedPacketId: ret.packetId } })
      return
    }
    if (ret?.path === '/round-diff') {
      navigate('/round-diff', { state: { restoreRoundDiff: true } })
      return
    }
    if (anchorId != null) selectPacket({ id: anchorId })
  }, [selectPacket, navigate])

  // Open flow when navigated from another view with state.
  useEffect(() => {
    const pid = location.state?.openFlowForPacketId
    if (pid == null) return
    const fr = location.state?.flowReturn
    if (fr && (fr.path === '/alerts' || fr.path === '/blocks' || fr.path === '/round-diff')) {
      flowReturnContextRef.current = fr
    }
    navigate(location.pathname, { replace: true, state: {} })
    showFlow({ id: pid }, { preserveFlowReturn: true })
  }, [location.pathname, location.state, navigate, showFlow])

  // Traffic table: J/K / arrows — keys from localStorage (Config page)
  useEffect(() => {
    function typingTarget(el) {
      const t = el?.tagName
      return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el?.isContentEditable
    }
    function onKeyDown(e) {
      if (typingTarget(e.target)) return
      // Esc — exit flow view, then clear the open packet / bulk selection
      if (e.key === 'Escape') {
        if (flowMode) { e.preventDefault(); clearFlow(); return }
        if (selected) { e.preventDefault(); setSelected(null); return }
        if (selectedPkts.size > 0) { e.preventDefault(); setSelectedPkts(new Set()); return }
        return
      }
      const b = getBindings()
      // Toggle current packet in bulk selection
      if (b.toggleSelect.includes(e.key) && selected) {
        e.preventDefault()
        toggleSingleSelect(selected.id)
        return
      }
      // Bulk-delete selection
      if (b.deleteSel.includes(e.key) && selectedPkts.size > 0) {
        e.preventDefault()
        bulkDelete()
        return
      }
      const { up, down } = b
      const list = flowMode ? flowMode.packets : packets
      if (!list.length) return
      let delta = 0
      if (up.includes(e.key)) delta = -1
      else if (down.includes(e.key)) delta = 1
      else return
      e.preventDefault()
      let idx = selected ? list.findIndex((p) => p.id === selected.id) : -1
      if (idx === -1) idx = delta > 0 ? 0 : list.length - 1
      else idx = Math.max(0, Math.min(list.length - 1, idx + delta))
      const next = list[idx]
      if (next) selectPacket(next)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [flowMode, packets, selected, selectPacket, selectedPkts, toggleSingleSelect, bulkDelete, resetPackets, clearFlow])

  useEffect(() => {
    const el = packetTableScrollRef.current
    if (!selected?.id || !el) return
    const row = el.querySelector(`tr[data-packet-id="${selected.id}"]`)
    if (row) {
      row.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
      return
    }
    // Row is outside the virtualized window — compute target offset by index.
    const list = flowMode ? flowMode.packets : packets
    const idx = list.findIndex((p) => p.id === selected.id)
    if (idx < 0) return
    const target = idx * ROW_H
    if (target < el.scrollTop || target > el.scrollTop + el.clientHeight - ROW_H) {
      el.scrollTo({ top: Math.max(0, target - el.clientHeight / 2), behavior: 'smooth' })
    }
  }, [selected?.id])

  // Close quick rule panel when selecting a different packet
  useEffect(() => { setShowQuickRule(false) }, [selected?.id])

  const isFlowActive = !!flowMode || !!sessionFilter
  const hasActiveFilter = !!expression.trim() || selectedServiceIDs.size > 0 || flagFilter || flagIDFilter || blockedFilter

  // Pull contains-style literals out of the parsed expression so the table
  // and detail panel can highlight matched substrings inline. Compound
  // expressions still produce useful highlights — anything more exotic just
  // doesn't get highlighted (matched-rule patterns and the flag regex still do).
  const exprHighlights = useMemo(() => extractHighlights(parsedExpression.tree), [parsedExpression.tree])

  // Per-target highlight patterns. Each is a `|`-joined regex of the
  // contains/icontains/etc. literals + any `matches` regexes targeting that
  // field. Flag regex is layered on top in the body/url-aware slots below.
  const userBodyRegex = exprHighlights.body
  const userURLRegex = exprHighlights.url
  const userHeadersAnyRegex = exprHighlights.headerAny

  // Search highlight in table rows — skip flag regex to keep noise low.
  const searchHighlightRegex = userBodyRegex || ''

  // Use flow mode packets when active, otherwise normal packets
  const displayPackets = flowMode ? flowMode.packets : packets
  const displayTotal = flowMode ? flowMode.total : total

  // ---- Row virtualization ----
  // Render only the rows in (and just outside) the viewport. Saves React from
  // reconciling thousands of <tr>s on every prepend/scroll.
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportH, setViewportH] = useState(600)
  useEffect(() => {
    const el = packetTableScrollRef.current
    if (!el) return
    const updateH = () => setViewportH(el.clientHeight || 600)
    const onScroll = () => setScrollTop(el.scrollTop)
    updateH()
    el.addEventListener('scroll', onScroll, { passive: true })
    const ro = new ResizeObserver(updateH)
    ro.observe(el)
    return () => {
      el.removeEventListener('scroll', onScroll)
      ro.disconnect()
    }
  }, [])
  const rowCount = displayPackets.length
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN)
  const endIndex = Math.min(rowCount, Math.ceil((scrollTop + viewportH) / ROW_H) + OVERSCAN)
  const topPad = startIndex * ROW_H
  const bottomPad = Math.max(0, (rowCount - endIndex) * ROW_H)
  const visiblePackets = displayPackets.slice(startIndex, endIndex)

  // FlagID highlight regex: built from the backend-provided matched values (typically 1-3).
  const flagidHighlightRegex = useMemo(() => {
    const vals = selected?.matched_flagids
    if (!vals || vals.length === 0) return ''
    return vals.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')
  }, [selected])

  // Pretty-printed body for the detail panel
  const formattedBody = useMemo(() => {
    if (!selected?.body_string) return { text: '', isJSON: false }
    return tryFormatJSON(selected.body_string)
  }, [selected?.body_string])

  // Local fallback: walk the wire format with no field names. Used when
  // the server-side .proto decode is unavailable (no proto_paths, method
  // not found, parse error, etc.).
  const decodedProto = useMemo(() => {
    if (!selected?.body) return null
    if (formattedBody.isJSON) return null
    const bytes = base64ToBytes(selected.body)
    if (bytes.length === 0) return null
    if (!looksLikeProtobuf(bytes)) return null
    const result = decodeProtobuf(bytes)
    if (!result.ok) return null
    return result
  }, [selected?.body, formattedBody.isJSON])

  // Predicate used to decide whether to try the server-side .proto decode.
  // It's intentionally more permissive than `decodedProto`: gRPC framing is
  // detected without inner-message parsing, and gRPC-shaped URLs (the path
  // is "/pkg.Service/Method") also trigger a decode attempt. This way the
  // server, which has the .proto descriptors, can still resolve the body
  // even when the descriptor-less local walk gave up.
  const mayBeGRPC = useMemo(() => {
    if (!selected?.body) return false
    if (formattedBody.isJSON) return false
    if (decodedProto) return true
    const bytes = base64ToBytes(selected.body)
    if (hasGRPCFraming(bytes)) return true
    // gRPC method path "/<pkg>.<Service>/<Method>" — usually paired with a
    // grpc-* content-type, but the URL alone is a decent signal.
    const url = selected?.url || ''
    if (url && /^\/[A-Za-z_][\w.]*\/[A-Za-z_]\w*(?:\?|$)/.test(url)) return true
    return false
  }, [selected?.body, selected?.url, formattedBody.isJSON, decodedProto])

  // Server-side decode using the configured .proto files. Resolves field
  // names via the gRPC method signature.
  const [decodedNamed, setDecodedNamed] = useState(null) // { method, message_type, frames: [{ json, error, bytes }] } or null
  const [decodedNamedError, setDecodedNamedError] = useState('')
  // Depend on selected?.body (a stable base64 string) rather than the
  // decodedProto memo: the memo is recomputed into a NEW object reference on
  // each body change. We gate on `mayBeGRPC` (lenient) so the server still
  // gets a chance when the local walk fails, which fixes the case where the
  // panel used to stay empty for grpc bodies without working local parse.
  useEffect(() => {
    setDecodedNamed(null)
    setDecodedNamedError('')
    if (!selected?.id) return
    if (!mayBeGRPC) return // body doesn't look like protobuf/grpc at all
    let cancelled = false
    api.decodePacket(selected.id)
      .then((res) => { if (!cancelled) setDecodedNamed(res) })
      .catch((err) => { if (!cancelled) setDecodedNamedError(err.message || String(err)) })
    return () => { cancelled = true }
  }, [selected?.id, selected?.body, mayBeGRPC])

  // Reset the custom-protocol override whenever the user clicks a different
  // packet — overrides are scoped to a single inspection, not sticky.
  useEffect(() => { setCustomProtocolOverride(''); setCustomPickerOpen(false) }, [selected?.id])

  // Service-bound protocol for the currently selected packet, if any.
  const boundCustomProtocolID = useMemo(() => {
    if (!selected?.service_id) return ''
    const svc = services.find((s) => s.id === selected.service_id)
    return svc?.protocol_id || ''
  }, [selected?.service_id, services])

  // Effective protocol to render: explicit override wins, then the
  // service-bound one, otherwise we don't fetch anything.
  const effectiveCustomProtocolID = customProtocolOverride || boundCustomProtocolID

  useEffect(() => {
    setDecodedCustom(null)
    setDecodedCustomError('')
    if (!selected?.id || !effectiveCustomProtocolID) return
    if (!selected?.body) return // wait until the body has been fetched
    let cancelled = false
    api.decodePacketCustom(selected.id, effectiveCustomProtocolID)
      .then((res) => { if (!cancelled) setDecodedCustom(res) })
      .catch((err) => { if (!cancelled) setDecodedCustomError(err.message || String(err)) })
    return () => { cancelled = true }
  }, [selected?.id, selected?.body, effectiveCustomProtocolID])

  // Hex-view toggle — kept unobtrusive: hidden by default, click "Show hex"
  // when the user wants to drag-select bytes and turn them into a filter.
  const [showHex, setShowHex] = useState(false)
  const selectedBytes = useMemo(() => base64ToBytes(selected?.body || ''), [selected?.body])

  // Click-to-filter from the Decoded panel: encode the selected field via
  // the backend (which has the .proto descriptors loaded) and either copy
  // the resulting `raw contains "..."` predicate, append it to the current
  // expression, or jump to the Rules page with the form pre-filled.
  const [encodeStatus, setEncodeStatus] = useState('') // '', 'copied', 'added', 'error'

  // Apply a fully-built predicate to one of the three actions (copy / add /
  // new rule). Shared by raw-byte hex selection and body-text selection so
  // those code paths don't reinvent the navigation/clipboard plumbing.
  const applyFilterPredicate = useCallback((kind, predicate, ruleNameSuffix) => {
    if (!predicate) return
    if (kind === 'copy') {
      copyText(predicate).then(() => setEncodeStatus('copied'))
        .catch(() => setEncodeStatus('error'))
    } else if (kind === 'add') {
      setExpression((prev) => {
        const e = (prev || '').trim()
        return e ? `(${e}) AND ${predicate}` : predicate
      })
      setEncodeStatus('added')
    } else if (kind === 'rule') {
      const svcId = selected?.service_id
      const svcPredicate = svcId ? `${quoteForFilter(svcId)}` : ''
      const expression = svcId
        ? `service == ${svcPredicate} AND ${predicate}`
        : predicate
      navigate('/rules', {
        state: {
          presetRule: {
            service_id: svcId || '',
            expression,
            name: ruleNameSuffix || 'custom-rule',
            action: 'drop',
          },
        },
      })
    }
    setTimeout(() => setEncodeStatus(''), 2000)
  }, [selected?.service_id, navigate])
  const handleDecodedFieldAction = useCallback(async (kind, field, value) => {
    if (!selected?.id || !decodedNamed?.method) return
    try {
      const res = await api.encodeProtoField({
        service_id: selected.service_id,
        method: decodedNamed.method,
        direction: selected.direction,
        field,
        value,
      })
      const escaped = res?.escaped ?? ''
      if (!escaped) throw new Error('encoder returned empty bytes')
      const rawPredicate = `raw contains "${escaped}"`
      // For "New drop rule" we want a more selective predicate scoped to the
      // gRPC method, so we override the generic applyFilterPredicate path.
      if (kind === 'rule') {
        const urlPredicate = `url endswith "/${decodedNamed.method.split('/').pop()}"`
        const svcPredicate = `service == ${quoteForFilter(selected.service_id)}`
        navigate('/rules', {
          state: {
            presetRule: {
              service_id: selected.service_id,
              expression: `${svcPredicate} AND ${urlPredicate} AND ${rawPredicate}`,
              name: `${decodedNamed.message_type}.${field}=${typeof value === 'string' ? value : JSON.stringify(value)}`,
              action: 'drop',
            },
          },
        })
      } else {
        applyFilterPredicate(kind, rawPredicate)
      }
    } catch (err) {
      console.error('encode-field failed:', err)
      setEncodeStatus('error')
      setTimeout(() => setEncodeStatus(''), 2000)
    }
  }, [selected?.id, selected?.service_id, selected?.direction, decodedNamed, navigate, applyFilterPredicate])

  // Body-text "Filter on selection": grabs whatever the user has highlighted
  // in the Body panel and turns it into `body contains "<text>"`. No backend
  // round-trip needed — text bodies are matched as-is.
  const handleBodyTextSelection = useCallback((kind) => {
    const sel = typeof window !== 'undefined' ? window.getSelection() : null
    const text = sel ? sel.toString() : ''
    if (!text.trim()) {
      setEncodeStatus('error')
      setTimeout(() => setEncodeStatus(''), 1500)
      return
    }
    const predicate = `body contains "${escapeStringForFilter(text)}"`
    applyFilterPredicate(kind, predicate, `body~${text.slice(0, 30)}`)
  }, [applyFilterPredicate])

  const matchedRuleForHighlight = useMemo(() => {
    if (!selected?.matched_rules?.length) return null
    return selected.matched_rules.find((r) => r.pattern) || null
  }, [selected?.matched_rules])

  const selectedRuleScope = matchedRuleForHighlight?.scope || ''
  const selectedRulePattern = matchedRuleForHighlight?.pattern || ''
  const highlightRuleInURL = !selectedRuleScope || selectedRuleScope.includes('url') || selectedRuleScope.includes('raw')
  const highlightRuleInHeaders = !selectedRuleScope || selectedRuleScope.includes('header') || selectedRuleScope.includes('raw')
  const highlightRuleInBody = !selectedRuleScope || selectedRuleScope.includes('body') || selectedRuleScope.includes('raw')
  const urlRegex = [flagRegex, userURLRegex, highlightRuleInURL ? selectedRulePattern : ''].filter(Boolean).join('|')
  const headersRegex = [flagRegex, userHeadersAnyRegex, highlightRuleInHeaders ? selectedRulePattern : ''].filter(Boolean).join('|')
  const bodyRegex = [flagRegex, userBodyRegex, highlightRuleInBody ? selectedRulePattern : ''].filter(Boolean).join('|')

  const { serviceName } = useServiceMap(services)

  return (
    <div className="p-4 flex flex-col h-full">
      {/* Flow banner */}
      {isFlowActive && (
        <div className="mb-2 flex items-center gap-3 bg-purple-900/30 border border-purple-700/50 rounded-lg px-3 py-2">
          <svg className="w-4 h-4 text-purple-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>
          </svg>
          <span className="text-sm text-purple-300">
            {flowMode ? (
              <>
                Flow from packet <span className="font-mono font-medium text-purple-200">#{flowMode.packetId}</span>
                <span className="text-purple-500 ml-2">({flowMode.total} packets, chronological order — correlated by auth token)</span>
              </>
            ) : (
              <>
                Session: <span className="font-mono font-medium text-purple-200">{sessionFilter}</span>
                <span className="text-purple-500 ml-2">({total} packets, chronological order)</span>
              </>
            )}
          </span>
          {(() => {
            // Prefer the round of the flow's anchor packet — that field is
            // already populated by the backend, so no client math is needed.
            // Fall back to the locally-derived current round (1 Hz timer
            // over the cached config) when the anchor packet doesn't carry
            // one.
            const anchorPkt = flowMode
              ? (flowMode.packets || []).find((p) => p.id === flowMode.packetId) || (flowMode.packets || [])[0]
              : (selected || (packets || [])[0])
            const fromPkt = (anchorPkt?.round && anchorPkt.round > 0)
              ? anchorPkt.round
              : (anchorPkt?.flagid_round && anchorPkt.flagid_round > 0 ? anchorPkt.flagid_round : null)
            const round = fromPkt ?? currentRound
            if (round == null) return null
            return (
              <span
                className="text-xs bg-teal-900/40 text-teal-300 border border-teal-700/60 rounded px-2 py-0.5"
                title={fromPkt != null ? 'Round attached to the flow anchor packet (backend)' : 'Live round derived from competition_start + round_duration'}
              >
                Round <span className="font-mono font-medium">{round}</span>
                {flowMode && currentRound != null && currentRound !== fromPkt && fromPkt != null && (
                  <span className="ml-1 text-teal-500/70 text-[10px]">/ now {currentRound}</span>
                )}
              </span>
            )
          })()}
          <div className="ml-auto">
            <ExploitButton packetId={flowMode ? flowMode.packetId : selected?.id} variant="primary" />
          </div>
          <a
            href={api.flowPcapDownloadUrl(flowMode ? flowMode.packetId : selected?.id)}
            download={`flow-${flowMode ? flowMode.packetId : selected?.id}.pcap`}
            className="text-xs bg-gray-700/60 hover:bg-gray-600/60 text-gray-300 px-2 py-1 rounded cursor-pointer flex items-center gap-1"
            title="Download this flow as a .pcap file"
          >
            ⬇ PCAP
          </a>
          <button
            onClick={() => setPinDialog({ anchorId: flowMode ? flowMode.packetId : selected?.id, name: '', notes: '', saving: false, error: '' })}
            className="text-xs bg-purple-800/30 hover:bg-purple-700/40 text-purple-400 px-2 py-1 rounded cursor-pointer"
            title="Save this flow for later comparison"
          >
            Pin flow
          </button>
          <button onClick={clearFlow} className="text-xs bg-purple-800/50 hover:bg-purple-700/50 text-purple-300 px-2 py-1 rounded cursor-pointer">
            Clear flow
          </button>
        </div>
      )}

      {/* Pin-flow inline dialog */}
      {pinDialog && (
        <div className="mb-2 bg-gray-900 border border-purple-700/50 rounded-lg px-4 py-3 flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <span className="text-sm text-purple-300 font-medium">
              {pinDialog.packetIds ? `Save selection (${pinDialog.packetIds.length} packets)` : 'Save flow'}
            </span>
            <input
              autoFocus
              value={pinDialog.name}
              onChange={(e) => setPinDialog((d) => ({ ...d, name: e.target.value }))}
              placeholder="Flow name..."
              maxLength={80}
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2.5 py-1 text-sm text-gray-100 focus:outline-none focus:border-purple-500"
              onKeyDown={(e) => { if (e.key === 'Escape') setPinDialog(null) }}
            />
            <input
              value={pinDialog.notes}
              onChange={(e) => setPinDialog((d) => ({ ...d, notes: e.target.value }))}
              placeholder="Notes (optional)..."
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2.5 py-1 text-sm text-gray-100 focus:outline-none focus:border-purple-500"
            />
            <button
              disabled={pinDialog.saving}
              onClick={async () => {
                const isSelection = !!pinDialog.packetIds
                if (!isSelection && !pinDialog.anchorId) return
                if (isSelection && pinDialog.packetIds.length === 0) return
                setPinDialog((d) => ({ ...d, saving: true, error: '' }))
                try {
                  const fallbackName = isSelection
                    ? `Selection (${pinDialog.packetIds.length} packets)`
                    : `Flow #${pinDialog.anchorId}`
                  const payload = {
                    name: pinDialog.name.trim() || fallbackName,
                    notes: pinDialog.notes.trim(),
                  }
                  if (isSelection) payload.packet_ids = pinDialog.packetIds
                  else payload.anchor_packet_id = pinDialog.anchorId
                  await api.createSavedFlow(payload)
                  setPinDialog(null)
                  setPinToast('Saved!')
                  setTimeout(() => setPinToast(null), 2000)
                } catch (err) {
                  setPinDialog((d) => ({ ...d, saving: false, error: err.message }))
                }
              }}
              className="text-xs px-3 py-1 bg-purple-700 hover:bg-purple-600 disabled:bg-gray-700 text-white rounded cursor-pointer transition-colors"
            >
              {pinDialog.saving ? 'Saving…' : 'Save'}
            </button>
            <button onClick={() => setPinDialog(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
          </div>
          {pinDialog.error && <span className="text-xs text-red-400">{pinDialog.error}</span>}
        </div>
      )}
      {pinToast && (
        <div className="fixed bottom-4 right-4 bg-purple-900 text-purple-200 text-xs px-3 py-1.5 rounded-full z-50">{pinToast}</div>
      )}

      {/* Filters — collapsible */}
      {trafficMode === 'static' && (
        <div className="mb-3 bg-gray-900 border border-gray-800 rounded-lg p-3 flex items-center gap-2 flex-wrap">
          <span className="text-xs px-2 py-1 rounded bg-indigo-900/40 text-indigo-300 border border-indigo-700/50">Static mode</span>
          <button
            onClick={handleStartCapture}
            disabled={captureBusy || captureStatus?.capturing}
            className="text-xs px-3 py-1.5 rounded bg-green-800/60 hover:bg-green-700/60 disabled:bg-gray-800 disabled:text-gray-600 text-green-200 cursor-pointer"
          >
            {captureBusy && !captureStatus?.capturing ? 'Starting...' : 'Start Capture'}
          </button>
          <button
            onClick={handleStopCapture}
            disabled={captureBusy || !captureStatus?.capturing}
            className="text-xs px-3 py-1.5 rounded bg-yellow-800/60 hover:bg-yellow-700/60 disabled:bg-gray-800 disabled:text-gray-600 text-yellow-200 cursor-pointer"
          >
            {captureBusy && captureStatus?.capturing ? 'Stopping...' : 'Stop Capture'}
          </button>
          <button
            onClick={handleApplyFlagIDs}
            disabled={applyBusy || captureStatus?.capturing || !captureStatus?.capture_start}
            className="text-xs px-3 py-1.5 rounded bg-teal-800/60 hover:bg-teal-700/60 disabled:bg-gray-800 disabled:text-gray-600 text-teal-200 cursor-pointer"
          >
            {applyBusy ? 'Applying...' : 'Apply Flag IDs'}
          </button>
          <button
            onClick={handleClearPackets}
            disabled={clearBusy}
            title="Hide all current packets from your view (per-user; teammates unaffected)"
            className="text-xs px-3 py-1.5 rounded bg-red-800/60 hover:bg-red-700/60 disabled:bg-gray-800 disabled:text-gray-600 text-red-200 cursor-pointer"
          >
            {clearBusy ? 'Clearing...' : 'Clear my view'}
          </button>
          <span className="text-xs text-gray-500 ml-auto">
            {captureStatus?.capturing ? 'Capturing traffic...' : 'Capture stopped'}
          </span>
        </div>
      )}
      <div className="mb-3">
        <button
          onClick={() => setFiltersCollapsed(!filtersCollapsed)}
          className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 mb-1 cursor-pointer"
        >
          <svg className={`w-3 h-3 transition-transform ${filtersCollapsed ? '-rotate-90' : ''}`} viewBox="0 0 12 12" fill="currentColor">
            <path d="M2 4l4 4 4-4z" />
          </svg>
          Filter {hasActiveFilter && <span className="bg-cyan-900/50 text-cyan-400 px-1.5 rounded text-[10px]">active</span>}
        </button>
        {!filtersCollapsed && (
          <div className="space-y-2">
            {services.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] uppercase tracking-wide text-gray-600 mr-1">Services</span>
                {services.map((svc) => {
                  const active = selectedServiceIDs.has(svc.id)
                  return (
                    <button
                      key={svc.id}
                      type="button"
                      onClick={() => {
                        setSelectedServiceIDs((prev) => {
                          const next = new Set(prev)
                          if (next.has(svc.id)) next.delete(svc.id)
                          else next.add(svc.id)
                          return next
                        })
                      }}
                      className={`text-xs px-2 py-1 rounded border transition-colors cursor-pointer ${
                        active
                          ? 'bg-cyan-700/40 border-cyan-600 text-cyan-100'
                          : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600'
                      }`}
                      title={`Filter by service ${svc.name}`}
                    >
                      {active ? '✓ ' : ''}{svc.name}
                    </button>
                  )
                })}
                {selectedServiceIDs.size > 0 && (
                  <button
                    type="button"
                    onClick={() => setSelectedServiceIDs(new Set())}
                    className="text-[10px] text-gray-500 hover:text-gray-300 ml-1 cursor-pointer underline"
                    title="Clear service filter"
                  >
                    clear
                  </button>
                )}
              </div>
            )}
            <FilterExpression
              value={expression}
              onChange={setExpression}
              placeholder='e.g. body contains "pippo" AND NOT header.User-Agent contains "bot"'
              compact
            />
            <div className="flex items-center gap-2 flex-wrap">
              {flagRegex && (
                <button
                  onClick={toggleFlagFilter}
                  className={`text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                    flagFilter
                      ? 'bg-yellow-900/50 text-yellow-300 border border-yellow-700/50'
                      : 'bg-gray-800 text-gray-400 border border-gray-700 hover:text-gray-300'
                  }`}
                >
                  <span>&#9873;</span> Contains Flag
                </button>
              )}
              {(flagIDEnabled || trafficMode === 'static') && (
                <button
                  onClick={toggleFlagIDFilter}
                  className={`text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                    flagIDFilter
                      ? 'bg-teal-900/50 text-teal-300 border border-teal-700/50'
                      : 'bg-gray-800 text-gray-400 border border-gray-700 hover:text-gray-300'
                  }`}
                >
                  <span>&#9881;</span> Contains my Flag IDs
                </button>
              )}
              <button
                onClick={toggleBlockedFilter}
                className={`text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                  blockedFilter
                    ? 'bg-red-900/50 text-red-300 border border-red-700/50'
                    : 'bg-gray-800 text-gray-400 border border-gray-700 hover:text-gray-300'
                }`}
              >
                <span>&#9888;</span> Blocked
              </button>
              <button
                onClick={() => addQuickFilter('direction == "request"')}
                className="text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 bg-gray-800 text-gray-400 border border-gray-700 hover:text-blue-300"
              >
                REQ
              </button>
              <button
                onClick={() => addQuickFilter('direction == "response"')}
                className="text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 bg-gray-800 text-gray-400 border border-gray-700 hover:text-green-300"
              >
                RES
              </button>
              {currentRound != null && (
                <button
                  onClick={() => addQuickFilter(`round == ${currentRound}`)}
                  className="text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 bg-gray-800 text-gray-400 border border-gray-700 hover:text-teal-300"
                >
                  Round {currentRound}
                </button>
              )}
              <button
                onClick={() => addQuickFilter('flagged AND NOT dropped')}
                className="text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 bg-gray-800 text-gray-400 border border-gray-700 hover:text-yellow-300"
              >
                Leaks
              </button>
              <button
                onClick={() => addQuickFilter('contains_flagid AND direction == "request"')}
                className="text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 bg-gray-800 text-gray-400 border border-gray-700 hover:text-teal-300"
              >
                FlagID probes
              </button>
              <select
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 cursor-pointer focus:outline-none focus:border-cyan-500 ml-auto"
                title="Sort order"
              >
                <option value="desc">Newest first</option>
                <option value="asc">Oldest first</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Packet table + detail split */}
      <div className="flex-1 flex gap-0 min-h-0 overflow-hidden">
        {/* Table */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0">
          <div ref={packetTableScrollRef} className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pl-2 pr-1 py-2 w-7">
                    {selectedPkts.size > 0 && (
                      <button type="button" onClick={() => setSelectedPkts(new Set())} title="Clear selection"
                        className="text-gray-600 hover:text-gray-400 cursor-pointer text-xs leading-none">✕</button>
                    )}
                  </th>
                  <th className="px-2 py-2 font-medium w-16" title="Packet ID">#</th>
                  <th className="px-2 py-2 font-medium w-14" title="Scoreboard round (from competition_start + round_duration)">Round</th>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Service</th>
                  <th className="px-3 py-2 font-medium">Dir</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium w-16"></th>
                  <th className="px-3 py-2 font-medium">Method</th>
                  <th className="px-3 py-2 font-medium">URL / Body</th>
                  <th className="px-3 py-2 font-medium">Peer</th>
                </tr>
              </thead>
              <tbody>
                {topPad > 0 && (
                  <tr aria-hidden="true" style={{ height: topPad }}><td colSpan="11" /></tr>
                )}
                {visiblePackets.map((pkt) => {
                  const rowBg = pkt.matched_rules?.length > 0
                    ? 'bg-red-950/20'
                    : pkt.contains_flagid && pkt.flagged
                      ? 'bg-gradient-to-r from-yellow-950/30 to-teal-950/30'
                      : pkt.contains_flagid
                        ? 'bg-teal-950/30'
                        : pkt.flagged
                          ? 'bg-yellow-950/20'
                          : '';
                  const cellText = pkt.url || (pkt.body_string?.slice(0, 80)) || '\u2014'
                  return (
                  <tr
                    key={pkt.id}
                    data-packet-id={pkt.id}
                    onClick={(e) => handleRowClick(pkt, e)}
                    style={{ height: ROW_H }}
                    className={`group border-b border-gray-800/50 cursor-pointer transition-colors select-none ${
                      selectedPkts.has(pkt.id) ? 'bg-blue-950/30 hover:bg-blue-950/40' :
                      selected?.id === pkt.id ? 'bg-gray-800' : 'hover:bg-gray-900/80'
                    } ${rowBg}`}
                  >
                    <td className="pl-2 pr-1 py-1.5 w-7" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedPkts.has(pkt.id)}
                        onChange={(e) => handleCheckboxClick(pkt, e)}
                        onClick={(e) => e.stopPropagation()}
                        title="Select (Shift+click row or checkbox for range, Cmd/Ctrl+click row to toggle, Del to delete selection)"
                        className={`w-3.5 h-3.5 cursor-pointer accent-cyan-500 transition-opacity ${
                          selectedPkts.has(pkt.id) ? 'opacity-100' : 'opacity-40 group-hover:opacity-90'
                        }`}
                      />
                    </td>
                    <td className="px-2 py-1.5 text-gray-500 font-mono text-[11px] tabular-nums whitespace-nowrap" title={`packet id ${pkt.id}`}>
                      #{pkt.id}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[11px] tabular-nums whitespace-nowrap">
                      {(() => {
                        // Backend computes the round from the packet timestamp
                        // (competition_start + round_duration) and ships it in
                        // every packet response, including SSE. The frontend
                        // just renders it — no polling, no client-side math.
                        // Fall back to the legacy flagid_round if the new
                        // field isn't present (older snapshots, etc.).
                        const v = pkt.round > 0 ? pkt.round : (pkt.flagid_round > 0 ? pkt.flagid_round : null)
                        return v != null
                          ? <span className="text-teal-400">{v}</span>
                          : <span className="text-gray-700">—</span>
                      })()}
                    </td>
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap font-mono text-xs">
                      {new Date(pkt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs truncate max-w-[8rem]" title={serviceName(pkt.service_id)}>
                      {serviceName(pkt.service_id)}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className={`text-xs px-1.5 py-0.5 rounded ${
                        pkt.direction === 'request' ? 'bg-blue-900/40 text-blue-400' : 'bg-green-900/40 text-green-400'
                      }`}>
                        {pkt.direction === 'request' ? 'REQ' : 'RES'}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-xs">
                      {pkt.status > 0 && <span className={`${pkt.status < 400 ? 'text-green-400' : 'text-red-400'}`}>{pkt.status}</span>}
                    </td>
                    <td className="px-3 py-1.5">
                      <div className="flex items-center gap-1">
                        {pkt.flagged && <span className="text-yellow-400 text-xs" title="Contains flag">&#9873;</span>}
                        {hasDropAction(pkt) && <span className="text-red-400 text-xs" title="Dropped by rule">&#9888;</span>}
                        {hasAlertAction(pkt) && <span className="text-yellow-400 text-xs" title="Alert rule triggered">&#9888;</span>}
                        {pkt.contains_flagid && <span className="text-teal-400 text-xs" title="Contains flag ID">&#9881;</span>}
                        <button
                          onClick={(e) => { e.stopPropagation(); showFlow(pkt) }}
                          className="ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded bg-purple-950/40 text-purple-300/80 border border-purple-900/40 hover:bg-purple-900/50 hover:text-purple-200 cursor-pointer flex items-center gap-1 transition-colors"
                          title={`Reconstruct full flow for ${getPeerIP(pkt)} (correlates across TCP connections)`}
                        >
                          <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                            <path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>
                          </svg>
                          Flow
                        </button>
                      </div>
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{pkt.method}</td>
                    <td className="px-3 py-1.5 text-gray-400 text-xs truncate max-w-xs">
                      <HighlightedText text={cellText} regex={searchHighlightRegex} />
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{getPeerIP(pkt)}</td>
                  </tr>
                  );
                })}
                {bottomPad > 0 && (
                  <tr aria-hidden="true" style={{ height: bottomPad }}><td colSpan="11" /></tr>
                )}
                {displayPackets.length === 0 && (
                  <tr><td colSpan="11" className="text-center py-8 text-gray-600">No packets found</td></tr>
                )}
              </tbody>
              {/* Infinite scroll sentinel — only shown outside flow mode */}
              {!flowMode && (
                <tfoot>
                  <tr>
                    <td colSpan="11" className="py-3 text-center text-xs text-gray-700">
                      <span ref={packetSentinelRef}>
                        {loading ? 'Loading…' : (!hasMore && packets.length > 0) ? '— end —' : ''}
                      </span>
                    </td>
                  </tr>
                </tfoot>
              )}
            </table>
          </div>

          {/* Bulk selection action bar */}
          {selectedPkts.size > 0 && (
            <div className="flex items-center gap-3 px-3 py-2 bg-blue-950/40 border-t border-blue-800/40 text-sm">
              <span className="text-blue-300 text-xs font-medium">{selectedPkts.size} packet{selectedPkts.size !== 1 ? 's' : ''} selected</span>
              <button
                onClick={() => setPinDialog({
                  packetIds: Array.from(selectedPkts),
                  name: '',
                  notes: '',
                  saving: false,
                  error: '',
                })}
                title="Pin selected packets as a saved flow (works across different sessions/IPs)"
                className="text-xs px-3 py-1 bg-purple-800/50 hover:bg-purple-700/60 text-purple-200 rounded cursor-pointer transition-colors"
              >
                Pin {selectedPkts.size}
              </button>
              <button
                onClick={async () => {
                  const ids = Array.from(selectedPkts)
                  try {
                    const res = await api.pcapExportSelection(ids)
                    setPinToast(`PCAP saved: ${res.filename} (${res.packet_count} packets)`)
                    setTimeout(() => setPinToast(null), 3500)
                  } catch (err) {
                    setPinToast(`PCAP save failed: ${err.message}`)
                    setTimeout(() => setPinToast(null), 3500)
                  }
                }}
                title="Save selected packets to a .pcap file (visible in Config → PCAP files)"
                className="text-xs px-3 py-1 bg-cyan-800/50 hover:bg-cyan-700/60 text-cyan-200 rounded cursor-pointer transition-colors"
              >
                Save PCAP
              </button>
              <button
                onClick={bulkDelete}
                title="Hide from your view (per-user; teammates unaffected)"
                className="text-xs px-3 py-1 bg-red-800/60 hover:bg-red-700/60 text-red-200 rounded cursor-pointer transition-colors"
              >
                Hide {selectedPkts.size}
              </button>
              <button
                onClick={() => { setSelectedPkts(new Set()); selectionAnchorRef.current = null }}
                className="text-xs text-gray-500 hover:text-gray-300 cursor-pointer"
              >
                Clear selection
              </button>
              <span className="text-gray-600 text-xs ml-auto">x = toggle · Del = hide</span>
            </div>
          )}

          {/* Pagination */}
          <div className="flex items-center justify-between px-3 py-2 bg-gray-900 border-t border-gray-800 text-sm text-gray-400">
            <div className="flex items-center gap-2">
              <button
                onClick={togglePause}
                disabled={trafficMode !== 'live'}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                  trafficMode !== 'live'
                    ? 'bg-gray-800 text-gray-600 border border-gray-700 cursor-default'
                    : paused
                    ? 'bg-yellow-900/50 text-yellow-300 border border-yellow-700/50'
                    : 'bg-gray-800 text-gray-400 border border-gray-700 hover:text-gray-300'
                }`}
                title={trafficMode !== 'live' ? 'Pause/Resume is only available in live mode' : (paused ? 'Resume live capture' : 'Pause live capture')}
              >
                {paused ? (
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21" /></svg>
                ) : (
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="3" width="6" height="18" /><rect x="14" y="3" width="6" height="18" /></svg>
                )}
                {paused ? 'Resume' : 'Pause'}
              </button>
              <span>{displayTotal} packet{displayTotal !== 1 ? 's' : ''}{paused ? ' (paused)' : ''}</span>
              <div className="flex items-center text-xs rounded overflow-hidden border border-gray-700 ml-1">
                {['live', 'static'].map((mode) => (
                  <button
                    key={mode}
                    onClick={() => switchMode(mode)}
                    className={`px-2.5 py-1 transition-colors cursor-pointer ${
                      trafficMode === mode
                        ? mode === 'static'
                          ? 'bg-indigo-900/60 text-indigo-300'
                          : 'bg-emerald-900/60 text-emerald-300'
                        : 'bg-gray-800 text-gray-500 hover:text-gray-300'
                    }`}
                    title={mode === 'live' ? 'Live capture mode' : 'Static capture mode'}
                  >
                    {mode === 'live' ? 'Live' : 'Static'}
                  </button>
                ))}
              </div>
            </div>
            {flowMode && (
              <span className="text-xs text-gray-600">{displayTotal} in flow</span>
            )}
            <div className="flex items-center gap-1 ml-auto">
              <button
                onClick={handleClearPackets}
                disabled={clearBusy}
                className="text-xs px-2.5 py-1 bg-gray-800 border border-gray-700 text-gray-400 hover:text-red-300 hover:border-red-800/60 rounded cursor-pointer transition-colors"
                title="Hide all current packets from your view (per-user; teammates unaffected)"
              >
                {clearBusy ? 'Clearing…' : 'Clear my view'}
              </button>
              {(getHiddenIds().length > 0 || !!getClearCursor()) && (
                <button
                  onClick={handleUnhideAll}
                  className="text-xs px-2.5 py-1 bg-gray-800 border border-gray-700 text-gray-400 hover:text-emerald-300 hover:border-emerald-800/60 rounded cursor-pointer transition-colors"
                  title="Restore all packets hidden by you"
                >
                  Show hidden
                </button>
              )}
              <button
                onClick={() => { setPcapDialog(true); setPcapResult(null) }}
                className="text-xs px-2.5 py-1 bg-gray-800 border border-gray-700 text-gray-400 hover:text-gray-200 rounded cursor-pointer transition-colors"
                title="Export matching packets as .pcap file"
              >
                ⬇ PCAP
              </button>
            </div>
          </div>
        </div>

        {/* PCAP export inline dialog */}
        {pcapDialog && (
          <div className="border-t border-gray-800 bg-gray-900 px-4 py-3 flex flex-col gap-2">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-sm text-gray-300 font-medium">Export PCAP</span>
              <span className="text-xs text-gray-500">Exports all packets matching current filters</span>
              <button
                disabled={pcapExporting}
                onClick={async () => {
                  setPcapExporting(true); setPcapResult(null)
                  try {
                    const params = {}
                    if (sessionFilter) params.session_id = sessionFilter
                    if (effectiveExpression) params.q = effectiveExpression
                    const data = await api.pcapExport(params)
                    setPcapResult(data)
                  } catch (err) {
                    alert('PCAP export failed: ' + err.message)
                  } finally {
                    setPcapExporting(false)
                  }
                }}
                className="text-xs px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 disabled:bg-gray-700 text-white rounded cursor-pointer transition-colors"
              >
                {pcapExporting ? 'Exporting…' : 'Export'}
              </button>
              {pcapResult && (
                <a
                  href={api.pcapDownloadUrl(pcapResult.filename)}
                  download={pcapResult.filename}
                  className="text-xs px-3 py-1.5 bg-green-800/60 hover:bg-green-700/60 text-green-300 rounded cursor-pointer transition-colors"
                >
                  ⬇ Download {pcapResult.filename} ({pcapResult.packet_count} pkts)
                </a>
              )}
              <button onClick={() => setPcapDialog(false)} className="text-gray-500 hover:text-gray-300 cursor-pointer ml-auto">&times;</button>
            </div>
          </div>
        )}

        {/* Detail panel — resizable */}
        {selected && (
          <>
            {/* Drag handle */}
            <div
              onMouseDown={startDrag}
              className="w-1.5 cursor-col-resize hover:bg-cyan-500/30 active:bg-cyan-500/50 transition-colors flex-shrink-0 rounded"
            />
            <div style={{ width: detailWidth }} className="flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
              <div className="flex items-center justify-between p-3 border-b border-gray-800 sticky top-0 bg-gray-900 z-10">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-medium text-gray-100">Packet #{selected.id}</h3>
                  <button
                    onClick={() => showFlow(selected)}
                    className="text-xs text-purple-400 hover:text-purple-300 cursor-pointer"
                    title={`Show flow for ${getPeerIP(selected)}`}
                  >
                    Flow
                  </button>
                  <ExploitButton packetId={selected.id} variant="link" />
                  <button
                    onClick={() => setShowQuickRule(!showQuickRule)}
                    className={`text-xs flex items-center gap-1 cursor-pointer transition-colors ${
                      showQuickRule ? 'text-red-300' : 'text-red-400 hover:text-red-300'
                    }`}
                    title="Create a drop/alert rule from this packet"
                  >
                    <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    Block
                  </button>
                  <button
                    onClick={() => setPinDialog({ anchorId: selected.id, name: '', notes: '', saving: false, error: '' })}
                    className="text-xs flex items-center gap-1 text-amber-400 hover:text-amber-300 cursor-pointer"
                    title="Pin this packet's flow to Saved Flows (shared with teammates)"
                  >
                    <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/>
                    </svg>
                    Pin
                  </button>
                </div>
                <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
              </div>
              <div className="p-3 space-y-2 text-sm">
                {/* Quick Rule Panel */}
                {showQuickRule && (
                  <QuickRulePanel
                    packet={selected}
                    services={services}
                    onCreated={() => setShowQuickRule(false)}
                    onCancel={() => setShowQuickRule(false)}
                  />
                )}

                {/* Compact metadata grid */}
                <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs bg-gray-800/50 rounded p-2">
                  <div><span className="text-gray-500">Service </span><span className="text-gray-300">{serviceName(selected.service_id)}</span></div>
                  <div><span className="text-gray-500">Time </span><span className="text-gray-300">{new Date(selected.timestamp).toLocaleTimeString()}</span></div>
                  <div><span className="text-gray-500">Direction </span><span className={selected.direction === 'request' ? 'text-blue-400' : 'text-green-400'}>{selected.direction === 'request' ? 'Request' : 'Response'}</span></div>
                  <div><span className="text-gray-500">Protocol </span><span className="text-gray-300">{selected.protocol}</span></div>
                  <div><span className="text-gray-500">Src </span><span className="text-gray-300 font-mono">{selected.src_ip}:{selected.src_port}</span></div>
                  <div><span className="text-gray-500">Dst </span><span className="text-gray-300 font-mono">{selected.dst_ip}:{selected.dst_port}</span></div>
                  {selected.method && <div><span className="text-gray-500">Method </span><span className="text-gray-300">{selected.method}</span></div>}
                  {selected.status > 0 && <div><span className="text-gray-500">Status </span><span className={selected.status < 400 ? 'text-green-400' : 'text-red-400'}>{selected.status}</span></div>}
                </div>

                {selected.url && (
                  <div className="text-xs">
                    <span className="text-gray-500">URL </span>
                    <span className="text-gray-300 break-all font-mono">
                      <HighlightedText text={selected.url} regex={urlRegex} flagidRegex={flagidHighlightRegex} />
                    </span>
                  </div>
                )}

                {selected.matched_rules?.length > 0 && (
                  <div className="border rounded px-2 py-1 bg-red-900/20 border-red-800/50">
                    <span className="text-xs font-medium text-red-400">Matched: </span>
                    {selected.matched_rules.map((r, i) => (
                      <span key={r.id} className="text-xs text-red-300">
                        {i > 0 && ', '}
                        {r.name}
                        {r.action ? <span className="text-gray-500 ml-1">({r.action})</span> : null}
                      </span>
                    ))}
                  </div>
                )}

                {selected.headers && Object.keys(selected.headers).length > 0 && (
                  <div className="flex-1">
                    <div className="text-gray-500 text-xs mb-1">Headers</div>
                    <div className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto" style={{ maxHeight: '40vh' }}>
                      {Object.entries(selected.headers).map(([k, v]) => (
                        <div key={k}>
                          <span className="text-cyan-400">{k}:</span>{' '}
                          <HighlightedText text={v} regex={headersRegex} flagidRegex={flagidHighlightRegex} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(selected.body_string || selected.body) && (
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-gray-500 text-xs">Body</span>
                      {formattedBody.isJSON && (
                        <span className="text-[10px] text-cyan-600 bg-cyan-900/30 px-1 py-0.5 rounded">JSON</span>
                      )}
                      {selected.body && (
                        <span className="text-[10px] text-gray-600 font-mono">
                          {base64ToBytes(selected.body).length} bytes
                        </span>
                      )}
                      <button
                        onClick={() => copyText(selected.body_string)}
                        className="text-[10px] text-gray-600 hover:text-gray-400 ml-auto cursor-pointer"
                        title="Copy raw body"
                        disabled={!selected.body_string}
                      >
                        Copy
                      </button>
                      {selected.body && (
                        <button
                          onClick={async () => { await copyRawBytesFromBase64(selected.body) }}
                          className="text-[10px] text-gray-600 hover:text-gray-400 cursor-pointer"
                          title="Copy body as raw bytes (binary clipboard when supported; otherwise hex)"
                        >
                          Copy bytes
                        </button>
                      )}
                      {selected.body_string && (
                        <RawSelectionActionButton
                          disabled={false}
                          onAction={(kind) => handleBodyTextSelection(kind)}
                        />
                      )}
                      {selected.body && selectedBytes.length > 0 && (
                        <button
                          type="button"
                          onClick={() => setShowHex((v) => !v)}
                          className={`text-[10px] cursor-pointer ${showHex ? 'text-cyan-400 hover:text-cyan-300' : 'text-gray-600 hover:text-gray-400'}`}
                          title="Toggle hex+ASCII view with byte selection"
                        >
                          {showHex ? 'Hide hex' : 'Show hex'}
                        </button>
                      )}
                    </div>
                    <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '60vh' }}>
                      {selected.body_string ? (
                        <HighlightedText text={formattedBody.text} regex={bodyRegex} flagidRegex={flagidHighlightRegex} />
                      ) : (
                        <span className="text-gray-500">
                          (non-UTF8 body) — use “Copy bytes”
                        </span>
                      )}
                    </pre>
                    {showHex && selectedBytes.length > 0 && (
                      <div className="mt-2">
                        <HexView
                          bytes={selectedBytes}
                          onSelectionAction={applyFilterPredicate}
                        />
                      </div>
                    )}
                  </div>
                )}

                {/* Custom-protocol decode. Only shown when a protocol is bound
                    to the service or the user explicitly opts in, so services
                    that don't use custom protocols stay clean (no stray picker
                    or red "decode error"). */}
                {!boundCustomProtocolID && !customProtocolOverride && !customPickerOpen && customProtocols.length > 0 && (
                  <button
                    onClick={() => setCustomPickerOpen(true)}
                    className="self-start text-[11px] text-gray-500 hover:text-cyan-300 cursor-pointer"
                  >
                    + Decode with custom protocol…
                  </button>
                )}
                {(boundCustomProtocolID || customProtocolOverride || customPickerOpen) && (
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-gray-500 text-xs">Decoded (custom protocol)</span>
                      {decodedCustom && (
                        <span className="text-[10px] text-cyan-300 bg-cyan-900/30 px-1 py-0.5 rounded">
                          {decodedCustom.protocol}
                        </span>
                      )}
                      <select
                        value={customProtocolOverride}
                        onChange={(e) => setCustomProtocolOverride(e.target.value)}
                        className="text-[10px] bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-gray-300 focus:outline-none focus:border-cyan-500"
                        title={boundCustomProtocolID ? 'Override the protocol bound to this service' : 'Decode this packet with a custom protocol'}
                      >
                        <option value="">{boundCustomProtocolID ? '— bound —' : '— pick a protocol —'}</option>
                        {customProtocols.map((p) => (
                          <option key={p.id} value={p.id}>Decode with: {p.name}</option>
                        ))}
                      </select>
                      {decodedCustomError && effectiveCustomProtocolID && (
                        <span className="text-[10px] text-red-400" title={decodedCustomError}>
                          decode error
                        </span>
                      )}
                    </div>
                    {decodedCustom && (
                      <div className="bg-gray-800 rounded p-2 text-xs font-mono overflow-auto" style={{ maxHeight: '60vh' }}>
                        {(decodedCustom.messages || []).map((msg, idx, arr) => (
                          <div key={idx} className={idx > 0 ? 'mt-2 pt-2 border-t border-gray-700' : ''}>
                            {arr.length > 1 && (
                              <div className="text-gray-500 text-[10px] mb-1">message {idx + 1} of {arr.length}</div>
                            )}
                            <CustomDecodedFields fields={msg || []} />
                          </div>
                        ))}
                        {decodedCustom.trailing_hex && (
                          <div className="mt-2 pt-2 border-t border-gray-700">
                            <span className="text-gray-500">trailing bytes: </span>
                            <span className="text-gray-300 break-all">{decodedCustom.trailing_hex}</span>
                          </div>
                        )}
                        {decodedCustom.error && (
                          <div className="mt-2 text-red-400">{decodedCustom.error}</div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {(decodedProto || decodedNamed || (mayBeGRPC && (decodedNamedError || decodedNamed === null))) && (
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-gray-500 text-xs">Decoded</span>
                      {decodedNamed ? (
                        <>
                          <span className="text-[10px] text-green-400 bg-green-900/30 px-1 py-0.5 rounded">
                            {decodedNamed.message_type}
                          </span>
                          <span className="text-[10px] text-gray-600">{decodedNamed.method}</span>
                        </>
                      ) : decodedProto ? (
                        <>
                          <span className="text-[10px] text-purple-400 bg-purple-900/30 px-1 py-0.5 rounded">
                            {decodedProto.framing === 'grpc' ? 'gRPC / protobuf (raw)' : 'protobuf (raw)'}
                          </span>
                          {decodedNamedError && (
                            <span className="text-[10px] text-gray-600" title={decodedNamedError}>
                              named decode unavailable
                            </span>
                          )}
                        </>
                      ) : (
                        <>
                          <span className="text-[10px] text-gray-400 bg-gray-800/60 px-1 py-0.5 rounded">
                            {decodedNamedError ? 'decode failed' : 'decoding…'}
                          </span>
                          {decodedNamedError && (
                            <span className="text-[10px] text-red-400" title={decodedNamedError}>
                              {decodedNamedError.length > 80 ? decodedNamedError.slice(0, 77) + '…' : decodedNamedError}
                            </span>
                          )}
                        </>
                      )}
                      {(decodedNamed?.frames?.length ?? decodedProto?.frames?.length ?? 0) > 1 && (
                        <span className="text-[10px] text-gray-600">{decodedNamed?.frames?.length ?? decodedProto?.frames?.length} frames</span>
                      )}
                    </div>
                    <div className="bg-gray-800 rounded p-2 text-xs font-mono overflow-auto" style={{ maxHeight: '60vh' }}>
                      {decodedNamed ? (
                        decodedNamed.frames.map((frame, idx) => (
                          <div key={idx} className={idx > 0 ? 'mt-2 pt-2 border-t border-gray-700' : ''}>
                            {decodedNamed.frames.length > 1 && (
                              <div className="text-gray-500 text-[10px] mb-1">frame {idx} ({frame.bytes}B)</div>
                            )}
                            {frame.json ? (
                              <DecodedNamedFrameView
                                frameJSON={frame.json}
                                onLeafAction={handleDecodedFieldAction}
                                fallbackHighlight={
                                  <HighlightedText text={frame.json} regex={bodyRegex} flagidRegex={flagidHighlightRegex} />
                                }
                              />
                            ) : (
                              <div className="text-red-400">{frame.error || 'decode error'}</div>
                            )}
                          </div>
                        ))
                      ) : decodedProto ? (
                        decodedProto.frames.map((frame, idx) => (
                          <div key={idx} className={idx > 0 ? 'mt-2 pt-2 border-t border-gray-700' : ''}>
                            {decodedProto.frames.length > 1 && (
                              <div className="text-gray-500 text-[10px] mb-1">frame {idx} ({frame.length}B)</div>
                            )}
                            {frame.error && frame.fields.length === 0 ? (
                              <div className="text-gray-500 italic">{frame.error}</div>
                            ) : (
                              <ProtobufFields fields={frame.fields} />
                            )}
                          </div>
                        ))
                      ) : (
                        <div className="text-gray-500 italic">
                          {decodedNamedError
                            ? 'No .proto descriptors and inner body could not be parsed locally.'
                            : 'Waiting for server-side decode…'}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {(loading || flowLoading) && <div className="fixed bottom-4 right-4 bg-gray-800 text-cyan-400 text-xs px-3 py-1.5 rounded-full">{flowLoading ? 'Reconstructing flow…' : 'Loading...'}</div>}
      {encodeStatus === 'copied' && <div className="fixed bottom-4 right-4 bg-green-800 text-green-200 text-xs px-3 py-1.5 rounded-full z-50">Filter copied to clipboard!</div>}
      {encodeStatus === 'added' && <div className="fixed bottom-4 right-4 bg-cyan-800 text-cyan-200 text-xs px-3 py-1.5 rounded-full z-50">Predicate added to filter</div>}
      {encodeStatus === 'error' && <div className="fixed bottom-4 right-4 bg-red-800 text-red-200 text-xs px-3 py-1.5 rounded-full z-50">Failed to encode field</div>}
    </div>
  )
}
