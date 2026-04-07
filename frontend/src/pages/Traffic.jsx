import { useState, useEffect, useCallback, useRef, useMemo, memo } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, subscribePacketStream } from '../api'
import { getTrafficNavKeys } from '../trafficNavKeys'

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
    if (navigator.clipboard?.write && typeof ClipboardItem !== 'undefined') {
      const blob = new Blob([bytes], { type: 'application/octet-stream' })
      await navigator.clipboard.write([new ClipboardItem({ 'application/octet-stream': blob })])
      return true
    }
  } catch {
    // ignore; fallback below
  }

  try {
    await navigator.clipboard.writeText(bytesToHex(bytes))
    return true
  } catch {
    return false
  }
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

function hasDropAction(pkt) {
  if (!pkt?.matched_rules?.length) return false
  return pkt.matched_rules.some((r) => r.action === 'drop' || r.action === 'both')
}

function hasAlertAction(pkt) {
  if (!pkt?.matched_rules?.length) return false
  return pkt.matched_rules.some((r) => r.action === 'alert' || r.action === 'both')
}

// Try to pretty-print JSON, return original string if not valid JSON
function tryFormatJSON(str) {
  if (!str) return { text: str, isJSON: false }
  const trimmed = str.trim()
  if ((trimmed[0] === '{' && trimmed[trimmed.length - 1] === '}') ||
      (trimmed[0] === '[' && trimmed[trimmed.length - 1] === ']')) {
    try {
      return { text: JSON.stringify(JSON.parse(trimmed), null, 2), isJSON: true }
    } catch {}
  }
  return { text: str, isJSON: false }
}

// ---- Quick Rule Panel ----

function QuickRulePanel({ packet, services, onCreated, onCancel }) {
  const [pattern, setPattern] = useState('')
  const [type, setType] = useState('string')
  const [scope, setScope] = useState('body')
  const [action, setAction] = useState('drop')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [selectedServices, setSelectedServices] = useState([packet.service_id])
  const allSelected = selectedServices.length === services.length

  // Smart pre-fill based on packet content
  useEffect(() => {
    if (packet.url && packet.direction === 'request') {
      setPattern(packet.url)
      setScope('url')
    } else if (packet.body_string) {
      setPattern(packet.body_string.length > 300 ? packet.body_string.slice(0, 300) : packet.body_string)
      setScope('body')
    }
  }, [packet])

  function toggleService(id) {
    setSelectedServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    )
  }

  function toggleAll() {
    setSelectedServices(allSelected ? [packet.service_id] : services.map(s => s.id))
  }

  async function handleCreate() {
    const p = pattern.trim()
    if (!p || selectedServices.length === 0) return
    setCreating(true)
    setError('')
    try {
      const label = p.length > 40 ? p.slice(0, 40) + '...' : p
      const promises = selectedServices.map(svcId =>
        api.createRule({
          service_id: svcId,
          name: `Quick: ${scope} ${type === 'regex' ? '~' : '='} ${label}`,
          type,
          scope,
          pattern: p,
          priority: 10,
          enabled: true,
          action,
        })
      )
      await Promise.all(promises)
      setSuccess(true)
      setTimeout(() => onCreated?.(), 800)
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }

  if (success) {
    return (
      <div className="bg-green-900/30 border border-green-700/50 rounded p-2 text-xs text-green-400 flex items-center gap-2">
        <span>&#10003;</span> Rule created for {selectedServices.length} service{selectedServices.length !== 1 ? 's' : ''} — traffic matching this pattern will be {action === 'alert' ? 'alerted' : 'dropped'}
      </div>
    )
  }

  return (
    <div className="bg-red-950/30 border border-red-800/50 rounded p-2 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <select value={action} onChange={e => setAction(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100 focus:outline-none focus:border-red-500">
          <option value="drop">Drop</option>
          <option value="alert">Alert</option>
          <option value="both">Both</option>
        </select>
        <select value={type} onChange={e => setType(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100 focus:outline-none focus:border-red-500">
          <option value="string">String</option>
          <option value="regex">Regex</option>
          <option value="bytes">Bytes</option>
        </select>
        {['url', 'body', 'header', 'raw'].map(s => {
          const active = scope.split(',').includes(s)
          return (
            <button key={s} type="button" onClick={() => {
              const cur = scope.split(',').filter(Boolean)
              const next = active ? cur.filter(x => x !== s) : [...cur, s]
              if (next.length > 0) setScope(next.join(','))
            }}
              className={`text-xs px-2 py-1 rounded cursor-pointer transition-colors border ${active ? 'bg-cyan-900/50 text-cyan-400 border-cyan-600/50' : 'bg-gray-800 text-gray-500 border-gray-700 hover:text-gray-300'}`}>
              {s}
            </button>
          )
        })}
      </div>
      {/* Multi-service selector */}
      <div className="flex items-center gap-2 flex-wrap text-[10px]">
        <button onClick={toggleAll}
          className={`px-1.5 py-0.5 rounded cursor-pointer transition-colors ${allSelected ? 'bg-cyan-800/60 text-cyan-300' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}>
          All
        </button>
        {services.map(s => (
          <button key={s.id} onClick={() => toggleService(s.id)}
            className={`px-1.5 py-0.5 rounded cursor-pointer transition-colors ${selectedServices.includes(s.id) ? 'bg-cyan-900/50 text-cyan-400' : 'bg-gray-800 text-gray-600 hover:text-gray-400'}`}>
            {s.name}
          </button>
        ))}
      </div>
      <textarea
        value={pattern}
        onChange={e => setPattern(e.target.value)}
        rows={3}
        className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-red-500 resize-y"
        placeholder="Pattern to match..."
        spellCheck={false}
      />
      <div className="flex items-center gap-2 flex-wrap">
        {/* Pre-fill shortcuts */}
        {packet.url && (
          <button onClick={() => { setPattern(packet.url); setScope('url'); setType('string') }}
            className="text-[10px] text-gray-500 hover:text-gray-300 cursor-pointer underline underline-offset-2">Fill URL</button>
        )}
        {packet.body_string && (
          <button onClick={() => { setPattern(packet.body_string.length > 300 ? packet.body_string.slice(0, 300) : packet.body_string); setScope('body'); setType('string') }}
            className="text-[10px] text-gray-500 hover:text-gray-300 cursor-pointer underline underline-offset-2">Fill Body</button>
        )}
      </div>
      {error && <div className="text-xs text-red-400">{error}</div>}
      <div className="flex items-center gap-2">
        <button onClick={handleCreate} disabled={creating || !pattern.trim()}
          className="bg-red-700 hover:bg-red-600 disabled:bg-gray-700 disabled:text-gray-500 text-white text-xs px-3 py-1.5 rounded transition-colors cursor-pointer disabled:cursor-default flex items-center gap-1">
          {creating ? 'Creating...' : <><span>&#9889;</span> Create Rule</>}
        </button>
        <button onClick={onCancel}
          className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs px-3 py-1.5 rounded transition-colors cursor-pointer">
          Cancel
        </button>
      </div>
    </div>
  )
}

// ---- Main Traffic component ----

export default function Traffic() {
  const navigate = useNavigate()
  const location = useLocation()
  const [services, setServices] = useState([])
  const [packets, setPackets] = useState([])
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(false)
  const [flowMode, setFlowMode] = useState(null) // { packetId, packets, total }
  /** Packet id used when entering flow (API or session fallback); restored on Clear flow */
  const flowEntryPacketIdRef = useRef(null)
  /** When opening flow from Alerts/Blocks, Clear flow navigates back and restores selection */
  const flowReturnContextRef = useRef(null)
  const packetTableScrollRef = useRef(null)
  const [filtersCollapsed, setFiltersCollapsed] = useState(false)
  const [copyStatus, setCopyStatus] = useState(null) // null | 'copying' | 'copied' | 'error'
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
  const [filters, setFilters] = useState({
    service_id: '', src_ip: '', dst_ip: '', protocol: '', method: '', direction: '',
    session_id: '', peer_ip: '', contains: '', regex: '', sort: 'desc',
    limit: 50, offset: 0,
  })

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
    api.listServices().then((data) => setServices(data || []))
    api.getConfig().then((cfg) => {
      if (cfg?.flag_regex) setFlagRegex(cfg.flag_regex)
      setFlagIDEnabled(!!cfg?.flagid_enabled)
      setTrafficMode(cfg?.traffic_mode || 'live')
    }).catch(() => {})
    api.getCaptureStatus().then(setCaptureStatus).catch(() => {})
  }, [])

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


  const loadPackets = useCallback(async () => {
    setLoading(true)
    try {
      const params = { ...filters }
      if (flagFilter) {
        params.flagged = 'true'
      }
      if (flagIDFilter) {
        params.contains_flagid = 'true'
      }
      if (blockedFilter) {
        params.dropped = 'true'
      }
      const data = await api.getPackets(params)
      setPackets(data.packets || [])
      setTotal(data.total)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [filters, flagFilter, flagIDFilter, blockedFilter])

  // Silent full refresh — for metadata changes (backfill) and periodic sync
  const refreshPackets = useCallback(async () => {
    if (pausedRef.current) return
    try {
      const params = { ...filters }
      if (flagFilter) params.flagged = 'true'
      if (flagIDFilter) params.contains_flagid = 'true'
      if (blockedFilter) params.dropped = 'true'
      const data = await api.getPackets(params)
      if (pausedRef.current) return
      setPackets(data.packets || [])
      setTotal(data.total)
    } catch {}
  }, [filters, flagFilter, flagIDFilter, blockedFilter])

  // Check if any text/complex filters are active (can't client-side filter these)
  const hasTextFilters = filters.contains || filters.regex || filters.src_ip || filters.dst_ip || filters.peer_ip

  // Handle streamed new packets: prepend to list without API round-trip
  const filtersRef = useRef(filters)
  const flagFilterRef = useRef(flagFilter)
  const flagIDFilterRef = useRef(flagIDFilter)
  useEffect(() => { filtersRef.current = filters }, [filters])
  useEffect(() => { flagFilterRef.current = flagFilter }, [flagFilter])
  useEffect(() => { flagIDFilterRef.current = flagIDFilter }, [flagIDFilter])
  const blockedFilterRef = useRef(blockedFilter)
  useEffect(() => { blockedFilterRef.current = blockedFilter }, [blockedFilter])

  const onNewPackets = useCallback((newPkts) => {
    if (pausedRef.current || newPkts.length === 0) return
    const f = filtersRef.current
    // Skip if user is not on page 1 (offset > 0) — new packets only go to the top/bottom
    if (f.offset > 0) return
    // Client-side filter for simple filters
    const filtered = newPkts.filter((p) => {
      if (f.service_id && p.service_id !== f.service_id) return false
      if (f.protocol && p.protocol !== f.protocol) return false
      if (f.method && p.method !== f.method) return false
      if (f.direction && p.direction !== f.direction) return false
      if (f.session_id && p.session_id !== f.session_id) return false
      if (flagFilterRef.current && !p.flagged) return false
      if (flagIDFilterRef.current && !p.contains_flagid) return false
      if (blockedFilterRef.current && !hasDropAction(p)) return false
      return true
    })
    if (filtered.length === 0) return

    const limit = f.limit || 50
    const isAsc = f.sort === 'asc'
    setPackets((prev) => {
      // Merge, deduplicate by id, sort by id
      const map = new Map()
      for (const p of prev) map.set(p.id, p)
      for (const p of filtered) map.set(p.id, p)
      const merged = Array.from(map.values())
      merged.sort((a, b) => isAsc ? a.id - b.id : b.id - a.id)
      return merged.slice(0, limit)
    })
    setTotal((prev) => prev + filtered.length)
  }, [])

  // Debounce filter changes: wait 300ms after last change before fetching
  useEffect(() => {
    const timer = setTimeout(() => { loadPackets() }, 300)
    return () => clearTimeout(timer)
  }, [loadPackets])

  // SSE: stream new packets + refresh on metadata changes.
  // When text filters are active, fall back to periodic full refresh.
  useEffect(() => {
    const streamEnabled = trafficMode === 'live' || (trafficMode === 'static' && !!captureStatus?.capturing)
    if (!streamEnabled) return
    if (paused) return
    const unsub = subscribePacketStream(
      hasTextFilters ? () => {} : onNewPackets,
      refreshPackets,
    )
    // When text filters are active, poll periodically since we can't client-side filter
    let poll
    if (hasTextFilters) {
      poll = setInterval(refreshPackets, 2000)
    }
    return () => {
      unsub()
      if (poll) clearInterval(poll)
    }
  }, [onNewPackets, refreshPackets, paused, hasTextFilters, trafficMode, captureStatus?.capturing])


  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value, offset: 0 }))
  }

  function nextPage() {
    setFilters((f) => ({ ...f, offset: f.offset + f.limit }))
  }
  function prevPage() {
    setFilters((f) => ({ ...f, offset: Math.max(0, f.offset - f.limit) }))
  }

  // Flow: reconstruct multi-connection flow via auth token correlation
  const showFlow = useCallback(async (pkt, opts = {}) => {
    if (pkt?.id == null) return
    if (!opts.preserveFlowReturn) flowReturnContextRef.current = null
    flowEntryPacketIdRef.current = pkt.id
    setLoading(true)
    try {
      const data = await api.getPacketFlow(pkt.id)
      setFlowMode({
        packetId: pkt.id,
        packets: data.packets || [],
        total: data.total || 0,
      })
    } catch (err) {
      console.error('Flow query failed, falling back to session_id:', err)
      setFilters((f) => ({
        ...f,
        session_id: pkt.session_id,
        sort: 'asc',
        offset: 0,
      }))
    } finally {
      setLoading(false)
    }
  }, [])

  function toggleFlagFilter() {
    setFlagFilter((v) => !v)
    setFilters((f) => ({ ...f, offset: 0 }))
  }

  async function copyExploit(packetId) {
    setCopyStatus('copying')
    try {
      const data = await api.generateExploit(packetId)
      await navigator.clipboard.writeText(data.code)
      setCopyStatus('copied')
      setTimeout(() => setCopyStatus(null), 2000)
    } catch (err) {
      console.error('Failed to generate exploit:', err)
      setCopyStatus('error')
      setTimeout(() => setCopyStatus(null), 3000)
    }
  }

  function toggleFlagIDFilter() {
    setFlagIDFilter((prev) => !prev)
    setFilters((f) => ({ ...f, offset: 0 }))
  }

  function toggleBlockedFilter() {
    setBlockedFilter((prev) => !prev)
    setFilters((f) => ({ ...f, offset: 0 }))
  }

  function togglePause() {
    if (trafficMode !== 'live') return
    setPaused((prev) => {
      const next = !prev
      pausedRef.current = next
      if (!next) {
        // Resuming — trigger a fresh fetch to catch up
        loadPackets()
      }
      return next
    })
  }

  async function handleStartCapture() {
    setCaptureBusy(true)
    try {
      const status = await api.startCapture()
      setCaptureStatus(status)
      await loadPackets()
    } finally {
      setCaptureBusy(false)
    }
  }

  async function handleStopCapture() {
    setCaptureBusy(true)
    try {
      const status = await api.stopCapture()
      setCaptureStatus(status)
      await loadPackets()
    } finally {
      setCaptureBusy(false)
    }
  }

  async function handleApplyFlagIDs() {
    setApplyBusy(true)
    try {
      await api.applyCaptureFlagIDs()
      await loadPackets()
    } finally {
      setApplyBusy(false)
    }
  }

  async function handleClearPackets() {
    if (!confirm('Delete all packets now? Alerts linked to packets will also be removed.')) return
    setClearBusy(true)
    try {
      await api.purgePackets()
      setSelected(null)
      setFlowMode(null)
      flowEntryPacketIdRef.current = null
      flowReturnContextRef.current = null
      setFilters((f) => ({ ...f, session_id: '', offset: 0 }))
      await loadPackets()
    } finally {
      setClearBusy(false)
    }
  }

  // Select a packet — fetch full detail if body is missing (SSE-pushed lightweight packets)
  const selectPacket = useCallback(async (pkt) => {
    if (!pkt) return
    if (pkt.body_string !== undefined) {
      setSelected(pkt)
      return
    }
    setSelected(pkt)
    try {
      const full = await api.getPacket(pkt.id)
      setSelected(full)
    } catch {}
  }, [])

  const clearFlow = useCallback(() => {
    const anchorId = flowEntryPacketIdRef.current
    const ret = flowReturnContextRef.current
    flowEntryPacketIdRef.current = null
    flowReturnContextRef.current = null
    setFlowMode(null)
    setFilters((f) => ({ ...f, session_id: '', sort: 'desc', offset: 0 }))
    if (ret?.path === '/alerts' && ret.alertId != null) {
      navigate('/alerts', { state: { restoreAlertId: ret.alertId } })
      return
    }
    if (ret?.path === '/blocks' && ret.packetId != null) {
      navigate('/blocks', { state: { restoreBlockedPacketId: ret.packetId } })
      return
    }
    if (anchorId != null) selectPacket({ id: anchorId })
  }, [selectPacket, navigate])

  // Open flow when navigated from Alerts / Blocks with state
  useEffect(() => {
    const pid = location.state?.openFlowForPacketId
    if (pid == null) return
    const fr = location.state?.flowReturn
    if (fr && (fr.path === '/alerts' || fr.path === '/blocks')) {
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
      const { up, down } = getTrafficNavKeys()
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
  }, [flowMode, packets, selected, selectPacket])

  useEffect(() => {
    if (!selected?.id || !packetTableScrollRef.current) return
    const row = packetTableScrollRef.current.querySelector(`tr[data-packet-id="${selected.id}"]`)
    row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [selected?.id])

  // Close quick rule panel when selecting a different packet
  useEffect(() => { setShowQuickRule(false) }, [selected?.id])

  const isFlowActive = !!flowMode || !!filters.session_id
  const hasActiveFilter = filters.contains || filters.regex || flagFilter || flagIDFilter || blockedFilter || filters.direction

  // Compute effective highlight regex: always include flag regex for yellow highlighting
  const highlightRegex = [filters.regex, flagRegex].filter(Boolean).join('|') || ''

  // Highlight regex for search terms only (used in table rows — no flag regex to avoid noise)
  const searchHighlightRegex = filters.regex || ''

  // Use flow mode packets when active, otherwise normal packets
  const displayPackets = flowMode ? flowMode.packets : packets
  const displayTotal = flowMode ? flowMode.total : total

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

  const matchedRuleForHighlight = useMemo(() => {
    if (!selected?.matched_rules?.length) return null
    return selected.matched_rules.find((r) => r.pattern) || null
  }, [selected?.matched_rules])

  const selectedRuleScope = matchedRuleForHighlight?.scope || ''
  const selectedRulePattern = matchedRuleForHighlight?.pattern || ''
  const highlightRuleInURL = !selectedRuleScope || selectedRuleScope.includes('url') || selectedRuleScope.includes('raw')
  const highlightRuleInHeaders = !selectedRuleScope || selectedRuleScope.includes('header') || selectedRuleScope.includes('raw')
  const highlightRuleInBody = !selectedRuleScope || selectedRuleScope.includes('body') || selectedRuleScope.includes('raw')
  const urlRegex = [highlightRegex, highlightRuleInURL ? selectedRulePattern : ''].filter(Boolean).join('|')
  const headersRegex = [highlightRegex, highlightRuleInHeaders ? selectedRulePattern : ''].filter(Boolean).join('|')
  const bodyRegex = [highlightRegex, highlightRuleInBody ? selectedRulePattern : ''].filter(Boolean).join('|')

  // Resolve service_id to service name
  const serviceName = (id) => {
    const svc = services.find((s) => s.id === id)
    return svc ? svc.name : id
  }

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
                Session: <span className="font-mono font-medium text-purple-200">{filters.session_id}</span>
                <span className="text-purple-500 ml-2">({total} packets, chronological order)</span>
              </>
            )}
          </span>
          <button
            onClick={() => copyExploit(flowMode ? flowMode.packetId : selected?.id)}
            disabled={copyStatus === 'copying'}
            className="ml-auto text-xs bg-cyan-800/50 hover:bg-cyan-700/50 text-cyan-300 px-2 py-1 rounded cursor-pointer flex items-center gap-1 disabled:opacity-50"
          >
            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
            </svg>
            {copyStatus === 'copying' ? 'Generating...' : 'Copy Exploit'}
          </button>
          <button onClick={clearFlow} className="text-xs bg-purple-800/50 hover:bg-purple-700/50 text-purple-300 px-2 py-1 rounded cursor-pointer">
            Clear flow
          </button>
        </div>
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
            className="text-xs px-3 py-1.5 rounded bg-red-800/60 hover:bg-red-700/60 disabled:bg-gray-800 disabled:text-gray-600 text-red-200 cursor-pointer"
          >
            {clearBusy ? 'Clearing...' : 'Clear Packets'}
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
          Filters {hasActiveFilter && <span className="bg-cyan-900/50 text-cyan-400 px-1.5 rounded text-[10px]">active</span>}
        </button>
        {!filtersCollapsed && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-3">
            <div className="grid grid-cols-5 gap-3">
              <FilterSelect label="Service" value={filters.service_id} onChange={(v) => setFilter('service_id', v)}
                options={[{ value: '', label: 'All' }, ...services.map((s) => ({ value: s.id, label: s.name }))]}
              />
              <FilterInput label="Peer IP" value={filters.peer_ip} onChange={(v) => setFilter('peer_ip', v)} placeholder="Attacker IP..." />
              <FilterInput label="Source IP" value={filters.src_ip} onChange={(v) => setFilter('src_ip', v)} placeholder="e.g. 10.10.0.5" />
              <FilterInput label="Dest IP" value={filters.dst_ip} onChange={(v) => setFilter('dst_ip', v)} placeholder="e.g. 10.10.0.1" />
              <FilterSelect label="Protocol" value={filters.protocol} onChange={(v) => setFilter('protocol', v)}
                options={[{ value: '', label: 'All' }, ...['http','https','h2','grpc','tcp'].map((p) => ({ value: p, label: p.toUpperCase() }))]}
              />
              <FilterSelect label="Method" value={filters.method} onChange={(v) => setFilter('method', v)}
                options={[{ value: '', label: 'All' }, ...['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map((m) => ({ value: m, label: m }))]}
              />
              <FilterSelect label="Dir" value={filters.direction} onChange={(v) => setFilter('direction', v)}
                options={[
                  { value: '', label: 'All' },
                  { value: 'request', label: 'REQ' },
                  { value: 'response', label: 'RES' },
                ]}
              />
              <FilterInput label="Contains" value={filters.contains} onChange={(v) => setFilter('contains', v)} placeholder="Text search..." />
              <FilterInput label="Regex" value={filters.regex} onChange={(v) => setFilter('regex', v)} placeholder="Regex pattern..." />
              <FilterSelect label="Sort" value={filters.sort} onChange={(v) => setFilter('sort', v)}
                options={[{ value: 'desc', label: 'Newest first' }, { value: 'asc', label: 'Oldest first' }]}
              />
            </div>
            <div className="mt-2 flex items-center gap-2">
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
                {displayPackets.map((pkt) => {
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
                    onClick={() => selectPacket(pkt)}
                    className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                      selected?.id === pkt.id ? 'bg-gray-800' : 'hover:bg-gray-900/80'
                    } ${rowBg}`}
                  >
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
                          className="text-gray-600 hover:text-purple-400 text-xs cursor-pointer ml-auto"
                          title={`Show flow for ${getPeerIP(pkt)}`}
                        >
                          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>
                          </svg>
                        </button>
                      </div>
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{pkt.method}</td>
                    <td className="px-3 py-1.5 text-gray-400 text-xs truncate max-w-xs">
                      <HighlightedText text={cellText} contains={filters.contains} regex={searchHighlightRegex} />
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{getPeerIP(pkt)}</td>
                  </tr>
                  );
                })}
                {displayPackets.length === 0 && (
                  <tr><td colSpan="8" className="text-center py-8 text-gray-600">No packets found</td></tr>
                )}
              </tbody>
            </table>
          </div>

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
            </div>
            {!flowMode && (
              <div className="flex gap-2">
                <button onClick={prevPage} disabled={filters.offset === 0} className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-30 cursor-pointer disabled:cursor-default">&laquo; Prev</button>
                <span className="px-2 py-1">{Math.floor(filters.offset / filters.limit) + 1} / {Math.max(1, Math.ceil(displayTotal / filters.limit))}</span>
                <button onClick={nextPage} disabled={filters.offset + filters.limit >= displayTotal} className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-30 cursor-pointer disabled:cursor-default">Next &raquo;</button>
              </div>
            )}
          </div>
        </div>

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
                  <button
                    onClick={() => copyExploit(selected.id)}
                    disabled={copyStatus === 'copying'}
                    className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer flex items-center gap-1 disabled:opacity-50"
                    title="Generate exploit skeleton from this flow"
                  >
                    <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
                    </svg>
                    {copyStatus === 'copying' ? '...' : 'Exploit'}
                  </button>
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
                      <HighlightedText text={selected.url} contains={filters.contains} regex={urlRegex} flagidRegex={flagidHighlightRegex} />
                    </span>
                  </div>
                )}

                {selected.matched_rules?.length > 0 && (
                  <div className="bg-red-900/20 border border-red-800/50 rounded px-2 py-1">
                    <span className="text-red-400 text-xs font-medium">Matched: </span>
                    {selected.matched_rules.map((r, i) => (
                      <span key={r.id} className="text-red-300 text-xs">
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
                          <HighlightedText text={v} contains={filters.contains} regex={headersRegex} flagidRegex={flagidHighlightRegex} />
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
                        onClick={() => navigator.clipboard.writeText(selected.body_string)}
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
                    </div>
                    <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '60vh' }}>
                      {selected.body_string ? (
                        <HighlightedText text={formattedBody.text} contains={filters.contains} regex={bodyRegex} flagidRegex={flagidHighlightRegex} />
                      ) : (
                        <span className="text-gray-500">
                          (non-UTF8 body) — use “Copy bytes”
                        </span>
                      )}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {loading && <div className="fixed bottom-4 right-4 bg-gray-800 text-cyan-400 text-xs px-3 py-1.5 rounded-full">Loading...</div>}
      {copyStatus === 'copied' && <div className="fixed bottom-4 right-4 bg-green-800 text-green-200 text-xs px-3 py-1.5 rounded-full z-50">Exploit copied to clipboard!</div>}
      {copyStatus === 'error' && <div className="fixed bottom-4 right-4 bg-red-800 text-red-200 text-xs px-3 py-1.5 rounded-full z-50">Failed to generate exploit</div>}
    </div>
  )
}

function FilterInput({ label, value, onChange, placeholder }) {
  return (
    <div>
      <label className="block text-xs text-gray-500 mb-1">{label}</label>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
      />
    </div>
  )
}

function FilterSelect({ label, value, onChange, options }) {
  return (
    <div>
      <label className="block text-xs text-gray-500 mb-1">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
      >
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  )
}