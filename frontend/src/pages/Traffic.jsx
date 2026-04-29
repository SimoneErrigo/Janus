import { useState, useEffect, useCallback, useRef, useMemo, memo } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, subscribePacketStream } from '../api'
import { getTrafficNavKeys } from '../trafficNavKeys'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { getDisplayName } from '../api'
import { hideParams, addHiddenIds, setClearCursor, getHiddenIds, getClearCursor, resetClearCursor, clearHiddenIds } from '../userHidden'
import QuickRulePanel from '../components/QuickRulePanel'
import { tryFormatJSON } from '../utils/formatting'
import { useServiceMap } from '../hooks/useServiceMap'

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

// Clipboard helper that falls back to a hidden textarea + execCommand when
// navigator.clipboard is unavailable (insecure context, e.g. HTTP on a LAN IP).
async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // fall through to legacy path
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '-9999px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    ta.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
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
  const [activeSessions, setActiveSessions] = useState([])
  const [selected, setSelected] = useState(null)
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
  const [pinDialog, setPinDialog] = useState(null) // null | { anchorId, name, notes, saving, error }
  const [pinToast, setPinToast] = useState(null)
  const [pcapDialog, setPcapDialog] = useState(false)
  const [pcapResult, setPcapResult] = useState(null) // { filename } after export
  const [pcapExporting, setPcapExporting] = useState(false)
  const [filters, setFilters] = useState({
    service_id: '', src_ip: '', dst_ip: '', protocol: '', method: '', direction: '',
    session_id: '', peer_ip: '', url: '',
    contains_body: '', contains_headers: '',
    regex: '', sort: 'desc',
    limit: 50,
  })
  const [filterNegated, setFilterNegated] = useState({
    service_id: false, src_ip: false, dst_ip: false, protocol: false, method: false,
    direction: false, peer_ip: false, url: false,
    contains_body: false, contains_headers: false,
    regex: false,
  })

  function toggleNegate(key) {
    setFilterNegated((prev) => ({ ...prev, [key]: !prev[key] }))
  }

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


  // Build API params, applying negation: if a filter is negated, send not_<field> instead of <field>
  const buildParams = useCallback((base) => {
    const params = { ...base }
    const negKeys = ['service_id', 'src_ip', 'dst_ip', 'protocol', 'method', 'direction', 'peer_ip', 'url', 'contains_body', 'contains_headers', 'regex']
    for (const key of negKeys) {
      if (filterNegated[key] && params[key]) {
        params[`not_${key}`] = params[key]
        delete params[key]
      }
    }
    return params
  }, [filterNegated])

  // Force refetch when user hides/unhides packets. Bumping this key re-runs the
  // hook's effect via fetchPage's dep list.
  const [hideVersion, setHideVersion] = useState(0)

  // fetchPage: called by the hook for each page load
  const fetchPage = useCallback(async (offset, limit) => {
    const params = buildParams({ ...filters, ...hideParams() })
    params.limit = limit
    params.offset = offset
    if (flagFilter) params.flagged = 'true'
    if (flagIDFilter) params.contains_flagid = 'true'
    if (blockedFilter) params.dropped = 'true'
    params.summary = '1'
    const data = await api.getPackets(params)
    return { items: data.packets || [], total: data.total }
  }, [filters, flagFilter, flagIDFilter, blockedFilter, buildParams, hideVersion])

  const {
    items: packets,
    total,
    loading,
    hasMore,
    sentinelRef: packetSentinelRef,
    prepend: prependPackets,
    refresh: refreshPackets,
    reset: resetPackets,
  } = useInfiniteList({ fetchPage, pageSize: filters.limit || 50 })

  // Check if any text/complex filters are active (can't client-side filter these).
  // Any active negation also forces server-side fetching.
  const hasNegation = Object.entries(filterNegated).some(([key, isNeg]) => isNeg && filters[key])
  const hasTextFilters = filters.contains_body || filters.contains_headers || filters.regex || filters.src_ip || filters.dst_ip || filters.peer_ip || filters.url || hasNegation

  // Refs for SSE client-side filtering (stale-closure-safe)
  const filtersRef = useRef(filters)
  const flagFilterRef = useRef(flagFilter)
  const flagIDFilterRef = useRef(flagIDFilter)
  const blockedFilterRef = useRef(blockedFilter)
  useEffect(() => { filtersRef.current = filters }, [filters])
  useEffect(() => { flagFilterRef.current = flagFilter }, [flagFilter])
  useEffect(() => { flagIDFilterRef.current = flagIDFilter }, [flagIDFilter])
  useEffect(() => { blockedFilterRef.current = blockedFilter }, [blockedFilter])

  // SSE new-packet handler: client-side filter then prepend
  const handleNewPackets = useCallback((newPkts) => {
    if (pausedRef.current || newPkts.length === 0) return
    const f = filtersRef.current
    const hiddenSet = new Set(getHiddenIds())
    const cursor = getClearCursor()
    const filtered = newPkts.filter((p) => {
      if (hiddenSet.has(Number(p.id))) return false
      if (cursor && p.timestamp && p.timestamp < cursor) return false
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
    if (filtered.length > 0) prependPackets(filtered, f.sort !== 'asc')
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


  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value }))
  }

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
      setFilters((f) => ({
        ...f,
        session_id: pkt.session_id,
        sort: 'asc',
      }))
    } finally {
      setFlowLoading(false)
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
      const ok = await copyText(data.code)
      if (!ok) throw new Error('clipboard copy failed')
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
      setFilters((f) => ({ ...f, session_id: '' }))
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
  const selectPacket = useCallback(async (pkt) => {
    if (!pkt) return
    const needsRefetch = pkt.lite || pkt.body_string === undefined
    setSelected(pkt)
    if (!needsRefetch) return
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
    setFilters((f) => ({ ...f, session_id: '', sort: 'desc' }))
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
      // x — toggle current packet in bulk selection
      if (e.key === 'x' && selected) {
        e.preventDefault()
        toggleSingleSelect(selected.id)
        return
      }
      // Delete / Backspace — bulk-delete selection
      if ((e.key === 'Delete' || e.key === 'Backspace') && selectedPkts.size > 0) {
        e.preventDefault()
        bulkDelete()
        return
      }
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
  }, [flowMode, packets, selected, selectPacket, selectedPkts, toggleSingleSelect, bulkDelete, resetPackets])

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

  const isFlowActive = !!flowMode || !!filters.session_id
  const hasActiveFilter = filters.contains_body || filters.contains_headers || filters.regex || flagFilter || flagIDFilter || blockedFilter || filters.direction

  // Compute effective highlight regex: always include flag regex for yellow highlighting
  const highlightRegex = [filters.regex, flagRegex].filter(Boolean).join('|') || ''

  // Highlight regex for search terms only (used in table rows — no flag regex to avoid noise)
  const searchHighlightRegex = filters.regex || ''

  // Use flow mode packets when active, otherwise normal packets
  const displayPackets = flowMode ? flowMode.packets : packets
  const displayTotal = flowMode ? flowMode.total : total

  // ---- Row virtualization ----
  // Render only the rows in (and just outside) the viewport. Saves React from
  // reconciling thousands of <tr>s on every prepend/scroll.
  const ROW_H = 32
  const OVERSCAN = 10
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
            <span className="text-sm text-purple-300 font-medium">Save flow</span>
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
                if (!pinDialog.anchorId) return
                setPinDialog((d) => ({ ...d, saving: true, error: '' }))
                try {
                  await api.createSavedFlow({
                    anchor_packet_id: pinDialog.anchorId,
                    name: pinDialog.name.trim() || `Flow #${pinDialog.anchorId}`,
                    notes: pinDialog.notes.trim(),
                  })
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
          Filters {hasActiveFilter && <span className="bg-cyan-900/50 text-cyan-400 px-1.5 rounded text-[10px]">active</span>}
        </button>
        {!filtersCollapsed && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-3">
            <div className="grid grid-cols-5 gap-3">
              <FilterSelect label="Service" value={filters.service_id} onChange={(v) => setFilter('service_id', v)}
                options={[{ value: '', label: 'All' }, ...services.map((s) => ({ value: s.id, label: s.name }))]}
                negated={filterNegated.service_id} onToggleNegate={() => toggleNegate('service_id')}
              />
              <FilterInput label="Peer IP" value={filters.peer_ip} onChange={(v) => setFilter('peer_ip', v)} placeholder="Attacker IP..."
                negated={filterNegated.peer_ip} onToggleNegate={() => toggleNegate('peer_ip')}
              />
              <FilterInput label="Source IP" value={filters.src_ip} onChange={(v) => setFilter('src_ip', v)} placeholder="e.g. 10.10.0.5"
                negated={filterNegated.src_ip} onToggleNegate={() => toggleNegate('src_ip')}
              />
              <FilterInput label="Dest IP" value={filters.dst_ip} onChange={(v) => setFilter('dst_ip', v)} placeholder="e.g. 10.10.0.1"
                negated={filterNegated.dst_ip} onToggleNegate={() => toggleNegate('dst_ip')}
              />
              <FilterSelect label="Protocol" value={filters.protocol} onChange={(v) => setFilter('protocol', v)}
                options={[{ value: '', label: 'All' }, ...['http','https','h2','grpc','tcp'].map((p) => ({ value: p, label: p.toUpperCase() }))]}
                negated={filterNegated.protocol} onToggleNegate={() => toggleNegate('protocol')}
              />
              <FilterSelect label="Method" value={filters.method} onChange={(v) => setFilter('method', v)}
                options={[{ value: '', label: 'All' }, ...['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map((m) => ({ value: m, label: m }))]}
                negated={filterNegated.method} onToggleNegate={() => toggleNegate('method')}
              />
              <FilterSelect label="Dir" value={filters.direction} onChange={(v) => setFilter('direction', v)}
                options={[
                  { value: '', label: 'All' },
                  { value: 'request', label: 'REQ' },
                  { value: 'response', label: 'RES' },
                ]}
                negated={filterNegated.direction} onToggleNegate={() => toggleNegate('direction')}
              />
              <FilterInput label="URL" value={filters.url} onChange={(v) => setFilter('url', v)} placeholder="URL path..."
                negated={filterNegated.url} onToggleNegate={() => toggleNegate('url')}
              />
              <FilterInput label="Body contains" value={filters.contains_body} onChange={(v) => setFilter('contains_body', v)} placeholder="Body text..."
                negated={filterNegated.contains_body} onToggleNegate={() => toggleNegate('contains_body')}
              />
              <FilterInput label="Header contains" value={filters.contains_headers} onChange={(v) => setFilter('contains_headers', v)} placeholder="Name: Value"
                negated={filterNegated.contains_headers} onToggleNegate={() => toggleNegate('contains_headers')}
              />
              <FilterInput label="Regex" value={filters.regex} onChange={(v) => setFilter('regex', v)} placeholder="Regex pattern..."
                negated={filterNegated.regex} onToggleNegate={() => toggleNegate('regex')}
              />
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
                  <th className="pl-2 pr-1 py-2 w-7">
                    {selectedPkts.size > 0 && (
                      <button type="button" onClick={() => setSelectedPkts(new Set())} title="Clear selection"
                        className="text-gray-600 hover:text-gray-400 cursor-pointer text-xs leading-none">✕</button>
                    )}
                  </th>
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
                  <tr aria-hidden="true" style={{ height: topPad }}><td colSpan="9" /></tr>
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
                      <HighlightedText text={cellText} contains={filters.contains_body} regex={searchHighlightRegex} />
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{getPeerIP(pkt)}</td>
                  </tr>
                  );
                })}
                {bottomPad > 0 && (
                  <tr aria-hidden="true" style={{ height: bottomPad }}><td colSpan="9" /></tr>
                )}
                {displayPackets.length === 0 && (
                  <tr><td colSpan="9" className="text-center py-8 text-gray-600">No packets found</td></tr>
                )}
              </tbody>
              {/* Infinite scroll sentinel — only shown outside flow mode */}
              {!flowMode && (
                <tfoot>
                  <tr>
                    <td colSpan="9" className="py-3 text-center text-xs text-gray-700">
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
                    if (filters.service_id) params.service_id = filters.service_id
                    if (filters.session_id) params.session_id = filters.session_id
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
                      <HighlightedText text={selected.url} contains={filters.url} regex={urlRegex} flagidRegex={flagidHighlightRegex} />
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
                      {(() => {
                        const hc = filters.contains_headers || ''
                        const colonIdx = hc.indexOf(':')
                        const headerName = colonIdx > 0 ? hc.slice(0, colonIdx).trim().toLowerCase() : ''
                        const headerValue = colonIdx > 0 ? hc.slice(colonIdx + 1).trim() : hc
                        return Object.entries(selected.headers).map(([k, v]) => {
                          const highlight = headerName === '' || k.toLowerCase() === headerName ? headerValue : ''
                          return (
                            <div key={k}>
                              <span className="text-cyan-400">{k}:</span>{' '}
                              <HighlightedText text={v} contains={highlight} regex={headersRegex} flagidRegex={flagidHighlightRegex} />
                            </div>
                          )
                        })
                      })()}
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
                    </div>
                    <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '60vh' }}>
                      {selected.body_string ? (
                        <HighlightedText text={formattedBody.text} contains={filters.contains_body} regex={bodyRegex} flagidRegex={flagidHighlightRegex} />
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

      {(loading || flowLoading) && <div className="fixed bottom-4 right-4 bg-gray-800 text-cyan-400 text-xs px-3 py-1.5 rounded-full">{flowLoading ? 'Reconstructing flow…' : 'Loading...'}</div>}
      {copyStatus === 'copied' && <div className="fixed bottom-4 right-4 bg-green-800 text-green-200 text-xs px-3 py-1.5 rounded-full z-50">Exploit copied to clipboard!</div>}
      {copyStatus === 'error' && <div className="fixed bottom-4 right-4 bg-red-800 text-red-200 text-xs px-3 py-1.5 rounded-full z-50">Failed to generate exploit</div>}
    </div>
  )
}

function FilterInput({ label, value, onChange, placeholder, negated, onToggleNegate }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <label className="text-xs text-gray-500">{label}</label>
        {onToggleNegate && (
          <button
            type="button"
            onClick={onToggleNegate}
            title={negated ? 'Exclude mode active — click to switch to include' : 'Click to exclude instead of include'}
            className={`text-[10px] px-1 py-0.5 rounded leading-none cursor-pointer transition-colors ${
              negated ? 'bg-red-900/60 text-red-400 border border-red-700/60' : 'text-gray-600 hover:text-gray-400'
            }`}
          >≠</button>
        )}
      </div>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full bg-gray-800 rounded px-2.5 py-1.5 text-gray-100 text-sm focus:outline-none transition-colors border ${
          negated && value ? 'border-red-700/60 focus:border-red-500' : 'border-gray-700 focus:border-cyan-500'
        }`}
      />
    </div>
  )
}

function FilterSelect({ label, value, onChange, options, negated, onToggleNegate }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <label className="text-xs text-gray-500">{label}</label>
        {onToggleNegate && (
          <button
            type="button"
            onClick={onToggleNegate}
            title={negated ? 'Exclude mode active — click to switch to include' : 'Click to exclude instead of include'}
            className={`text-[10px] px-1 py-0.5 rounded leading-none cursor-pointer transition-colors ${
              negated ? 'bg-red-900/60 text-red-400 border border-red-700/60' : 'text-gray-600 hover:text-gray-400'
            }`}
          >≠</button>
        )}
      </div>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full bg-gray-800 rounded px-2.5 py-1.5 text-gray-100 text-sm focus:outline-none transition-colors border ${
          negated && value ? 'border-red-700/60 focus:border-red-500' : 'border-gray-700 focus:border-cyan-500'
        }`}
      >
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  )
}