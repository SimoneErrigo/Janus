import { useState, useEffect, useCallback, useMemo, memo, useRef } from 'react'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, subscribePacketStream } from '../api'
import { hideParams, addHiddenIds } from '../userHidden'

function toJSRegex(pattern) {
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

const HighlightedBody = memo(function HighlightedBody({ text, pattern }) {
  if (!text || !pattern) return <>{text}</>

  const result = useMemo(() => {
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
      const parts = []
      let pos = 0
      for (const r of ranges) {
        if (r.start > pos) parts.push(<span key={`t${pos}`}>{text.slice(pos, r.start)}</span>)
        parts.push(<mark key={`m${r.start}`} className="bg-red-500/40 text-red-200 rounded px-0.5">{r.text}</mark>)
        pos = r.end
      }
      if (pos < text.length) parts.push(<span key={`t${pos}`}>{text.slice(pos)}</span>)
      return parts
    } catch {
      return null
    }
  }, [text, pattern])

  return <>{result ?? text}</>
})

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

function BlockedPacketDetail({ packet, rule }) {
  const formattedBody = useMemo(() => tryFormatJSON(packet.body_string), [packet.body_string])
  const headers = useMemo(() => {
    if (!packet.headers) return []
    if (typeof packet.headers === 'string') {
      try { return Object.entries(JSON.parse(packet.headers)) } catch { return [] }
    }
    if (typeof packet.headers === 'object') return Object.entries(packet.headers)
    return []
  }, [packet.headers])

  // Scope-aware highlighting from matched rule
  const pattern = rule?.pattern || null
  const scope = rule?.scope || null
  const highlightUrl = !scope || scope.includes('url') || scope.includes('raw')
  const highlightHeaders = !scope || scope.includes('header') || scope.includes('raw')
  const highlightBody = !scope || scope.includes('body') || scope.includes('raw')

  return (
    <div>
      <div className="text-gray-500 text-xs mb-1">Packet #{packet.id}</div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs bg-gray-800/50 rounded p-2">
        <div><span className="text-gray-500">Direction </span><span className={packet.direction === 'request' ? 'text-blue-400' : 'text-green-400'}>{packet.direction}</span></div>
        <div><span className="text-gray-500">Protocol </span><span className="text-gray-300">{packet.protocol}</span></div>
        <div><span className="text-gray-500">Src </span><span className="text-gray-300 font-mono">{packet.src_ip}:{packet.src_port}</span></div>
        <div><span className="text-gray-500">Dst </span><span className="text-gray-300 font-mono">{packet.dst_ip}:{packet.dst_port}</span></div>
        {packet.method && <div><span className="text-gray-500">Method </span><span className="text-gray-300">{packet.method}</span></div>}
        {packet.status > 0 && <div><span className="text-gray-500">Status </span><span className="text-gray-300">{packet.status}</span></div>}
      </div>

      {packet.matched_rules?.length > 0 && (
        <div className="mt-2 bg-red-900/20 border border-red-800/50 rounded px-2 py-1.5">
          <span className="text-red-400 text-xs font-medium">Matched rules: </span>
          {packet.matched_rules.map((r, i) => (
            <span key={r.id} className="text-xs">
              {i > 0 && ', '}
              <span className={r.action === 'drop' ? 'text-red-300' : r.action === 'both' ? 'text-purple-300' : 'text-orange-300'}>
                {r.name}
              </span>
              <span className="text-gray-600 ml-1">({r.action})</span>
            </span>
          ))}
        </div>
      )}

      {packet.url && (
        <div className="mt-2">
          <div className="text-gray-500 text-xs mb-1">URL</div>
          <div className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 break-all">
            <HighlightedBody text={packet.url} pattern={highlightUrl ? pattern : null} />
          </div>
        </div>
      )}

      {headers.length > 0 && (
        <div className="mt-2">
          <div className="text-gray-500 text-xs mb-1">Headers</div>
          <div className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 space-y-0.5 overflow-auto" style={{ maxHeight: '20vh' }}>
            {headers.map(([k, v]) => (
              <div key={k} className="break-all">
                <span className="text-gray-500">{k}: </span>
                <HighlightedBody text={Array.isArray(v) ? v.join(', ') : String(v)} pattern={highlightHeaders ? pattern : null} />
              </div>
            ))}
          </div>
        </div>
      )}

      {packet.body_string && (
        <div className="mt-2">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-gray-500 text-xs">Body</span>
            {formattedBody.isJSON && <span className="text-xs px-1 py-0.5 bg-cyan-900/40 text-cyan-400 rounded">JSON</span>}
          </div>
          <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '40vh' }}>
            <HighlightedBody text={formattedBody.text} pattern={highlightBody ? pattern : null} />
          </pre>
        </div>
      )}
    </div>
  )
}

export default function Blocks() {
  const navigate = useNavigate()
  const location = useLocation()
  const [services, setServices] = useState([])
  const [selectedPacket, setSelectedPacket] = useState(null)
  const [filters, setFilters] = useState({
    service_id: '', src_ip: '', limit: 50,
  })
  const [filterNegated, setFilterNegated] = useState({ service_id: false, src_ip: false })
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)

  const fetchPage = useCallback(async (offset, limit) => {
    const params = { ...filters, ...hideParams(), dropped: 'true', sort: 'desc', limit, offset }
    if (filterNegated.service_id && params.service_id) { params.not_service_id = params.service_id; delete params.service_id }
    if (filterNegated.src_ip && params.src_ip) { params.not_src_ip = params.src_ip; delete params.src_ip }
    const data = await api.getPackets(params)
    return { items: data.packets || [], total: data.total }
  }, [filters, filterNegated])

  const {
    items: packets,
    total,
    loading,
    sentinelRef: blockSentinelRef,
    refresh: refreshBlocks,
    reset: resetBlocks,
  } = useInfiniteList({ fetchPage, pageSize: 50 })

  function togglePause() {
    const next = !pausedRef.current
    pausedRef.current = next
    setPaused(next)
    if (!next) refreshBlocks()
  }

  useEffect(() => {
    api.listServices().then((data) => setServices(data || []))
  }, [])

  // Reset when filters change. Depend on fetchPage so any filter/negation edit
  // fires a fresh fetch — even while paused.
  useEffect(() => {
    const timer = setTimeout(() => resetBlocks(), 200)
    return () => clearTimeout(timer)
  }, [fetchPage, resetBlocks])

  useEffect(() => {
    const id = location.state?.restoreBlockedPacketId
    if (id == null) return
    navigate(location.pathname, { replace: true, state: {} })
    ;(async () => {
      try {
        const full = await api.getPacket(id)
        setSelectedPacket(full)
      } catch (err) {
        console.error(err)
      }
    })()
  }, [location.state, location.pathname, navigate])

  function handleClearAll() {
    if (!confirm('Hide all blocked packets from your view? (Teammates still see them.)')) return
    if (packets.length > 0) addHiddenIds(packets.map((p) => p.id))
    resetBlocks()
    setSelectedPacket(null)
  }

  useEffect(() => {
    const interval = setInterval(() => {
      if (!pausedRef.current) refreshBlocks()
    }, 5000)
    return () => clearInterval(interval)
  }, [refreshBlocks])

  // Live refresh blocks only when streamed packets include drop-capable matches.
  useEffect(() => {
    const unsub = subscribePacketStream(
      (pkts) => {
        if (pausedRef.current) return
        if (!Array.isArray(pkts) || pkts.length === 0) return
        const shouldReload = pkts.some((p) =>
          Array.isArray(p.matched_rules) &&
          p.matched_rules.some((r) => r.action === 'drop' || r.action === 'both')
        )
        if (shouldReload) refreshBlocks()
      },
      () => { if (!pausedRef.current) refreshBlocks() },
    )
    return () => unsub()
  }, [refreshBlocks])

  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value }))
  }

  const serviceName = (id) => {
    const svc = services.find((s) => s.id === id)
    return svc ? svc.name : id
  }

  // Find the first drop/both rule from the selected packet for highlighting
  const selectedRule = useMemo(() => {
    if (!selectedPacket?.matched_rules?.length) return null
    const dropRule = selectedPacket.matched_rules.find(r => r.action === 'drop' || r.action === 'both')
    return dropRule || selectedPacket.matched_rules[0]
  }, [selectedPacket])

  return (
    <div className="p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-semibold text-gray-100">Blocks</h2>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1">
            <select
              value={filters.service_id}
              onChange={(e) => setFilter('service_id', e.target.value)}
              className={`bg-gray-800 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none transition-colors border ${filterNegated.service_id && filters.service_id ? 'border-red-700/60 focus:border-red-500' : 'border-gray-700 focus:border-cyan-500'}`}
            >
              <option value="">All Services</option>
              {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <button type="button" title="Toggle exclude mode" onClick={() => setFilterNegated(p => ({ ...p, service_id: !p.service_id }))}
              className={`text-xs px-1.5 py-1 rounded cursor-pointer transition-colors ${filterNegated.service_id ? 'bg-red-900/60 text-red-400 border border-red-700/60' : 'text-gray-600 hover:text-gray-400 border border-transparent'}`}>≠</button>
          </div>
          <div className="flex items-center gap-1">
            <input
              value={filters.src_ip}
              onChange={(e) => setFilter('src_ip', e.target.value)}
              placeholder="Source IP..."
              className={`bg-gray-800 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none transition-colors border w-36 ${filterNegated.src_ip && filters.src_ip ? 'border-red-700/60 focus:border-red-500' : 'border-gray-700 focus:border-cyan-500'}`}
            />
            <button type="button" title="Toggle exclude mode" onClick={() => setFilterNegated(p => ({ ...p, src_ip: !p.src_ip }))}
              className={`text-xs px-1.5 py-1 rounded cursor-pointer transition-colors ${filterNegated.src_ip ? 'bg-red-900/60 text-red-400 border border-red-700/60' : 'text-gray-600 hover:text-gray-400 border border-transparent'}`}>≠</button>
          </div>
          <button
            onClick={togglePause}
            className={`text-sm px-4 py-2 rounded transition-colors cursor-pointer ${
              paused
                ? 'bg-cyan-900/50 hover:bg-cyan-800/50 text-cyan-400'
                : 'bg-gray-800 hover:bg-gray-700 text-gray-300'
            }`}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button
            onClick={handleClearAll}
            disabled={total === 0}
            className="bg-red-900/50 hover:bg-red-800/50 disabled:bg-gray-800 disabled:text-gray-600 text-red-400 text-sm px-4 py-2 rounded transition-colors cursor-pointer disabled:cursor-default"
          >
            Clear All
          </button>
        </div>
      </div>

      <div className="flex-1 flex gap-0 min-h-0">
        {/* Blocked packets list */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Service</th>
                  <th className="px-3 py-2 font-medium">Source IP</th>
                  <th className="px-3 py-2 font-medium">Method</th>
                  <th className="px-3 py-2 font-medium">Matched Rules</th>
                </tr>
              </thead>
              <tbody>
                {packets.map((pkt) => (
                  <tr
                    key={pkt.id}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                      selectedPacket?.id === pkt.id ? 'bg-red-950/30' : 'hover:bg-gray-900/80'
                    }`}
                  >
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap font-mono text-xs">
                      {new Date(pkt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{serviceName(pkt.service_id)}</td>
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{pkt.src_ip}</td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{pkt.method}</td>
                    <td className="px-3 py-1.5 text-xs">
                      {pkt.matched_rules?.map((r, i) => (
                        <span key={r.id}>
                          {i > 0 && ', '}
                          <span className={`px-1.5 py-0.5 rounded ${
                            r.action === 'drop' ? 'bg-red-900/40 text-red-400' :
                            r.action === 'both' ? 'bg-purple-900/40 text-purple-400' :
                            'bg-orange-900/40 text-orange-400'
                          }`}>
                            {r.name}
                          </span>
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
                {packets.length === 0 && (
                  <tr><td colSpan="5" className="text-center py-8 text-gray-600">No blocked packets</td></tr>
                )}
              </tbody>
              <tfoot>
                <tr>
                  <td colSpan="5" className="py-2 text-center text-xs text-gray-700">
                    <span ref={blockSentinelRef}>
                      {loading ? 'Loading…' : ''}
                    </span>
                  </td>
                </tr>
              </tfoot>
            </table>
          </div>

          {/* Footer: total count */}
          <div className="flex items-center px-3 py-2 bg-gray-900 border-t border-gray-800 text-sm text-gray-500">
            <span>{total} blocked packet{total !== 1 ? 's' : ''}</span>
          </div>
        </div>

        {/* Detail panel */}
        {selectedPacket && (
          <>
            <div className="w-1.5 flex-shrink-0" />
            <div className="w-[400px] flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
              <div className="flex items-center justify-between p-3 border-b border-gray-800 sticky top-0 bg-gray-900 z-10">
                <h3 className="text-sm font-medium text-gray-100">Blocked Packet #{selectedPacket.id}</h3>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => navigate('/traffic', {
                      state: {
                        openFlowForPacketId: selectedPacket.id,
                        flowReturn: { path: '/blocks', packetId: selectedPacket.id },
                      },
                    })}
                    className="text-xs text-purple-400 hover:text-purple-300 cursor-pointer"
                    title="Open Traffic and show flow for this packet"
                  >
                    Flow
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (!confirm('Hide this packet from your view? (Teammates still see it.)')) return
                      addHiddenIds([selectedPacket.id])
                      setSelectedPacket(null)
                      resetBlocks()
                    }}
                    className="text-xs text-red-500 hover:text-red-400 cursor-pointer"
                    title="Hide this packet from your view (per-user; teammates unaffected)"
                  >
                    Hide
                  </button>
                  <button type="button" onClick={() => setSelectedPacket(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
                </div>
              </div>
              <div className="p-3 space-y-3 text-sm">
                <BlockedPacketDetail packet={selectedPacket} rule={selectedRule} />
              </div>
            </div>
          </>
        )}
      </div>

      {loading && <div className="fixed bottom-4 right-4 bg-gray-800 text-red-400 text-xs px-3 py-1.5 rounded-full">Loading...</div>}
    </div>
  )
}
