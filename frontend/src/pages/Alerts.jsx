import { useState, useEffect, useCallback, useMemo, memo } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, subscribePacketStream } from '../api'

// Strip Go/PCRE inline flags like (?i) that are invalid in JavaScript regex
function toJSRegex(pattern) {
  if (!pattern) return null
  // Remove inline flags (?i), (?s), (?m), (?is), etc.
  const cleaned = pattern.replace(/\(\?[ismUux]+\)/g, '')
  if (!cleaned) return null
  try {
    return new RegExp(cleaned, 'gi')
  } catch {
    // If regex is still invalid, try escaping it as a literal string
    try {
      return new RegExp(cleaned.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
    } catch {
      return null
    }
  }
}

// Highlight matching text segments — memoized to avoid re-running regex on every render
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
        parts.push(<mark key={`m${r.start}`} className="bg-orange-500/40 text-orange-200 rounded px-0.5">{r.text}</mark>)
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

// Try to pretty-print JSON
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

function LinkedPacketDetail({ packet, pattern, scope }) {
  const formattedBody = useMemo(() => tryFormatJSON(packet.body_string), [packet.body_string])
  const headers = useMemo(() => {
    if (!packet.headers) return []
    if (typeof packet.headers === 'string') {
      try { return Object.entries(JSON.parse(packet.headers)) } catch { return [] }
    }
    if (typeof packet.headers === 'object') return Object.entries(packet.headers)
    return []
  }, [packet.headers])

  // Only highlight the section that matches the rule's scope
  const highlightUrl = !scope || scope === 'url' || scope === 'raw'
  const highlightHeaders = !scope || scope === 'header' || scope === 'raw'
  const highlightBody = !scope || scope === 'body' || scope === 'raw'

  return (
    <div>
      <div className="text-gray-500 text-xs mb-1">Linked Packet #{packet.id}</div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs bg-gray-800/50 rounded p-2">
        <div><span className="text-gray-500">Direction </span><span className={packet.direction === 'request' ? 'text-blue-400' : 'text-green-400'}>{packet.direction}</span></div>
        <div><span className="text-gray-500">Protocol </span><span className="text-gray-300">{packet.protocol}</span></div>
        <div><span className="text-gray-500">Src </span><span className="text-gray-300 font-mono">{packet.src_ip}:{packet.src_port}</span></div>
        <div><span className="text-gray-500">Dst </span><span className="text-gray-300 font-mono">{packet.dst_ip}:{packet.dst_port}</span></div>
        {packet.method && <div><span className="text-gray-500">Method </span><span className="text-gray-300">{packet.method}</span></div>}
        {packet.status_code > 0 && <div><span className="text-gray-500">Status </span><span className="text-gray-300">{packet.status_code}</span></div>}
      </div>

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

export default function Alerts() {
  const navigate = useNavigate()
  const location = useLocation()
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [linkedPacket, setLinkedPacket] = useState(null)
  const [filters, setFilters] = useState({
    service_id: '', rule_id: '', src_ip: '', limit: 50, offset: 0,
  })

  useEffect(() => {
    api.listServices().then((data) => setServices(data || []))
  }, [])

  const loadAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.listAlerts(filters)
      setAlerts(data.alerts || [])
      setTotal(data.total)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => { loadAlerts() }, [loadAlerts])

  useEffect(() => {
    const id = location.state?.restoreAlertId
    if (id == null) return
    navigate(location.pathname, { replace: true, state: {} })
    ;(async () => {
      try {
        const data = await api.getAlert(id)
        if (data?.alert) {
          setSelectedAlert(data.alert)
          setLinkedPacket(data.packet ?? null)
        }
      } catch (err) {
        console.error(err)
      }
    })()
  }, [location.state, location.pathname, navigate])

  useEffect(() => {
    const interval = setInterval(loadAlerts, 5000)
    return () => clearInterval(interval)
  }, [loadAlerts])

  // Live refresh alerts only when streamed packets include alert-capable matches.
  useEffect(() => {
    const unsub = subscribePacketStream(
      (pkts) => {
        if (!Array.isArray(pkts) || pkts.length === 0) return
        const shouldReload = pkts.some((p) =>
          Array.isArray(p.matched_rules) &&
          p.matched_rules.some((r) => r.action === 'alert' || r.action === 'both')
        )
        if (shouldReload) loadAlerts()
      },
      loadAlerts,
    )
    return () => unsub()
  }, [loadAlerts])

  async function handleClearAll() {
    if (!confirm('Clear all alerts?')) return
    try {
      await api.clearAlerts()
      loadAlerts()
      setSelectedAlert(null)
      setLinkedPacket(null)
    } catch (err) {
      console.error(err)
    }
  }

  async function viewAlert(alert) {
    setSelectedAlert(alert)
    try {
      const data = await api.getAlert(alert.id)
      setLinkedPacket(data.packet)
    } catch (err) {
      console.error(err)
      setLinkedPacket(null)
    }
  }

  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value, offset: 0 }))
  }

  function nextPage() {
    setFilters((f) => ({ ...f, offset: f.offset + f.limit }))
  }
  function prevPage() {
    setFilters((f) => ({ ...f, offset: Math.max(0, f.offset - f.limit) }))
  }

  const serviceName = (id) => {
    const svc = services.find((s) => s.id === id)
    return svc ? svc.name : id
  }

  return (
    <div className="p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-semibold text-gray-100">Alerts</h2>
        <div className="flex items-center gap-3">
          <select
            value={filters.service_id}
            onChange={(e) => setFilter('service_id', e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Services</option>
            {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <input
            value={filters.src_ip}
            onChange={(e) => setFilter('src_ip', e.target.value)}
            placeholder="Source IP..."
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 w-40"
          />
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
        {/* Alert list */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Service</th>
                  <th className="px-3 py-2 font-medium">Rule</th>
                  <th className="px-3 py-2 font-medium">Source IP</th>
                  <th className="px-3 py-2 font-medium">Pattern Matched</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => viewAlert(alert)}
                    className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                      selectedAlert?.id === alert.id ? 'bg-orange-950/30' : 'hover:bg-gray-900/80'
                    }`}
                  >
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap font-mono text-xs">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{serviceName(alert.service_id)}</td>
                    <td className="px-3 py-1.5">
                      <span className="text-xs px-1.5 py-0.5 bg-orange-900/40 text-orange-400 rounded">
                        {alert.rule_name || alert.rule_id}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{alert.src_ip}</td>
                    <td className="px-3 py-1.5 text-gray-400 text-xs font-mono truncate max-w-xs">
                      {alert.pattern_matched.length > 60 ? alert.pattern_matched.slice(0, 60) + '...' : alert.pattern_matched}
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr><td colSpan="5" className="text-center py-8 text-gray-600">No alerts</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between px-3 py-2 bg-gray-900 border-t border-gray-800 text-sm text-gray-400">
            <span>{total} alert{total !== 1 ? 's' : ''}</span>
            <div className="flex gap-2">
              <button onClick={prevPage} disabled={filters.offset === 0} className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-30 cursor-pointer disabled:cursor-default">&laquo; Prev</button>
              <span className="px-2 py-1">{Math.floor(filters.offset / filters.limit) + 1} / {Math.max(1, Math.ceil(total / filters.limit))}</span>
              <button onClick={nextPage} disabled={filters.offset + filters.limit >= total} className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-30 cursor-pointer disabled:cursor-default">Next &raquo;</button>
            </div>
          </div>
        </div>

        {/* Detail panel */}
        {selectedAlert && (
          <>
            <div className="w-1.5 flex-shrink-0" />
            <div className="w-[400px] flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
              <div className="flex items-center justify-between p-3 border-b border-gray-800 sticky top-0 bg-gray-900 z-10">
                <h3 className="text-sm font-medium text-gray-100">Alert #{selectedAlert.id}</h3>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={!linkedPacket?.id}
                    onClick={() => linkedPacket?.id && selectedAlert && navigate('/traffic', {
                      state: {
                        openFlowForPacketId: linkedPacket.id,
                        flowReturn: { path: '/alerts', alertId: selectedAlert.id },
                      },
                    })}
                    className="text-xs text-purple-400 hover:text-purple-300 disabled:text-gray-600 disabled:cursor-default cursor-pointer"
                    title={linkedPacket?.id ? 'Open Traffic and show flow for this packet' : 'Load packet detail first'}
                  >
                    Flow
                  </button>
                  <button type="button" onClick={() => { setSelectedAlert(null); setLinkedPacket(null) }} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
                </div>
              </div>
              <div className="p-3 space-y-3 text-sm">
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs bg-gray-800/50 rounded p-2">
                  <div><span className="text-gray-500">Service </span><span className="text-gray-300">{serviceName(selectedAlert.service_id)}</span></div>
                  <div><span className="text-gray-500">Time </span><span className="text-gray-300">{new Date(selectedAlert.timestamp).toLocaleString()}</span></div>
                  <div><span className="text-gray-500">Rule </span><span className="text-orange-400">{selectedAlert.rule_name || selectedAlert.rule_id}</span></div>
                  <div><span className="text-gray-500">Source IP </span><span className="text-gray-300 font-mono">{selectedAlert.src_ip}</span></div>
                </div>

                <div className="text-xs">
                  <span className="text-gray-500">Pattern matched: </span>
                  <span className="text-orange-300 font-mono break-all">{selectedAlert.pattern_matched}</span>
                  {selectedAlert.matched_scope && (
                    <span className="ml-2 px-1.5 py-0.5 bg-gray-700 text-gray-400 rounded text-xs">scope: {selectedAlert.matched_scope}</span>
                  )}
                </div>

                {linkedPacket && (
                  <LinkedPacketDetail packet={linkedPacket} pattern={selectedAlert.pattern_matched} scope={selectedAlert.matched_scope} />
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {loading && <div className="fixed bottom-4 right-4 bg-gray-800 text-orange-400 text-xs px-3 py-1.5 rounded-full">Loading...</div>}
    </div>
  )
}
