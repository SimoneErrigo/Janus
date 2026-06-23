import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, subscribePacketStream } from '../api'
import { addHiddenIds, getHiddenIds, getClearCursor, getHiddenAlertIds, addHiddenAlertIds } from '../userHidden'
import HighlightedBody from '../components/HighlightedBody'
import FilterExpression from '../components/FilterExpression'
import { tryFormatJSON } from '../utils/formatting'
import { useServiceMap } from '../hooks/useServiceMap'

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
        {packet.status > 0 && <div><span className="text-gray-500">Status </span><span className="text-gray-300">{packet.status}</span></div>}
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
  const [services, setServices] = useState([])
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [linkedPacket, setLinkedPacket] = useState(null)
  const [expression, setExpression] = useState('')
  const [filters, setFilters] = useState({ service_id: '', src_ip: '' })
  const [filterNegated, setFilterNegated] = useState({ service_id: false, src_ip: false })
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)

  const fetchPage = useCallback(async (offset, limit) => {
    const params = { limit, offset }
    if (expression.trim()) params.q = expression
    if (filters.service_id) {
      if (filterNegated.service_id) params.not_service_id = filters.service_id
      else params.service_id = filters.service_id
    }
    if (filters.src_ip) {
      if (filterNegated.src_ip) params.not_src_ip = filters.src_ip
      else params.src_ip = filters.src_ip
    }
    const data = await api.listAlerts(params)
    return { items: data.alerts || [], total: data.total }
  }, [expression, filters, filterNegated])

  const {
    items: alertsRaw,
    total: totalRaw,
    loading,
    sentinelRef: alertSentinelRef,
    refresh: refreshAlerts,
    reset: resetAlerts,
  } = useInfiniteList({ fetchPage, pageSize: 50 })

  // Filter out alerts whose linked packet this user has hidden, plus any alerts
  // the user dismissed from their own view via "Clear All".
  const [hideVersion, setHideVersion] = useState(0)
  const alerts = useMemo(() => {
    const hiddenPkts = new Set(getHiddenIds())
    const hiddenAlerts = new Set(getHiddenAlertIds())
    const cursor = getClearCursor()
    return alertsRaw.filter((a) => {
      if (hiddenAlerts.has(Number(a.id))) return false
      if (hiddenPkts.has(Number(a.packet_id))) return false
      if (cursor && a.timestamp && a.timestamp < cursor) return false
      return true
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertsRaw, hideVersion])
  const hiddenCount = alertsRaw.length - alerts.length
  const total = Math.max(0, totalRaw - hiddenCount)

  function setFilter(key, value) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }

  function togglePause() {
    const next = !pausedRef.current
    pausedRef.current = next
    setPaused(next)
    if (!next) refreshAlerts()
  }

  useEffect(() => {
    api.listServices().then((data) => setServices(data || []))
  }, [])

  // Reset when filters change. Depend on fetchPage so any filter/negation edit
  // fires a fresh fetch — even while paused.
  useEffect(() => {
    const timer = setTimeout(() => resetAlerts(), 200)
    return () => clearTimeout(timer)
  }, [fetchPage, resetAlerts])

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

  // Live refresh alerts only when streamed packets include alert-capable matches.
  useEffect(() => {
    const unsub = subscribePacketStream(
      (pkts) => {
        if (pausedRef.current) return
        if (!Array.isArray(pkts) || pkts.length === 0) return
        const shouldReload = pkts.some((p) =>
          Array.isArray(p.matched_rules) &&
          p.matched_rules.some((r) => r.action === 'alert' || r.action === 'both')
        )
        if (shouldReload) refreshAlerts()
      },
      () => { if (!pausedRef.current) refreshAlerts() },
    )
    return () => unsub()
  }, [refreshAlerts])

  function handleClearAll() {
    if (!confirm('Hide all alerts from your view? (Teammates still see them.)')) return
    if (alertsRaw.length > 0) addHiddenAlertIds(alertsRaw.map((a) => a.id))
    setSelectedAlert(null)
    setLinkedPacket(null)
    setHideVersion((v) => v + 1)
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

  const { serviceName } = useServiceMap(services)

  return (
    <div className="p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-2xl font-semibold text-gray-100">Alerts</h2>
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

      <div className="mb-3">
        <FilterExpression
          value={expression}
          onChange={setExpression}
          placeholder='Filter alerts by linked-packet attrs — e.g. service == "web" AND src in (10.0.0.0/8)'
          compact
        />
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
              <tfoot>
                <tr>
                  <td colSpan="5" className="py-2 text-center text-xs text-gray-700">
                    <span ref={alertSentinelRef}>
                      {loading ? 'Loading…' : ''}
                    </span>
                  </td>
                </tr>
              </tfoot>
            </table>
          </div>

          {/* Footer: total count */}
          <div className="flex items-center px-3 py-2 bg-gray-900 border-t border-gray-800 text-sm text-gray-500">
            <span>{total} alert{total !== 1 ? 's' : ''}</span>
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
                  {linkedPacket?.id && (
                    <button
                      type="button"
                      onClick={() => {
                        if (!confirm('Hide this packet from your view? (Teammates still see it.)')) return
                        addHiddenIds([linkedPacket.id])
                        setLinkedPacket(null)
                        setSelectedAlert(null)
                        refreshAlerts()
                      }}
                      className="text-xs text-red-500 hover:text-red-400 cursor-pointer"
                      title="Hide this packet from your view (per-user; teammates unaffected)"
                    >
                      Hide
                    </button>
                  )}
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
