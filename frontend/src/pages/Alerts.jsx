import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

export default function Alerts() {
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
    const interval = setInterval(loadAlerts, 5000)
    return () => clearInterval(interval)
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
                <button onClick={() => { setSelectedAlert(null); setLinkedPacket(null) }} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
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
                </div>

                {linkedPacket && (
                  <div>
                    <div className="text-gray-500 text-xs mb-1">Linked Packet #{linkedPacket.id}</div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs bg-gray-800/50 rounded p-2">
                      <div><span className="text-gray-500">Direction </span><span className={linkedPacket.direction === 'request' ? 'text-blue-400' : 'text-green-400'}>{linkedPacket.direction}</span></div>
                      <div><span className="text-gray-500">Protocol </span><span className="text-gray-300">{linkedPacket.protocol}</span></div>
                      <div><span className="text-gray-500">Src </span><span className="text-gray-300 font-mono">{linkedPacket.src_ip}:{linkedPacket.src_port}</span></div>
                      <div><span className="text-gray-500">Dst </span><span className="text-gray-300 font-mono">{linkedPacket.dst_ip}:{linkedPacket.dst_port}</span></div>
                      {linkedPacket.method && <div><span className="text-gray-500">Method </span><span className="text-gray-300">{linkedPacket.method}</span></div>}
                      {linkedPacket.url && <div className="col-span-2"><span className="text-gray-500">URL </span><span className="text-gray-300 font-mono break-all">{linkedPacket.url}</span></div>}
                    </div>
                    {linkedPacket.body_string && (
                      <div className="mt-2">
                        <div className="text-gray-500 text-xs mb-1">Body</div>
                        <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '40vh' }}>
                          {linkedPacket.body_string}
                        </pre>
                      </div>
                    )}
                  </div>
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
