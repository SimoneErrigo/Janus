import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

export default function Traffic() {
  const [services, setServices] = useState([])
  const [packets, setPackets] = useState([])
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({
    service_id: '', src_ip: '', dst_ip: '', protocol: '',
    contains: '', regex: '', flagged: '', sort: 'desc',
    limit: 50, offset: 0,
  })

  useEffect(() => {
    api.listServices().then((data) => setServices(data || []))
  }, [])

  const loadPackets = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.getPackets(filters)
      setPackets(data.packets || [])
      setTotal(data.total)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => { loadPackets() }, [loadPackets])

  // Auto-refresh every 3 seconds
  useEffect(() => {
    const interval = setInterval(loadPackets, 3000)
    return () => clearInterval(interval)
  }, [loadPackets])

  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value, offset: 0 }))
  }

  function nextPage() {
    setFilters((f) => ({ ...f, offset: f.offset + f.limit }))
  }
  function prevPage() {
    setFilters((f) => ({ ...f, offset: Math.max(0, f.offset - f.limit) }))
  }

  return (
    <div className="p-6 flex flex-col h-full">
      {/* Filters */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
        <div className="grid grid-cols-4 gap-3">
          <FilterSelect label="Service" value={filters.service_id} onChange={(v) => setFilter('service_id', v)}
            options={[{ value: '', label: 'All' }, ...services.map((s) => ({ value: s.id, label: s.name }))]}
          />
          <FilterInput label="Source IP" value={filters.src_ip} onChange={(v) => setFilter('src_ip', v)} placeholder="e.g. 10.10.0.5" />
          <FilterInput label="Dest IP" value={filters.dst_ip} onChange={(v) => setFilter('dst_ip', v)} placeholder="e.g. 10.10.0.1" />
          <FilterSelect label="Protocol" value={filters.protocol} onChange={(v) => setFilter('protocol', v)}
            options={[{ value: '', label: 'All' }, ...['http','https','h2','grpc','tcp'].map((p) => ({ value: p, label: p.toUpperCase() }))]}
          />
          <FilterInput label="Contains" value={filters.contains} onChange={(v) => setFilter('contains', v)} placeholder="Text search..." />
          <FilterInput label="Regex" value={filters.regex} onChange={(v) => setFilter('regex', v)} placeholder="Regex pattern..." />
          <FilterSelect label="Flagged" value={filters.flagged} onChange={(v) => setFilter('flagged', v)}
            options={[{ value: '', label: 'All' }, { value: 'true', label: 'Flagged only' }, { value: 'false', label: 'Not flagged' }]}
          />
          <FilterSelect label="Sort" value={filters.sort} onChange={(v) => setFilter('sort', v)}
            options={[{ value: 'desc', label: 'Newest first' }, { value: 'asc', label: 'Oldest first' }]}
          />
        </div>
      </div>

      {/* Packet table + detail split */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* Table */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Dir</th>
                  <th className="px-3 py-2 font-medium">Source</th>
                  <th className="px-3 py-2 font-medium">Method</th>
                  <th className="px-3 py-2 font-medium">URL / Body</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium w-8"></th>
                </tr>
              </thead>
              <tbody>
                {packets.map((pkt) => (
                  <tr
                    key={pkt.id}
                    onClick={() => setSelected(pkt)}
                    className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                      selected?.id === pkt.id ? 'bg-gray-800' : 'hover:bg-gray-900/80'
                    } ${pkt.matched_rules?.length > 0 ? 'bg-red-950/20' : ''}`}
                  >
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap font-mono text-xs">
                      {new Date(pkt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className={`text-xs px-1.5 py-0.5 rounded ${
                        pkt.direction === 'request' ? 'bg-blue-900/40 text-blue-400' : 'bg-green-900/40 text-green-400'
                      }`}>
                        {pkt.direction === 'request' ? 'REQ' : 'RES'}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{pkt.src_ip}</td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{pkt.method}</td>
                    <td className="px-3 py-1.5 text-gray-400 text-xs truncate max-w-xs">{pkt.url || (pkt.body_string?.slice(0, 80)) || '—'}</td>
                    <td className="px-3 py-1.5 text-xs">
                      {pkt.status > 0 && <span className={`${pkt.status < 400 ? 'text-green-400' : 'text-red-400'}`}>{pkt.status}</span>}
                    </td>
                    <td className="px-3 py-1.5">
                      {pkt.flagged && <span className="text-yellow-400 text-xs" title="Contains flag">&#9873;</span>}
                      {pkt.matched_rules?.length > 0 && <span className="text-red-400 text-xs ml-1" title="Rule matched">&#9888;</span>}
                    </td>
                  </tr>
                ))}
                {packets.length === 0 && (
                  <tr><td colSpan="7" className="text-center py-8 text-gray-600">No packets found</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between px-3 py-2 bg-gray-900 border-t border-gray-800 text-sm text-gray-400">
            <span>{total} packet{total !== 1 ? 's' : ''}</span>
            <div className="flex gap-2">
              <button onClick={prevPage} disabled={filters.offset === 0} className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-30 cursor-pointer disabled:cursor-default">&laquo; Prev</button>
              <span className="px-2 py-1">{Math.floor(filters.offset / filters.limit) + 1} / {Math.max(1, Math.ceil(total / filters.limit))}</span>
              <button onClick={nextPage} disabled={filters.offset + filters.limit >= total} className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-30 cursor-pointer disabled:cursor-default">Next &raquo;</button>
            </div>
          </div>
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-96 bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
            <div className="flex items-center justify-between p-3 border-b border-gray-800">
              <h3 className="text-sm font-medium text-gray-100">Packet #{selected.id}</h3>
              <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer">&times;</button>
            </div>
            <div className="p-3 space-y-3 text-sm">
              <DetailRow label="Service" value={selected.service_id} />
              <DetailRow label="Time" value={new Date(selected.timestamp).toLocaleString()} />
              <DetailRow label="Direction" value={selected.direction} />
              <DetailRow label="Protocol" value={selected.protocol} />
              <DetailRow label="Source" value={`${selected.src_ip}:${selected.src_port}`} />
              <DetailRow label="Destination" value={`${selected.dst_ip}:${selected.dst_port}`} />
              {selected.method && <DetailRow label="Method" value={selected.method} />}
              {selected.url && <DetailRow label="URL" value={selected.url} />}
              {selected.status > 0 && <DetailRow label="Status" value={selected.status} />}

              {selected.flagged && (
                <div className="bg-yellow-900/20 border border-yellow-800/50 rounded p-2 text-yellow-400 text-xs">
                  Contains flag pattern
                </div>
              )}

              {selected.matched_rules?.length > 0 && (
                <div className="bg-red-900/20 border border-red-800/50 rounded p-2">
                  <div className="text-red-400 text-xs font-medium mb-1">Matched Rules:</div>
                  {selected.matched_rules.map((r) => (
                    <div key={r.id} className="text-red-300 text-xs">{r.name} ({r.id})</div>
                  ))}
                </div>
              )}

              {selected.headers && Object.keys(selected.headers).length > 0 && (
                <div>
                  <div className="text-gray-500 text-xs mb-1">Headers</div>
                  <div className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 max-h-40 overflow-auto">
                    {Object.entries(selected.headers).map(([k, v]) => (
                      <div key={k}><span className="text-cyan-400">{k}:</span> {v}</div>
                    ))}
                  </div>
                </div>
              )}

              {selected.body_string && (
                <div>
                  <div className="text-gray-500 text-xs mb-1">Body</div>
                  <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 max-h-60 overflow-auto whitespace-pre-wrap break-all">{selected.body_string}</pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {loading && <div className="fixed bottom-4 right-4 bg-gray-800 text-cyan-400 text-xs px-3 py-1.5 rounded-full">Loading...</div>}
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

function DetailRow({ label, value }) {
  return (
    <div className="flex">
      <span className="text-gray-500 w-24 flex-shrink-0">{label}</span>
      <span className="text-gray-300 break-all">{value}</span>
    </div>
  )
}
