import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../api'

// Highlight matching text in a string based on contains/regex filter
function HighlightedText({ text, contains, regex }) {
  if (!text || (!contains && !regex)) return <>{text}</>

  try {
    let re
    if (regex) {
      re = new RegExp(`(${regex})`, 'gi')
    } else if (contains) {
      re = new RegExp(`(${contains.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
    }
    if (!re) return <>{text}</>

    const parts = text.split(re)
    return (
      <>
        {parts.map((part, i) =>
          re.test(part) ? (
            <mark key={i} className="bg-yellow-500/40 text-yellow-200 rounded px-0.5">{part}</mark>
          ) : (
            <span key={i}>{part}</span>
          )
        )}
      </>
    )
  } catch {
    return <>{text}</>
  }
}

// Get the peer (external) IP from a packet
function getPeerIP(pkt) {
  return pkt.direction === 'request' ? pkt.src_ip : pkt.dst_ip
}

export default function Traffic() {
  const [services, setServices] = useState([])
  const [packets, setPackets] = useState([])
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(false)
  const [flowMode, setFlowMode] = useState(null) // { packetId, packets, total }
  const [filtersCollapsed, setFiltersCollapsed] = useState(false)
  const [copyStatus, setCopyStatus] = useState(null) // null | 'copying' | 'copied' | 'error'
  const [flagFilter, setFlagFilter] = useState(false)
  const [flagRegex, setFlagRegex] = useState('')
  const [flagIDFilter, setFlagIDFilter] = useState(false)
  const [flagIDEnabled, setFlagIDEnabled] = useState(false)
  const [filters, setFilters] = useState({
    service_id: '', src_ip: '', dst_ip: '', protocol: '', method: '',
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
    }).catch(() => {})
  }, [])

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
      const data = await api.getPackets(params)
      setPackets(data.packets || [])
      setTotal(data.total)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [filters, flagFilter, flagIDFilter])

  useEffect(() => { loadPackets() }, [loadPackets])

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

  // Flow: reconstruct multi-connection flow via auth token correlation
  async function showFlow(pkt) {
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
      // Fallback to session_id filter
      setFilters((f) => ({
        ...f,
        session_id: pkt.session_id,
        sort: 'asc',
        offset: 0,
      }))
    } finally {
      setLoading(false)
    }
  }

  function clearFlow() {
    setFlowMode(null)
    setFilters((f) => ({ ...f, session_id: '', sort: 'desc', offset: 0 }))
  }

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
    setFlagIDFilter((v) => !v)
    setFilters((f) => ({ ...f, offset: 0 }))
  }

  const isFlowActive = !!flowMode || !!filters.session_id
  const hasActiveFilter = filters.contains || filters.regex || flagFilter || flagIDFilter

  // Compute effective highlight regex: combine user regex and flag regex when active
  const highlightRegex = [filters.regex, flagFilter && flagRegex ? flagRegex : null].filter(Boolean).join('|') || ''

  // Use flow mode packets when active, otherwise normal packets
  const displayPackets = flowMode ? flowMode.packets : packets
  const displayTotal = flowMode ? flowMode.total : total

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
              {flagIDEnabled && (
                <button
                  onClick={toggleFlagIDFilter}
                  className={`text-xs px-3 py-1.5 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                    flagIDFilter
                      ? 'bg-emerald-900/50 text-emerald-300 border border-emerald-700/50'
                      : 'bg-gray-800 text-gray-400 border border-gray-700 hover:text-gray-300'
                  }`}
                >
                  <span>&#9872;</span> Contains my Flag IDs
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Packet table + detail split */}
      <div className="flex-1 flex gap-0 min-h-0 overflow-hidden">
        {/* Table */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0">
          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Service</th>
                  <th className="px-3 py-2 font-medium">Dir</th>
                  <th className="px-3 py-2 font-medium">Peer</th>
                  <th className="px-3 py-2 font-medium">Method</th>
                  <th className="px-3 py-2 font-medium">URL / Body</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium w-16"></th>
                </tr>
              </thead>
              <tbody>
                {displayPackets.map((pkt) => (
                  <tr
                    key={pkt.id}
                    onClick={() => setSelected(pkt)}
                    className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                      selected?.id === pkt.id ? 'bg-gray-800' : 'hover:bg-gray-900/80'
                    } ${pkt.matched_rules?.length > 0 ? 'bg-red-950/20' : ''} ${flagIDFilter ? 'bg-emerald-950/20' : ''}`}
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
                    <td className="px-3 py-1.5 text-gray-300 font-mono text-xs">{getPeerIP(pkt)}</td>
                    <td className="px-3 py-1.5 text-gray-300 text-xs">{pkt.method}</td>
                    <td className="px-3 py-1.5 text-gray-400 text-xs truncate max-w-xs">{pkt.url || (pkt.body_string?.slice(0, 80)) || '\u2014'}</td>
                    <td className="px-3 py-1.5 text-xs">
                      {pkt.status > 0 && <span className={`${pkt.status < 400 ? 'text-green-400' : 'text-red-400'}`}>{pkt.status}</span>}
                    </td>
                    <td className="px-3 py-1.5 flex items-center gap-1">
                      {pkt.flagged && <span className="text-yellow-400 text-xs" title="Contains flag">&#9873;</span>}
                      {pkt.matched_rules?.length > 0 && <span className="text-red-400 text-xs" title="Rule matched">&#9888;</span>}
                      <button
                        onClick={(e) => { e.stopPropagation(); showFlow(pkt) }}
                        className="text-gray-600 hover:text-purple-400 text-xs cursor-pointer ml-auto"
                        title={`Show flow for ${getPeerIP(pkt)}`}
                      >
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>
                        </svg>
                      </button>
                    </td>
                  </tr>
                ))}
                {displayPackets.length === 0 && (
                  <tr><td colSpan="8" className="text-center py-8 text-gray-600">No packets found</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between px-3 py-2 bg-gray-900 border-t border-gray-800 text-sm text-gray-400">
            <span>{displayTotal} packet{displayTotal !== 1 ? 's' : ''}</span>
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
                </div>
                <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
              </div>
              <div className="p-3 space-y-2 text-sm">
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
                      <HighlightedText text={selected.url} contains={filters.contains} regex={highlightRegex} />
                    </span>
                  </div>
                )}

                {selected.flagged && (
                  <div className="bg-yellow-900/20 border border-yellow-800/50 rounded px-2 py-1 text-yellow-400 text-xs">
                    Contains flag pattern
                  </div>
                )}

                {selected.matched_rules?.length > 0 && (
                  <div className="bg-red-900/20 border border-red-800/50 rounded px-2 py-1">
                    <span className="text-red-400 text-xs font-medium">Matched: </span>
                    {selected.matched_rules.map((r, i) => (
                      <span key={r.id} className="text-red-300 text-xs">{i > 0 && ', '}{r.name}</span>
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
                          <HighlightedText text={v} contains={filters.contains} regex={highlightRegex} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selected.body_string && (
                  <div className="flex-1">
                    <div className="text-gray-500 text-xs mb-1">Body</div>
                    <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '60vh' }}>
                      <HighlightedText text={selected.body_string} contains={filters.contains} regex={highlightRegex} />
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
