import { useState, useEffect, useCallback, useMemo, useRef, memo } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { getTrafficNavKeys } from '../trafficNavKeys'
import QuickRulePanel from '../components/QuickRulePanel'
import { copyText } from '../utils/clipboard'
import { tryFormatJSON } from '../utils/formatting'

function base64ToBytes(b64) {
  if (!b64) return new Uint8Array()
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  } catch { return new Uint8Array() }
}

function fmtTime(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleTimeString()
}

function flowPcapUrl(anchorPacketId) {
  return api.flowPcapDownloadUrl(anchorPacketId)
}

// ---- Packet detail panel (reused per flow column) ----

const PacketDetail = memo(function PacketDetail({ packet, services, onClose, onCopyExploit, copyStatus }) {
  const [showQuickRule, setShowQuickRule] = useState(false)

  // Close the rule panel when switching to a different packet.
  useEffect(() => { setShowQuickRule(false) }, [packet?.id])

  const formattedBody = useMemo(() => tryFormatJSON(packet?.body_string || ''), [packet?.body_string])
  if (!packet) return null
  return (
    <div className="flex-shrink-0 w-96 bg-gray-900 border-l border-gray-800 overflow-auto">
      <div className="flex items-center justify-between p-3 border-b border-gray-800 sticky top-0 bg-gray-900 z-10">
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="text-sm font-medium text-gray-100">Packet #{packet.id}</h3>
          {onCopyExploit && (
            <button
              onClick={() => onCopyExploit(packet.id)}
              disabled={copyStatus === 'copying'}
              className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer disabled:opacity-50"
              title="Generate exploit skeleton from this flow"
            >
              {copyStatus === 'copying' ? '…' : 'Exploit'}
            </button>
          )}
          <button
            onClick={() => setShowQuickRule((v) => !v)}
            className={`text-xs flex items-center gap-1 cursor-pointer transition-colors ${showQuickRule ? 'text-red-300' : 'text-red-400 hover:text-red-300'}`}
            title="Create a drop/alert rule from this packet"
          >
            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            Block
          </button>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 cursor-pointer text-lg leading-none">&times;</button>
      </div>
      <div className="p-3 space-y-2 text-sm">
        {showQuickRule && services && (
          <QuickRulePanel
            packet={packet}
            services={services}
            onCreated={() => setShowQuickRule(false)}
            onCancel={() => setShowQuickRule(false)}
          />
        )}
        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs bg-gray-800/50 rounded p-2">
          <div><span className="text-gray-500">Time </span><span className="text-gray-300">{fmtTime(packet.timestamp)}</span></div>
          <div><span className="text-gray-500">Protocol </span><span className="text-gray-300">{packet.protocol}</span></div>
          <div><span className="text-gray-500">Direction </span><span className={packet.direction === 'request' ? 'text-blue-400' : 'text-green-400'}>{packet.direction === 'request' ? 'Request' : 'Response'}</span></div>
          <div><span className="text-gray-500">Session </span><span className="text-gray-300 font-mono text-[10px] truncate">{packet.session_id}</span></div>
          <div><span className="text-gray-500">Src </span><span className="text-gray-300 font-mono">{packet.src_ip}:{packet.src_port}</span></div>
          <div><span className="text-gray-500">Dst </span><span className="text-gray-300 font-mono">{packet.dst_ip}:{packet.dst_port}</span></div>
          {packet.method && <div><span className="text-gray-500">Method </span><span className="text-gray-300">{packet.method}</span></div>}
          {packet.status > 0 && <div><span className="text-gray-500">Status </span><span className={packet.status < 400 ? 'text-green-400' : 'text-red-400'}>{packet.status}</span></div>}
        </div>
        {packet.url && (
          <div className="text-xs">
            <span className="text-gray-500">URL </span>
            <span className="text-gray-300 break-all font-mono">{packet.url}</span>
          </div>
        )}
        {packet.matched_rules?.length > 0 && (
          <div className="border rounded px-2 py-1 bg-red-900/20 border-red-800/50">
            <span className="text-xs font-medium text-red-400">Matched: </span>
            {packet.matched_rules.map((r, i) => (
              <span key={r.id} className="text-xs text-red-300">
                {i > 0 && ', '}{r.name}{r.action ? <span className="text-gray-500 ml-1">({r.action})</span> : null}
              </span>
            ))}
          </div>
        )}
        {packet.headers && Object.keys(packet.headers).length > 0 && (
          <div>
            <div className="text-gray-500 text-xs mb-1">Headers</div>
            <div className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto" style={{ maxHeight: '35vh' }}>
              {Object.entries(packet.headers).map(([k, v]) => (
                <div key={k}><span className="text-cyan-400">{k}:</span> {v}</div>
              ))}
            </div>
          </div>
        )}
        {(packet.body_string || packet.body) && (
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-gray-500 text-xs">Body</span>
              {formattedBody.isJSON && <span className="text-[10px] text-cyan-600 bg-cyan-900/30 px-1 py-0.5 rounded">JSON</span>}
              {packet.body && <span className="text-[10px] text-gray-600 font-mono">{base64ToBytes(packet.body).length} bytes</span>}
              <button
                onClick={() => copyText(packet.body_string || '')}
                disabled={!packet.body_string}
                className="text-[10px] text-gray-600 hover:text-gray-400 ml-auto cursor-pointer disabled:opacity-50"
              >Copy</button>
            </div>
            <pre className="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: '55vh' }}>
              {packet.body_string || <span className="text-gray-500">(non-UTF8 body)</span>}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
})

// ---- Single-flow inspector: list on left, selected packet detail on right ----

function FlowInspector({ flowData, services, diffSet, onNavigate, onCopyExploit, copyStatus, isFocused, onFocus }) {
  const { flow, packets, missing_count: missing } = flowData
  const [selectedId, setSelectedId] = useState(null)
  const selected = useMemo(() => packets.find((p) => p.id === selectedId) || null, [packets, selectedId])
  const tableRef = useRef(null)

  // Arrow-key navigation. Only the focused inspector handles keys so side-by-
  // side comparison doesn't fight for them.
  useEffect(() => {
    if (!isFocused) return
    function typingTarget(el) {
      const t = el?.tagName
      return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el?.isContentEditable
    }
    function onKeyDown(e) {
      if (typingTarget(e.target)) return
      if (packets.length === 0) return
      const { up, down } = getTrafficNavKeys()
      let delta = 0
      if (up.includes(e.key)) delta = -1
      else if (down.includes(e.key)) delta = 1
      else return
      e.preventDefault()
      let idx = selectedId != null ? packets.findIndex((p) => p.id === selectedId) : -1
      if (idx === -1) idx = delta > 0 ? 0 : packets.length - 1
      else idx = Math.max(0, Math.min(packets.length - 1, idx + delta))
      const next = packets[idx]
      if (next) setSelectedId(next.id)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [isFocused, packets, selectedId])

  // Scroll the selected row into view when it changes.
  useEffect(() => {
    if (selectedId == null || !tableRef.current) return
    const row = tableRef.current.querySelector(`tr[data-packet-id="${selectedId}"]`)
    row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [selectedId])

  return (
    <div className="flex flex-col h-full min-h-0 flex-1 min-w-0" onMouseDown={onFocus}>
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-900/60">
        <div className="flex items-baseline gap-2 min-w-0">
          <span className="text-sm font-medium text-purple-300 truncate">{flow.name}</span>
          {flow.created_by && <span className="text-[10px] text-gray-600">by {flow.created_by}</span>}
          {flow.notes && <span className="text-xs text-gray-500 truncate">{flow.notes}</span>}
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <button
            onClick={() => onNavigate(flow.anchor_packet_id)}
            className="text-xs text-purple-400 hover:text-purple-300 cursor-pointer"
            title="Open in Traffic page"
          >Open in Traffic</button>
          <a
            href={flowPcapUrl(flow.anchor_packet_id)}
            download={`flow-${flow.anchor_packet_id}.pcap`}
            className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
            title="Download this flow as a .pcap file"
          >⬇ PCAP</a>
          <span className="text-[11px] text-gray-600">
            {packets.length} packets{missing > 0 ? ` (${missing} deleted)` : ''}
          </span>
        </div>
      </div>
      <div className="flex-1 flex min-h-0">
        <div ref={tableRef} className="flex-1 overflow-auto min-w-0">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-900 z-10">
              <tr className="text-left text-gray-600 border-b border-gray-800">
                <th className="px-2 py-2 w-10">#</th>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Dir</th>
                <th className="px-3 py-2">Method</th>
                <th className="px-3 py-2">URL / Body</th>
                <th className="px-3 py-2 w-14">Status</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt, i) => {
                const isSelected = pkt.id === selectedId
                const isDiff = diffSet?.has(i)
                return (
                  <tr
                    key={pkt.id}
                    data-packet-id={pkt.id}
                    onClick={() => setSelectedId((prev) => prev === pkt.id ? null : pkt.id)}
                    className={`border-b border-gray-800/40 cursor-pointer transition-colors ${
                      isSelected ? 'bg-gray-800' : (isDiff ? 'bg-yellow-950/20 hover:bg-yellow-950/30' : 'hover:bg-gray-900/60')
                    }`}
                  >
                    <td className="px-2 py-1.5 text-gray-600 text-right">{i + 1}</td>
                    <td className="px-3 py-1.5 font-mono text-gray-500 whitespace-nowrap">{fmtTime(pkt.timestamp)}</td>
                    <td className="px-3 py-1.5">
                      <span className={`px-1.5 py-0.5 rounded ${pkt.direction === 'request' ? 'bg-blue-900/40 text-blue-400' : 'bg-green-900/40 text-green-400'}`}>
                        {pkt.direction === 'request' ? 'REQ' : 'RES'}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-gray-400">{pkt.method}</td>
                    <td className="px-3 py-1.5 text-gray-300 truncate max-w-md">
                      {pkt.url || pkt.body_string?.slice(0, 80) || '—'}
                    </td>
                    <td className="px-3 py-1.5">
                      {pkt.status > 0 && <span className={pkt.status < 400 ? 'text-green-400' : 'text-red-400'}>{pkt.status}</span>}
                    </td>
                  </tr>
                )
              })}
              {packets.length === 0 && (
                <tr><td colSpan="6" className="text-center py-8 text-gray-700">All packets in this flow were deleted</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {selected && (
          <PacketDetail
            packet={selected}
            services={services}
            onClose={() => setSelectedId(null)}
            onCopyExploit={onCopyExploit}
            copyStatus={copyStatus}
          />
        )}
      </div>
    </div>
  )
}

// ---- Main page ----

export default function SavedFlows() {
  const navigate = useNavigate()
  const [flows, setFlows] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedIds, setSelectedIds] = useState([]) // array to preserve order
  const [flowData, setFlowData] = useState({}) // id -> { flow, packets, missing_count }
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [error, setError] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [copyStatus, setCopyStatus] = useState(null)
  const [services, setServices] = useState([])
  const [focusedFlowId, setFocusedFlowId] = useState(null)

  useEffect(() => { api.listServices().then((d) => setServices(d || [])).catch(() => {}) }, [])

  const loadFlows = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.listSavedFlows()
      setFlows(data.flows || [])
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { loadFlows() }, [loadFlows])

  const toggleSelect = useCallback(async (id) => {
    const already = selectedIds.includes(id)
    if (already) {
      setSelectedIds((prev) => prev.filter((x) => x !== id))
      return
    }
    // Cap at 2 selections to keep comparison usable; newest replaces oldest.
    setSelectedIds((prev) => (prev.length >= 2 ? [prev[1], id] : [...prev, id]))
    if (!flowData[id]) {
      setLoadingDetail(true)
      try {
        const data = await api.getSavedFlow(id)
        setFlowData((prev) => ({ ...prev, [id]: data }))
      } catch (err) { setError(err.message) }
      finally { setLoadingDetail(false) }
    }
  }, [selectedIds, flowData])

  async function deleteFlow(id, e) {
    e.stopPropagation()
    if (!confirm('Delete this saved flow?')) return
    try {
      await api.deleteSavedFlow(id)
      setFlows((prev) => prev.filter(f => f.id !== id))
      setSelectedIds((prev) => prev.filter((x) => x !== id))
      setFlowData((prev) => { const n = { ...prev }; delete n[id]; return n })
    } catch (err) { setError(err.message) }
  }

  async function deleteSelectedFlows() {
    if (selectedIds.length === 0) return
    if (!confirm(`Delete ${selectedIds.length} selected flow${selectedIds.length !== 1 ? 's' : ''}?`)) return
    const ids = [...selectedIds]
    try {
      await Promise.all(ids.map((id) => api.deleteSavedFlow(id)))
      setFlows((prev) => prev.filter(f => !ids.includes(f.id)))
      setSelectedIds([])
      setFlowData((prev) => {
        const n = { ...prev }
        ids.forEach((id) => delete n[id])
        return n
      })
    } catch (err) { setError(err.message) }
  }

  function openInTraffic(anchorPacketId) {
    navigate('/traffic', { state: { openFlowForPacketId: anchorPacketId } })
  }

  async function handleCopyExploit(packetId) {
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

  const loadedSelected = selectedIds.map((id) => flowData[id]).filter(Boolean)
  const isComparison = loadedSelected.length === 2

  // Keep keyboard focus on a sensible inspector: default to the first selected,
  // and clear focus if its flow is deselected.
  useEffect(() => {
    if (selectedIds.length === 0) { setFocusedFlowId(null); return }
    if (focusedFlowId == null || !selectedIds.includes(focusedFlowId)) {
      setFocusedFlowId(selectedIds[0])
    }
  }, [selectedIds, focusedFlowId])

  // Compute the set of "differing" row indices when comparing two flows.
  // A row index is flagged if method|url|direction differs between the two.
  const diffSets = useMemo(() => {
    if (!isComparison) return [null, null]
    const [a, b] = loadedSelected
    const maxLen = Math.max(a.packets.length, b.packets.length)
    const aDiffs = new Set()
    const bDiffs = new Set()
    for (let i = 0; i < maxLen; i++) {
      const pa = a.packets[i]
      const pb = b.packets[i]
      const la = pa ? `${pa.method || ''}|${pa.url || ''}|${pa.direction || ''}|${pa.body_string || ''}` : ''
      const lb = pb ? `${pb.method || ''}|${pb.url || ''}|${pb.direction || ''}|${pb.body_string || ''}` : ''
      if (la !== lb) { aDiffs.add(i); bDiffs.add(i) }
    }
    return [aDiffs, bDiffs]
  }, [loadedSelected, isComparison])

  return (
    <div className="flex h-full">
      {/* Collapsed rail (thin vertical strip with expand button) */}
      {!sidebarOpen && (
        <div className="w-8 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col items-center py-2">
          <button
            onClick={() => setSidebarOpen(true)}
            title="Expand saved flows list"
            className="text-gray-500 hover:text-gray-200 cursor-pointer text-xs w-full py-2"
          >▶</button>
          <div className="text-[10px] text-gray-600 mt-2 [writing-mode:vertical-rl] rotate-180">
            {flows.length} saved
          </div>
        </div>
      )}

      {/* Left: flow list (collapsible) */}
      {sidebarOpen && (
        <div className="w-72 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
            <h2 className="text-sm font-medium text-gray-100">Saved Flows</h2>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-600">{flows.length} saved</span>
              <button
                onClick={() => setSidebarOpen(false)}
                title="Collapse list"
                className="text-gray-500 hover:text-gray-200 cursor-pointer text-xs"
              >◀</button>
            </div>
          </div>
          {selectedIds.length > 0 && (
            <div className="px-3 py-2 border-b border-gray-800 bg-gray-900/60 flex items-center justify-between">
              <span className="text-[11px] text-gray-500">{selectedIds.length} selected</span>
              <button
                onClick={deleteSelectedFlows}
                className="text-[11px] px-2 py-1 rounded bg-red-900/40 text-red-300 hover:bg-red-800/50 hover:text-red-200 border border-red-800/50 cursor-pointer"
                title="Delete selected saved flows"
              >Delete selected</button>
            </div>
          )}
          {error && <div className="mx-3 mt-2 text-xs text-red-400 bg-red-900/20 border border-red-800/50 rounded px-2 py-1">{error}</div>}
          <div className="flex-1 overflow-auto py-1">
            {loading && <div className="text-center py-8 text-gray-600 text-sm">Loading…</div>}
            {!loading && flows.length === 0 && (
              <div className="text-center py-8 text-gray-700 text-sm">
                No saved flows yet.<br />
                <span className="text-xs text-gray-600">Use "Pin flow" in the Traffic page.</span>
              </div>
            )}
            {flows.map((flow) => {
              const idx = selectedIds.indexOf(flow.id)
              const isSelected = idx !== -1
              return (
                <div
                  key={flow.id}
                  onClick={() => toggleSelect(flow.id)}
                  className={`flex items-start gap-2 px-3 py-2.5 cursor-pointer border-b border-gray-800/40 transition-colors ${
                    isSelected ? 'bg-purple-950/40 hover:bg-purple-950/50' : 'hover:bg-gray-800/50'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => {}}
                    onClick={(e) => e.stopPropagation()}
                    className="mt-0.5 accent-purple-500 flex-shrink-0 cursor-pointer"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-sm text-gray-200 truncate">{flow.name}</span>
                      {isSelected && <span className="text-[10px] px-1 rounded bg-purple-800/60 text-purple-200">{idx === 0 ? 'A' : 'B'}</span>}
                    </div>
                    <div className="text-xs text-gray-600 mt-0.5">
                      <span>{flow.packet_ids?.length ?? 0} packets</span>
                      {flow.created_by && <span className="ml-2">by {flow.created_by}</span>}
                    </div>
                    <div className="text-xs text-gray-700">{new Date(flow.created_at).toLocaleString()}</div>
                    {flow.notes && <div className="text-xs text-gray-500 italic truncate mt-0.5">{flow.notes}</div>}
                  </div>
                  <button
                    onClick={(e) => deleteFlow(flow.id, e)}
                    className="text-gray-700 hover:text-red-400 cursor-pointer text-sm flex-shrink-0 mt-0.5"
                    title="Delete"
                  >✕</button>
                </div>
              )
            })}
          </div>
          {isComparison && (
            <div className="px-3 py-2 border-t border-gray-800 text-xs text-purple-400 bg-purple-950/20">
              Comparing two flows — differing rows highlighted in yellow.
            </div>
          )}
        </div>
      )}

      {/* Right: detail / comparison */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {loadingDetail && loadedSelected.length === 0 && (
          <div className="flex-1 flex items-center justify-center text-gray-600 text-sm">Loading flow…</div>
        )}
        {!loadingDetail && loadedSelected.length === 0 && (
          <div className="flex-1 flex items-center justify-center text-gray-700 text-sm">
            Select a flow from the list to inspect it. Select a second to compare.
          </div>
        )}
        {loadedSelected.length === 1 && (
          <FlowInspector
            flowData={loadedSelected[0]}
            services={services}
            diffSet={null}
            onNavigate={openInTraffic}
            onCopyExploit={handleCopyExploit}
            copyStatus={copyStatus}
            isFocused={focusedFlowId === loadedSelected[0].flow.id}
            onFocus={() => setFocusedFlowId(loadedSelected[0].flow.id)}
          />
        )}
        {isComparison && (
          <>
            <FlowInspector
              flowData={loadedSelected[0]}
              services={services}
              diffSet={diffSets[0]}
              onNavigate={openInTraffic}
              onCopyExploit={handleCopyExploit}
              copyStatus={copyStatus}
              isFocused={focusedFlowId === loadedSelected[0].flow.id}
              onFocus={() => setFocusedFlowId(loadedSelected[0].flow.id)}
            />
            <div className="w-px bg-gray-800 flex-shrink-0" />
            <FlowInspector
              flowData={loadedSelected[1]}
              services={services}
              diffSet={diffSets[1]}
              onNavigate={openInTraffic}
              onCopyExploit={handleCopyExploit}
              copyStatus={copyStatus}
              isFocused={focusedFlowId === loadedSelected[1].flow.id}
              onFocus={() => setFocusedFlowId(loadedSelected[1].flow.id)}
            />
          </>
        )}
      </div>

      {copyStatus === 'copied' && <div className="fixed bottom-4 right-4 bg-green-800 text-green-200 text-xs px-3 py-1.5 rounded-full z-50">Exploit copied!</div>}
      {copyStatus === 'error' && <div className="fixed bottom-4 right-4 bg-red-800 text-red-200 text-xs px-3 py-1.5 rounded-full z-50">Failed to generate exploit</div>}
    </div>
  )
}
