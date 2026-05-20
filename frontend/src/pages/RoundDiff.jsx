import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import ErrorBanner from '../components/ErrorBanner'

// All the heavy lifting (tokenisation, novelty scoring, twin selection,
// char-level diff, suspicion tagging, route grouping) now lives in the Go
// backend at /api/round-diff. This page just renders the result and exposes
// inspect / open-flow actions on every packet referenced.

export default function RoundDiff() {
  const navigate = useNavigate()
  const [services, setServices] = useState([])
  const [selected, setSelected] = useState([])
  const [roundA, setRoundA] = useState('')
  const [roundB, setRoundB] = useState('')
  const [includeDiff, setIncludeDiff] = useState(true)
  const [topK, setTopK] = useState(24)
  const [rows, setRows] = useState([])
  const [packet, setPacket] = useState(null)
  const [packetError, setPacketError] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.listServices().then((svcs) => {
      const list = svcs || []
      setServices(list)
      setSelected(list.slice(0, 2).map((s) => s.id))
    }).catch((err) => setError(err.message))
    api.getFlagIDStatus().then((st) => {
      const cur = st?.clock_round || st?.current_round
      if (cur > 1) {
        setRoundA(String(cur - 1))
        setRoundB(String(cur))
      }
    }).catch(() => {})
  }, [])

  const canRun = useMemo(
    () => selected.length > 0 && Number(roundA) > 0 && Number(roundB) > 0,
    [selected, roundA, roundB],
  )
  const oneService = selected.length === 1

  function toggleService(id) {
    setSelected((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id)
      if (prev.length >= 2) return prev
      return [...prev, id]
    })
  }

  async function inspectPacket(id) {
    setPacketError('')
    try {
      setPacket(await api.getPacket(id))
    } catch (err) {
      setPacketError(err.message)
    }
  }

  function openFlow(id) {
    navigate('/traffic', {
      state: {
        openFlowForPacketId: id,
        flowReturn: { path: '/round-diff' },
      },
    })
  }

  async function loadDiff() {
    if (!canRun) return
    setLoading(true)
    setError('')
    setPacket(null)
    try {
      const results = await Promise.all(selected.map((svcId) =>
        api.getRoundDiff({
          service_id: svcId,
          round_a: Number(roundA),
          round_b: Number(roundB),
          top_k: topK,
          include_diff: includeDiff ? '1' : '0',
        }),
      ))
      setRows(results)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-semibold text-gray-100">Round Diff</h2>
        <button
          onClick={loadDiff}
          disabled={!canRun || loading}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer disabled:cursor-default"
        >
          {loading ? 'Comparing...' : 'Compare'}
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
        <div className="flex items-end gap-3 flex-wrap">
          <label className="text-sm text-gray-400">
            Round A
            <input value={roundA} onChange={(e) => setRoundA(e.target.value)} type="number" min="1"
              className="block mt-1 w-24 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
          </label>
          <label className="text-sm text-gray-400">
            Round B
            <input value={roundB} onChange={(e) => setRoundB(e.target.value)} type="number" min="1"
              className="block mt-1 w-24 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
          </label>
          <label className="text-sm text-gray-400">
            Top K
            <input value={topK} onChange={(e) => setTopK(Math.max(1, Math.min(200, Number(e.target.value) || 1)))} type="number" min="1" max="200"
              className="block mt-1 w-20 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
          </label>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] uppercase tracking-wide text-gray-600 mr-1">Services max 2</span>
            {services.map((svc) => {
              const active = selected.includes(svc.id)
              const disabled = !active && selected.length >= 2
              return (
                <button key={svc.id} onClick={() => toggleService(svc.id)} disabled={disabled}
                  className={`text-xs px-2 py-1 rounded border transition-colors cursor-pointer disabled:cursor-default ${
                    active
                      ? 'bg-cyan-700/40 border-cyan-600 text-cyan-100'
                      : disabled
                        ? 'bg-gray-900 border-gray-800 text-gray-700'
                        : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
                  }`}
                >
                  {svc.name}
                </button>
              )
            })}
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-400 ml-auto">
            <input type="checkbox" checked={includeDiff} onChange={(e) => setIncludeDiff(e.target.checked)} className="accent-cyan-500" />
            Inline diff
          </label>
        </div>
      </div>

      <ErrorBanner error={error || packetError} className="mb-4" />

      <div className={`${oneService ? 'grid grid-cols-1' : 'grid grid-cols-1 xl:grid-cols-2'} gap-4 overflow-auto`}>
        {rows.map((r) => (
          <ServiceCard
            key={r.service_id}
            data={r}
            roundA={roundA}
            roundB={roundB}
            onInspect={inspectPacket}
            onFlow={openFlow}
          />
        ))}
        {!loading && rows.length === 0 && (
          <div className="text-gray-600 text-sm">Choose one or two services, then compare.</div>
        )}
      </div>

      {packet && (
        <div className="mt-4 bg-gray-900 border border-cyan-800/50 rounded-lg p-4 text-xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-300">Packet <span className="font-mono text-cyan-300">#{packet.id}</span></span>
            <div className="flex items-center gap-3">
              <button onClick={() => openFlow(packet.id)} className="text-purple-300 hover:text-purple-200 cursor-pointer">open flow</button>
              <button onClick={() => setPacket(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer">close</button>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-2 mb-2 text-gray-400">
            <div>Dir <span className="text-gray-200">{packet.direction}</span></div>
            <div>Status <span className="text-gray-200">{packet.status || '-'}</span></div>
            <div>Src <span className="font-mono text-gray-300">{packet.src_ip}:{packet.src_port}</span></div>
            <div>Dst <span className="font-mono text-gray-300">{packet.dst_ip}:{packet.dst_port}</span></div>
          </div>
          {packet.url && <div className="bg-gray-800 rounded p-2 mb-2 font-mono text-gray-300 break-all">{packet.method} {packet.url}</div>}
          <div className="grid grid-cols-2 gap-2">
            <pre className="bg-gray-800 rounded p-2 text-gray-300 overflow-auto whitespace-pre-wrap break-all max-h-72">{JSON.stringify(packet.headers || {}, null, 2)}</pre>
            <pre className="bg-gray-800 rounded p-2 text-gray-300 overflow-auto whitespace-pre-wrap break-all max-h-72">{packet.body_string || '(empty body)'}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

function ServiceCard({ data, roundA, roundB, onInspect, onFlow }) {
  if (!data) return null
  const { stats_a: sa, stats_b: sb, novel_packets: novels = [], suspicious_in_b: suspicious = [],
    new_routes: newR = [], gone_routes: goneR = [], changed_routes: changedR = [] } = data
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-lg font-medium text-gray-100">{data.service_name || data.service_id}</h3>
        <span className="text-[10px] uppercase tracking-wide text-gray-600">
          rounds {roundA} → {roundB} · scanned {data.packets_scanned}
          {data.truncated && <span className="text-amber-400 ml-2">· truncated</span>}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs mb-4">
        <StatsBox label={`Round ${roundA}`} stats={sa} />
        <StatsBox label={`Round ${roundB}`} stats={sb} />
      </div>

      <SuspiciousSection items={suspicious} onInspect={onInspect} onFlow={onFlow} />

      <NovelSection items={novels} onInspect={onInspect} onFlow={onFlow} />

      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
        <RouteList title="New route patterns" items={newR} primary="count_b" color="text-emerald-300" />
        <RouteList title="Gone route patterns" items={goneR} primary="count_a" color="text-red-300" />
        <RouteDeltaList title="Changed route volume" items={changedR} />
      </div>
    </div>
  )
}

function StatsBox({ label, stats }) {
  const s = stats || {}
  return (
    <div className="bg-gray-800/60 rounded p-2">
      <div className="text-gray-500 mb-1">{label}</div>
      <div className="grid grid-cols-3 gap-y-1">
        <span>Total <b className="text-gray-200">{s.total || 0}</b></span>
        <span>Req <b className="text-blue-300">{s.req || 0}</b></span>
        <span>Res <b className="text-green-300">{s.res || 0}</b></span>
        <span>Flags <b className="text-yellow-300">{s.flagged || 0}</b></span>
        <span>FlagIDs <b className="text-teal-300">{s.flagids || 0}</b></span>
        <span>Drops <b className="text-red-300">{s.dropped || 0}</b></span>
      </div>
    </div>
  )
}

function SuspiciousSection({ items, onInspect, onFlow }) {
  if (!items || items.length === 0) return null
  return (
    <div className="mb-4 bg-red-950/20 border border-red-900/50 rounded p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-red-200">Suspicious payloads ({items.length} buckets)</span>
        <span className="text-[10px] uppercase tracking-wide text-red-400/70">attack-shape matches in round B</span>
      </div>
      <div className="space-y-1 max-h-72 overflow-auto">
        {items.map((b) => (
          <div key={b.key} className="bg-gray-900/60 rounded px-2 py-1 text-xs">
            <div className="flex items-start justify-between gap-2">
              <span className="text-red-200 font-mono">
                {b.scope} · {(b.tags || []).join(' + ')}
              </span>
              <span className="text-gray-500 whitespace-nowrap">{b.count}</span>
            </div>
            {b.samples?.length > 0 && (
              <div className="mt-1 flex items-center gap-1 flex-wrap">
                {b.samples.map((s) => (
                  <span key={s.packet_id} className="flex items-center gap-1">
                    <button onClick={() => onInspect(s.packet_id)} className="text-cyan-300 hover:text-cyan-200 font-mono cursor-pointer">#{s.packet_id}</button>
                    <button onClick={() => onFlow(s.packet_id)} className="text-purple-300 hover:text-purple-200 cursor-pointer">flow</button>
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function NovelSection({ items, onInspect, onFlow }) {
  if (!items || items.length === 0) {
    return (
      <div className="text-xs text-gray-600">
        No novel packets vs round A — every payload in round B shares its tokens with prior traffic.
      </div>
    )
  }
  return (
    <div className="mb-2">
      <div className="text-sm text-gray-300 mb-2">Most novel packets in round B ({items.length})</div>
      <div className="space-y-2 max-h-[36rem] overflow-auto">
        {items.map((it) => (
          <NovelPacketRow key={it.packet_id} item={it} onInspect={onInspect} onFlow={onFlow} />
        ))}
      </div>
    </div>
  )
}

function NovelPacketRow({ item, onInspect, onFlow }) {
  const [expanded, setExpanded] = useState(false)
  const pct = Math.round((item.score || 0) * 100)
  const tags = item.suspicion_tags || []
  return (
    <div className="bg-gray-950/50 border border-gray-800 rounded p-2 text-xs">
      <div className="flex items-center justify-between gap-2 mb-1">
        <div className="flex items-center gap-2 min-w-0">
          <button onClick={() => setExpanded((v) => !v)} className="text-gray-500 hover:text-gray-300 cursor-pointer font-mono w-4">
            {expanded ? '▼' : '▶'}
          </button>
          <span className="font-mono text-cyan-300 truncate">{item.route_key}</span>
          {tags.length > 0 && (
            <span className="text-red-300 font-mono">!{tags.join('+')}</span>
          )}
        </div>
        <div className="flex items-center gap-2 whitespace-nowrap">
          <span className={`font-mono ${pct >= 50 ? 'text-red-300' : pct >= 20 ? 'text-amber-300' : 'text-gray-400'}`}>{pct}%</span>
          <span className="text-gray-600">{item.scope}</span>
          <button onClick={() => onInspect(item.packet_id)} className="text-cyan-300 hover:text-cyan-200 font-mono cursor-pointer">#{item.packet_id}</button>
          <button onClick={() => onFlow(item.packet_id)} className="text-purple-300 hover:text-purple-200 cursor-pointer">flow</button>
        </div>
      </div>
      {item.novel_tokens?.length > 0 && (
        <div className="text-[11px] text-gray-500 mb-1">
          novel: <span className="font-mono text-amber-200">{item.novel_tokens.join(' · ')}</span>
        </div>
      )}
      <div className="font-mono text-gray-400 break-all whitespace-pre-wrap text-[11px] line-clamp-2">
        {item.preview}
      </div>
      {expanded && item.diff && item.diff.length > 0 && (
        <DiffViewer ops={item.diff} twinPacketId={item.twin_packet_id} onInspect={onInspect} onFlow={onFlow} />
      )}
      {expanded && (!item.diff || item.diff.length === 0) && (
        <div className="mt-2 text-[11px] text-gray-600 italic">
          No twin found in round A for this route — every byte is new.
        </div>
      )}
    </div>
  )
}

function DiffViewer({ ops, twinPacketId, onInspect, onFlow }) {
  return (
    <div className="mt-2 bg-gray-900/60 border border-gray-800 rounded p-2">
      <div className="flex items-center justify-between mb-1 text-[10px] uppercase tracking-wide text-gray-600">
        <span>Diff vs closest round-A twin</span>
        {twinPacketId > 0 && (
          <span className="flex items-center gap-2">
            <button onClick={() => onInspect(twinPacketId)} className="text-cyan-400 hover:text-cyan-200 font-mono cursor-pointer">#{twinPacketId}</button>
            <button onClick={() => onFlow(twinPacketId)} className="text-purple-400 hover:text-purple-200 cursor-pointer">flow</button>
          </span>
        )}
      </div>
      <div className="font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all">
        {ops.map((op, i) => {
          if (op.op === 'eq') return <span key={i} className="text-gray-400">{op.text}</span>
          if (op.op === 'ins') return <span key={i} className="bg-emerald-900/40 text-emerald-200 rounded px-0.5">{op.text}</span>
          if (op.op === 'del') return <span key={i} className="bg-red-900/40 text-red-200 line-through rounded px-0.5">{op.text}</span>
          return null
        })}
      </div>
    </div>
  )
}

function RouteList({ title, items, primary, color }) {
  return (
    <div>
      <div className="text-xs text-gray-500 mb-1">{title}</div>
      {items.length === 0 ? (
        <div className="text-xs text-gray-700">No change</div>
      ) : (
        <div className="space-y-1 max-h-60 overflow-auto">
          {items.map((it) => (
            <div key={it.key} className="flex items-center justify-between gap-3 text-xs bg-gray-800/40 rounded px-2 py-1">
              <span className={`${color} font-mono truncate`}>{it.key}</span>
              <span className="text-gray-500">{it[primary]}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RouteDeltaList({ title, items }) {
  return (
    <div>
      <div className="text-xs text-gray-500 mb-1">{title}</div>
      {items.length === 0 ? (
        <div className="text-xs text-gray-700">No change</div>
      ) : (
        <div className="space-y-1 max-h-60 overflow-auto">
          {items.map((it) => {
            const delta = (it.count_b || 0) - (it.count_a || 0)
            return (
              <div key={it.key} className="flex items-center justify-between gap-3 text-xs bg-gray-800/40 rounded px-2 py-1">
                <span className="text-gray-300 font-mono truncate">{it.key}</span>
                <span className={delta > 0 ? 'text-emerald-300' : 'text-red-300'}>
                  {it.count_a}{' -> '}{it.count_b} ({delta > 0 ? '+' : ''}{delta})
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
