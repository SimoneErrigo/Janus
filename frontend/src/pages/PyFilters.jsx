import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'

// --- example scripts, one per pattern, so alert vs drop is obvious ---

const ALERT_EXAMPLE = `# ALERT ONLY — return a string (the reason) to raise an Alert.
# flow is forgiving: flow.method, flow.path, flow.headers["x"], flow.json()...
def match(flow):
    if flow.method == "POST" and "/admin" in flow.path:
        return "POST to an admin endpoint"   # string -> ALERT
    return False
`

const DROP_EXAMPLE = `# ALERT + DROP (async) — return a dict with a "drop" filter expression to
# block FUTURE matching traffic (fail2ban-style, content-only, never by IP).
def match(flow):
    if "sqlmap" in flow.header("user-agent").lower():   # missing header -> ""
        return {
            "match": True,
            "reason": "sqlmap user-agent",
            "drop": 'header.User-Agent icontains "sqlmap"',
        }
    return False
`

const STATEFUL_EXAMPLE = `# STATEFUL — module-level state persists across packets. Here: alert (and
# block) a user only from their SECOND login onward. Use Repeat >= 2 to test.
logins = {}

def match(flow):
    if flow.method == "POST" and flow.path == "/login":
        user = (flow.json() or {}).get("user")   # parsed body, None-safe
        if user:
            logins[user] = logins.get(user, 0) + 1
            if logins[user] > 1:
                return {
                    "match": True,
                    "reason": "repeated login for %s (#%d)" % (user, logins[user]),
                    "drop": 'body contains "\\"user\\":\\"%s\\""' % user,
                }
    return False
`

const BLOCK_EXAMPLE = `# INLINE BLOCK — return {"drop": True} to drop the CURRENT request in real
# time (not just future traffic). Requires the "Blocking" checkbox: the script
# then runs synchronously on the request path. Here: block a registration whose
# password was already used by an earlier one.
seen = {}

def match(flow):
    if flow.method == "POST" and "register" in flow.path:
        pw = (flow.json() or {}).get("password")
        if pw:
            seen[pw] = seen.get(pw, 0) + 1
            if seen[pw] >= 2:
                return {
                    "match": True,
                    "reason": "duplicate registration password (#%d)" % seen[pw],
                    "drop": True,   # block THIS request now
                }
    return False
`

const EXAMPLES = [
  { key: 'alert', label: 'Alert example', code: ALERT_EXAMPLE },
  { key: 'drop', label: 'Drop (future) example', code: DROP_EXAMPLE },
  { key: 'block', label: 'Inline block example', code: BLOCK_EXAMPLE },
  { key: 'stateful', label: 'Stateful example', code: STATEFUL_EXAMPLE },
]

// --- sample flows for the tester ---

const REQUEST_FLOW = {
  id: 0,
  service: 'web',
  direction: 'request',
  method: 'POST',
  url: '/login',
  status: 0,
  src: '10.60.5.7',
  dst: '10.60.1.1',
  sport: 54321,
  dport: 8080,
  headers: { 'User-Agent': 'curl/8.0', 'Content-Type': 'application/json' },
  body: '{"user":"alice","password":"x"}',
  flagged: false,
  contains_flagid: false,
}

const RESPONSE_FLOW = {
  id: 0,
  service: 'web',
  direction: 'response',
  method: '',
  url: '/login',
  status: 200,
  src: '10.60.1.1',
  dst: '10.60.5.7',
  sport: 8080,
  dport: 54321,
  headers: { 'Content-Type': 'application/json' },
  body: '{"ok":true,"token":"abc123"}',
  flagged: false,
  contains_flagid: false,
}

// mapPacketToFlow mirrors the backend FlowFromPacket shape so a real packet can
// be tested without a server round-trip.
function mapPacketToFlow(p) {
  return {
    id: p.id,
    service: p.service_id || '',
    direction: p.direction || '',
    method: p.method || '',
    url: p.url || '',
    status: p.status || 0,
    src: p.src_ip || '',
    dst: p.dst_ip || '',
    sport: p.src_port || 0,
    dport: p.dst_port || 0,
    headers: p.headers || {},
    body: p.body_string || '',
    flagged: !!p.flagged,
    contains_flagid: !!p.contains_flagid,
  }
}

const EMPTY_DRAFT = { id: null, name: '', code: ALERT_EXAMPLE, enabled: true, blocking: false }

export default function PyFilters() {
  const [scripts, setScripts] = useState([])
  const [status, setStatus] = useState(null)
  const [draft, setDraft] = useState(EMPTY_DRAFT)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)

  // tester state
  const [testFlowJSON, setTestFlowJSON] = useState(JSON.stringify(REQUEST_FLOW, null, 2))
  const [repeat, setRepeat] = useState(1)
  const [packetId, setPacketId] = useState('')
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [loadingFlow, setLoadingFlow] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.listPyFilters()
      setScripts(data?.scripts || [])
      setStatus(data?.status || null)
    } catch (e) {
      setError(e.message || 'failed to load')
    }
  }, [])

  useEffect(() => { load() }, [load])

  const editing = draft.id !== null
  const flash = (msg) => { setNotice(msg); setTimeout(() => setNotice(''), 2500) }

  const startNew = () => { setDraft(EMPTY_DRAFT); setTestResult(null); setError('') }
  const startEdit = (s) => {
    setDraft({ id: s.id, name: s.name, code: s.code, enabled: s.enabled, blocking: !!s.blocking })
    setTestResult(null)
    setError('')
  }

  async function save() {
    if (!draft.name.trim()) { setError('name is required'); return }
    setSaving(true)
    setError('')
    const payload = { name: draft.name, code: draft.code, enabled: draft.enabled, blocking: draft.blocking }
    try {
      if (editing) {
        await api.updatePyFilter(draft.id, payload)
        flash('Filter saved')
      } else {
        const created = await api.createPyFilter(payload)
        setDraft({ id: created.id, name: created.name, code: created.code, enabled: created.enabled, blocking: !!created.blocking })
        flash('Filter created')
      }
      await load()
    } catch (e) {
      setError(e.message || 'save failed')
    } finally {
      setSaving(false)
    }
  }

  async function toggle(s) {
    try {
      // Preserve blocking — PUT replaces the whole script.
      await api.updatePyFilter(s.id, { name: s.name, code: s.code, enabled: !s.enabled, blocking: !!s.blocking })
      await load()
    } catch (e) {
      setError(e.message || 'toggle failed')
    }
  }

  async function remove(s) {
    if (!window.confirm(`Delete Python filter "${s.name}"?`)) return
    try {
      await api.deletePyFilter(s.id)
      if (draft.id === s.id) startNew()
      await load()
    } catch (e) {
      setError(e.message || 'delete failed')
    }
  }

  function loadExample(code) {
    setDraft((d) => ({ ...d, code }))
    setTestResult(null)
  }

  // Direction toggle: rewrite the sample flow's direction and sensible defaults,
  // preserving user edits when the JSON still parses.
  function applyDirection(dir) {
    let flow
    try {
      flow = JSON.parse(testFlowJSON)
    } catch {
      flow = dir === 'response' ? { ...RESPONSE_FLOW } : { ...REQUEST_FLOW }
      setTestFlowJSON(JSON.stringify(flow, null, 2))
      return
    }
    flow.direction = dir
    if (dir === 'response') {
      flow.method = ''
      if (!flow.status) flow.status = 200
    } else {
      if (!flow.method) flow.method = 'POST'
      flow.status = 0
    }
    setTestFlowJSON(JSON.stringify(flow, null, 2))
  }

  const parsedFlow = useMemo(() => {
    try { return JSON.parse(testFlowJSON) } catch { return null }
  }, [testFlowJSON])
  const flowIsArray = Array.isArray(parsedFlow)
  const currentDirection = (parsedFlow && !flowIsArray && parsedFlow.direction) || 'request'

  async function loadPacket(id) {
    setError('')
    setLoadingFlow(true)
    setTestResult(null)
    try {
      const p = await api.getPacket(id)
      if (!p || !p.id) throw new Error('packet not found')
      setTestFlowJSON(JSON.stringify(mapPacketToFlow(p), null, 2))
      setPacketId(String(p.id))
      flash(`Loaded packet #${p.id} (${p.direction})`)
    } catch (e) {
      setError(e.message || 'failed to load packet')
    } finally {
      setLoadingFlow(false)
    }
  }

  async function loadFlow(id) {
    setError('')
    setLoadingFlow(true)
    setTestResult(null)
    try {
      const data = await api.getPacketFlow(id)
      const pkts = data?.packets || []
      if (!pkts.length) throw new Error('no packets in that flow')
      setTestFlowJSON(JSON.stringify(pkts.map(mapPacketToFlow), null, 2))
      flash(`Loaded flow of ${pkts.length} packet(s) from #${id}`)
    } catch (e) {
      setError(e.message || 'failed to load flow')
    } finally {
      setLoadingFlow(false)
    }
  }

  async function loadLatestPacket() {
    setError('')
    setLoadingFlow(true)
    try {
      const data = await api.getPackets({ limit: 1, sort: 'desc' })
      const first = (data?.packets || [])[0]
      if (!first) throw new Error('no packets captured yet')
      await loadPacket(first.id)
    } catch (e) {
      setError(e.message || 'failed to load latest packet')
      setLoadingFlow(false)
    }
  }

  async function runTest() {
    setTesting(true)
    setTestResult(null)
    setError('')
    let parsed
    try {
      parsed = JSON.parse(testFlowJSON)
    } catch {
      setError('sample flow is not valid JSON')
      setTesting(false)
      return
    }
    const body = {
      name: draft.name || 'test',
      code: draft.code,
      repeat: Math.max(1, Number(repeat) || 1),
    }
    // A JSON array = a whole flow (sequence of packets); an object = one packet.
    if (Array.isArray(parsed)) body.flows = parsed
    else body.flow = parsed
    try {
      const res = await api.testPyFilter(body)
      setTestResult(res)
    } catch (e) {
      setError(e.message || 'test failed')
    } finally {
      setTesting(false)
    }
  }

  const statusBadge = useMemo(() => {
    if (!status) return null
    if (!status.available) {
      return <Badge tone="red">python3 not found — scripts will not run</Badge>
    }
    return (
      <div className="flex items-center gap-2 flex-wrap">
        <Badge tone="green">python ready</Badge>
        <Badge tone="gray">{status.enabled_count}/{status.script_count} enabled</Badge>
        {status.blocking_count > 0 && (
          <Badge tone="amber" title="Filters running inline (synchronously) on the request path">
            {status.blocking_count} inline
          </Badge>
        )}
        {status.worker_healthy && <Badge tone="cyan">worker running</Badge>}
        {status.last_error && <Badge tone="amber" title={status.last_error}>last error</Badge>}
      </div>
    )
  }, [status])

  return (
    <div className="p-6 space-y-4 max-w-6xl">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-2xl font-semibold text-gray-100">Python Filters</h2>
          <p className="text-xs text-gray-500 max-w-2xl">
            mitmproxy-style scriptable filtering. Each script defines{' '}
            <code className="text-cyan-300">def match(flow)</code> and runs against every captured
            packet (request <em>and</em> response). Module-level state persists, so you can express
            stateful checks. What a match does is decided by what you return — see the legend below.
          </p>
        </div>
        {statusBadge}
      </header>

      {status && status.last_error && (
        <div className="text-xs text-amber-300 bg-amber-950/40 border border-amber-800/50 rounded px-3 py-2 font-mono break-all">
          {status.last_error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-4">
        {/* Script list */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs uppercase tracking-wide text-gray-500">Filters</h3>
            <button
              onClick={startNew}
              className="text-xs px-2 py-1 rounded bg-cyan-700/40 text-cyan-200 border border-cyan-700/50 hover:bg-cyan-700/60 cursor-pointer"
            >
              + New
            </button>
          </div>
          {scripts.length === 0 && (
            <p className="text-xs text-gray-600 italic">No filters yet.</p>
          )}
          {scripts.map((s) => (
            <div
              key={s.id}
              className={`rounded border px-3 py-2 cursor-pointer transition-colors ${
                draft.id === s.id
                  ? 'bg-gray-800 border-cyan-700/60'
                  : 'bg-gray-900 border-gray-800 hover:border-gray-700'
              }`}
              onClick={() => startEdit(s)}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-gray-200 truncate" title={s.name}>{s.name}</span>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {s.blocking && (
                    <span
                      className="text-[10px] px-1.5 py-0.5 rounded border bg-rose-900/40 text-rose-300 border-rose-700/50"
                      title="Inline blocking — runs synchronously and can drop the current request"
                    >
                      INLINE
                    </span>
                  )}
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    s.enabled
                      ? 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50'
                      : 'bg-gray-800 text-gray-500 border-gray-700'
                  }`}>
                    {s.enabled ? 'ON' : 'OFF'}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-3 mt-1.5">
                <button
                  onClick={(e) => { e.stopPropagation(); toggle(s) }}
                  className="text-[11px] text-gray-400 hover:text-cyan-300 cursor-pointer"
                >
                  {s.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); remove(s) }}
                  className="text-[11px] text-gray-400 hover:text-red-400 cursor-pointer"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}

          <ReturnLegend />
          <FlowApiCheatsheet />
        </div>

        {/* Editor + test */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="Filter name (e.g. repeat-login)"
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
            />
            <label className="flex items-center gap-1.5 text-xs text-gray-400 select-none cursor-pointer">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
              />
              Enabled
            </label>
            <label
              className="flex items-center gap-1.5 text-xs text-gray-400 select-none cursor-pointer"
              title="Run this filter synchronously on the request path so a match returning {'drop': True} blocks the CURRENT request in real time. Adds ~tens of µs per request on this service; a stuck script fails open."
            >
              <input
                type="checkbox"
                checked={draft.blocking}
                onChange={(e) => setDraft({ ...draft, blocking: e.target.checked })}
              />
              Blocking
            </label>
            <button
              onClick={save}
              disabled={saving}
              className="text-sm px-3 py-1.5 rounded bg-cyan-700 text-white hover:bg-cyan-600 disabled:opacity-50 cursor-pointer"
            >
              {saving ? 'Saving…' : editing ? 'Save' : 'Create'}
            </button>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] text-gray-500">Load example:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.key}
                onClick={() => loadExample(ex.code)}
                className="text-[11px] px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 cursor-pointer"
              >
                {ex.label}
              </button>
            ))}
          </div>

          <textarea
            value={draft.code}
            onChange={(e) => setDraft({ ...draft, code: e.target.value })}
            rows={18}
            spellCheck={false}
            className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500 leading-relaxed"
          />

          {error && (
            <div className="text-xs text-red-300 bg-red-950/40 border border-red-800/50 rounded px-3 py-2 font-mono break-all">
              {error}
            </div>
          )}
          {notice && (
            <div className="text-xs text-emerald-300">{notice}</div>
          )}

          {/* Test panel */}
          <div className="bg-gray-900 border border-gray-800 rounded p-3 space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <h3 className="text-xs uppercase tracking-wide text-gray-500">Test the script</h3>
              <div className="flex items-center gap-2">
                <label className="text-[11px] text-gray-500 flex items-center gap-1" title="Re-run the same flow N times so stateful scripts (module globals) can trigger — e.g. a 2nd login.">
                  Repeat
                  <input
                    type="number" min={1} max={500}
                    value={repeat}
                    onChange={(e) => setRepeat(e.target.value)}
                    className="w-14 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100"
                  />
                </label>
                <button
                  onClick={runTest}
                  disabled={testing || !status?.available}
                  className="text-xs px-2.5 py-1 rounded bg-cyan-700 text-white hover:bg-cyan-600 disabled:opacity-50 cursor-pointer"
                >
                  {testing ? 'Running…' : 'Run test'}
                </button>
              </div>
            </div>

            {/* Sample source controls */}
            <div className="flex items-center gap-2 flex-wrap text-[11px]">
              {flowIsArray ? (
                <span className="px-2 py-1 rounded border border-cyan-700/50 bg-cyan-900/20 text-cyan-300">
                  Flow sequence — {parsedFlow.length} packet(s)
                </span>
              ) : (
                <div className="inline-flex rounded border border-gray-700 overflow-hidden">
                  {['request', 'response'].map((d) => (
                    <button
                      key={d}
                      onClick={() => applyDirection(d)}
                      className={`px-2 py-1 cursor-pointer ${
                        currentDirection === d ? 'bg-cyan-700 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'
                      }`}
                    >
                      {d === 'request' ? 'Request' : 'Response'}
                    </button>
                  ))}
                </div>
              )}
              <span className="text-gray-600">from traffic:</span>
              <input
                type="number"
                value={packetId}
                onChange={(e) => setPacketId(e.target.value)}
                placeholder="#"
                className="w-20 bg-gray-800 border border-gray-700 rounded px-1.5 py-1 text-gray-100"
              />
              <button
                onClick={() => packetId && loadPacket(packetId)}
                disabled={loadingFlow || !packetId}
                className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 disabled:opacity-50 cursor-pointer"
                title="Load just this packet"
              >
                Load packet
              </button>
              <button
                onClick={() => packetId && loadFlow(packetId)}
                disabled={loadingFlow || !packetId}
                className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 disabled:opacity-50 cursor-pointer"
                title="Load the whole request+response flow this packet belongs to"
              >
                Load flow
              </button>
              <button
                onClick={loadLatestPacket}
                disabled={loadingFlow}
                className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 disabled:opacity-50 cursor-pointer"
              >
                {loadingFlow ? 'Loading…' : 'Latest'}
              </button>
            </div>

            <textarea
              value={testFlowJSON}
              onChange={(e) => setTestFlowJSON(e.target.value)}
              rows={12}
              spellCheck={false}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500"
            />

            {testResult && <TestVerdict result={testResult} />}
          </div>
        </div>
      </div>
    </div>
  )
}

function TestVerdict({ result }) {
  if (result.script_error) {
    return (
      <div className="rounded border border-red-800/50 bg-red-950/40 p-2">
        <div className="text-xs font-semibold text-red-300 mb-1">Script error</div>
        <pre className="text-[11px] text-red-300/90 font-mono whitespace-pre-wrap break-all">{result.script_error}</pre>
      </div>
    )
  }

  const steps = result.steps || []

  // Whole-flow (sequence) result: a verdict per packet, in order.
  if (steps.length > 1) {
    const matched = steps.filter((s) => s.matched).length
    return (
      <div className="rounded border border-gray-700 bg-gray-800/40 p-2 space-y-1.5">
        <div className="text-xs text-gray-300">
          Flow of {steps.length} packet(s) —{' '}
          <span className={matched ? 'text-emerald-300' : 'text-gray-400'}>{matched} matched</span>
        </div>
        <div className="space-y-1">
          {steps.map((s) => <StepRow key={s.index} step={s} />)}
        </div>
      </div>
    )
  }

  // Single flow/packet.
  const m0 = (steps[0]?.matches || result.matches || [])[0]
  if (!result.matched) {
    return (
      <div className="rounded border border-gray-700 bg-gray-800/50 p-2 text-xs text-gray-400">
        No match — this flow would be ignored.
      </div>
    )
  }
  const drop = m0?.drop
  const block = m0?.block
  const border = block ? 'border-rose-700/50 bg-rose-950/30' : drop ? 'border-amber-700/50 bg-amber-950/30' : 'border-emerald-700/50 bg-emerald-950/30'
  return (
    <div className={`rounded border p-2 ${border}`}>
      <div className="flex items-center gap-2 mb-1">
        <VerdictBadge drop={drop} block={block} />
        {m0?.reason && <span className="text-xs text-gray-300">{m0.reason}</span>}
      </div>
      {block ? (
        <div className="text-[11px] text-rose-200/90">
          Drops <strong>this</strong> request in real time (inline). Takes effect on live traffic only when the
          filter has <strong>Blocking</strong> enabled.
        </div>
      ) : drop ? (
        <div className="text-[11px] text-amber-200/90">
          Installs a drop rule <code className="font-mono bg-black/30 px-1 rounded">{drop}</code> — future
          matching traffic is blocked (content-only).
        </div>
      ) : (
        <div className="text-[11px] text-emerald-200/80">Raises an alert on the Alerts page.</div>
      )}
    </div>
  )
}

function StepRow({ step }) {
  const m0 = step.matches?.[0]
  const drop = m0?.drop
  const block = m0?.block
  return (
    <div className="flex items-center gap-2 text-[11px]">
      <span className="text-gray-600 w-6 text-right">#{step.index}</span>
      {step.direction && (
        <span className={`px-1 rounded border text-[10px] ${
          step.direction === 'response'
            ? 'border-indigo-700/50 text-indigo-300 bg-indigo-900/20'
            : 'border-sky-700/50 text-sky-300 bg-sky-900/20'
        }`}>
          {step.direction === 'response' ? 'RES' : 'REQ'}
        </span>
      )}
      {step.matched ? (
        <>
          <VerdictBadge drop={drop} block={block} small />
          {m0?.reason && <span className="text-gray-400 truncate">{m0.reason}</span>}
        </>
      ) : (
        <span className="text-gray-600">no match</span>
      )}
    </div>
  )
}

function VerdictBadge({ drop, block, small }) {
  const cls = block
    ? 'bg-rose-900/50 text-rose-200 border-rose-700/50'
    : drop
    ? 'bg-amber-900/50 text-amber-200 border-amber-700/50'
    : 'bg-emerald-900/50 text-emerald-200 border-emerald-700/50'
  return (
    <span className={`${small ? 'text-[10px]' : 'text-[10px]'} px-1.5 py-0.5 rounded border font-semibold ${cls}`}>
      {block ? 'ALERT + BLOCK' : drop ? 'ALERT + DROP' : 'ALERT'}
    </span>
  )
}

function ReturnLegend() {
  return (
    <div className="mt-3 rounded border border-gray-800 bg-gray-900/60 p-3 space-y-1.5">
      <h4 className="text-[10px] uppercase tracking-wide text-gray-500">What match(flow) returns</h4>
      <LegendRow code="return False" desc="ignore (no match)" tone="gray" />
      <LegendRow code='return "reason"' desc="ALERT only" tone="green" />
      <LegendRow code='{"match": True, "drop": "<expr>"}' desc="ALERT + block future traffic (async)" tone="amber" />
      <LegendRow code='{"match": True, "drop": True}' desc="ALERT + block THIS request now (needs Blocking)" tone="red" />
      <p className="text-[10px] text-gray-600 pt-1 leading-snug">
        <code className="text-gray-500">drop</code> as an expression blocks <em>future</em> matching traffic
        (content-only: <code className="text-gray-500">body</code>/<code className="text-gray-500">url</code>/<code className="text-gray-500">header</code>/<code className="text-gray-500">service</code>;
        IP/port rejected, SNAT-unsafe). <code className="text-gray-500">drop: True</code> drops the current
        request inline — only when the filter has <strong>Blocking</strong> on.
      </p>
    </div>
  )
}

function FlowApiCheatsheet() {
  const rows = [
    ['flow.method / url / path', 'POST, /login?x=1, /login'],
    ['flow.status / service', 'response status, service id'],
    ['flow.is_request / is_response', 'direction helpers'],
    ['flow.headers["Cookie"]', 'case-insensitive, missing → ""'],
    ['flow.query["id"] / .all("id")', 'parsed query string'],
    ['flow.cookies["session"]', 'parsed Cookie header'],
    ['flow.json() / flow.body / .bytes', 'body as JSON / str / bytes'],
    ['flow.request / flow.response', 'correlated side (never None)'],
    ['flow.messages[-1]', 'most recent message (this service)'],
    ['flow.recent(3) / last_request', 'recent history'],
  ]
  return (
    <div className="mt-3 rounded border border-gray-800 bg-gray-900/60 p-3 space-y-1">
      <h4 className="text-[10px] uppercase tracking-wide text-gray-500">Flow API — quick to write, forgiving</h4>
      <div className="space-y-0.5">
        {rows.map(([code, desc]) => (
          <div key={code} className="flex items-baseline gap-2">
            <code className="text-[11px] text-cyan-300 font-mono break-all flex-shrink-0">{code}</code>
            <span className="text-[10px] text-gray-500 truncate">{desc}</span>
          </div>
        ))}
      </div>
      <p className="text-[10px] text-gray-600 pt-1 leading-snug">
        Still a dict (<code className="text-gray-500">flow["body"]</code>, <code className="text-gray-500">flow.get(...)</code> work).
        Missing fields read as <code className="text-gray-500">""</code>. For inline <strong>Blocking</strong> filters
        <code className="text-gray-500"> flow.response</code> is empty (the response doesn't exist yet).
      </p>
    </div>
  )
}

function LegendRow({ code, desc, tone }) {
  const dot = { gray: 'bg-gray-500', green: 'bg-emerald-400', amber: 'bg-amber-400', red: 'bg-rose-400' }[tone]
  return (
    <div className="flex items-start gap-2">
      <span className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${dot}`} />
      <div className="min-w-0">
        <code className="text-[11px] text-cyan-300 font-mono break-all">{code}</code>
        <span className="text-[11px] text-gray-500"> — {desc}</span>
      </div>
    </div>
  )
}

function Badge({ tone, children, title }) {
  const tones = {
    green: 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50',
    red: 'bg-red-900/40 text-red-300 border-red-700/50',
    amber: 'bg-amber-900/40 text-amber-300 border-amber-700/50',
    cyan: 'bg-cyan-900/30 text-cyan-300 border-cyan-700/40',
    gray: 'bg-gray-800 text-gray-400 border-gray-700',
  }
  return (
    <span title={title} className={`text-[10px] px-1.5 py-0.5 rounded border ${tones[tone] || tones.gray}`}>
      {children}
    </span>
  )
}
