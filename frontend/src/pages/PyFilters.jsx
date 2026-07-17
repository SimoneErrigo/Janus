import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { PY_FILTER_SNIPPETS, PY_FILTER_TEMPLATES, STARTER_CODE } from '../utils/pyFilterCatalog'

const REQUEST_FLOW = {
  id: 0,
  service: 'web',
  session: 'example-connection',
  protocol: 'http',
  timestamp: 1700000000,
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
  body_complete: true,
  truncated: false,
  flagged: false,
  contains_flagid: false,
}

const RESPONSE_FLOW = {
  ...REQUEST_FLOW,
  direction: 'response',
  method: '',
  status: 200,
  src: REQUEST_FLOW.dst,
  dst: REQUEST_FLOW.src,
  sport: REQUEST_FLOW.dport,
  dport: REQUEST_FLOW.sport,
  headers: { 'Content-Type': 'application/json' },
  body: '{"ok":true,"token":"abc123"}',
}

function emptyDraft() {
  return {
    id: null,
    name: '',
    code: STARTER_CODE,
    enabled: false,
    mode: 'observe',
    service_ids: ['*'],
    directions: [],
    protocols: [],
  }
}

function scriptDraft(script) {
  return {
    id: script.id,
    name: script.name,
    code: script.code,
    enabled: script.enabled,
    mode: script.mode || (script.blocking ? 'block' : 'observe'),
    service_ids: script.service_ids?.length ? script.service_ids : ['*'],
    directions: script.directions || [],
    protocols: script.protocols || [],
  }
}

function draftFingerprint(value) {
  return JSON.stringify({
    id: value.id,
    name: value.name,
    code: value.code,
    enabled: value.enabled,
    mode: value.mode,
    service_ids: value.service_ids,
    directions: value.directions,
    protocols: value.protocols,
  })
}

function isFlowObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

// Preview only. ID-based tests resolve the original bytes, timestamp and flow
// metadata on the backend rather than round-tripping this lossy JSON view.
function packetPreview(packet) {
  return {
    id: packet.id,
    service: packet.service_id || '',
    session: packet.session_id || '',
    protocol: packet.protocol || '',
    round: packet.round || 0,
    timestamp: packet.timestamp || '',
    truncated: !!packet.capture_truncated,
    body_complete: !packet.capture_truncated,
    decoded: packet.decoded || {},
    direction: packet.direction || '',
    method: packet.method || '',
    url: packet.url || '',
    status: packet.status || 0,
    src: packet.src_ip || '',
    dst: packet.dst_ip || '',
    sport: packet.src_port || 0,
    dport: packet.dst_port || 0,
    headers: packet.headers || {},
    body: packet.body_string || '',
    flagged: !!packet.flagged,
    contains_flagid: !!packet.contains_flagid,
  }
}

function hasTestError(result) {
  if (!result || result.script_error) return true
  return (result.steps || []).some((step) => (step.matches || []).some((match) => match.error))
}

function hasRewrite(step) {
  return !!step && (step.rewritten === true || step.rewrite != null || step.rewrite_b64 != null)
}

export default function PyFilters() {
  const [scripts, setScripts] = useState([])
  const [status, setStatus] = useState(null)
  const [draft, setDraft] = useState(emptyDraft)
  const [services, setServices] = useState([])
  const [protocolPresets, setProtocolPresets] = useState([])
  const [scopeReady, setScopeReady] = useState(false)
  const [scopeError, setScopeError] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const [updating, setUpdating] = useState(false)

  const [testFlowJSON, setTestFlowJSON] = useState(JSON.stringify(REQUEST_FLOW, null, 2))
  const [testSource, setTestSource] = useState({ kind: 'custom' })
  const [repeat, setRepeat] = useState(1)
  const [packetId, setPacketId] = useState('')
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [loadingFlow, setLoadingFlow] = useState(false)

  const codeRef = useRef(null)
  const codeSelection = useRef(null)
  const draftRevision = useRef(0)
  const testGeneration = useRef(0)

  const invalidateTest = useCallback(() => {
    testGeneration.current += 1
    setTestResult(null)
    setTesting(false)
  }, [])

  const load = useCallback(async () => {
    try {
      const data = await api.listPyFilters()
      setScripts(data?.scripts || [])
      setStatus(data?.status || null)
    } catch (requestError) {
      setError(requestError.message || 'failed to load')
    }
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    let cancelled = false
    setScopeReady(false)
    setScopeError('')
    Promise.all([api.listServices(), api.listProtocolPresets()])
      .then(([serviceItems, presetItems]) => {
        if (cancelled) return
        setServices(serviceItems || [])
        setProtocolPresets(presetItems || [])
        setScopeReady(true)
      })
      .catch((requestError) => {
        if (cancelled) return
        setScopeError(`Traffic scope unavailable: ${requestError.message || 'failed to load services and protocols'}`)
      })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!notice) return undefined
    const timer = window.setTimeout(() => setNotice(''), 2500)
    return () => window.clearTimeout(timer)
  }, [notice])

  const editing = draft.id !== null
  const busy = saving || updating
  const validTest = !!testResult && !hasTestError(testResult)
  const storedScript = editing ? scripts.find((script) => script.id === draft.id) : null
  const draftDirty = draftFingerprint(draft) !== draftFingerprint(storedScript ? scriptDraft(storedScript) : emptyDraft())

  const parsedFlow = useMemo(() => {
    try { return JSON.parse(testFlowJSON) } catch { return null }
  }, [testFlowJSON])
  const flowIsArray = Array.isArray(parsedFlow)
  const currentDirection = (parsedFlow && !flowIsArray && parsedFlow.direction) || 'request'
  const testStepCount = testSource.kind === 'flow'
    ? testSource.evaluatedCount
    : flowIsArray ? Math.min(parsedFlow.length, 200) : 1
  const repeatLimit = Math.max(1, Math.min(50, Math.floor(2000 / Math.max(1, testStepCount))))

  useEffect(() => {
    setRepeat((current) => Math.min(Math.max(1, Number(current) || 1), repeatLimit))
  }, [repeatLimit])

  function changeDraft(patch, affectsTest = true) {
    draftRevision.current += 1
    setDraft((current) => ({ ...current, ...patch }))
    if (affectsTest) invalidateTest()
  }

  function resetEditor(next) {
    draftRevision.current += 1
    codeSelection.current = null
    setDraft(next)
    invalidateTest()
    setError('')
  }

  function confirmDiscard() {
    return !draftDirty || window.confirm('Discard the unsaved Python filter changes?')
  }

  function startNew() {
    if (busy) { setError('Wait for the current filter update to finish'); return }
    if (!confirmDiscard()) return
    resetEditor(emptyDraft())
  }

  function startEdit(script) {
    if (draft.id === script.id) return
    if (busy) { setError('Wait for the current filter update to finish'); return }
    if (!confirmDiscard()) return
    resetEditor(scriptDraft(script))
  }

  async function save() {
    if (busy) { setError('Wait for the current filter update to finish'); return }
    if (!draft.name.trim()) { setError('name is required'); return }
    if (!scopeReady) { setError(scopeError || 'wait for services and protocols to finish loading'); return }
    if (!draft.service_ids.length) { setError('select at least one service'); return }
    if (!validTest) { setError(`run a successful test before ${editing ? 'saving changes' : 'creating the filter'}`); return }

    const payload = {
      name: draft.name,
      code: draft.code,
      enabled: editing ? draft.enabled : false,
      mode: draft.mode,
      blocking: draft.mode !== 'observe',
      service_ids: draft.service_ids,
      directions: draft.directions,
      protocols: draft.protocols,
    }
    const saveRevision = draftRevision.current
    setSaving(true)
    setError('')
    try {
      let saved
      if (editing) {
        saved = await api.updatePyFilter(draft.id, payload)
      } else {
        saved = await api.createPyFilter(payload)
      }
      if (draftRevision.current === saveRevision) {
        setDraft(scriptDraft(saved))
        setNotice(editing ? 'Filter saved' : 'Filter created disabled; enable it when ready')
      } else {
        // A create must still become an edit, otherwise saving the newer draft
        // would accidentally create a duplicate filter.
        if (!editing) setDraft((current) => ({ ...current, id: saved.id, enabled: saved.enabled }))
        setNotice('Saved the tested snapshot; newer editor changes remain unsaved')
      }
      await load()
    } catch (requestError) {
      setError(requestError.message || 'save failed')
    } finally {
      setSaving(false)
    }
  }

  async function toggle(script) {
    if (busy) { setError('Wait for the current filter update to finish'); return }
    if (draft.id === script.id && draftDirty) {
      setError('Save and test, or discard the editor changes before enabling this filter')
      return
    }
    setUpdating(true)
    try {
      const updated = await api.updatePyFilter(script.id, {
        name: script.name,
        code: script.code,
        enabled: !script.enabled,
        mode: script.mode || (script.blocking ? 'block' : 'observe'),
        blocking: !!script.blocking,
        service_ids: script.service_ids || ['*'],
        directions: script.directions || [],
        protocols: script.protocols || [],
      })
      setDraft((current) => current.id === script.id ? { ...current, enabled: updated.enabled } : current)
      await load()
    } catch (requestError) {
      setError(requestError.message || 'toggle failed')
    } finally {
      setUpdating(false)
    }
  }

  async function remove(script) {
    if (busy) { setError('Wait for the current filter update to finish'); return }
    const dirtyWarning = draft.id === script.id && draftDirty ? ' Unsaved editor changes will also be lost.' : ''
    if (!window.confirm(`Delete Python filter "${script.name}"?${dirtyWarning}`)) return
    setUpdating(true)
    try {
      await api.deletePyFilter(script.id)
      if (draft.id === script.id) resetEditor(emptyDraft())
      await load()
    } catch (requestError) {
      setError(requestError.message || 'delete failed')
    } finally {
      setUpdating(false)
    }
  }

  function loadTemplate(template) {
    if (draft.code !== STARTER_CODE && draft.code !== template.code && !window.confirm('Replace the current editor contents with this template?')) return
    codeSelection.current = null
    changeDraft({
      name: draft.name || template.key,
      code: template.code,
      // Templates never arm themselves. The dry-run result offers promotion.
      mode: 'observe',
      directions: template.directions || [],
      protocols: template.protocols || [],
    })
    setNotice(`${template.title} loaded in Observe mode`)
  }

  function insertSnippet(code) {
    const textarea = codeRef.current
    const selection = codeSelection.current
    const start = selection?.start ?? draft.code.length
    const end = selection?.end ?? start
    const lineStart = draft.code.lastIndexOf('\n', Math.max(0, start - 1)) + 1
    const indent = (draft.code.slice(lineStart, start).match(/^\s*/) || [''])[0]
    const inserted = code.split('\n').map((line, index) => index === 0 ? line : indent + line).join('\n')
    const next = draft.code.slice(0, start) + inserted + draft.code.slice(end)
    const cursor = start + inserted.length

    changeDraft({ code: next })
    codeSelection.current = { start: cursor, end: cursor }
    window.requestAnimationFrame(() => {
      textarea?.focus()
      textarea?.setSelectionRange(cursor, cursor)
    })
  }

  function applyDirection(direction) {
    let flow
    try {
      flow = JSON.parse(testFlowJSON)
      if (!isFlowObject(flow)) flow = direction === 'response' ? { ...RESPONSE_FLOW } : { ...REQUEST_FLOW }
    } catch {
      flow = direction === 'response' ? { ...RESPONSE_FLOW } : { ...REQUEST_FLOW }
    }
    flow.direction = direction
    if (direction === 'response') {
      flow.method = ''
      flow.status ||= 200
    } else {
      flow.method ||= 'POST'
      flow.status = 0
    }
    setTestFlowJSON(JSON.stringify(flow, null, 2))
    setTestSource({ kind: 'custom' })
    invalidateTest()
  }

  async function loadPacket(id) {
    setError('')
    setLoadingFlow(true)
    invalidateTest()
    try {
      const packet = await api.getPacket(id)
      if (!packet?.id) throw new Error('packet not found')
      setTestFlowJSON(JSON.stringify(packetPreview(packet), null, 2))
      setTestSource({ kind: 'packet', id: Number(packet.id) })
      setPacketId(String(packet.id))
      setNotice(`Packet #${packet.id} selected; original server data will be tested`)
    } catch (requestError) {
      setError(requestError.message || 'failed to load packet')
    } finally {
      setLoadingFlow(false)
    }
  }

  async function loadFlow(id) {
    setError('')
    setLoadingFlow(true)
    invalidateTest()
    try {
      const data = await api.getPacketFlow(id)
      const packets = data?.packets || []
      if (!packets.length) throw new Error('no packets in that flow')
      const preview = packets.slice(0, 20).map(packetPreview)
      const evaluatedCount = Math.min(packets.length, 200)
      setTestFlowJSON(JSON.stringify(preview, null, 2))
      setTestSource({ kind: 'flow', id: Number(id), count: packets.length, evaluatedCount, previewCount: preview.length })
      setPacketId(String(id))
      setNotice(packets.length > evaluatedCount
        ? `Flow selected; the first ${evaluatedCount} original packets will be tested (safety limit)`
        : `Flow selected; all ${evaluatedCount} original packet(s) will be tested server-side`)
    } catch (requestError) {
      setError(requestError.message || 'failed to load flow')
    } finally {
      setLoadingFlow(false)
    }
  }

  async function loadLatestPacket() {
    setError('')
    setLoadingFlow(true)
    invalidateTest()
    try {
      const data = await api.getPackets({ limit: 1, sort: 'desc' })
      const packet = (data?.packets || [])[0]
      if (!packet) throw new Error('no packets captured yet')
      await loadPacket(packet.id)
    } catch (requestError) {
      setError(requestError.message || 'failed to load latest packet')
      setLoadingFlow(false)
    }
  }

  async function runTest() {
    const body = {
      name: draft.name || 'test',
      code: draft.code,
      mode: draft.mode,
      service_ids: draft.service_ids,
      directions: draft.directions,
      protocols: draft.protocols,
      repeat: Math.min(repeatLimit, Math.max(1, Number(repeat) || 1)),
    }

    if (testSource.kind === 'packet') {
      body.packet_id = testSource.id
    } else if (testSource.kind === 'flow') {
      body.flow_packet_id = testSource.id
    } else {
      let parsed
      try {
        parsed = JSON.parse(testFlowJSON)
      } catch {
        setError('sample flow is not valid JSON')
        return
      }
      if (Array.isArray(parsed)) {
        if (parsed.length === 0) { setError('sample sequence must contain at least one flow object'); return }
        if (parsed.length > 200) { setError('sample sequence can contain at most 200 flow objects'); return }
        if (!parsed.every(isFlowObject)) { setError('every sample sequence item must be a JSON object'); return }
        body.flows = parsed
      } else {
        if (!isFlowObject(parsed)) { setError('sample flow must be a JSON object'); return }
        body.flow = parsed
      }
    }

    const runID = ++testGeneration.current
    setTesting(true)
    setTestResult(null)
    setError('')
    try {
      const result = await api.testPyFilter(body)
      if (testGeneration.current === runID) setTestResult(result)
    } catch (requestError) {
      if (testGeneration.current === runID) setError(requestError.message || 'test failed')
    } finally {
      if (testGeneration.current === runID) setTesting(false)
    }
  }

  const statusBadges = useMemo(() => {
    if (!status) return null
    if (!status.available) return <Badge tone="red">python3 not found — filters cannot run</Badge>
    return (
      <div className="flex items-center justify-end gap-2 flex-wrap">
        <Badge tone="green">python ready</Badge>
        <Badge tone="gray">{status.enabled_count}/{status.script_count} enabled</Badge>
        <Badge tone="gray">queue {status.queue_depth || 0}/{status.queue_capacity || 0}</Badge>
        {status.queue_dropped > 0 && <Badge tone="amber">{status.queue_dropped} skipped</Badge>}
        {status.blocking_count > 0 && <Badge tone="amber">{status.blocking_count} inline</Badge>}
        {status.worker_healthy && <Badge tone="cyan">worker running</Badge>}
      </div>
    )
  }, [status])

  return (
    <div className="p-6 space-y-4 max-w-7xl">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-2xl font-semibold text-gray-100">Python Filters</h2>
          <p className="text-xs text-gray-500 max-w-2xl">
            Start in Observe, test against a real captured flow, then move inline only when the result is safe.
            Janus supplies bounded connection state, flag counters and timing helpers to{' '}
            <code className="text-cyan-300">def match(flow)</code>.
          </p>
          <p className="mt-1 text-[10px] text-amber-600">Trusted team-admin code: Python filters are not an OS sandbox.</p>
        </div>
        {statusBadges}
      </header>

      <WorkflowStrip />

      {status?.last_error && (
        <div role="alert" className="text-xs text-amber-300 bg-amber-950/40 border border-amber-800/50 rounded px-3 py-2 font-mono break-all">
          {status.last_error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[270px_1fr] gap-4 items-start">
        <aside className="space-y-2 min-w-0">
          <div className="flex items-center justify-between">
            <h3 className="text-xs uppercase tracking-wide text-gray-500">Saved filters</h3>
            <button onClick={startNew} className="text-xs px-2 py-1 rounded bg-cyan-700/40 text-cyan-200 border border-cyan-700/50 hover:bg-cyan-700/60 cursor-pointer">
              + New
            </button>
          </div>
          {scripts.length === 0 && <p className="text-xs text-gray-600 italic">No filters yet.</p>}
          {scripts.map((script) => (
            <div
              key={script.id}
              role="button"
              tabIndex={0}
              aria-current={draft.id === script.id ? 'true' : undefined}
              onClick={() => startEdit(script)}
              onKeyDown={(event) => {
                if (event.target !== event.currentTarget || (event.key !== 'Enter' && event.key !== ' ')) return
                event.preventDefault()
                startEdit(script)
              }}
              className={`rounded-lg border px-3 py-2 cursor-pointer transition-colors ${
                draft.id === script.id
                  ? 'bg-gray-800 border-cyan-700/60 ring-1 ring-cyan-700/30'
                  : 'bg-gray-900 border-gray-800 hover:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-gray-200 truncate" title={script.name}>{script.name}</span>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {(script.mode || (script.blocking ? 'block' : 'observe')) !== 'observe' && <Badge tone="amber">INLINE</Badge>}
                  <Badge tone={script.enabled ? 'green' : 'gray'}>{script.enabled ? 'ON' : 'OFF'}</Badge>
                </div>
              </div>
              <div className="flex items-center gap-3 mt-1.5">
                <span className="text-[10px] text-gray-600 truncate flex-1" title={scopeSummary(script, services)}>{scopeSummary(script, services)}</span>
                <button onClick={(event) => { event.stopPropagation(); toggle(script) }} className="text-[11px] text-gray-400 hover:text-cyan-300 cursor-pointer">
                  {script.enabled ? 'Disable' : 'Enable'}
                </button>
                <button onClick={(event) => { event.stopPropagation(); remove(script) }} className="text-[11px] text-gray-400 hover:text-red-400 cursor-pointer">
                  Delete
                </button>
              </div>
            </div>
          ))}

          <details className="rounded-lg border border-gray-800 bg-gray-900/50">
            <summary className="px-3 py-2 text-[11px] text-gray-400 cursor-pointer select-none">Return values &amp; safety</summary>
            <div className="px-3 pb-3"><ReturnLegend /></div>
          </details>
        </aside>

        <main className="space-y-4 min-w-0">
          <section className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 space-y-3">
            <SectionTitle number="1" title="Configure" detail="Name, safety mode and traffic scope" />
            <div className="flex items-center gap-2">
              <input
                aria-label="Filter name"
                value={draft.name}
                onChange={(event) => changeDraft({ name: event.target.value }, false)}
                placeholder="Filter name (e.g. flag-out-guard)"
                className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={save}
                disabled={busy || !scopeReady || !validTest || !draft.name.trim()}
                title={!scopeReady
                  ? (scopeError || 'Loading services and protocols')
                  : !draft.name.trim()
                  ? 'Name the filter first'
                  : !validTest ? `Run an error-free dry test before ${editing ? 'saving' : 'creating'}` : undefined}
                className="text-sm px-3 py-1.5 rounded bg-cyan-700 text-white hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {saving ? 'Saving…' : editing ? 'Save' : 'Create'}
              </button>
            </div>
            {(!scopeReady || !validTest || !draft.name.trim()) && (
              <p className="text-[10px] text-gray-600">
                {!scopeReady
                  ? 'Services and protocols must load before this filter can be saved.'
                  : !draft.name.trim()
                  ? `Name the filter, then run one error-free dry test to unlock ${editing ? 'Save' : 'Create'}.`
                  : `Run one error-free dry test to unlock ${editing ? 'Save' : 'Create'}.`}
              </p>
            )}
            <ModeSelector
              mode={draft.mode}
              onChange={(mode) => {
                changeDraft({ mode })
              }}
            />
            <ScopeEditor
              draft={draft}
              services={services}
              protocolPresets={protocolPresets}
              ready={scopeReady}
              onChange={(patch) => changeDraft(patch)}
            />
          </section>

          <section className="space-y-3">
            <SectionTitle number="2" title="Write the filter" detail="Start from a guided pattern or insert one API primitive" />
            <TemplateGallery templates={PY_FILTER_TEMPLATES} onLoad={loadTemplate} />
            <SnippetExplorer snippets={PY_FILTER_SNIPPETS} onInsert={insertSnippet} />
            <div className="rounded-lg border border-gray-800 bg-gray-950 overflow-hidden focus-within:border-cyan-600/70 transition-colors">
              <div className="flex items-center justify-between px-3 py-1.5 border-b border-gray-800 bg-gray-900/60">
                <span className="text-[11px] font-mono text-gray-500">Python · def match(flow)</span>
                <span className="text-[10px] text-gray-600 tabular-nums">{draft.code.split('\n').length} lines</span>
              </div>
              <textarea
                ref={codeRef}
                aria-label="Python filter code"
                value={draft.code}
                onChange={(event) => {
                  changeDraft({ code: event.target.value })
                  codeSelection.current = { start: event.target.selectionStart, end: event.target.selectionEnd }
                }}
                onSelect={(event) => { codeSelection.current = { start: event.target.selectionStart, end: event.target.selectionEnd } }}
                rows={18}
                spellCheck={false}
                className="w-full bg-transparent px-3 py-2.5 text-xs font-mono text-gray-100 focus:outline-none leading-relaxed resize-y block"
              />
            </div>
          </section>

          {scopeError && <div role="alert" className="text-xs text-red-300 bg-red-950/40 border border-red-800/50 rounded px-3 py-2 font-mono break-all">{scopeError}</div>}
          {error && <div role="alert" className="text-xs text-red-300 bg-red-950/40 border border-red-800/50 rounded px-3 py-2 font-mono break-all">{error}</div>}
          {notice && <div role="status" aria-live="polite" className="text-xs text-emerald-300">{notice}</div>}

          <section className="bg-gray-900 border border-gray-800 rounded-lg p-3 space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <SectionTitle number="3" title="Test, review, activate" detail="Dry-run only: this test never changes live traffic" />
              <div className="flex items-center gap-2">
                <label className="text-[11px] text-gray-500 flex items-center gap-1" title={`Re-run the sequence in one isolated worker to exercise connection state (max ${repeatLimit} for this input).`}>
                  Repeat
                  <input
                    type="number"
                    min={1}
                    max={repeatLimit}
                    value={repeat}
                    onChange={(event) => { setRepeat(event.target.value); invalidateTest() }}
                    className="w-14 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100"
                  />
                </label>
                <button onClick={runTest} disabled={testing || !status?.available} className="text-xs px-2.5 py-1 rounded bg-cyan-700 text-white hover:bg-cyan-600 disabled:opacity-50 cursor-pointer">
                  {testing ? 'Running…' : 'Run dry test'}
                </button>
              </div>
            </div>

            <div className="rounded border border-gray-800 bg-gray-950/40 p-2 space-y-2">
              <div className="flex items-center gap-2 flex-wrap text-[11px]">
                <TestSourceBadge source={testSource} flowIsArray={flowIsArray} parsedFlow={parsedFlow} />
                {testSource.kind === 'custom' && !flowIsArray && (
                  <div className="inline-flex rounded border border-gray-700 overflow-hidden">
                    {['request', 'response'].map((direction) => (
                      <button
                        key={direction}
                        aria-pressed={currentDirection === direction}
                        onClick={() => applyDirection(direction)}
                        className={`px-2 py-1 cursor-pointer ${currentDirection === direction ? 'bg-cyan-700 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}
                      >
                        {direction === 'request' ? 'Request' : 'Response'}
                      </button>
                    ))}
                  </div>
                )}
                <span className="text-gray-600 ml-auto">Captured traffic:</span>
                <input
                  aria-label="Captured packet ID"
                  type="number"
                  value={packetId}
                  onChange={(event) => setPacketId(event.target.value)}
                  placeholder="packet #"
                  className="w-24 bg-gray-800 border border-gray-700 rounded px-1.5 py-1 text-gray-100"
                />
                <button onClick={() => packetId && loadPacket(packetId)} disabled={loadingFlow || !packetId} title="Use original bytes and timestamp" className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 disabled:opacity-50 cursor-pointer">
                  Use packet
                </button>
                <button onClick={() => packetId && loadFlow(packetId)} disabled={loadingFlow || !packetId} title="Resolve the complete flow server-side" className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 disabled:opacity-50 cursor-pointer">
                  Use full flow
                </button>
                <button onClick={loadLatestPacket} disabled={loadingFlow} className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:border-cyan-600 hover:text-cyan-300 disabled:opacity-50 cursor-pointer">
                  {loadingFlow ? 'Loading…' : 'Latest packet'}
                </button>
              </div>
            </div>

            <details key={testSource.kind} open={testSource.kind === 'custom'} className="rounded border border-gray-800 bg-gray-950/30">
              <summary className="px-2 py-1.5 text-[11px] text-gray-500 cursor-pointer select-none">
                {testSource.kind === 'custom' ? 'Synthetic JSON input' : 'Server data preview'}
                {testSource.kind !== 'custom' && <span className="ml-2 text-emerald-600">exact server data will be used</span>}
              </summary>
              <div className="px-2 pb-2 space-y-1">
                {testSource.kind !== 'custom' && <p className="text-[10px] text-gray-600">Editing this preview switches to synthetic JSON{testSource.kind === 'flow' && testSource.count > testSource.previewCount ? ` using only the ${testSource.previewCount} previewed packets` : ''}.</p>}
                <textarea
                  aria-label={testSource.kind === 'custom' ? 'Synthetic flow JSON' : 'Server data preview JSON'}
                  value={testFlowJSON}
                  onChange={(event) => {
                    setTestFlowJSON(event.target.value)
                    setTestSource({ kind: 'custom' })
                    invalidateTest()
                  }}
                  rows={10}
                  spellCheck={false}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </details>

            {testResult && (
              <TestVerdict
                result={testResult}
                mode={draft.mode}
                onPromote={draft.mode === 'observe' && !hasTestError(testResult) ? () => {
                  changeDraft({ mode: 'block' })
                  setNotice('Inline mode selected; run the dry test again before saving')
                } : null}
              />
            )}
          </section>
        </main>
      </div>
    </div>
  )
}

function WorkflowStrip() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 rounded-lg border border-gray-800 bg-gray-900/40 divide-y sm:divide-y-0 sm:divide-x divide-gray-800">
      <WorkflowStep number="1" title="Observe" detail="Choose a template and narrow its scope" />
      <WorkflowStep number="2" title="Dry-run" detail="Use a real packet or complete flow" />
      <WorkflowStep number="3" title="Promote" detail="Move inline only after reviewing matches" />
    </div>
  )
}

function WorkflowStep({ number, title, detail }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2">
      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-950 text-[10px] text-cyan-300 border border-cyan-800">{number}</span>
      <div><span className="block text-xs text-gray-300">{title}</span><span className="block text-[10px] text-gray-600">{detail}</span></div>
    </div>
  )
}

function SectionTitle({ number, title, detail }) {
  return (
    <div className="flex items-center gap-2 min-w-0">
      <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded bg-gray-800 text-[10px] text-cyan-300 border border-gray-700">{number}</span>
      <div className="min-w-0">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">{title}</h3>
        <p className="text-[10px] text-gray-600 truncate">{detail}</p>
      </div>
    </div>
  )
}

function ModeSelector({ mode, onChange }) {
  const inline = mode !== 'observe'
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-gray-600 mb-1">Execution mode</div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <button
          type="button"
          aria-pressed={!inline}
          onClick={() => onChange('observe')}
          className={`text-left rounded border p-2 cursor-pointer ${!inline ? 'border-emerald-700 bg-emerald-950/25 ring-1 ring-emerald-800/30' : 'border-gray-800 bg-gray-950/30 hover:border-gray-700'}`}
        >
          <span className="block text-xs text-emerald-300">Observe <span className="text-[9px] text-emerald-600">RECOMMENDED FIRST</span></span>
          <span className="block text-[10px] text-gray-500 mt-0.5">Async alert-only evaluation. It cannot delay or modify traffic.</span>
        </button>
        <button
          type="button"
          aria-pressed={inline}
          onClick={() => onChange('block')}
          className={`text-left rounded border p-2 cursor-pointer ${inline ? 'border-amber-700 bg-amber-950/25 ring-1 ring-amber-800/30' : 'border-gray-800 bg-gray-950/30 hover:border-gray-700'}`}
        >
          <span className="block text-xs text-amber-300">Inline</span>
          <span className="block text-[10px] text-gray-500 mt-0.5">Synchronous: flow.drop/close or flow.rewrite can modify traffic. Fails open on timeout.</span>
        </button>
      </div>
      {inline && <p className="text-[10px] text-amber-500/90 mt-1.5">For HTTP body rules, require <code>flow.body_complete</code>; chunked/oversized requests expose incomplete bodies inline. Ordinary HTTP/1 responses run inline within the buffer limit, while streaming/SSE/gRPC responses remain observe-only. TCP/WebSocket support both directions. Scope this mode narrowly.</p>}
    </div>
  )
}

function ScopeEditor({ draft, services, protocolPresets, ready, onChange }) {
  const allServices = draft.service_ids.includes('*')

  function toggleService(id) {
    if (allServices) { onChange({ service_ids: [id] }); return }
    const next = draft.service_ids.includes(id)
      ? draft.service_ids.filter((item) => item !== id)
      : [...draft.service_ids, id]
    onChange({ service_ids: next.length ? next : ['*'] })
  }

  function toggleDirection(direction) {
    const next = draft.directions.includes(direction)
      ? draft.directions.filter((item) => item !== direction)
      : [...draft.directions, direction]
    onChange({ directions: next })
  }

  return (
    <div className="space-y-2">
      <fieldset disabled={!ready} aria-busy={!ready} className={`rounded border border-gray-800 bg-gray-950/30 px-2 py-2 ${ready ? '' : 'opacity-50'}`}>
        <legend className="sr-only">Apply filter to services</legend>
        {!ready && <p className="mb-2 text-[10px] text-gray-500">Loading services…</p>}
        <ScopeRow label="Service">
          <ScopeChip active={allServices} onClick={() => onChange({ service_ids: ['*'] })}>All services</ScopeChip>
          {services.map((service) => <ScopeChip key={service.id} active={!allServices && draft.service_ids.includes(service.id)} onClick={() => toggleService(service.id)}>{service.name}</ScopeChip>)}
        </ScopeRow>
        {ready && services.length === 0 && <p className="mt-1.5 text-[10px] text-gray-600">No services configured yet; this filter will apply to all services.</p>}
      </fieldset>

      <details className="rounded border border-gray-800 bg-gray-950/30">
        <summary className="px-2 py-1.5 cursor-pointer select-none flex items-center gap-2">
          <span className="text-[11px] text-gray-400">Advanced scope</span>
          <span className="text-[10px] text-cyan-500 truncate">{draft.directions.length ? draft.directions.join('+') : 'both directions'} · {draft.protocols.length ? draft.protocols.join(', ') : 'all protocols'}</span>
        </summary>
        <fieldset disabled={!ready} aria-busy={!ready} className={`border-t border-gray-800 px-2 py-2 space-y-2.5 ${ready ? '' : 'opacity-50'}`}>
          {!ready && <p className="text-[10px] text-gray-500">Loading protocols…</p>}
          <ScopeRow label="Direction">
            <ScopeChip active={draft.directions.length === 0} onClick={() => onChange({ directions: [] })}>Both</ScopeChip>
            {['request', 'response'].map((direction) => <ScopeChip key={direction} active={draft.directions.includes(direction)} onClick={() => toggleDirection(direction)}>{direction}</ScopeChip>)}
          </ScopeRow>
          <ScopeRow label="Protocols">
            <ScopeChip active={draft.protocols.length === 0} onClick={() => onChange({ protocols: [] })}>All</ScopeChip>
            {draft.protocols.map((protocol) => <ScopeChip key={protocol} active onClick={() => onChange({ protocols: draft.protocols.filter((item) => item !== protocol) })}>{protocol} ×</ScopeChip>)}
            <select
              aria-label="Add protocol to filter scope"
              value=""
              onChange={(event) => {
                const protocol = event.target.value
                if (protocol && !draft.protocols.includes(protocol)) onChange({ protocols: [...draft.protocols, protocol] })
              }}
              className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[11px] text-gray-400"
            >
              <option value="">+ add protocol</option>
              {protocolPresets.filter((preset) => !draft.protocols.includes(preset.id)).map((preset) => <option key={preset.id} value={preset.id}>{preset.label}</option>)}
            </select>
          </ScopeRow>
        </fieldset>
      </details>
    </div>
  )
}

function ScopeRow({ label, children }) {
  return <div className="flex items-start gap-2 flex-wrap"><span className="w-16 pt-1 text-[10px] uppercase tracking-wide text-gray-600">{label}</span>{children}</div>
}

function ScopeChip({ active, onClick, children }) {
  return <button type="button" aria-pressed={active} onClick={onClick} className={`text-[11px] px-2 py-1 rounded border cursor-pointer ${active ? 'bg-cyan-900/30 border-cyan-700 text-cyan-200' : 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300'}`}>{children}</button>
}

function scopeSummary(script, serviceCatalog = []) {
  const allServices = script.service_ids?.includes('*') || !script.service_ids?.length
  const services = allServices
    ? 'all services'
    : script.service_ids.map((id) => serviceCatalog.find((service) => String(service.id) === String(id))?.name || id).join(', ')
  const directions = script.directions?.length ? script.directions.join('+') : 'both directions'
  const protocols = script.protocols?.length ? script.protocols.join(', ') : 'all protocols'
  return `${services} · ${directions} · ${protocols}`
}

const TEMPLATE_ACCENTS = {
  rose: 'hover:border-rose-700',
  amber: 'hover:border-amber-700',
  cyan: 'hover:border-cyan-700',
  violet: 'hover:border-violet-700',
  emerald: 'hover:border-emerald-700',
}

function TemplateGallery({ templates, onLoad }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] uppercase tracking-wide text-gray-600">Guided templates</span>
        <span className="text-[10px] text-emerald-700">always loaded in Observe</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-2">
        {templates.map((template) => (
          <button key={template.key} type="button" onClick={() => onLoad(template)} className={`text-left rounded border border-gray-800 bg-gray-900/50 p-2 cursor-pointer transition-colors ${TEMPLATE_ACCENTS[template.accent] || TEMPLATE_ACCENTS.cyan}`}>
            <span className="block text-xs text-gray-200">{template.title}</span>
            <span className="block text-[10px] leading-snug text-gray-600 mt-1">{template.description}</span>
            <span className="block text-[9px] uppercase tracking-wide text-gray-700 mt-2">
              {template.difficulty || 'guided'} · {template.mode === 'observe' ? 'observe pattern' : 'inline after test'}
            </span>
          </button>
        ))}
      </div>
    </div>
  )
}

function SnippetExplorer({ snippets, onInsert }) {
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const query = search.trim().toLowerCase()
  const categories = [...new Set(snippets.map((snippet) => snippet.group))]
  const visible = snippets.filter((snippet) => {
    if (category && snippet.group !== category) return false
    return !query || `${snippet.group} ${snippet.label} ${snippet.detail} ${snippet.code}`.toLowerCase().includes(query)
  })
  const groups = [...new Set(visible.map((snippet) => snippet.group))]

  return (
    <details className="rounded border border-gray-800 bg-gray-900/40">
      <summary className="px-3 py-2 text-[11px] text-gray-400 cursor-pointer select-none">API &amp; snippet explorer <span className="text-gray-700">— {snippets.length} entries · insert at cursor</span></summary>
      <div className="border-t border-gray-800 p-2 space-y-2">
        <div className="grid grid-cols-1 sm:grid-cols-[1fr_180px] gap-2">
          <input aria-label="Search Python filter API and snippets" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search flags, duration, rate, state, HTTP…" className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 focus:outline-none focus:border-cyan-600" />
          <select aria-label="Filter Python API by category" value={category} onChange={(event) => setCategory(event.target.value)} className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-cyan-600">
            <option value="">All categories</option>
            {categories.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </div>
        {groups.map((group) => (
          <details key={group} open={query || category === group ? true : undefined} className="rounded border border-gray-800/70 bg-gray-950/20">
            <summary className="px-2 py-1.5 text-[10px] uppercase tracking-wide text-gray-500 cursor-pointer select-none">
              {group} <span className="text-gray-700">· {visible.filter((snippet) => snippet.group === group).length}</span>
            </summary>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-1 border-t border-gray-800/70 p-1.5">
              {visible.filter((snippet) => snippet.group === group).map((snippet) => (
                <button key={`${snippet.group}-${snippet.label}`} type="button" onClick={() => onInsert(snippet.code)} className="text-left rounded border border-gray-800 bg-gray-950/40 px-2 py-1.5 hover:border-cyan-800 cursor-pointer min-w-0">
                  <span className="block text-[11px] text-cyan-300">{snippet.label}</span>
                  <code className="block text-[9px] text-gray-600 truncate" title={snippet.code}>{snippet.code}</code>
                  <span className="block text-[9px] text-gray-700">{snippet.detail}</span>
                </button>
              ))}
            </div>
          </details>
        ))}
        {visible.length === 0 && <p className="text-[11px] text-gray-600">No API entry matches that search.</p>}
      </div>
    </details>
  )
}

function TestSourceBadge({ source, flowIsArray, parsedFlow }) {
  if (source.kind === 'packet') return <Badge tone="green">SERVER PACKET #{source.id}</Badge>
  if (source.kind === 'flow') return <Badge tone="green">SERVER FLOW · {source.evaluatedCount}{source.count > source.evaluatedCount ? `/${source.count}` : ''} packets</Badge>
  if (flowIsArray) return <Badge tone="cyan">SYNTHETIC SEQUENCE · {parsedFlow.length} packets</Badge>
  return <Badge tone="gray">SYNTHETIC PACKET</Badge>
}

function TestVerdict({ result, mode, onPromote }) {
  if (result.script_error) {
    return <ResultBox tone="red" title="Script definition error"><pre className="text-[11px] text-red-300/90 font-mono whitespace-pre-wrap break-all">{result.script_error}</pre></ResultBox>
  }

  const steps = result.steps || []
  const runtimeError = steps.some((step) => (step.matches || []).some((match) => match.error))
  const inline = mode !== 'observe'
  const matched = steps.filter((step) => step.matched && !(step.matches || []).every((match) => match.error)).length
  const rewrites = steps.filter(hasRewrite).length

  return (
    <div className="rounded border border-gray-700 bg-gray-800/40 p-2 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <span className="text-xs text-gray-300">Dry-run complete · </span>
          <span className={runtimeError ? 'text-red-300 text-xs' : matched || rewrites ? 'text-emerald-300 text-xs' : 'text-gray-500 text-xs'}>
            {runtimeError ? 'runtime error' : `${matched} match${matched === 1 ? '' : 'es'}${rewrites ? ` · ${rewrites} rewrite${rewrites === 1 ? '' : 's'}` : ''}`}
          </span>
        </div>
        {onPromote && (
          <button type="button" onClick={onPromote} className="text-[11px] px-2 py-1 rounded border border-amber-700 bg-amber-950/40 text-amber-300 hover:bg-amber-900/40 cursor-pointer">
            Promote to Inline
          </button>
        )}
      </div>

      {steps.length === 0 && <p className="text-[11px] text-gray-500">No test steps were returned.</p>}
      {steps.length === 1 ? <SingleStepResult step={steps[0]} fallbackMatches={result.matches} inline={inline} /> : (
        <div className="space-y-1 max-h-72 overflow-auto pr-1">
          {steps.map((step) => <StepRow key={step.index} step={step} inline={inline} />)}
        </div>
      )}
      <p className="text-[10px] text-gray-600 border-t border-gray-700/60 pt-1.5">
        This was an isolated dry-run. {inline ? 'Save the filter to apply inline actions to live traffic.' : 'Observe mode turns every match into an alert; drop and rewrite requests remain disarmed.'}
      </p>
    </div>
  )
}

function SingleStepResult({ step, fallbackMatches, inline }) {
  if (!step) return null
  const matches = step.matches || fallbackMatches || []
  return (
    <div className="space-y-1.5">
      {matches.length === 0 && !hasRewrite(step) && <p className="text-[11px] text-gray-500">No match — this input would be ignored.</p>}
      {matches.map((match, index) => (
        <div key={`${match.script || 'test'}-${index}`} className={`rounded border p-2 ${match.error ? 'border-red-800/50 bg-red-950/30' : match.block ? 'border-rose-800/50 bg-rose-950/20' : 'border-emerald-800/50 bg-emerald-950/20'}`}>
          <div className="flex items-center gap-2"><VerdictBadge match={match} inline={inline} />{match.reason && <span className="text-[11px] text-gray-300 break-all">{match.reason}</span>}</div>
        </div>
      ))}
      {hasRewrite(step) && <RewriteNote text={step.rewrite || ''} exact={step.rewrite_b64 || ''} inline={inline} />}
      {step.console?.length > 0 && <ConsoleOutput lines={step.console} />}
    </div>
  )
}

function StepRow({ step, inline }) {
  const matches = step.matches || []
  return (
    <div className="flex items-center gap-2 text-[11px] min-w-0">
      <span className="text-gray-600 w-7 text-right flex-shrink-0">#{step.index + 1}</span>
      {step.direction && <Badge tone={step.direction === 'response' ? 'cyan' : 'gray'}>{step.direction === 'response' ? 'RES' : 'REQ'}</Badge>}
      {matches.map((match, index) => <VerdictBadge key={`${match.script || 'test'}-${index}`} match={match} inline={inline} />)}
      {matches[0]?.reason && <span className="text-gray-400 truncate" title={matches[0].reason}>{matches[0].reason}</span>}
      {hasRewrite(step) && <Badge tone={inline ? 'amber' : 'gray'}>{inline ? 'WOULD REWRITE' : 'REWRITE DISARMED'}</Badge>}
      {step.console?.length > 0 && <span className="text-[10px] text-gray-500" title={step.console.map((line) => line.text).join('')}>console</span>}
      {!step.matched && !hasRewrite(step) && <span className="text-gray-600">no match</span>}
    </div>
  )
}

function VerdictBadge({ match, inline }) {
  if (match.error) return <Badge tone="red">ERROR</Badge>
  if (match.block) return <Badge tone={inline ? 'amber' : 'gray'}>{inline ? 'WOULD DROP' : 'DROP DISARMED'}</Badge>
  return <Badge tone="green">ALERT</Badge>
}

function RewriteNote({ text, exact, inline }) {
  const preview = text ? (text.length > 300 ? `${text.slice(0, 300)}…` : text) : '<empty payload>'
  const byteLength = exact ? Math.floor(exact.length * 3 / 4) - (exact.endsWith('==') ? 2 : exact.endsWith('=') ? 1 : 0) : 0
  return (
    <div className="rounded border border-fuchsia-800/50 bg-fuchsia-950/20 p-2">
      <div className="flex items-center gap-2 mb-1"><Badge tone={inline ? 'amber' : 'gray'}>{inline ? 'WOULD REWRITE' : 'REWRITE DISARMED'}</Badge></div>
      <pre className="text-[11px] text-fuchsia-100/80 font-mono whitespace-pre-wrap break-all">{preview}</pre>
      {exact && <span className="block mt-1 text-[9px] text-gray-600">exact binary payload available · {byteLength} bytes</span>}
    </div>
  )
}

function ConsoleOutput({ lines }) {
  return <pre className="rounded border border-gray-700 bg-black/30 p-2 text-[11px] text-gray-400 whitespace-pre-wrap break-all">{lines.map((line) => `[${line.script}] ${line.text}`).join('\n')}</pre>
}

function ReturnLegend() {
  return (
    <div className="space-y-2 pt-1">
      <LegendRow code="return False" desc="ignore" tone="gray" />
      <LegendRow code='flow.alert("reason")' desc="alert only" tone="green" />
      <LegendRow code='flow.drop("reason")' desc="drop current message in Inline" tone="red" />
      <LegendRow code='flow.close("reason")' desc="close where the protocol supports it; otherwise drop" tone="amber" />
      <LegendRow code='flow.rewrite(content, "reason")' desc="replace current payload in Inline" tone="fuchsia" />
      <p className="text-[10px] text-gray-600 pt-1.5 leading-snug border-t border-gray-800/70">Observe never modifies traffic. Inline actions are bounded and fail open on timeout.</p>
    </div>
  )
}

function LegendRow({ code, desc, tone }) {
  const dots = { gray: 'bg-gray-500', green: 'bg-emerald-400', amber: 'bg-amber-400', red: 'bg-rose-400', fuchsia: 'bg-fuchsia-400' }
  return (
    <div className="flex items-start gap-2">
      <span className={`mt-[5px] w-1.5 h-1.5 rounded-full flex-shrink-0 ${dots[tone]}`} />
      <div className="min-w-0"><code className="text-[11px] text-cyan-300 font-mono break-words">{code}</code><span className="text-[11px] text-gray-500"> — {desc}</span></div>
    </div>
  )
}

function ResultBox({ tone, title, children }) {
  const classes = tone === 'red' ? 'border-red-800/50 bg-red-950/40 text-red-300' : 'border-gray-700 bg-gray-800/40 text-gray-300'
  return <div className={`rounded border p-2 ${classes}`}><div className="text-xs font-semibold mb-1">{title}</div>{children}</div>
}

function Badge({ tone, children, title }) {
  const tones = {
    green: 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50',
    red: 'bg-red-900/40 text-red-300 border-red-700/50',
    amber: 'bg-amber-900/40 text-amber-300 border-amber-700/50',
    cyan: 'bg-cyan-900/30 text-cyan-300 border-cyan-700/40',
    gray: 'bg-gray-800 text-gray-400 border-gray-700',
  }
  return <span title={title} className={`text-[10px] px-1.5 py-0.5 rounded border whitespace-nowrap ${tones[tone] || tones.gray}`}>{children}</span>
}
