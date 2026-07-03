import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'

const STARTER_CODE = `# Runs against every captured packet. Return one of:
#   False / None          -> no match
#   True                  -> match (no reason)
#   "reason string"       -> match, shown on the Alerts page
#   {"match": True, "reason": "...", "drop": "<filter expr>"}
#       -> match AND, fail2ban-style, install a content-only drop rule so
#          FUTURE matching traffic is blocked by the fast in-process engine.
#          The drop expression may only use content fields (body/url/header/
#          service); IP/port fields are rejected (SNAT-unsafe).
#
# Module-level state persists across calls, so you can count things over time.
#
# flow fields: id, service, direction, method, url, status, src, dst,
#              sport, dport, headers (dict), body (str), flagged,
#              contains_flagid, timestamp

import json

logins = {}

def match(flow):
    if flow["method"] == "POST" and flow["url"] == "/login":
        try:
            user = json.loads(flow["body"]).get("user")
        except Exception:
            user = None
        if user:
            logins[user] = logins.get(user, 0) + 1
            if logins[user] > 1:
                # Alert, and block this user's future requests by content:
                return {
                    "match": True,
                    "reason": "repeated login for %s (#%d)" % (user, logins[user]),
                    "drop": 'body contains "\\"user\\":\\"%s\\""' % user,
                }
    return False
`

const SAMPLE_FLOW = {
  method: 'POST',
  url: '/login',
  service: 'web',
  direction: 'request',
  status: 0,
  src: '10.60.5.7',
  dst: '10.60.1.1',
  headers: { 'User-Agent': 'curl/8.0', 'Content-Type': 'application/json' },
  body: '{"user":"alice","password":"x"}',
  flagged: false,
  contains_flagid: false,
}

const EMPTY_DRAFT = { id: null, name: '', code: STARTER_CODE, enabled: true }

export default function PyFilters() {
  const [scripts, setScripts] = useState([])
  const [status, setStatus] = useState(null)
  const [draft, setDraft] = useState(EMPTY_DRAFT)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const [testFlowJSON, setTestFlowJSON] = useState(JSON.stringify(SAMPLE_FLOW, null, 2))
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)

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

  const startNew = () => { setDraft(EMPTY_DRAFT); setTestResult(null); setError('') }
  const startEdit = (s) => {
    setDraft({ id: s.id, name: s.name, code: s.code, enabled: s.enabled })
    setTestResult(null)
    setError('')
  }

  const flash = (msg) => { setNotice(msg); setTimeout(() => setNotice(''), 2500) }

  async function save() {
    if (!draft.name.trim()) { setError('name is required'); return }
    setSaving(true)
    setError('')
    try {
      if (editing) {
        await api.updatePyFilter(draft.id, { name: draft.name, code: draft.code, enabled: draft.enabled })
        flash('Filter saved')
      } else {
        const created = await api.createPyFilter({ name: draft.name, code: draft.code, enabled: draft.enabled })
        setDraft({ id: created.id, name: created.name, code: created.code, enabled: created.enabled })
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
      await api.updatePyFilter(s.id, { name: s.name, code: s.code, enabled: !s.enabled })
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

  async function runTest() {
    setTesting(true)
    setTestResult(null)
    setError('')
    let flow
    try {
      flow = JSON.parse(testFlowJSON)
    } catch {
      setError('sample flow is not valid JSON')
      setTesting(false)
      return
    }
    try {
      const res = await api.testPyFilter({ name: draft.name || 'test', code: draft.code, flow })
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
            packet; module-level state persists, so you can express stateful checks (e.g. “same user
            logs in more than once”). Matches surface on the <span className="text-gray-300">Alerts</span> page.
            A match can also return a <code className="text-cyan-300">drop</code> filter expression
            to block <em>future</em> matching traffic (fail2ban-style, content-only — never by IP).
          </p>
        </div>
        {statusBadge}
      </header>

      {status && status.last_error && (
        <div className="text-xs text-amber-300 bg-amber-950/40 border border-amber-800/50 rounded px-3 py-2 font-mono break-all">
          {status.last_error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-4">
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
                <span className={`text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0 ${
                  s.enabled
                    ? 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50'
                    : 'bg-gray-800 text-gray-500 border-gray-700'
                }`}>
                  {s.enabled ? 'ON' : 'OFF'}
                </span>
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
            <button
              onClick={save}
              disabled={saving}
              className="text-sm px-3 py-1.5 rounded bg-cyan-700 text-white hover:bg-cyan-600 disabled:opacity-50 cursor-pointer"
            >
              {saving ? 'Saving…' : editing ? 'Save' : 'Create'}
            </button>
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
          <div className="bg-gray-900 border border-gray-800 rounded p-3 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs uppercase tracking-wide text-gray-500">Test against a sample flow</h3>
              <button
                onClick={runTest}
                disabled={testing || !status?.available}
                className="text-xs px-2.5 py-1 rounded bg-gray-700 text-gray-100 hover:bg-gray-600 disabled:opacity-50 cursor-pointer"
              >
                {testing ? 'Running…' : 'Run test'}
              </button>
            </div>
            <textarea
              value={testFlowJSON}
              onChange={(e) => setTestFlowJSON(e.target.value)}
              rows={10}
              spellCheck={false}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500"
            />
            {testResult && (
              <div className="text-xs space-y-1">
                {testResult.script_error ? (
                  <div className="text-red-300 font-mono whitespace-pre-wrap break-all">
                    {testResult.script_error}
                  </div>
                ) : testResult.matched ? (
                  <div className="space-y-1">
                    <div className="text-emerald-300">
                      Matched{testResult.matches?.[0]?.reason ? `: ${testResult.matches[0].reason}` : ''}
                    </div>
                    {testResult.matches?.[0]?.drop && (
                      <div className="text-amber-300">
                        Would install drop rule: <code className="font-mono">{testResult.matches[0].drop}</code>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-gray-400">No match.</div>
                )}
              </div>
            )}
          </div>
        </div>
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
