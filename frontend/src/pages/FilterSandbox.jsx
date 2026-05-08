import { useMemo, useState } from 'react'
import FilterExpression from '../components/FilterExpression'
import { parse, evaluate } from '../utils/filterAst'

const SAMPLE_PACKET = {
  service_id: 'svc-a',
  protocol: 'https',
  direction: 'request',
  method: 'POST',
  url: '/api/admin/login',
  status: 0,
  src_ip: '10.0.5.7',
  dst_ip: '10.60.1.1',
  src_port: 54321,
  dst_port: 8080,
  body_string: '{"user":"pippo","note":"asdrubale"}',
  headers: { 'User-Agent': 'curl/7.0', 'Authorization': 'Bearer abc123', 'X-Test': 'pluto' },
  flagged: false,
  contains_flagid: false,
  matched_rules: [],
}

// Standalone sandbox to exercise FilterExpression. Lets you build an
// expression and live-eval it against an editable sample packet using the
// JS-side evaluator (the same one Traffic.jsx will use for SSE filtering).
export default function FilterSandbox() {
  const [expression, setExpression] = useState('')
  const [packetJSON, setPacketJSON] = useState(JSON.stringify(SAMPLE_PACKET, null, 2))

  const packet = useMemo(() => {
    try { return JSON.parse(packetJSON) } catch { return null }
  }, [packetJSON])

  const evalResult = useMemo(() => {
    if (!packet) return { error: 'invalid JSON' }
    const r = parse(expression)
    if (!r.ok) return { error: r.error || 'parse error' }
    try {
      return { match: evaluate(r.tree, packet) }
    } catch (e) {
      return { error: e.message || String(e) }
    }
  }, [expression, packet])

  return (
    <div className="p-4 space-y-4 max-w-5xl">
      <header>
        <h1 className="text-xl font-bold text-cyan-400">Filter Expression Sandbox</h1>
        <p className="text-xs text-gray-500">
          Standalone playground for the unified filter / rule expression component. Edit the sample
          packet on the right and watch the evaluator update live. The expression is the single
          string you'd send to <code className="text-cyan-300">/api/packets?q=…</code> or save as
          a rule.
        </p>
      </header>

      <FilterExpression
        value={expression}
        onChange={setExpression}
        placeholder='e.g. body contains "pippo" OR header.User-Agent contains "bot"'
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div className="bg-gray-900 border border-gray-800 rounded p-3 space-y-2">
          <h2 className="text-xs uppercase tracking-wide text-gray-500">Sample packet (editable JSON)</h2>
          <textarea
            value={packetJSON}
            onChange={e => setPacketJSON(e.target.value)}
            rows={20}
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500"
            spellCheck={false}
          />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded p-3 space-y-2">
          <h2 className="text-xs uppercase tracking-wide text-gray-500">Result</h2>
          {evalResult.error ? (
            <div className="text-red-400 text-sm">Error: {evalResult.error}</div>
          ) : (
            <div className={`text-2xl font-bold ${evalResult.match ? 'text-emerald-400' : 'text-gray-500'}`}>
              {evalResult.match ? 'MATCH' : 'no match'}
            </div>
          )}
          <div className="pt-3">
            <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-1">Serialized expression</h3>
            <pre className="bg-gray-800 border border-gray-700 rounded p-2 text-xs font-mono text-gray-100 whitespace-pre-wrap break-all">
              {expression || <span className="text-gray-600 italic">(empty)</span>}
            </pre>
          </div>
          <div className="pt-3 text-[11px] text-gray-500 space-y-1">
            <p>
              <strong className="text-gray-400">Try:</strong>
            </p>
            <ul className="list-disc pl-5 space-y-0.5">
              <li><code className="text-cyan-300">body contains "pippo" AND NOT header contains "asdrubale"</code></li>
              <li><code className="text-cyan-300">url matches "^/api/.*" OR method == "DELETE"</code></li>
              <li><code className="text-cyan-300">src in (10.0.0.0/8) AND status &gt;= 400</code></li>
              <li><code className="text-cyan-300">header.Authorization startswith "Bearer "</code></li>
              <li><code className="text-cyan-300">flagged AND NOT dropped</code></li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
