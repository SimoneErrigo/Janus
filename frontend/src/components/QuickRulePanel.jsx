import { useState, useEffect } from 'react'
import { api } from '../api'
import FilterExpression from './FilterExpression'

// Inline rule creation from a captured packet. The pattern is now a unified
// expression. Quick-fill buttons seed common shapes (URL contains, body
// contains, multi-scope OR) so users don't have to type the DSL by hand.
export default function QuickRulePanel({ packet, services, onCreated, onCancel }) {
  const [expression, setExpression] = useState('')
  const [action, setAction] = useState('alert')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [selectedServices, setSelectedServices] = useState([packet.service_id])
  const allSelected = selectedServices.length === services.length

  // Seed the expression on first open: prefer URL for requests, body otherwise.
  useEffect(() => {
    if (packet.url && packet.direction === 'request') {
      setExpression(`url contains ${quote(packet.url)}`)
    } else if (packet.body_string) {
      const snippet = packet.body_string.length > 200
        ? packet.body_string.slice(0, 200)
        : packet.body_string
      setExpression(`body contains ${quote(snippet)}`)
    }
  }, [packet])

  function fillURL() {
    if (packet.url) setExpression(`url contains ${quote(packet.url)}`)
  }
  function fillBody() {
    if (packet.body_string) {
      const snippet = packet.body_string.length > 200
        ? packet.body_string.slice(0, 200)
        : packet.body_string
      setExpression(`body contains ${quote(snippet)}`)
    }
  }
  function fillBoth() {
    if (packet.url && packet.body_string) {
      const b = packet.body_string.length > 200
        ? packet.body_string.slice(0, 200)
        : packet.body_string
      setExpression(`url contains ${quote(packet.url)} OR body contains ${quote(b)}`)
    }
  }

  function toggleService(id) {
    setSelectedServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    )
  }
  function toggleAll() {
    setSelectedServices(allSelected ? [packet.service_id] : services.map(s => s.id))
  }

  async function handleCreate() {
    const expr = expression.trim()
    if (!expr || selectedServices.length === 0) return
    setCreating(true)
    setError('')
    try {
      const label = expr.length > 40 ? expr.slice(0, 40) + '…' : expr
      const promises = selectedServices.map(svcId =>
        api.createRule({
          service_id: svcId,
          name: `Quick: ${label}`,
          expression: expr,
          priority: 10,
          enabled: true,
          action,
        })
      )
      await Promise.all(promises)
      setSuccess(true)
      setTimeout(() => onCreated?.(), 800)
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }

  if (success) {
    return (
      <div className="bg-green-900/30 border border-green-700/50 rounded p-2 text-xs text-green-400 flex items-center gap-2">
        <span>&#10003;</span> Rule created for {selectedServices.length} service{selectedServices.length !== 1 ? 's' : ''} — traffic matching this expression will be {action === 'alert' ? 'alerted' : action === 'both' ? 'alerted and dropped' : 'dropped'}
      </div>
    )
  }

  return (
    <div className="bg-red-950/30 border border-red-800/50 rounded p-2 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <select value={action} onChange={e => setAction(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100 focus:outline-none focus:border-red-500">
          <option value="drop">Drop</option>
          <option value="alert">Alert</option>
          <option value="both">Both</option>
        </select>
        {packet.url && (
          <button onClick={fillURL} className="text-[10px] px-2 py-1 rounded bg-gray-800 text-gray-400 hover:text-cyan-300 cursor-pointer">
            URL
          </button>
        )}
        {packet.body_string && (
          <button onClick={fillBody} className="text-[10px] px-2 py-1 rounded bg-gray-800 text-gray-400 hover:text-cyan-300 cursor-pointer">
            Body
          </button>
        )}
        {packet.url && packet.body_string && (
          <button onClick={fillBoth} className="text-[10px] px-2 py-1 rounded bg-gray-800 text-gray-400 hover:text-cyan-300 cursor-pointer">
            URL OR Body
          </button>
        )}
      </div>

      <div className="flex items-center gap-2 flex-wrap text-[10px]">
        <span className="text-gray-500">Apply to:</span>
        <button onClick={toggleAll}
          className={`px-1.5 py-0.5 rounded cursor-pointer transition-colors ${allSelected ? 'bg-cyan-800/60 text-cyan-300' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}>
          All
        </button>
        {services.map(s => (
          <button key={s.id} onClick={() => toggleService(s.id)}
            className={`px-1.5 py-0.5 rounded cursor-pointer transition-colors ${selectedServices.includes(s.id) ? 'bg-cyan-900/50 text-cyan-400' : 'bg-gray-800 text-gray-600 hover:text-gray-400'}`}>
            {s.name}
          </button>
        ))}
      </div>

      <FilterExpression
        value={expression}
        onChange={setExpression}
        placeholder='e.g. url contains "/api/admin" AND header.User-Agent contains "curl"'
        compact
      />

      {error && <div className="text-xs text-red-400">{error}</div>}

      <div className="flex items-center gap-2">
        <button onClick={handleCreate} disabled={creating || !expression.trim()}
          className="bg-red-700 hover:bg-red-600 disabled:bg-gray-700 disabled:text-gray-500 text-white text-xs px-3 py-1.5 rounded transition-colors cursor-pointer disabled:cursor-default flex items-center gap-1">
          {creating ? 'Creating...' : <><span>&#9889;</span> Create Rule</>}
        </button>
        <button onClick={onCancel}
          className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs px-3 py-1.5 rounded transition-colors cursor-pointer">
          Cancel
        </button>
      </div>
    </div>
  )
}

// Quote a string literal for the DSL: wrap in double quotes, escape \ and ".
function quote(s) {
  return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'
}
