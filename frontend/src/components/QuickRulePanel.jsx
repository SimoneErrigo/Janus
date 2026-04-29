import { useState, useEffect } from 'react'
import { api } from '../api'

// Inline "Block / Alert" rule creation from a captured packet. Pre-fills the
// pattern from the packet's URL or body, and can fan out to multiple services.
export default function QuickRulePanel({ packet, services, onCreated, onCancel }) {
  const [pattern, setPattern] = useState('')
  const [type, setType] = useState('string')
  const [scope, setScope] = useState('body')
  const [action, setAction] = useState('drop')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [selectedServices, setSelectedServices] = useState([packet.service_id])
  const allSelected = selectedServices.length === services.length

  useEffect(() => {
    if (packet.url && packet.direction === 'request') {
      setPattern(packet.url)
      setScope('url')
    } else if (packet.body_string) {
      setPattern(packet.body_string.length > 300 ? packet.body_string.slice(0, 300) : packet.body_string)
      setScope('body')
    }
  }, [packet])

  function toggleService(id) {
    setSelectedServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    )
  }

  function toggleAll() {
    setSelectedServices(allSelected ? [packet.service_id] : services.map(s => s.id))
  }

  async function handleCreate() {
    const p = pattern.trim()
    if (!p || selectedServices.length === 0) return
    setCreating(true)
    setError('')
    try {
      const label = p.length > 40 ? p.slice(0, 40) + '...' : p
      const promises = selectedServices.map(svcId =>
        api.createRule({
          service_id: svcId,
          name: `Quick: ${scope} ${type === 'regex' ? '~' : '='} ${label}`,
          type, scope, pattern: p,
          priority: 10, enabled: true, action,
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
        <span>&#10003;</span> Rule created for {selectedServices.length} service{selectedServices.length !== 1 ? 's' : ''} — traffic matching this pattern will be {action === 'alert' ? 'alerted' : action === 'both' ? 'alerted and dropped' : 'dropped'}
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
        <select value={type} onChange={e => setType(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100 focus:outline-none focus:border-red-500">
          <option value="string">String</option>
          <option value="regex">Regex</option>
          <option value="bytes">Bytes</option>
        </select>
        {['url', 'body', 'header', 'raw'].map(s => {
          const active = scope.split(',').includes(s)
          return (
            <button key={s} type="button" onClick={() => {
              const cur = scope.split(',').filter(Boolean)
              const next = active ? cur.filter(x => x !== s) : [...cur, s]
              if (next.length > 0) setScope(next.join(','))
            }}
              className={`text-xs px-2 py-1 rounded cursor-pointer transition-colors border ${active ? 'bg-cyan-900/50 text-cyan-400 border-cyan-600/50' : 'bg-gray-800 text-gray-500 border-gray-700 hover:text-gray-300'}`}>
              {s}
            </button>
          )
        })}
      </div>
      <div className="flex items-center gap-2 flex-wrap text-[10px]">
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
      <textarea
        value={pattern}
        onChange={e => setPattern(e.target.value)}
        rows={3}
        className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-red-500 resize-y"
        placeholder="Pattern to match..."
        spellCheck={false}
      />
      <div className="flex items-center gap-2 flex-wrap">
        {packet.url && (
          <button onClick={() => { setPattern(packet.url); setScope('url'); setType('string') }}
            className="text-[10px] text-gray-500 hover:text-gray-300 cursor-pointer underline underline-offset-2">Fill URL</button>
        )}
        {packet.body_string && (
          <button onClick={() => { setPattern(packet.body_string.length > 300 ? packet.body_string.slice(0, 300) : packet.body_string); setScope('body'); setType('string') }}
            className="text-[10px] text-gray-500 hover:text-gray-300 cursor-pointer underline underline-offset-2">Fill Body</button>
        )}
      </div>
      {error && <div className="text-xs text-red-400">{error}</div>}
      <div className="flex items-center gap-2">
        <button onClick={handleCreate} disabled={creating || !pattern.trim()}
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
