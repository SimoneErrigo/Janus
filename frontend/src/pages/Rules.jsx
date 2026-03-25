import { useState, useEffect } from 'react'
import { api } from '../api'

const matchTypes = ['string', 'regex', 'bytes']
const scopes = ['header', 'body', 'url', 'raw']

export default function Rules() {
  const [services, setServices] = useState([])
  const [selectedService, setSelectedService] = useState('')
  const [rules, setRules] = useState([])
  const [editing, setEditing] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.listServices().then((data) => {
      const svcs = data || []
      setServices(svcs)
      if (svcs.length > 0 && !selectedService) setSelectedService(svcs[0].id)
    })
  }, [])

  useEffect(() => {
    if (selectedService) loadRules()
  }, [selectedService])

  async function loadRules() {
    try {
      const data = await api.listRules(selectedService)
      setRules(data || [])
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleSave(rule) {
    setError('')
    try {
      const payload = { ...rule, priority: parseInt(rule.priority, 10) || 0 }
      if (rule._isNew) {
        await api.createRule(payload)
      } else {
        await api.updateRule(rule.id, payload)
      }
      setEditing(null)
      loadRules()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleToggle(rule) {
    try {
      await api.updateRule(rule.id, { ...rule, enabled: !rule.enabled })
      loadRules()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDelete(id) {
    if (!confirm('Delete this rule?')) return
    try {
      await api.deleteRule(id)
      loadRules()
    } catch (err) {
      setError(err.message)
    }
  }

  const isAutoFlag = (rule) => rule.name?.startsWith('Auto flag filter')

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold text-gray-100">Drop Rules</h2>
        <div className="flex items-center gap-3">
          <select
            value={selectedService}
            onChange={(e) => setSelectedService(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
          >
            {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <button
            onClick={() => setEditing({ _isNew: true, service_id: selectedService, name: '', type: 'string', scope: 'body', pattern: '', priority: 10, enabled: true })}
            disabled={!selectedService}
            className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
          >
            + Add Rule
          </button>
        </div>
      </div>

      {error && <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm px-4 py-2 rounded mb-4">{error}</div>}

      {editing && (
        <RuleForm rule={editing} onSave={handleSave} onCancel={() => setEditing(null)} />
      )}

      {services.length === 0 ? (
        <p className="text-gray-600 text-center py-8">No services configured. Add a service first.</p>
      ) : (
        <div className="space-y-2">
          {rules.map((rule) => (
            <div key={rule.id} className={`bg-gray-900 border rounded-lg p-4 flex items-center justify-between ${
              isAutoFlag(rule) ? 'border-yellow-800/50' : 'border-gray-800'
            }`}>
              <div className="flex items-center gap-4">
                <button
                  onClick={() => handleToggle(rule)}
                  className={`w-10 h-5 rounded-full relative transition-colors cursor-pointer ${rule.enabled ? 'bg-cyan-600' : 'bg-gray-700'}`}
                >
                  <div className={`w-4 h-4 bg-white rounded-full absolute top-0.5 transition-transform ${rule.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-100">{rule.name}</span>
                    {isAutoFlag(rule) && <span className="text-xs px-1.5 py-0.5 bg-yellow-900/40 text-yellow-400 rounded">Auto Flag</span>}
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5 font-mono">
                    <span className="px-1.5 py-0.5 bg-gray-800 rounded mr-1">{rule.type}</span>
                    <span className="px-1.5 py-0.5 bg-gray-800 rounded mr-2">{rule.scope}</span>
                    <span className="text-gray-400">{rule.pattern.length > 60 ? rule.pattern.slice(0, 60) + '...' : rule.pattern}</span>
                    <span className="ml-2 text-gray-600">priority: {rule.priority}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => setEditing(rule)} className="text-gray-400 hover:text-cyan-400 text-sm px-3 py-1 cursor-pointer">Edit</button>
                <button onClick={() => handleDelete(rule.id)} className="text-gray-400 hover:text-red-400 text-sm px-3 py-1 cursor-pointer">Delete</button>
              </div>
            </div>
          ))}
          {rules.length === 0 && <p className="text-gray-600 text-center py-8">No rules for this service.</p>}
        </div>
      )}
    </div>
  )
}

function RuleForm({ rule, onSave, onCancel }) {
  const [form, setForm] = useState(rule)

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 mb-4">
      <h3 className="text-lg font-medium text-gray-100 mb-4">{form._isNew ? 'New Rule' : 'Edit Rule'}</h3>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Name</label>
          <input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="Rule name"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Priority</label>
          <input type="number" value={form.priority} onChange={(e) => set('priority', e.target.value)} placeholder="0"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Match Type</label>
          <select value={form.type} onChange={(e) => set('type', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500">
            {matchTypes.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Scope</label>
          <select value={form.scope} onChange={(e) => set('scope', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500">
            {scopes.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="col-span-2">
          <label className="block text-sm text-gray-400 mb-1">Pattern</label>
          <input value={form.pattern} onChange={(e) => set('pattern', e.target.value)} placeholder="Pattern to match"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500" />
        </div>
        <div className="flex items-center gap-2 col-span-2">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} className="accent-cyan-500" id="rule-enabled" />
          <label htmlFor="rule-enabled" className="text-sm text-gray-400">Enabled</label>
        </div>
      </div>
      <div className="flex gap-2 mt-4">
        <button onClick={() => onSave(form)} className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer">Save</button>
        <button onClick={onCancel} className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded transition-colors cursor-pointer">Cancel</button>
      </div>
    </div>
  )
}
