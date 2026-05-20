import { useState, useEffect, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '../api'
import ErrorBanner from '../components/ErrorBanner'
import FilterExpression from '../components/FilterExpression'
import { useServiceMap } from '../hooks/useServiceMap'

const actions = ['drop', 'alert', 'both']

// Compact one-line preview of a rule for the list view.
function ruleSummary(rule) {
  const expr = rule.expression || ''
  if (!expr) return '(no expression)'
  return expr.length > 90 ? expr.slice(0, 90) + '…' : expr
}

export default function Rules() {
  const [services, setServices] = useState([])
  const [selectedService, setSelectedService] = useState('')
  const [rules, setRules] = useState([])
  const [editing, setEditing] = useState(null)
  const [error, setError] = useState('')
  const [showPresets, setShowPresets] = useState(false)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [actionFilter, setActionFilter] = useState('all') // 'all' | 'drop' | 'alert' | 'both'
  const ruleFormAnchorRef = useRef(null)
  const location = useLocation()
  const navigate = useNavigate()

  useEffect(() => {
    api.listServices().then((data) => {
      const svcs = data || []
      setServices(svcs)
      if (svcs.length > 0 && !selectedService) setSelectedService('_all')
    })
  }, [])

  // Receive a pre-filled rule from another page (e.g. Traffic "New drop rule").
  // We consume location.state and clear it so a back-navigation doesn't re-open
  // the form. The form is opened immediately so the user only confirms + saves.
  useEffect(() => {
    const preset = location.state?.presetRule
    if (!preset) return
    setEditing({
      _isNew: true,
      service_id: preset.service_id || (services[0]?.id || ''),
      name: preset.name || '',
      expression: preset.expression || '',
      priority: 10,
      enabled: true,
      action: preset.action || 'drop',
    })
    if (preset.service_id) setSelectedService(preset.service_id)
    navigate(location.pathname, { replace: true, state: null })
    setTimeout(() => ruleFormAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
  }, [location.state, location.pathname, navigate, services])

  useEffect(() => {
    loadRules()
  }, [selectedService])

  async function loadRules() {
    try {
      const serviceId = selectedService === '_all' ? '' : selectedService
      const data = await api.listRules(serviceId)
      setRules(data || [])
      setSelectedIds(new Set())
    } catch (err) {
      setError(err.message)
    }
  }

  const { serviceName } = useServiceMap(services)

  async function handleSave(rule, targetServiceIds) {
    setError('')
    try {
      const payload = { ...rule, priority: parseInt(rule.priority, 10) || 0 }
      if (rule._isNew) {
        const svcIds = targetServiceIds && targetServiceIds.length > 0
          ? targetServiceIds
          : [payload.service_id]
        const promises = svcIds.map(svcId =>
          api.createRule({ ...payload, service_id: svcId })
        )
        await Promise.all(promises)
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

  async function handleBulkDelete() {
    if (selectedIds.size === 0) return
    if (!confirm(`Delete ${selectedIds.size} selected rule(s)?`)) return
    try {
      await api.bulkDeleteRules([...selectedIds])
      setSelectedIds(new Set())
      loadRules()
    } catch (err) {
      setError(err.message)
    }
  }

  function toggleSelect(id) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const filteredRules = actionFilter === 'all' ? rules : rules.filter(r => (r.action || 'drop') === actionFilter)

  function toggleSelectAll() {
    const allSelected = filteredRules.length > 0 && filteredRules.every(r => selectedIds.has(r.id))
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (allSelected) filteredRules.forEach(r => next.delete(r.id))
      else filteredRules.forEach(r => next.add(r.id))
      return next
    })
  }

  useEffect(() => {
    if (!editing) return
    requestAnimationFrame(() => {
      ruleFormAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    })
  }, [editing])

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold text-gray-100">Rules</h2>
        <div className="flex items-center gap-3">
          <select
            value={selectedService}
            onChange={(e) => setSelectedService(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="_all">All Services</option>
            {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <button
            onClick={() => setShowPresets(!showPresets)}
            disabled={services.length === 0}
            className={`text-sm px-4 py-2 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
              showPresets
                ? 'bg-orange-700 hover:bg-orange-600 text-white'
                : 'bg-orange-900/50 hover:bg-orange-800/50 text-orange-300 border border-orange-700/50'
            }`}
          >
            <span>&#9889;</span> Presets
          </button>
          {selectedIds.size > 0 && (
            <button
              onClick={handleBulkDelete}
              className="bg-red-900/50 hover:bg-red-800/50 text-red-400 text-sm px-4 py-2 rounded transition-colors cursor-pointer"
            >
              Delete {selectedIds.size} selected
            </button>
          )}
          <button
            onClick={() => setEditing({ _isNew: true, service_id: selectedService === '_all' ? (services[0]?.id || '') : selectedService, name: '', expression: '', priority: 10, enabled: true, action: 'drop' })}
            disabled={!selectedService || services.length === 0}
            className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
          >
            + Add Rule
          </button>
        </div>
      </div>

      <ErrorBanner error={error} className="mb-4" />

      {showPresets && (
        <PresetPanel
          services={services}
          defaultServiceId={selectedService === '_all' ? '' : selectedService}
          onCreated={() => { setShowPresets(false); loadRules() }}
          onCancel={() => setShowPresets(false)}
        />
      )}

      <div ref={ruleFormAnchorRef}>
        {editing && (
          <RuleForm rule={editing} services={services} onSave={handleSave} onCancel={() => setEditing(null)} />
        )}
      </div>

      {services.length === 0 ? (
        <p className="text-gray-600 text-center py-8">No services configured. Add a service first.</p>
      ) : (
        <div className="space-y-2">
          {rules.length > 0 && (
            <div className="flex items-center gap-3 mb-2 px-1 flex-wrap">
              <div className="flex items-center gap-2">
                <input type="checkbox" checked={filteredRules.length > 0 && filteredRules.every(r => selectedIds.has(r.id))}
                  onChange={toggleSelectAll} className="accent-cyan-500 cursor-pointer" />
                <span className="text-xs text-gray-500">Select all ({filteredRules.length})</span>
              </div>
              <div className="flex items-center gap-1 ml-auto">
                <span className="text-xs text-gray-600 mr-1">Action:</span>
                {['all', 'drop', 'alert', 'both'].map((a) => (
                  <button
                    key={a}
                    onClick={() => setActionFilter(a)}
                    className={`text-xs px-2 py-0.5 rounded border transition-colors cursor-pointer ${
                      actionFilter === a
                        ? a === 'drop' ? 'bg-red-900/50 text-red-300 border-red-700/50'
                          : a === 'alert' ? 'bg-orange-900/50 text-orange-300 border-orange-700/50'
                          : a === 'both' ? 'bg-purple-900/50 text-purple-300 border-purple-700/50'
                          : 'bg-cyan-900/50 text-cyan-300 border-cyan-700/50'
                        : 'bg-gray-800 text-gray-500 border-gray-700 hover:text-gray-300'
                    }`}
                  >
                    {a === 'all' ? 'All' : a.charAt(0).toUpperCase() + a.slice(1)}
                  </button>
                ))}
              </div>
            </div>
          )}
          {filteredRules.map((rule) => (
            <div key={rule.id} className={`bg-gray-900 border rounded-lg p-4 flex items-center justify-between ${selectedIds.has(rule.id) ? 'border-cyan-700/50' : 'border-gray-800'}`}>
              <div className="flex items-center gap-4">
                <input type="checkbox" checked={selectedIds.has(rule.id)}
                  onChange={() => toggleSelect(rule.id)} className="accent-cyan-500 cursor-pointer flex-shrink-0" />
                <button
                  onClick={() => handleToggle(rule)}
                  className={`w-10 h-5 rounded-full relative transition-colors cursor-pointer ${rule.enabled ? 'bg-cyan-600' : 'bg-gray-700'}`}
                >
                  <div className={`w-4 h-4 bg-white rounded-full absolute top-0.5 transition-transform ${rule.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-100">{rule.name}</span>
                    {selectedService === '_all' && <span className="text-xs px-1.5 py-0.5 bg-cyan-900/40 text-cyan-400 rounded">{serviceName(rule.service_id)}</span>}
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5 font-mono">
                    <span className={`px-1.5 py-0.5 rounded mr-2 ${
                      rule.action === 'drop' ? 'bg-red-900/40 text-red-400' :
                      rule.action === 'alert' ? 'bg-orange-900/40 text-orange-400' :
                      rule.action === 'both' ? 'bg-purple-900/40 text-purple-400' :
                      'bg-gray-800 text-gray-400'
                    }`}>{rule.action || 'drop'}</span>
                    <span className="text-gray-300">{ruleSummary(rule)}</span>
                    <span className="ml-2 text-gray-600">priority: {rule.priority}</span>
                    {rule.created_by && (
                      <span className="ml-2 text-gray-600">by: <span className="text-gray-500">{rule.created_by}</span></span>
                    )}
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

// ---- Preset Panel (loads from backend) ----

function PresetPanel({ services, defaultServiceId, onCreated, onCancel }) {
  const [categories, setCategories] = useState([])
  const [loadingPresets, setLoadingPresets] = useState(true)
  const [selected, setSelected] = useState({})
  const [targetServices, setTargetServices] = useState(
    defaultServiceId ? [defaultServiceId] : services.map(s => s.id)
  )
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [expandedCat, setExpandedCat] = useState(null)
  const allServicesSelected = targetServices.length === services.length

  useEffect(() => {
    let mounted = true
    api.getPresets().then(data => {
      if (mounted) {
        setCategories(data || [])
        setLoadingPresets(false)
      }
    }).catch(err => {
      if (mounted) {
        setError('Failed to load presets: ' + err.message)
        setLoadingPresets(false)
      }
    })
    return () => { mounted = false }
  }, [])

  function togglePreset(category, index) {
    setSelected(prev => {
      const cat = { ...(prev[category] || {}) }
      if (cat[index]) delete cat[index]
      else cat[index] = true
      return { ...prev, [category]: cat }
    })
  }

  function toggleCategory(categoryName, rulesCount) {
    const catSelected = selected[categoryName] || {}
    const allOn = rulesCount > 0 && Object.keys(catSelected).length === rulesCount
    if (allOn) {
      setSelected(prev => ({ ...prev, [categoryName]: {} }))
    } else {
      const all = {}
      for (let i = 0; i < rulesCount; i++) all[i] = true
      setSelected(prev => ({ ...prev, [categoryName]: all }))
    }
  }

  function toggleService(id) {
    setTargetServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    )
  }

  function toggleAllServices() {
    setTargetServices(allServicesSelected ? [] : services.map(s => s.id))
  }

  const totalSelected = Object.values(selected).reduce(
    (sum, cat) => sum + Object.keys(cat).length, 0
  )
  const totalRules = totalSelected * targetServices.length

  async function handleCreate() {
    if (totalRules === 0 || targetServices.length === 0) return
    setCreating(true)
    setError('')
    setResult(null)
    try {
      const selectedMap = {}
      for (const [catName, indices] of Object.entries(selected)) {
        const idxList = Object.keys(indices).map(Number)
        if (idxList.length > 0) selectedMap[catName] = idxList
      }

      const res = await api.applyPresets({
        service_ids: targetServices,
        selected: selectedMap,
      })
      setResult(res)
      setTimeout(() => onCreated(), 1200)
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }

  if (loadingPresets) {
    return (
      <div className="bg-gray-900 border border-orange-800/50 rounded-lg p-5 mb-4 text-gray-500 text-sm">
        Loading presets...
      </div>
    )
  }

  return (
    <div className="bg-gray-900 border border-orange-800/50 rounded-lg p-5 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-100">Attack Presets</h3>
        <span className="text-xs text-gray-500">{totalSelected} presets &times; {targetServices.length} services = {totalRules} rules</span>
      </div>

      <div className="mb-4">
        <div className="text-xs text-gray-500 mb-1.5">Apply to services:</div>
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={toggleAllServices}
            className={`text-xs px-2 py-1 rounded cursor-pointer transition-colors ${allServicesSelected ? 'bg-cyan-800/60 text-cyan-300' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}>
            All
          </button>
          {services.map(s => (
            <button key={s.id} onClick={() => toggleService(s.id)}
              className={`text-xs px-2 py-1 rounded cursor-pointer transition-colors ${targetServices.includes(s.id) ? 'bg-cyan-900/50 text-cyan-400' : 'bg-gray-800 text-gray-600 hover:text-gray-400'}`}>
              {s.name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 mb-4">
        {categories.map((cat) => {
          const catSelected = selected[cat.name] || {}
          const countSelected = Object.keys(catSelected).length
          const isExpanded = expandedCat === cat.name
          return (
            <div key={cat.name} className="bg-gray-800/50 border border-gray-700/50 rounded">
              <div className="flex items-center justify-between px-3 py-2">
                <button onClick={() => setExpandedCat(isExpanded ? null : cat.name)}
                  className="flex items-center gap-2 text-sm text-gray-200 hover:text-white cursor-pointer flex-1 text-left">
                  <span>{cat.icon}</span>
                  <span className="font-medium">{cat.name}</span>
                  {countSelected > 0 && <span className="text-[10px] text-cyan-400 bg-cyan-900/50 px-1.5 rounded">{countSelected}/{cat.rules.length}</span>}
                  <svg className={`w-3 h-3 ml-auto text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} viewBox="0 0 12 12" fill="currentColor">
                    <path d="M2 4l4 4 4-4z" />
                  </svg>
                </button>
                <button onClick={() => toggleCategory(cat.name, cat.rules.length)}
                  className="text-[10px] text-gray-500 hover:text-cyan-400 cursor-pointer ml-2 whitespace-nowrap">
                  {countSelected === cat.rules.length ? 'None' : 'All'}
                </button>
              </div>
              {isExpanded && (
                <div className="px-3 pb-2 space-y-1">
                  {cat.rules.map((preset, idx) => (
                    <label key={idx} className="flex items-start gap-2 text-xs cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={!!catSelected[idx]}
                        onChange={() => togglePreset(cat.name, idx)}
                        className="accent-cyan-500 mt-0.5"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="text-gray-300 group-hover:text-white">{preset.name}</span>
                          <span className={`px-1 py-0.5 rounded text-[10px] ${
                            preset.action === 'drop' ? 'bg-red-900/40 text-red-400' :
                            preset.action === 'alert' ? 'bg-orange-900/40 text-orange-400' :
                            'bg-purple-900/40 text-purple-400'
                          }`}>{preset.action}</span>
                        </div>
                        <div className="text-[10px] text-gray-600 font-mono truncate">{preset.pattern}</div>
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>

      <ErrorBanner error={error} className="mb-3" />
      {result && (
        <div className="bg-green-900/30 border border-green-700/50 text-green-400 text-sm px-4 py-2 rounded mb-3">
          Created {result.created} rules{result.errors > 0 ? `, ${result.errors} errors` : ''}
        </div>
      )}

      <div className="flex items-center gap-2">
        <button onClick={handleCreate}
          disabled={creating || totalRules === 0}
          className="bg-orange-600 hover:bg-orange-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer disabled:cursor-default flex items-center gap-1.5">
          {creating ? 'Creating...' : <><span>&#9889;</span> Create {totalRules} Rule{totalRules !== 1 ? 's' : ''}</>}
        </button>
        <button onClick={onCancel}
          className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded transition-colors cursor-pointer">
          Cancel
        </button>
      </div>
    </div>
  )
}

// ---- Rule Form (with multi-service for new rules) ----

function RuleForm({ rule, services, onSave, onCancel }) {
  const [form, setForm] = useState({
    ...rule,
    action: rule.action || 'drop',
    expression: rule.expression || '',
  })
  const [targetServices, setTargetServices] = useState([rule.service_id])
  const [preview, setPreview] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState('')
  const [previewPacket, setPreviewPacket] = useState(null)
  const [previewPacketError, setPreviewPacketError] = useState('')
  const [previewLimit, setPreviewLimit] = useState(10)
  const isFlagRule = form.id?.startsWith('flag-auto-')
  const allSelected = targetServices.length === services.length

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  function toggleService(id) {
    setTargetServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    )
  }

  function toggleAll() {
    setTargetServices(allSelected ? [form.service_id || services[0]?.id] : services.map(s => s.id))
  }

  function handleSubmit() {
    // Send expression as the canonical form. Legacy type/scope/pattern stay
    // attached to the original rule object so the backend's duplicate-check
    // and any non-migrated callers keep working — they're harmless because
    // the rule store's auto-derive only kicks in when expression is empty.
    onSave(form, form._isNew ? targetServices : null)
  }

  async function previewRule(limit = previewLimit) {
    const expr = form.expression.trim()
    if (!expr) return
    setPreviewLoading(true)
    setPreviewError('')
    setPreview(null)
    setPreviewPacket(null)
    try {
      const svcIds = form._isNew ? targetServices : [form.service_id]
      const scoped = svcIds.filter(Boolean)
      const targets = scoped.length > 0 ? scoped : ['']
      const results = await Promise.all(targets.map((svcId) =>
        api.getPackets({
          q: expr,
          service_id: svcId,
          sort: 'desc',
          limit,
          summary: '1',
        }).then((res) => ({ svcId, res }))
      ))
      const packets = results.flatMap((r) => r.res.packets || [])
      const total = results.reduce((sum, r) => sum + (r.res.total || 0), 0)
      setPreview({ total, packets })
    } catch (err) {
      setPreviewError(err.message)
    } finally {
      setPreviewLoading(false)
    }
  }

  function loadMorePreview() {
    const next = previewLimit + 25
    setPreviewLimit(next)
    previewRule(next)
  }

  async function inspectPreviewPacket(id) {
    setPreviewPacketError('')
    try {
      const pkt = await api.getPacket(id)
      setPreviewPacket(pkt)
    } catch (err) {
      setPreviewPacketError(err.message)
    }
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 mb-4">
      <h3 className="text-lg font-medium text-gray-100 mb-4">{form._isNew ? 'New Rule' : 'Edit Rule'}</h3>
      <div className="grid grid-cols-2 gap-4 mb-4">
        {form._isNew ? (
          <div className="col-span-2">
            <label className="block text-sm text-gray-400 mb-1">Services</label>
            <div className="flex items-center gap-2 flex-wrap">
              <button type="button" onClick={toggleAll}
                className={`text-xs px-2 py-1 rounded cursor-pointer transition-colors ${allSelected ? 'bg-cyan-800/60 text-cyan-300' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}>
                All
              </button>
              {services.map(s => (
                <button type="button" key={s.id} onClick={() => toggleService(s.id)}
                  className={`text-xs px-2 py-1 rounded cursor-pointer transition-colors ${targetServices.includes(s.id) ? 'bg-cyan-900/50 text-cyan-400' : 'bg-gray-800 text-gray-600 hover:text-gray-400'}`}>
                  {s.name}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div>
            <label className="block text-sm text-gray-400 mb-1">Service</label>
            <select
              value={form.service_id}
              onChange={(e) => set('service_id', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
            >
              {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
        )}
        <div>
          <label className="block text-sm text-gray-400 mb-1">Name</label>
          <input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="Rule name"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
        </div>
        {!form._isNew && <div />}
        <div>
          <label className="block text-sm text-gray-400 mb-1">Priority</label>
          <input type="number" value={form.priority} onChange={(e) => set('priority', e.target.value)} placeholder="0"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500" />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Action</label>
          <select
            value={form.action}
            onChange={(e) => set('action', e.target.value)}
            disabled={isFlagRule}
            className={`w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 ${isFlagRule ? 'opacity-60 cursor-not-allowed' : ''}`}
          >
            {actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          {isFlagRule && (
            <div className="text-xs text-yellow-500 mt-1">
              Flag rules must be alert-only. Dropping flags breaks the checker.
            </div>
          )}
        </div>
      </div>

      <div className="mb-4">
        <label className="block text-sm text-gray-400 mb-1">Match expression</label>
        <FilterExpression
          value={form.expression}
          onChange={(v) => set('expression', v)}
          placeholder='e.g. body contains "/api/admin" AND header.User-Agent contains "curl"'
        />
      </div>

      <div className="mb-4 bg-gray-950/60 border border-gray-800 rounded p-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              setPreviewLimit(10)
              previewRule(10)
            }}
            disabled={!form.expression.trim() || previewLoading}
            className="bg-gray-800 hover:bg-gray-700 disabled:bg-gray-800 disabled:text-gray-600 text-gray-200 text-xs px-3 py-1.5 rounded transition-colors cursor-pointer disabled:cursor-default"
          >
            {previewLoading ? 'Testing...' : 'Test on captured packets'}
          </button>
          {preview && <span className="text-xs text-gray-400">Matches: <span className="text-cyan-300 font-mono">{preview.total}</span></span>}
          {preview && <span className="text-xs text-gray-500">shown: {preview.packets.length}</span>}
          {previewError && <span className="text-xs text-red-400">{previewError}</span>}
        </div>
        {preview?.packets?.length > 0 && (
          <div className="mt-2 overflow-auto max-h-80">
            <table className="w-full text-xs">
              <tbody>
                {preview.packets.map((p) => (
                  <tr key={p.id} onClick={() => inspectPreviewPacket(p.id)}
                    className={`border-t border-gray-800/60 cursor-pointer hover:bg-gray-900/80 ${previewPacket?.id === p.id ? 'bg-cyan-950/20' : ''}`}>
                    <td className="py-1 pr-2 text-gray-500 font-mono">#{p.id}</td>
                    <td className="py-1 pr-2 text-gray-400">{p.direction}</td>
                    <td className="py-1 pr-2 text-gray-400">{p.method || p.status || '-'}</td>
                    <td className="py-1 pr-2 text-gray-500 font-mono">{p.src_ip}</td>
                    <td className="py-1 text-gray-300 truncate max-w-md">{p.url || p.body_string || '(no preview)'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {preview && preview.packets.length < preview.total && (
          <button
            type="button"
            onClick={loadMorePreview}
            disabled={previewLoading}
            className="mt-2 bg-gray-800 hover:bg-gray-700 disabled:bg-gray-800 disabled:text-gray-600 text-gray-300 text-xs px-3 py-1.5 rounded cursor-pointer"
          >
            Load more packets
          </button>
        )}
        {previewPacketError && <div className="text-xs text-red-400 mt-2">{previewPacketError}</div>}
        {previewPacket && (
          <div className="mt-3 border-t border-gray-800 pt-3 text-xs">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400">Packet <span className="font-mono text-cyan-300">#{previewPacket.id}</span></span>
              <button type="button" onClick={() => setPreviewPacket(null)} className="text-gray-500 hover:text-gray-300 cursor-pointer">close</button>
            </div>
            <div className="grid grid-cols-2 gap-2 mb-2 text-gray-400">
              <div>Dir <span className="text-gray-200">{previewPacket.direction}</span></div>
              <div>Status <span className="text-gray-200">{previewPacket.status || '-'}</span></div>
              <div>Src <span className="font-mono text-gray-300">{previewPacket.src_ip}:{previewPacket.src_port}</span></div>
              <div>Dst <span className="font-mono text-gray-300">{previewPacket.dst_ip}:{previewPacket.dst_port}</span></div>
            </div>
            {previewPacket.url && <div className="bg-gray-800 rounded p-2 mb-2 font-mono text-gray-300 break-all">{previewPacket.method} {previewPacket.url}</div>}
            <div className="grid grid-cols-2 gap-2">
              <pre className="bg-gray-800 rounded p-2 text-gray-300 overflow-auto whitespace-pre-wrap break-all max-h-56">{JSON.stringify(previewPacket.headers || {}, null, 2)}</pre>
              <pre className="bg-gray-800 rounded p-2 text-gray-300 overflow-auto whitespace-pre-wrap break-all max-h-56">{previewPacket.body_string || '(empty body)'}</pre>
            </div>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 mb-4">
        <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} className="accent-cyan-500" id="rule-enabled" />
        <label htmlFor="rule-enabled" className="text-sm text-gray-400">Enabled</label>
      </div>

      <div className="flex gap-2">
        <button onClick={handleSubmit}
          disabled={!form.expression.trim() || !form.name.trim()}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer disabled:cursor-default">
          {form._isNew && targetServices.length > 1
            ? `Save (${targetServices.length} services)`
            : 'Save'}
        </button>
        <button onClick={onCancel} className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded transition-colors cursor-pointer">Cancel</button>
      </div>
    </div>
  )
}
