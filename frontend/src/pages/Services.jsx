import { useState, useEffect } from 'react'
import { api } from '../api'
import ErrorBanner from '../components/ErrorBanner'

const protocols = ['http', 'https', 'h2', 'grpc', 'tcp']
const tlsModes = ['', 'selfsigned', 'challenge']

const emptyService = {
  id: '', name: '', listen_addr: '', listen_port: '', target_addr: '',
  protocol: 'http', tls_mode: '', cert_file: '', key_file: '',
  target_tls: false, proto_paths: [], enabled: true,
}

export default function Services() {
  const [services, setServices] = useState([])
  const [editing, setEditing] = useState(null) // null or service object
  const [error, setError] = useState('')

  useEffect(() => { loadServices() }, [])

  async function loadServices() {
    try {
      const data = await api.listServices()
      setServices(data || [])
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleSave(svc) {
    setError('')
    try {
      const payload = {
        ...svc,
        listen_port: parseInt(svc.listen_port, 10),
        proto_paths: Array.isArray(svc.proto_paths)
          ? svc.proto_paths
          : (svc.proto_paths || '').split('\n').map((p) => p.trim()).filter(Boolean),
      }
      if (svc._isNew) {
        await api.createService(payload)
      } else {
        await api.updateService(svc.id, payload)
      }
      setEditing(null)
      loadServices()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDelete(id) {
    if (!confirm('Delete this service?')) return
    try {
      await api.deleteService(id)
      loadServices()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold text-gray-100">Services</h2>
        <button
          onClick={() => setEditing({ ...emptyService, _isNew: true })}
          className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
        >
          + Add Service
        </button>
      </div>

      <ErrorBanner error={error} className="mb-4" />

      {editing && (
        <ServiceForm
          service={editing}
          onSave={handleSave}
          onCancel={() => setEditing(null)}
        />
      )}

      <div className="space-y-3">
        {services.map((svc) => (
          <div key={svc.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`w-2.5 h-2.5 rounded-full ${svc.enabled ? 'bg-green-500' : 'bg-gray-600'}`} />
              <div>
                <div className="font-medium text-gray-100">{svc.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">
                  {svc.listen_addr}:{svc.listen_port} &rarr; {svc.target_addr}
                  <span className="ml-2 px-1.5 py-0.5 bg-gray-800 rounded text-gray-400">{svc.protocol}</span>
                  {svc.tls_mode && <span className="ml-1 px-1.5 py-0.5 bg-gray-800 rounded text-gray-400">TLS: {svc.tls_mode}</span>}
                  {svc.target_tls && <span className="ml-1 px-1.5 py-0.5 bg-yellow-900/40 rounded text-yellow-400">Backend TLS</span>}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setEditing(svc)} className="text-gray-400 hover:text-cyan-400 text-sm px-3 py-1 cursor-pointer">Edit</button>
              <button onClick={() => handleDelete(svc.id)} className="text-gray-400 hover:text-red-400 text-sm px-3 py-1 cursor-pointer">Delete</button>
            </div>
          </div>
        ))}
        {services.length === 0 && !editing && (
          <p className="text-gray-600 text-center py-8">No services configured. Add one to get started.</p>
        )}
      </div>
    </div>
  )
}

function ServiceForm({ service, onSave, onCancel }) {
  const [form, setForm] = useState(service)

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  const needsTLS = ['https', 'h2', 'grpc'].includes(form.protocol)
  const isGRPC = form.protocol === 'grpc'
  const protoPathsText = Array.isArray(form.proto_paths) ? form.proto_paths.join('\n') : (form.proto_paths || '')

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 mb-4">
      <h3 className="text-lg font-medium text-gray-100 mb-4">{form._isNew ? 'New Service' : 'Edit Service'}</h3>
      <div className="grid grid-cols-2 gap-4">
        <Field label="Service ID" value={form.id} onChange={(v) => set('id', v)} disabled={!form._isNew} placeholder="e.g. web1" />
        <Field label="Name" value={form.name} onChange={(v) => set('name', v)} placeholder="e.g. Web Challenge" />
        <Field label="Listen Address" value={form.listen_addr} onChange={(v) => set('listen_addr', v)} placeholder="e.g. 10.10.0.1" />
        <Field label="Listen Port" value={form.listen_port} onChange={(v) => set('listen_port', v)} placeholder="e.g. 8080" type="number" />
        <Field label="Target Address" value={form.target_addr} onChange={(v) => set('target_addr', v)} placeholder="e.g. 127.0.0.1:9080" />
        <div className="flex items-center gap-2">
          <input type="checkbox" checked={form.target_tls || false} onChange={(e) => set('target_tls', e.target.checked)} className="accent-cyan-500" id="target-tls" />
          <label htmlFor="target-tls" className="text-sm text-gray-400">Backend uses TLS</label>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Protocol</label>
          <select value={form.protocol} onChange={(e) => set('protocol', e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500">
            {protocols.map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
        </div>
        {needsTLS && (
          <>
            <div>
              <label className="block text-sm text-gray-400 mb-1">TLS Mode</label>
              <select value={form.tls_mode} onChange={(e) => set('tls_mode', e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500">
                {tlsModes.map((m) => <option key={m} value={m}>{m || 'None'}</option>)}
              </select>
            </div>
            {form.tls_mode === 'challenge' && (
              <>
                <Field label="Cert File Path" value={form.cert_file} onChange={(v) => set('cert_file', v)} placeholder="/path/to/cert.pem" />
                <Field label="Key File Path" value={form.key_file} onChange={(v) => set('key_file', v)} placeholder="/path/to/key.pem" />
              </>
            )}
          </>
        )}
        {isGRPC && (
          <div className="col-span-2">
            <label className="block text-sm text-gray-400 mb-1">
              .proto File Paths
              <span className="text-gray-600 ml-2 text-xs">one per line — used to decode gRPC bodies with field names</span>
            </label>
            <textarea
              value={protoPathsText}
              onChange={(e) => set('proto_paths', e.target.value)}
              placeholder="/protos/cheesycheats.proto&#10;/protos/cheesycheatsAPI.proto"
              rows={3}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        )}
        <div className="flex items-center gap-2 col-span-2">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} className="accent-cyan-500" id="enabled" />
          <label htmlFor="enabled" className="text-sm text-gray-400">Enabled (start proxy immediately)</label>
        </div>
      </div>
      <div className="flex gap-2 mt-4">
        <button onClick={() => onSave(form)} className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer">Save</button>
        <button onClick={onCancel} className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded transition-colors cursor-pointer">Cancel</button>
      </div>
    </div>
  )
}

function Field({ label, value, onChange, placeholder, type = 'text', disabled = false }) {
  return (
    <div>
      <label className="block text-sm text-gray-400 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 disabled:opacity-50 transition-colors"
      />
    </div>
  )
}
