import { useState, useEffect } from 'react'
import { api } from '../api'

export default function Config() {
  const [config, setConfig] = useState(null)
  const [form, setForm] = useState({})
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    loadConfig()
  }, [])

  async function loadConfig() {
    try {
      const data = await api.getConfig()
      setConfig(data)
      setForm(data)
    } catch (err) {
      setError(err.message)
    }
  }

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }))
    setSaved(false)
  }

  async function handleSave(e) {
    e.preventDefault()
    setError('')
    setSaved(false)
    try {
      const data = await api.updateConfig(form)
      setConfig(data)
      setForm(data)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      setError(err.message)
    }
  }

  if (!config) return <div className="p-6 text-gray-500">Loading...</div>

  return (
    <div className="p-6">
      <h2 className="text-2xl font-semibold text-gray-100 mb-6">Configuration</h2>

      <form onSubmit={handleSave} className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-lg space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">VM IP Address</label>
          <input
            value={form.vm_ip || ''}
            onChange={(e) => set('vm_ip', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
            placeholder="e.g. 10.10.0.1"
          />
          <p className="text-xs text-gray-600 mt-1">The IP address of this VM in the competition network</p>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Network Interface</label>
          <input
            value={form.network_interface || ''}
            onChange={(e) => set('network_interface', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
            placeholder="e.g. eth0"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Team Password</label>
          <input
            type="password"
            value={form.team_password || ''}
            onChange={(e) => set('team_password', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
            placeholder="Password for frontend access"
          />
          <p className="text-xs text-gray-600 mt-1">Changing this will require re-login with the new password</p>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Flag Regex</label>
          <input
            value={form.flag_regex || ''}
            onChange={(e) => set('flag_regex', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500 transition-colors"
            placeholder="e.g. [A-Z0-9]{31}="
          />
          <p className="text-xs text-gray-600 mt-1">Regex pattern to identify flags in traffic</p>
        </div>

        {error && <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm px-4 py-2 rounded">{error}</div>}
        {saved && <div className="bg-green-900/30 border border-green-800 text-green-400 text-sm px-4 py-2 rounded">Configuration saved</div>}

        <button
          type="submit"
          className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
        >
          Save Configuration
        </button>
      </form>
    </div>
  )
}
