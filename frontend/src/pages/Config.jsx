import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { getTrafficNavKeys, saveTrafficNavKeys, keysToInputString, parseKeyList, defaultTrafficNavKeys } from '../trafficNavKeys'

export default function Config() {
  const [config, setConfig] = useState(null)
  const [form, setForm] = useState({})
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  // Flag ID state
  const [flagIDStatus, setFlagIDStatus] = useState(null)
  const [flagIDCountdown, setFlagIDCountdown] = useState('')
  const [flagIDSaved, setFlagIDSaved] = useState(false)
  const [flagIDError, setFlagIDError] = useState('')

  // Cleanup state
  const [cleanupConfig, setCleanupConfig] = useState(null)
  const [cleanupForm, setCleanupForm] = useState({})
  const [cleanupSaved, setCleanupSaved] = useState(false)
  const [cleanupError, setCleanupError] = useState('')
  const [cleanupResult, setCleanupResult] = useState(null)
  const [cleanupRunning, setCleanupRunning] = useState(false)
  const [purgeRunning, setPurgeRunning] = useState(false)
  const [purgePacketsRunning, setPurgePacketsRunning] = useState(false)
  const [dbSizeMB, setDbSizeMB] = useState(0)

  const [trafficNavUp, setTrafficNavUp] = useState('')
  const [trafficNavDown, setTrafficNavDown] = useState('')
  const [trafficNavSaved, setTrafficNavSaved] = useState(false)
  const [trafficNavError, setTrafficNavError] = useState('')

  // PCAP state
  const [pcapFiles, setPcapFiles] = useState([])
  const [pcapSaved, setPcapSaved] = useState(false)

  // PCAP import state
  const navigate = useNavigate()
  const [importFile, setImportFile] = useState(null)
  const [importServiceID, setImportServiceID] = useState('')
  const [importStatus, setImportStatus] = useState(null) // {state, packets_imported, service_id, error}
  const [importError, setImportError] = useState('')
  const [services, setServices] = useState([])
  const importFileRef = useRef(null)

  useEffect(() => {
    loadConfig()
    loadCleanupConfig()
    loadFlagIDData()
    api.listPcapFiles().then(d => setPcapFiles(d?.files || [])).catch(() => {})
    api.listServices().then(d => setServices(d || [])).catch(() => {})
  }, [])

  async function startPcapImport(e) {
    e.preventDefault()
    setImportError('')
    if (!importFile) {
      setImportError('Select a .pcap file first.')
      return
    }
    try {
      const { import_id, service_id } = await api.pcapImport(importFile, importServiceID)
      setImportStatus({ state: 'running', packets_imported: 0, service_id })
      const poll = async () => {
        try {
          const st = await api.getPcapImportStatus(import_id)
          setImportStatus(st)
          if (st.state === 'running') {
            setTimeout(poll, 800)
          } else if (st.state === 'done') {
            api.listServices().then(d => setServices(d || [])).catch(() => {})
          }
        } catch (err) {
          setImportError(err.message)
        }
      }
      poll()
    } catch (err) {
      setImportError(err.message)
    }
  }

  useEffect(() => {
    const k = getTrafficNavKeys()
    setTrafficNavUp(keysToInputString(k.up))
    setTrafficNavDown(keysToInputString(k.down))
  }, [])

  async function loadFlagIDData() {
    try {
      const status = await api.getFlagIDStatus()
      setFlagIDStatus(status)
    } catch {}
  }

  // Refresh flag ID status every 10 seconds for countdown
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const status = await api.getFlagIDStatus()
        setFlagIDStatus(status)
      } catch {}
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  // Update countdown timer every second
  useEffect(() => {
    const interval = setInterval(() => {
      if (!flagIDStatus?.next_fetch) {
        setFlagIDCountdown('')
        return
      }
      const diff = Math.max(0, Math.floor((new Date(flagIDStatus.next_fetch) - Date.now()) / 1000))
      setFlagIDCountdown(`${diff}s`)
    }, 1000)
    return () => clearInterval(interval)
  }, [flagIDStatus])

  const loadCleanupConfig = useCallback(async () => {
    try {
      const data = await api.getCleanupConfig()
      setCleanupConfig(data)
      setCleanupForm({ max_age_minutes: data.max_age_minutes, max_db_size_mb: data.max_db_size_mb })
      setDbSizeMB(data.db_size_mb)
    } catch (err) {
      setCleanupError(err.message)
    }
  }, [])

  // Refresh DB size every 30 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const data = await api.getCleanupConfig()
        setDbSizeMB(data.db_size_mb)
      } catch {}
    }, 30000)
    return () => clearInterval(interval)
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
      const data = await api.updateConfig({
        team_password: form.team_password,
        flag_regex: form.flag_regex,
        traffic_mode: form.traffic_mode || 'live',
        flow_correlation_window_seconds: parseInt(form.flow_correlation_window_seconds, 10) || 120,
      })
      setConfig(data)
      setForm(data)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleFlagIDSave(e) {
    e.preventDefault()
    setFlagIDError('')
    setFlagIDSaved(false)
    try {
      const data = await api.updateConfig({
        flagid_enabled: form.flagid_enabled,
        flagid_api_url: form.flagid_api_url,
        flagid_team_id: form.flagid_team_id,
        flagid_poll_interval: parseInt(form.flagid_poll_interval, 10) || 30,
        flagid_format: form.flagid_format,
        round_duration_seconds: parseInt(form.round_duration_seconds, 10) || 120,
        competition_start: form.competition_start || '',
        keep_rounds: parseInt(form.keep_rounds, 10) || 5,
      })
      setConfig(data)
      setForm(data)
      setFlagIDSaved(true)
      setTimeout(() => setFlagIDSaved(false), 3000)
      // Refresh status after config change
      setTimeout(loadFlagIDData, 500)
    } catch (err) {
      setFlagIDError(err.message)
    }
  }

  async function handleCleanupSave(e) {
    e.preventDefault()
    setCleanupError('')
    setCleanupSaved(false)
    try {
      const data = await api.updateCleanupConfig({
        max_age_minutes: parseInt(cleanupForm.max_age_minutes, 10) || 0,
        max_db_size_mb: parseInt(cleanupForm.max_db_size_mb, 10) || 0,
      })
      setCleanupConfig(data)
      setDbSizeMB(data.db_size_mb)
      setCleanupSaved(true)
      setTimeout(() => setCleanupSaved(false), 3000)
    } catch (err) {
      setCleanupError(err.message)
    }
  }

  async function handleRunCleanup() {
    setCleanupRunning(true)
    setCleanupResult(null)
    try {
      const result = await api.runCleanup()
      setCleanupResult(result)
      setDbSizeMB(result.db_size_mb)
    } catch (err) {
      setCleanupError(err.message)
    } finally {
      setCleanupRunning(false)
    }
  }

  async function handlePurgeAll() {
    if (!confirm('Delete ALL packets and alerts? This cannot be undone.')) return
    setPurgeRunning(true)
    setCleanupResult(null)
    try {
      const result = await api.purgeAll()
      setCleanupResult(result)
      setDbSizeMB(result.db_size_mb)
    } catch (err) {
      setCleanupError(err.message)
    } finally {
      setPurgeRunning(false)
    }
  }

  async function handlePurgePackets() {
    if (!confirm('Delete ALL packets? Alerts linked to packets will also be removed. This cannot be undone.')) return
    setPurgePacketsRunning(true)
    setCleanupResult(null)
    try {
      const result = await api.purgePackets()
      setCleanupResult(result)
      setDbSizeMB(result.db_size_mb)
    } catch (err) {
      setCleanupError(err.message)
    } finally {
      setPurgePacketsRunning(false)
    }
  }

  if (!config) return <div className="p-6 text-gray-500">Loading...</div>

  return (
    <div className="p-6 space-y-6">
      <h2 className="text-2xl font-semibold text-gray-100">Configuration</h2>

      <form onSubmit={handleSave} className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-lg space-y-4">
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

        <div>
          <label className="block text-sm text-gray-400 mb-1">Traffic Mode</label>
          <select
            value={form.traffic_mode || 'live'}
            onChange={(e) => set('traffic_mode', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="live">Live (continuous capture + periodic flagId/backfill)</option>
            <option value="static">Static (manual start/stop + manual apply flagIds)</option>
          </select>
          <p className="text-xs text-gray-600 mt-1">Switching to static mode disables periodic backfill and auto-cleanup policies.</p>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Flow Correlation Window (seconds)</label>
          <input
            type="number"
            min="5"
            value={form.flow_correlation_window_seconds ?? 120}
            onChange={(e) => set('flow_correlation_window_seconds', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
          />
          <p className="text-xs text-gray-600 mt-1">Used by flow reconstruction to correlate related sessions in high-load traffic.</p>
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

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-lg space-y-4 mt-6">
        <h3 className="text-lg font-medium text-gray-100">Traffic keyboard</h3>
        <p className="text-xs text-gray-500">Select previous/next packet on the Traffic page. Uses browser <code className="text-gray-400">KeyboardEvent.key</code> names (comma-separated), e.g. <code className="text-gray-400">k, K, ArrowUp</code>.</p>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Previous packet (up in list)</label>
          <input
            value={trafficNavUp}
            onChange={(e) => { setTrafficNavUp(e.target.value); setTrafficNavError('') }}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500"
            spellCheck={false}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Next packet (down in list)</label>
          <input
            value={trafficNavDown}
            onChange={(e) => { setTrafficNavDown(e.target.value); setTrafficNavError('') }}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500"
            spellCheck={false}
          />
        </div>
        {trafficNavError && <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm px-4 py-2 rounded">{trafficNavError}</div>}
        {trafficNavSaved && <div className="bg-green-900/30 border border-green-800 text-green-400 text-sm px-4 py-2 rounded">Shortcuts saved (this browser only)</div>}
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => {
              const up = parseKeyList(trafficNavUp)
              const down = parseKeyList(trafficNavDown)
              if (up.length === 0 || down.length === 0) {
                setTrafficNavError('Each field needs at least one key.')
                return
              }
              saveTrafficNavKeys(up, down)
              setTrafficNavSaved(true)
              setTrafficNavError('')
              setTimeout(() => setTrafficNavSaved(false), 2500)
            }}
            className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
          >
            Save shortcuts
          </button>
          <button
            type="button"
            onClick={() => {
              const d = defaultTrafficNavKeys()
              setTrafficNavUp(keysToInputString(d.up))
              setTrafficNavDown(keysToInputString(d.down))
              saveTrafficNavKeys(d.up, d.down)
              setTrafficNavSaved(true)
              setTrafficNavError('')
              setTimeout(() => setTrafficNavSaved(false), 2500)
            }}
            className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded transition-colors cursor-pointer"
          >
            Reset defaults
          </button>
        </div>
      </div>

      {/* Flag IDs section — configurable */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-lg space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium text-gray-100">Flag IDs</h3>
          <div className="flex items-center gap-2">
            {form.flagid_enabled && flagIDStatus?.current_round > 0 && (
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-400 font-mono">
                Round {flagIDStatus.current_round}
              </span>
            )}
            <span className={`text-xs px-2 py-0.5 rounded ${form.flagid_enabled ? 'bg-emerald-900/40 text-emerald-400' : 'bg-gray-800 text-gray-500'}`}>
              {form.flagid_enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>

        <form onSubmit={handleFlagIDSave} className="space-y-4">
          <div className="flex items-center gap-3">
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={form.flagid_enabled || false}
                onChange={(e) => set('flagid_enabled', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-600"></div>
            </label>
            <span className="text-sm text-gray-300">Enable Flag ID fetching</span>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">API URL</label>
            <input
              value={form.flagid_api_url || ''}
              onChange={(e) => set('flagid_api_url', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500 transition-colors"
              placeholder="e.g. http://10.10.0.1:8080/api/flagids"
            />
            <p className="text-xs text-gray-600 mt-1">URL of the competition flag ID API endpoint</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Team ID</label>
              <input
                value={form.flagid_team_id || ''}
                onChange={(e) => set('flagid_team_id', e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
                placeholder="e.g. team_1"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Poll Interval (s)</label>
              <input
                type="number"
                min="5"
                value={form.flagid_poll_interval ?? 30}
                onChange={(e) => set('flagid_poll_interval', e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Competition Format</label>
            <select
              value={form.flagid_format || 'cyberchallenge'}
              onChange={(e) => set('flagid_format', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
            >
              <option value="cyberchallenge">CyberChallenge</option>
              <option value="saarctf">saarCTF</option>
              <option value="faustctf">FaustCTF</option>
              <option value="forcad">ForcAD</option>
            </select>
            <p className="text-xs text-gray-600 mt-1">Response format of the flag ID API</p>
          </div>

          {/* Competition Timing */}
          <div className="border-t border-gray-800 pt-3">
            <h4 className="text-sm font-medium text-gray-300 mb-3">Competition Timing</h4>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Round Duration (s)</label>
                <input
                  type="number"
                  min="10"
                  value={form.round_duration_seconds ?? 120}
                  onChange={(e) => set('round_duration_seconds', e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Keep Rounds</label>
                <input
                  type="number"
                  min="1"
                  value={form.keep_rounds ?? 5}
                  onChange={(e) => set('keep_rounds', e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
                />
                <p className="text-xs text-gray-600 mt-1">Older rounds are pruned</p>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Start Time (RFC3339)</label>
                <input
                  value={form.competition_start || ''}
                  onChange={(e) => set('competition_start', e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm font-mono focus:outline-none focus:border-cyan-500 transition-colors"
                  placeholder="2026-03-29T10:00:00Z"
                />
              </div>
            </div>
          </div>

          {flagIDError && <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm px-4 py-2 rounded">{flagIDError}</div>}
          {flagIDSaved && <div className="bg-green-900/30 border border-green-800 text-green-400 text-sm px-4 py-2 rounded">Flag ID settings saved</div>}

          <button
            type="submit"
            className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
          >
            Save Flag ID Settings
          </button>
        </form>

        {/* Live status & fetched flag IDs */}
        {flagIDStatus?.enabled && (
          <>
            <div className="border-t border-gray-800 pt-3">
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs bg-gray-800/50 rounded p-2">
                <div>
                  <span className="text-gray-500">Last fetch: </span>
                  <span className="text-gray-300">
                    {flagIDStatus.last_fetch ? new Date(flagIDStatus.last_fetch).toLocaleTimeString() : 'Never'}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Next refresh: </span>
                  <span className="text-cyan-400 font-mono">{flagIDCountdown || '...'}</span>
                </div>
                <div>
                  <span className="text-gray-500">Current round: </span>
                  <span className="text-cyan-400 font-mono">{flagIDStatus.current_round || '—'}</span>
                </div>
                <div>
                  <span className="text-gray-500">Keeping: </span>
                  <span className="text-gray-300">{flagIDStatus.keep_rounds || '—'} rounds</span>
                </div>
                {flagIDStatus.last_error && (
                  <div className="col-span-2">
                    <span className="text-red-400">Error: {flagIDStatus.last_error}</span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 mt-2">
                <button
                  onClick={async () => { await api.refreshFlagIDs(); loadFlagIDData() }}
                  className="text-xs bg-cyan-800/50 hover:bg-cyan-700/50 text-cyan-300 px-2.5 py-1 rounded cursor-pointer transition-colors"
                >
                  Refresh Now
                </button>
              </div>
            </div>

          </>
        )}
      </div>

      {/* Cleanup section */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-lg space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium text-gray-100">Database Cleanup</h3>
          <div className="text-sm">
            <span className="text-gray-500">DB Size: </span>
            <span className={`font-mono font-medium ${
              cleanupForm.max_db_size_mb > 0 && dbSizeMB >= cleanupForm.max_db_size_mb * 0.85 ? 'text-red-400' :
              cleanupForm.max_db_size_mb > 0 && dbSizeMB >= cleanupForm.max_db_size_mb * 0.7 ? 'text-yellow-400' :
              'text-cyan-400'
            }`}>
              {dbSizeMB.toFixed(1)} MB
            </span>
            {cleanupForm.max_db_size_mb > 0 && (
              <span className="text-gray-600"> / {cleanupForm.max_db_size_mb} MB</span>
            )}
          </div>
        </div>

        <form onSubmit={handleCleanupSave} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Max Age (minutes)</label>
              <input
                type="number"
                min="0"
                value={cleanupForm.max_age_minutes ?? 0}
                onChange={(e) => setCleanupForm((f) => ({ ...f, max_age_minutes: e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
              />
              <p className="text-xs text-gray-600 mt-1">Delete packets older than N minutes (0 = off)</p>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Max DB Size (MB)</label>
              <input
                type="number"
                min="0"
                value={cleanupForm.max_db_size_mb ?? 0}
                onChange={(e) => setCleanupForm((f) => ({ ...f, max_db_size_mb: e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
              />
              <p className="text-xs text-gray-600 mt-1">Delete oldest when DB exceeds N MB (0 = off)</p>
            </div>
          </div>

          {cleanupError && <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm px-4 py-2 rounded">{cleanupError}</div>}
          {cleanupSaved && <div className="bg-green-900/30 border border-green-800 text-green-400 text-sm px-4 py-2 rounded">Cleanup settings saved</div>}

          {cleanupResult && (
            <div className="bg-cyan-900/20 border border-cyan-800/50 text-cyan-300 text-sm px-4 py-2 rounded">
              Deleted {cleanupResult.packets_deleted} packets, {cleanupResult.alerts_deleted} alerts in {cleanupResult.duration_ms}ms.
              DB now {cleanupResult.db_size_mb.toFixed(1)} MB.
            </div>
          )}

          <div className="flex gap-2 flex-wrap">
            <button
              type="submit"
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
            >
              Save Cleanup Settings
            </button>
            <button
              type="button"
              onClick={handleRunCleanup}
              disabled={cleanupRunning}
              className="bg-orange-700 hover:bg-orange-600 disabled:bg-gray-700 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
            >
              {cleanupRunning ? 'Running...' : 'Run Cleanup Now'}
            </button>
            <button
              type="button"
              onClick={handlePurgePackets}
              disabled={purgePacketsRunning}
              className="bg-yellow-700 hover:bg-yellow-600 disabled:bg-gray-700 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
            >
              {purgePacketsRunning ? 'Deleting...' : 'Clear Packets'}
            </button>
            <button
              type="button"
              onClick={handlePurgeAll}
              disabled={purgeRunning}
              className="bg-red-700 hover:bg-red-600 disabled:bg-gray-700 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
            >
              {purgeRunning ? 'Deleting...' : 'Delete All Data'}
            </button>
          </div>
        </form>
      </div>

      {/* PCAP Export section */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-2xl space-y-4">
        <h3 className="text-lg font-medium text-gray-100">PCAP Export</h3>
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            try {
              await api.updateConfig({
                pcap_export_dir: form.pcap_export_dir || '',
                pcap_auto_save: !!form.pcap_auto_save,
              })
              setPcapSaved(true)
              setTimeout(() => setPcapSaved(false), 2000)
            } catch {}
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm text-gray-400 mb-1">Export Directory</label>
            <input
              type="text"
              value={form.pcap_export_dir || ''}
              onChange={(e) => setForm(f => ({ ...f, pcap_export_dir: e.target.value }))}
              placeholder="/data/pcap"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
            />
            <p className="text-xs text-gray-600 mt-1">Directory where .pcap files are saved.</p>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={!!form.pcap_auto_save}
                onChange={(e) => setForm(f => ({ ...f, pcap_auto_save: e.target.checked }))}
                className="accent-cyan-500"
              />
              <span className="text-sm text-gray-300">Auto-save PCAP when static capture stops</span>
            </label>
          </div>
          <div className="flex items-center gap-3">
            <button type="submit" className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded cursor-pointer">Save</button>
            {pcapSaved && <span className="text-green-400 text-sm">Saved</span>}
          </div>
        </form>

        {/* PCAP file list */}
        {pcapFiles.length > 0 && (
          <div className="mt-4">
            <h4 className="text-sm font-medium text-gray-300 mb-2">Saved PCAP Files</h4>
            <div className="space-y-1">
              {pcapFiles.map((f) => (
                <div key={f.name} className="flex items-center justify-between bg-gray-800 rounded px-3 py-2 text-sm">
                  <div>
                    <span className="text-gray-200 font-mono">{f.name}</span>
                    <span className="ml-2 text-gray-500 text-xs">{(f.size_bytes / 1024).toFixed(1)} KB</span>
                    {f.mod_time && <span className="ml-2 text-gray-600 text-xs">{new Date(f.mod_time).toLocaleString()}</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    <a
                      href={api.pcapDownloadUrl(f.name)}
                      download={f.name}
                      className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
                    >
                      Download
                    </a>
                    <button
                      type="button"
                      onClick={async () => {
                        try {
                          await api.deletePcapFile(f.name)
                          setPcapFiles(prev => prev.filter(p => p.name !== f.name))
                        } catch {}
                      }}
                      className="text-xs text-red-500 hover:text-red-400 cursor-pointer"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        {pcapFiles.length === 0 && (
          <p className="text-xs text-gray-600 mt-2">No PCAP files saved yet. Use the "⬇ PCAP" button in Traffic to export.</p>
        )}
      </div>

      {/* PCAP Import section */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 max-w-2xl space-y-4">
        <h3 className="text-lg font-medium text-gray-100">PCAP Import</h3>
        <p className="text-xs text-gray-500">
          Upload a .pcap capture. Janus reassembles TCP streams and reconstructs HTTP request/response pairs
          when possible; otherwise raw TCP payloads are stored per direction.
        </p>
        <form onSubmit={startPcapImport} className="space-y-3">
          <div>
            <label className="block text-sm text-gray-400 mb-1">PCAP file</label>
            <input
              ref={importFileRef}
              type="file"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
              onChange={(e) => setImportFile(e.target.files?.[0] || null)}
              className="text-sm text-gray-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-gray-800 file:text-gray-200 file:cursor-pointer hover:file:bg-gray-700"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Target service</label>
            <select
              value={importServiceID}
              onChange={(e) => setImportServiceID(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500"
            >
              <option value="">(create new virtual service named pcap:&lt;filename&gt;)</option>
              {services.map(s => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={importStatus?.state === 'running'}
              className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white text-sm px-4 py-2 rounded cursor-pointer"
            >
              {importStatus?.state === 'running' ? 'Importing…' : 'Import'}
            </button>
            {importStatus?.state === 'done' && (
              <>
                <span className="text-green-400 text-sm">
                  Imported {importStatus.packets_imported} packets
                </span>
                <button
                  type="button"
                  onClick={() => navigate(`/traffic?service_id=${encodeURIComponent(importStatus.service_id || '')}`)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer underline"
                >
                  Open in Traffic →
                </button>
              </>
            )}
            {importStatus?.state === 'error' && (
              <span className="text-red-400 text-sm">Error: {importStatus.error}</span>
            )}
            {importStatus?.state === 'running' && (
              <span className="text-xs text-gray-500">Parsing & inserting…</span>
            )}
          </div>
          {importError && <p className="text-sm text-red-400">{importError}</p>}
        </form>
      </div>
    </div>
  )
}