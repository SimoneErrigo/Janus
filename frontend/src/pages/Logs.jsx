import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'

const DEFAULT_DOZZLE_PORT = 14000

export default function Logs() {
  // Port comes from the backend config (DOZZLE_PORT env). Falls back to the
  // compose default while the request is in flight or if the API is down.
  const [port, setPort] = useState(DEFAULT_DOZZLE_PORT)

  useEffect(() => {
    let cancelled = false
    api.getConfig()
      .then((cfg) => { if (!cancelled && cfg?.dozzle_port) setPort(cfg.dozzle_port) })
      .catch(() => { /* keep default */ })
    return () => { cancelled = true }
  }, [])

  // Build the URL from the same hostname the user used to reach the frontend.
  // Works whether the team is on the VM (localhost) or on a laptop hitting VM_IP.
  const dozzleUrl = useMemo(() => {
    if (typeof window === 'undefined') return `http://localhost:${port}`
    return `${window.location.protocol}//${window.location.hostname}:${port}`
  }, [port])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-900">
        <div>
          <h2 className="text-sm font-medium text-gray-100">Container Logs (Dozzle)</h2>
          <p className="text-xs text-gray-600">
            Open <span className="font-mono text-gray-400">{dozzleUrl}</span> in a new tab.
            Login with the credentials in <span className="font-mono">data/dozzle/users.yml</span>.
          </p>
        </div>
        <a
          href={dozzleUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer border border-gray-700 hover:border-cyan-600 rounded px-2 py-1"
          title="Open Dozzle in a new browser tab"
        >
          Open in new tab ↗
        </a>
      </div>
    </div>
  )
}
