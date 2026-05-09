import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { api, clearToken, getDisplayName } from '../api'

const navItems = [
  { to: '/services', label: 'Services', icon: ServerIcon },
  { to: '/traffic', label: 'Traffic', icon: PacketIcon },
  { to: '/rules', label: 'Rules', icon: ShieldIcon },
  { to: '/protocols', label: 'Protocols', icon: ProtocolsIcon },
  { to: '/alerts', label: 'Alerts', icon: AlertIcon },
  { to: '/blocks', label: 'Blocks', icon: BlockIcon },
  { to: '/saved-flows', label: 'Saved Flows', icon: BookmarkIcon },
  { to: '/system', label: 'System', icon: SystemIcon },
  { to: '/logs', label: 'Logs', icon: LogsIcon },
  { to: '/config', label: 'Config', icon: GearIcon },
]

export default function Layout() {
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)
  const [trafficMode, setTrafficMode] = useState('live')
  const [activeSessions, setActiveSessions] = useState([])
  const myName = getDisplayName()

  useEffect(() => {
    let mounted = true
    api.getConfig().then((cfg) => {
      if (!mounted) return
      setTrafficMode(cfg?.traffic_mode || 'live')
    }).catch(() => {})
    const t = setInterval(async () => {
      try {
        const cfg = await api.getConfig()
        if (mounted) setTrafficMode(cfg?.traffic_mode || 'live')
      } catch {}
    }, 30000)
    return () => {
      mounted = false
      clearInterval(t)
    }
  }, [])

  useEffect(() => {
    let mounted = true
    const poll = async () => {
      try {
        const data = await api.getSessionActive()
        if (mounted) setActiveSessions(data?.sessions || [])
      } catch {}
    }
    poll()
    const t = setInterval(poll, 10000)
    return () => { mounted = false; clearInterval(t) }
  }, [])

  function handleLogout() {
    clearToken()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-gray-950 text-gray-100">
      {/* Sidebar */}
      <nav className={`${collapsed ? 'w-12' : 'w-56'} bg-gray-900 border-r border-gray-800 flex flex-col transition-all duration-200 flex-shrink-0`}>
        <div className="p-2 border-b border-gray-800 flex items-center justify-between">
          {!collapsed && (
            <div className="px-2 min-w-0">
              <h1 className="text-xl font-bold text-cyan-400 tracking-wide">JANUS</h1>
              <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0 ${
                    trafficMode === 'static'
                      ? 'bg-indigo-900/40 text-indigo-300 border-indigo-700/50'
                      : 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50'
                  }`}
                  title={`Traffic mode: ${trafficMode}`}
                >
                  {trafficMode === 'static' ? 'STATIC' : 'LIVE'}
                </span>
                {activeSessions.length > 0 && (
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded border bg-cyan-900/30 text-cyan-400 border-cyan-700/40 flex-shrink-0 cursor-default"
                    title={activeSessions.map(s => s.name).join(', ')}
                  >
                    {activeSessions.length} online
                  </span>
                )}
              </div>
              {myName && (
                <p className="text-[10px] text-gray-600 mt-0.5 truncate" title={myName}>
                  {myName}
                </p>
              )}
            </div>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 text-gray-500 hover:text-gray-300 cursor-pointer rounded hover:bg-gray-800 flex-shrink-0"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <svg className={`w-4 h-4 transition-transform ${collapsed ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M15 18l-6-6 6-6" />
            </svg>
          </button>
        </div>
        <div className="flex-1 py-2">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                `flex items-center ${collapsed ? 'justify-center px-0 py-2.5' : 'gap-3 px-4 py-2.5'} text-sm transition-colors ${
                  isActive
                    ? 'bg-gray-800 text-cyan-400 border-r-2 border-cyan-400'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {!collapsed && label}
            </NavLink>
          ))}
        </div>
        <div className="p-2 border-t border-gray-800">
          <button
            onClick={handleLogout}
            title={collapsed ? 'Logout' : undefined}
            className={`w-full text-sm text-gray-500 hover:text-red-400 transition-colors cursor-pointer ${collapsed ? 'text-center py-1' : 'text-left px-2'}`}
          >
            {collapsed ? (
              <svg className="w-4 h-4 mx-auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" />
              </svg>
            ) : 'Logout'}
          </button>
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}

function ServerIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" />
      <circle cx="6" cy="6" r="1" /><circle cx="6" cy="18" r="1" />
    </svg>
  )
}

function PacketIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 0 1-9 9m9-9a9 9 0 0 0-9-9m9 9H3m9 9a9 9 0 0 1-9-9m9 9c1.66 0 3-4.03 3-9s-1.34-9-3-9m0 18c-1.66 0-3-4.03-3-9s1.34-9 3-9m-9 9a9 9 0 0 1 9-9" />
    </svg>
  )
}

function ShieldIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function AlertIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  )
}

function BlockIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
    </svg>
  )
}

function SystemIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  )
}

function GearIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  )
}

function LogsIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" />
    </svg>
  )
}

function ProtocolsIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 6h16" /><path d="M4 12h10" /><path d="M4 18h16" />
      <circle cx="18" cy="12" r="2" />
    </svg>
  )
}

function BookmarkIcon(props) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
    </svg>
  )
}
