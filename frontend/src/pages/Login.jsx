import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { api, setToken, setDisplayName, getDisplayName, hasToken } from '../api'

export default function Login() {
  const [displayName, setName] = useState(() => getDisplayName())
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  if (hasToken()) {
    return <Navigate to="/" replace />
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await api.login(password, displayName.trim())
      setToken(data.token)
      setDisplayName(data.display_name || displayName.trim())
      navigate('/', { replace: true })
    } catch (err) {
      const message = err instanceof Error ? err.message.trim() : ''
      setError(/invalid password|unauthorized/i.test(message)
        ? 'Invalid password'
        : `Login failed${message ? `: ${message}` : ''}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-cyan-400 tracking-wider">JANUS</h1>
          <p className="text-gray-500 mt-2 text-sm">CTF Attack & Defense Proxy</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-800 rounded-lg p-6 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Your Name <span className="text-gray-600">(optional)</span></label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setName(e.target.value)}
              maxLength={32}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
              placeholder="e.g. alice"
              autoFocus
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Team Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
              placeholder="Enter password..."
            />
          </div>

          {error && (
            <p role="alert" className="text-red-400 text-sm">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading || !password}
            className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-medium py-2 px-4 rounded text-sm transition-colors cursor-pointer"
          >
            {loading ? 'Authenticating...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  )
}
