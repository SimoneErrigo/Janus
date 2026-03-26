import { useState, useEffect } from 'react'
import { api } from '../api'

function formatUptime(secs) {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  return `${h}h ${m}m ${s}s`
}

function barColor(percent) {
  if (percent >= 85) return 'bg-red-500'
  if (percent >= 70) return 'bg-yellow-500'
  return 'bg-cyan-500'
}

function textColor(percent) {
  if (percent >= 85) return 'text-red-400'
  if (percent >= 70) return 'text-yellow-400'
  return 'text-cyan-400'
}

function PercentBar({ label, percent, detail }) {
  const pct = Math.min(100, Math.max(0, percent || 0))
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-gray-300">{label}</span>
        <span className={`text-sm font-bold ${textColor(pct)}`}>{pct.toFixed(1)}%</span>
      </div>
      <div className="w-full bg-gray-800 rounded-full h-2.5">
        <div
          className={`h-2.5 rounded-full transition-all duration-500 ${barColor(pct)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {detail && <p className="text-xs text-gray-500 mt-1.5">{detail}</p>}
    </div>
  )
}

function StatCard({ label, value, unit, sub }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <p className="text-sm text-gray-400 mb-1">{label}</p>
      <p className="text-2xl font-bold text-gray-100">
        {value}
        {unit && <span className="text-sm font-normal text-gray-500 ml-1">{unit}</span>}
      </p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  )
}

export default function System() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState(null)
  const [countdown, setCountdown] = useState(10)

  useEffect(() => {
    let mounted = true

    async function fetchStats() {
      try {
        const data = await api.getSystemStats()
        if (mounted) {
          setStats(data)
          setError(null)
          setCountdown(10)
        }
      } catch (err) {
        if (mounted) setError(err.message)
      }
    }

    fetchStats()
    const interval = setInterval(fetchStats, 10000)
    const tick = setInterval(() => {
      if (mounted) setCountdown(c => Math.max(0, c - 1))
    }, 1000)

    return () => {
      mounted = false
      clearInterval(interval)
      clearInterval(tick)
    }
  }, [])

  if (error && !stats) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-gray-100 mb-4">System</h1>
        <div className="bg-red-950/30 border border-red-800/50 rounded-lg p-4 text-red-400">
          Failed to load system stats: {error}
        </div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-gray-100 mb-4">System</h1>
        <p className="text-gray-500">Loading...</p>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-100">System</h1>
        <span className="text-xs text-gray-500">
          Refresh in {countdown}s
        </span>
      </div>

      {/* Resource bars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <PercentBar
          label="CPU"
          percent={stats.cpu.usage_percent}
        />
        <PercentBar
          label="RAM"
          percent={stats.ram.usage_percent}
          detail={`${stats.ram.used_mb.toFixed(0)} / ${stats.ram.total_mb.toFixed(0)} MB (${stats.ram.available_mb.toFixed(0)} MB available)`}
        />
        <PercentBar
          label="Disk"
          percent={stats.disk.usage_percent}
          detail={`${stats.disk.used_mb.toFixed(0)} / ${stats.disk.total_mb.toFixed(0)} MB (${stats.disk.available_mb.toFixed(0)} MB free)`}
        />
      </div>

      {/* Detail cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="DB Size"
          value={stats.db_size_mb.toFixed(1)}
          unit="MB"
        />
        <StatCard
          label="Process RSS"
          value={stats.process.rss_mb.toFixed(1)}
          unit="MB"
        />
        <StatCard
          label="Goroutines"
          value={stats.process.goroutine_count}
        />
        <StatCard
          label="Uptime"
          value={formatUptime(stats.uptime_secs)}
        />
      </div>

      {/* Redis (conditional) */}
      {stats.redis_mem_mb != null && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Redis Memory"
            value={stats.redis_mem_mb.toFixed(2)}
            unit="MB"
          />
        </div>
      )}

      {stats.redis_mem_mb == null && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-3 text-xs text-gray-500">
          Redis is unavailable — stats not shown
        </div>
      )}
    </div>
  )
}
