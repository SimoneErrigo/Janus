// Inline error banner used across Rules, Services, Config, etc.
// Renders nothing when error is falsy so callers can write {error && <ErrorBanner.../>}
// or simply <ErrorBanner error={error} />.
export default function ErrorBanner({ error, className = '' }) {
  if (!error) return null
  return (
    <div className={`bg-red-900/30 border border-red-800 text-red-400 text-sm px-4 py-2 rounded ${className}`.trim()}>
      {error}
    </div>
  )
}
