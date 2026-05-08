const DOZZLE_URL = 'http://localhost:9999'

export default function Logs() {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-900">
        <div>
          <h2 className="text-sm font-medium text-gray-100">Container Logs (Dozzle)</h2>
          <p className="text-xs text-gray-600">
            Dozzle runs on localhost only. Open it in a new tab.
          </p>
        </div>
        <a
          href={DOZZLE_URL}
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
