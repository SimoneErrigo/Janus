import { useEffect } from 'react'
import { shortcutGroups, keyLabel } from '../shortcuts'
import { getBindings } from '../trafficNavKeys'

// Renders a single key cap.
function Kbd({ children }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[1.4rem] px-1.5 py-0.5 text-[11px] font-mono font-medium text-gray-200 bg-gray-800 border border-gray-700 border-b-2 rounded">
      {children}
    </kbd>
  )
}

/**
 * ShortcutsLegend — a uniform, app-wide keyboard shortcuts overlay. Opened with
 * `?` from anywhere (wired in Layout) and listed per area.
 */
export default function ShortcutsLegend({ onClose }) {
  useEffect(() => {
    function onKey(e) {
      // Close on Esc or the configured "toggle help" key.
      if (e.key === 'Escape' || getBindings().toggleHelp.includes(e.key)) {
        // Stop the event reaching page/global handlers (e.g. Traffic's Esc).
        e.preventDefault()
        e.stopPropagation()
        onClose()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const groups = shortcutGroups()

  return (
    <div
      className="fixed inset-0 z-[70] bg-black/60 flex items-center justify-center p-4"
      onMouseDown={onClose}
    >
      <div
        className="bg-gray-900 border border-gray-700 rounded-lg shadow-xl max-w-lg w-full max-h-[80vh] flex flex-col"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-100 flex items-center gap-2">
            <KeyboardGlyph className="w-4 h-4 text-cyan-400" />
            Keyboard shortcuts
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 cursor-pointer"
            title="Close (Esc)"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div className="overflow-auto p-4 space-y-4">
          {groups.map((group) => (
            <div key={group.title}>
              <h4 className="text-[11px] uppercase tracking-wide text-gray-500 mb-1.5">{group.title}</h4>
              <ul className="space-y-1">
                {group.items.map((item, i) => (
                  <li key={i} className="flex items-center justify-between gap-4 text-xs">
                    <span className="text-gray-300">{item.desc}</span>
                    <span className="flex items-center gap-1 flex-shrink-0">
                      {item.keys.map((k, j) => (
                        <span key={j} className="flex items-center gap-1">
                          {j > 0 && <span className="text-gray-600">/</span>}
                          <Kbd>{keyLabel(k)}</Kbd>
                        </span>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <p className="text-[11px] text-gray-600 pt-1 border-t border-gray-800">
            Key shortcuts can be customised on the <span className="text-gray-400">Config</span> page (Esc and mouse gestures are fixed).
          </p>
        </div>
      </div>
    </div>
  )
}

function KeyboardGlyph({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="6" width="20" height="12" rx="2" />
      <path d="M6 10h0M10 10h0M14 10h0M18 10h0M8 14h8" />
    </svg>
  )
}
