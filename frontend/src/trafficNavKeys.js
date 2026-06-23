const LS_KEY = 'janus_traffic_nav_keys'

// Single source of truth for the customizable keyboard shortcuts. Each action
// is matched against KeyboardEvent.key values. Stored per-browser in
// localStorage; unset actions fall back to their defaults. Esc-based actions
// (close dialogs / exit flow) are intentionally fixed and not listed here.
export const SHORTCUT_ACTIONS = [
  { id: 'down',          label: 'Next packet / row',          scope: 'Traffic · Saved Flows', defaults: ['j', 'J', 'ArrowDown'] },
  { id: 'up',            label: 'Previous packet / row',      scope: 'Traffic · Saved Flows', defaults: ['k', 'K', 'ArrowUp'] },
  { id: 'toggleSelect',  label: 'Toggle packet in selection', scope: 'Traffic',               defaults: ['x'] },
  { id: 'deleteSel',     label: 'Delete selected packets',    scope: 'Traffic',               defaults: ['Delete', 'Backspace'] },
  { id: 'toggleHelp',    label: 'Show / hide shortcuts help', scope: 'Global',                defaults: ['?'] },
  { id: 'toggleSidebar', label: 'Collapse / expand sidebar',  scope: 'Global',                defaults: ['['] },
]

export function defaultBindings() {
  const out = {}
  for (const a of SHORTCUT_ACTIONS) out[a.id] = [...a.defaults]
  return out
}

// Returns the active bindings: stored values merged over defaults, so older
// stored blobs (which only had up/down) still resolve the newer actions.
export function getBindings() {
  const def = defaultBindings()
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (!raw) return def
    const j = JSON.parse(raw)
    const out = {}
    for (const a of SHORTCUT_ACTIONS) {
      const v = j?.[a.id]
      const cleaned = Array.isArray(v) ? v.filter((k) => typeof k === 'string' && k) : []
      out[a.id] = cleaned.length > 0 ? cleaned : def[a.id]
    }
    return out
  } catch {
    return def
  }
}

export function saveBindings(map) {
  localStorage.setItem(LS_KEY, JSON.stringify(map))
}

/** Split comma-separated key names (as in KeyboardEvent.key, e.g. ArrowUp, k) */
export function parseKeyList(str) {
  if (!str || typeof str !== 'string') return []
  return str
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

export function keysToInputString(keys) {
  return (keys || []).join(', ')
}

// ---- Backward-compatible helpers (up/down only) -------------------------
// Used by the Traffic and Saved Flows tables for prev/next navigation.

export function defaultTrafficNavKeys() {
  const d = defaultBindings()
  return { up: d.up, down: d.down }
}

export function getTrafficNavKeys() {
  const b = getBindings()
  return { up: b.up, down: b.down }
}

export function saveTrafficNavKeys(up, down) {
  saveBindings({ ...getBindings(), up, down })
}
