const LS_KEY = 'janus_traffic_nav_keys'

export function defaultTrafficNavKeys() {
  return {
    up: ['k', 'K', 'ArrowUp'],
    down: ['j', 'J', 'ArrowDown'],
  }
}

/** Split comma-separated key names (as in KeyboardEvent.key, e.g. ArrowUp, k) */
export function parseKeyList(str) {
  if (!str || typeof str !== 'string') return []
  return str
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

export function getTrafficNavKeys() {
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (!raw) return defaultTrafficNavKeys()
    const j = JSON.parse(raw)
    const def = defaultTrafficNavKeys()
    const up = Array.isArray(j.up) && j.up.length > 0 ? j.up : def.up
    const down = Array.isArray(j.down) && j.down.length > 0 ? j.down : def.down
    return { up, down }
  } catch {
    return defaultTrafficNavKeys()
  }
}

export function saveTrafficNavKeys(up, down) {
  localStorage.setItem(LS_KEY, JSON.stringify({ up, down }))
}

export function keysToInputString(keys) {
  return (keys || []).join(', ')
}
