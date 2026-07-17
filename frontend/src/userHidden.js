// Per-user, client-side packet-hiding helpers.
//
// The proxy is a single shared instance — every teammate sees the same DB. To
// let users clear/delete packets from *their own view* without affecting
// teammates, we track two things per user (localStorage, keyed by display name):
//
//   - hidden_ids: packet IDs the user dismissed (capped at MAX_HIDDEN)
//   - clear_cursor: ISO timestamp; packets older than this are hidden
//
// Both are sent as query params to /api/packets so the backend filters them
// out of queries. Rules, alerts, and flows remain shared across users.

import { getDisplayName } from './api'

const MAX_HIDDEN = 500 // matches the /api/packets exclude_ids cap

function keyHidden() {
  return `janus_hidden_ids_${getDisplayName() || '_guest'}`
}
function keyCursor() {
  return `janus_clear_cursor_${getDisplayName() || '_guest'}`
}
function keyHiddenAlerts() {
  return `janus_hidden_alert_ids_${getDisplayName() || '_guest'}`
}
function keyViewCursor(view) {
  return `janus_${view}_clear_cursor_${getDisplayName() || '_guest'}`
}

export function getHiddenIds() {
  try {
    const raw = localStorage.getItem(keyHidden())
    if (!raw) return []
    const arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr.slice(-MAX_HIDDEN) : []
  } catch {
    return []
  }
}

export function addHiddenIds(ids) {
  if (!ids || ids.length === 0) return
  const existing = new Set(getHiddenIds())
  for (const id of ids) existing.add(Number(id))
  let next = Array.from(existing)
  if (next.length > MAX_HIDDEN) next = next.slice(next.length - MAX_HIDDEN)
  try { localStorage.setItem(keyHidden(), JSON.stringify(next)) } catch { /* private mode/quota: hiding remains best-effort */ }
}

export function clearHiddenIds() {
  try { localStorage.removeItem(keyHidden()) } catch { /* local storage may be unavailable */ }
}

export function getHiddenAlertIds() {
  try {
    const raw = localStorage.getItem(keyHiddenAlerts())
    if (!raw) return []
    const arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr.slice(-MAX_HIDDEN) : []
  } catch {
    return []
  }
}

export function addHiddenAlertIds(ids) {
  if (!ids || ids.length === 0) return
  const existing = new Set(getHiddenAlertIds())
  for (const id of ids) existing.add(Number(id))
  let next = Array.from(existing)
  if (next.length > MAX_HIDDEN) next = next.slice(next.length - MAX_HIDDEN)
  try { localStorage.setItem(keyHiddenAlerts(), JSON.stringify(next)) } catch { /* private mode/quota: hiding remains best-effort */ }
}

export function clearHiddenAlertIds() {
  try { localStorage.removeItem(keyHiddenAlerts()) } catch { /* local storage may be unavailable */ }
}

export function getClearCursor() {
  return localStorage.getItem(keyCursor()) || ''
}

export function setClearCursor(iso) {
  try { localStorage.setItem(keyCursor(), iso) } catch { /* local storage may be unavailable */ }
}

export function resetClearCursor() {
  try { localStorage.removeItem(keyCursor()) } catch { /* local storage may be unavailable */ }
}

export function getViewClearCursor(view) {
  try { return localStorage.getItem(keyViewCursor(view)) || '' } catch { return '' }
}

export function setViewClearCursor(view, iso) {
  try { localStorage.setItem(keyViewCursor(view), iso) } catch { /* local storage may be unavailable */ }
}

export function getEffectiveClearCursor(view) {
  const globalCursor = getClearCursor()
  const viewCursor = getViewClearCursor(view)
  return viewCursor > globalCursor ? viewCursor : globalCursor
}

// Build query params to send on /api/packets requests. Pruning is done when
// assembling params: IDs older than the cursor can be dropped from the list
// since they'd be filtered by hidden_before anyway.
export function hideParams() {
  const out = {}
  const cursor = getClearCursor()
  if (cursor) out.hidden_before = cursor
  const ids = getHiddenIds()
  if (ids.length > 0) out.exclude_ids = ids.join(',')
  return out
}

// Client-side predicate for filtering lists that don't go through /api/packets
// (e.g. flow responses, alerts, blocks). Returns true if the packet (or any
// object with {id, timestamp?}) should be visible.
export function isVisible(p) {
  if (!p) return false
  const ids = new Set(getHiddenIds())
  if (ids.has(Number(p.id))) return false
  const cursor = getClearCursor()
  if (cursor && p.timestamp && p.timestamp < cursor) return false
  return true
}

// Predicate for alert/block rows that carry a packet_id (not their own id).
export function isPacketVisible(packetId, packetTimestamp) {
  if (packetId == null) return true
  const ids = new Set(getHiddenIds())
  if (ids.has(Number(packetId))) return false
  const cursor = getClearCursor()
  if (cursor && packetTimestamp && packetTimestamp < cursor) return false
  return true
}
