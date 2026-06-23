import { getBindings } from './trafficNavKeys'

// Pretty-print a KeyboardEvent.key value for display in the legend.
const KEY_LABELS = {
  ArrowUp: '↑',
  ArrowDown: '↓',
  ArrowLeft: '←',
  ArrowRight: '→',
  ' ': 'Space',
  Escape: 'Esc',
  Delete: 'Del',
  Backspace: '⌫',
  Enter: '↵',
}

export function keyLabel(key) {
  if (KEY_LABELS[key]) return KEY_LABELS[key]
  if (typeof key === 'string' && key.length === 1) return key.toUpperCase()
  return key
}

// Returns true when the event target is a text-entry field, so global
// shortcuts don't fire while the user is typing. Shared by every handler.
export function isTypingTarget(el) {
  const t = el?.tagName
  return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el?.isContentEditable
}

/**
 * The single source of truth for the shortcuts legend. Navigation keys are
 * read live from localStorage so the legend reflects the user's Config choices.
 */
export function shortcutGroups() {
  const b = getBindings()
  return [
    {
      title: 'Global',
      items: [
        { keys: b.toggleHelp, desc: 'Show / hide this shortcuts help', editable: true },
        { keys: b.toggleSidebar, desc: 'Collapse / expand the sidebar', editable: true },
        { keys: ['Escape'], desc: 'Close dialogs, panels, or flow view' },
      ],
    },
    {
      title: 'Traffic',
      items: [
        { keys: b.down, desc: 'Select next packet', editable: true },
        { keys: b.up, desc: 'Select previous packet', editable: true },
        { keys: b.toggleSelect, desc: 'Toggle packet in bulk selection', editable: true },
        { keys: b.deleteSel, desc: 'Delete selected packets', editable: true },
        { keys: ['Escape'], desc: 'Exit flow view / clear selection' },
      ],
    },
    {
      title: 'Selection (mouse)',
      items: [
        { keys: ['Shift + Click'], desc: 'Select / extend a range of rows (Traffic, Rules)' },
        { keys: ['Ctrl/⌘ + Click'], desc: 'Toggle a single row in the selection (Traffic)' },
      ],
    },
    {
      title: 'Saved Flows',
      items: [
        { keys: b.down, desc: 'Select next packet in the focused flow', editable: true },
        { keys: b.up, desc: 'Select previous packet in the focused flow', editable: true },
      ],
    },
  ]
}
