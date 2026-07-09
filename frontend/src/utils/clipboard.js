// Clipboard helper that falls back to a hidden textarea + execCommand when
// navigator.clipboard is unavailable (insecure context, e.g. HTTP on a LAN IP).
export async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // fall through to legacy path
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '-9999px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    ta.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}

function base64ToBytes(b64) {
  if (!b64) return new Uint8Array()
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  } catch {
    return new Uint8Array()
  }
}

function bytesToHex(bytes, maxBytes = 1024 * 64) {
  const n = Math.min(bytes.length, maxBytes)
  let out = ''
  for (let i = 0; i < n; i++) out += bytes[i].toString(16).padStart(2, '0')
  if (bytes.length > n) out += `...(+${bytes.length - n} bytes)`
  return out
}

// Copy a base64-encoded body to the clipboard as raw bytes. Uses the binary
// clipboard when available (secure context), else falls back to a hex string.
// Returns false when there are no bytes to copy.
export async function copyRawBytesFromBase64(b64) {
  const bytes = base64ToBytes(b64)
  if (!bytes || bytes.length === 0) return false

  try {
    if (navigator.clipboard?.write && typeof ClipboardItem !== 'undefined' && window.isSecureContext) {
      const blob = new Blob([bytes], { type: 'application/octet-stream' })
      await navigator.clipboard.write([new ClipboardItem({ 'application/octet-stream': blob })])
      return true
    }
  } catch {
    // ignore; fall back to hex text
  }
  return copyText(bytesToHex(bytes))
}

