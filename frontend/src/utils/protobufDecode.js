// Protobuf wire-format decoder (no .proto required).
//
// Walks the protobuf wire format and produces a tree of fields. For LEN
// values it tries to recurse as a nested message; if that fails it falls
// back to UTF-8 string or raw bytes.
//
// Also peels gRPC framing when present: a gRPC message body is
// [1 byte compression flag][4 byte length BE][protobuf bytes], optionally
// repeated for multiple frames.

const WIRE_VARINT = 0
const WIRE_I64 = 1
const WIRE_LEN = 2
const WIRE_SGROUP = 3
const WIRE_EGROUP = 4
const WIRE_I32 = 5

function readVarint(buf, pos) {
  let result = 0n
  let shift = 0n
  let p = pos
  while (p < buf.length) {
    const b = buf[p++]
    result |= BigInt(b & 0x7f) << shift
    if ((b & 0x80) === 0) {
      // Return as Number if it fits, else as BigInt
      if (result <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return { value: Number(result), next: p }
      }
      return { value: result, next: p }
    }
    shift += 7n
    if (shift > 70n) return null
  }
  return null
}

function isPrintableUTF8(bytes) {
  if (bytes.length === 0) return false
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    let printable = 0
    for (const ch of text) {
      const cp = ch.codePointAt(0)
      // allow tab, newline, carriage return, and any non-control char
      if (cp === 9 || cp === 10 || cp === 13 || cp >= 32) printable++
      else return false
    }
    return printable >= text.length * 0.95
  } catch {
    return false
  }
}

function bytesToHex(bytes, max = 64) {
  const n = Math.min(bytes.length, max)
  let out = ''
  for (let i = 0; i < n; i++) out += bytes[i].toString(16).padStart(2, '0')
  if (bytes.length > n) out += `…(+${bytes.length - n}B)`
  return out
}

function tryDecodeMessage(buf) {
  const fields = []
  let pos = 0
  while (pos < buf.length) {
    const tag = readVarint(buf, pos)
    if (!tag) return null
    pos = tag.next
    const tagNum = typeof tag.value === 'bigint' ? Number(tag.value) : tag.value
    const wire = tagNum & 0x7
    const fieldNum = tagNum >>> 3
    if (fieldNum === 0) return null

    if (wire === WIRE_VARINT) {
      const v = readVarint(buf, pos)
      if (!v) return null
      pos = v.next
      fields.push({ field: fieldNum, type: 'varint', value: v.value })
    } else if (wire === WIRE_I64) {
      if (pos + 8 > buf.length) return null
      const view = new DataView(buf.buffer, buf.byteOffset + pos, 8)
      fields.push({ field: fieldNum, type: 'i64', value: view.getBigUint64(0, true).toString() })
      pos += 8
    } else if (wire === WIRE_I32) {
      if (pos + 4 > buf.length) return null
      const view = new DataView(buf.buffer, buf.byteOffset + pos, 4)
      fields.push({ field: fieldNum, type: 'i32', value: view.getUint32(0, true) })
      pos += 4
    } else if (wire === WIRE_LEN) {
      const len = readVarint(buf, pos)
      if (!len) return null
      pos = len.next
      const lenN = typeof len.value === 'bigint' ? Number(len.value) : len.value
      if (lenN < 0 || pos + lenN > buf.length) return null
      const sub = buf.subarray(pos, pos + lenN)
      pos += lenN
      // Try nested message first
      const nested = lenN > 0 ? tryDecodeMessage(sub) : null
      if (nested) {
        fields.push({ field: fieldNum, type: 'message', value: nested, raw: sub })
      } else if (isPrintableUTF8(sub)) {
        fields.push({ field: fieldNum, type: 'string', value: new TextDecoder('utf-8').decode(sub) })
      } else {
        fields.push({ field: fieldNum, type: 'bytes', value: bytesToHex(sub), length: sub.length })
      }
    } else if (wire === WIRE_SGROUP || wire === WIRE_EGROUP) {
      // Deprecated groups — bail out.
      return null
    } else {
      return null
    }
  }
  return fields
}

// Detect gRPC framing and peel it. Returns an array of frames (each a
// Uint8Array of the inner protobuf bytes) or null if no framing detected.
function peelGRPCFrames(bytes) {
  const frames = []
  let pos = 0
  while (pos < bytes.length) {
    if (pos + 5 > bytes.length) return null
    const compressed = bytes[pos]
    if (compressed !== 0 && compressed !== 1) return null
    const view = new DataView(bytes.buffer, bytes.byteOffset + pos + 1, 4)
    const len = view.getUint32(0, false)
    if (compressed === 1) return null // can't decode compressed without knowing the algo
    if (pos + 5 + len > bytes.length) return null
    frames.push(bytes.subarray(pos + 5, pos + 5 + len))
    pos += 5 + len
  }
  if (frames.length === 0) return null
  return frames
}

// Public entry point: takes raw bytes (Uint8Array), returns
// { ok, frames: [{ fields, length }], raw } or { ok: false, reason }.
export function decodeProtobuf(bytes) {
  if (!bytes || bytes.length === 0) {
    return { ok: false, reason: 'empty' }
  }

  // Try gRPC framing first
  const grpcFrames = peelGRPCFrames(bytes)
  if (grpcFrames) {
    const frames = []
    for (const f of grpcFrames) {
      const fields = f.length > 0 ? tryDecodeMessage(f) : []
      if (!fields) return { ok: false, reason: 'gRPC framing detected but inner protobuf failed to parse' }
      frames.push({ fields, length: f.length })
    }
    return { ok: true, framing: 'grpc', frames }
  }

  // Otherwise try as raw protobuf
  const fields = tryDecodeMessage(bytes)
  if (!fields) {
    return { ok: false, reason: 'not a valid protobuf message' }
  }
  return { ok: true, framing: 'none', frames: [{ fields, length: bytes.length }] }
}

// Quick sniff: does this look like protobuf/gRPC at all? Used to decide
// whether to surface the "Decoded" view.
export function looksLikeProtobuf(bytes) {
  if (!bytes || bytes.length < 2) return false
  // gRPC framing fingerprint: byte 0 is 0 or 1, length matches
  if (bytes.length >= 5) {
    const c = bytes[0]
    if (c === 0 || c === 1) {
      const view = new DataView(bytes.buffer, bytes.byteOffset + 1, 4)
      const len = view.getUint32(0, false)
      if (5 + len === bytes.length || 5 + len <= bytes.length) return true
    }
  }
  // Otherwise: try a tentative decode
  const r = tryDecodeMessage(bytes)
  return r !== null
}
