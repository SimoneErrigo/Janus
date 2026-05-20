// Shared renderers for decoded protobuf / gRPC / custom-protocol trees.
//
// These were previously inline in pages/Traffic.jsx; SavedFlows now needs
// the same renderers so pinned flows show decoded bodies for grpc and
// user-defined binary protocols instead of just raw bytes.

import { useMemo } from 'react'

// Render a decoded protobuf field tree (from the descriptor-less local
// wire-format walk in utils/protobufDecode.js).
export function ProtobufFields({ fields, depth = 0 }) {
  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 12 }}>
      {fields.map((f, i) => {
        const tagColor = 'text-purple-400'
        const typeColor = 'text-gray-500'
        if (f.type === 'message') {
          return (
            <div key={i}>
              <span className={tagColor}>{f.field}</span>
              <span className={typeColor}> ({'message'}, {f.raw.length}B)</span>
              <ProtobufFields fields={f.value} depth={depth + 1} />
            </div>
          )
        }
        let valueEl
        if (f.type === 'string') {
          valueEl = <span className="text-green-300">{JSON.stringify(f.value)}</span>
        } else if (f.type === 'bytes') {
          valueEl = <span className="text-yellow-300">0x{f.value} <span className="text-gray-500">({f.length}B)</span></span>
        } else if (f.type === 'varint' || f.type === 'i64' || f.type === 'i32') {
          valueEl = <span className="text-cyan-300">{String(f.value)}</span>
        } else {
          valueEl = <span>{String(f.value)}</span>
        }
        return (
          <div key={i}>
            <span className={tagColor}>{f.field}</span>
            <span className={typeColor}> ({f.type}): </span>
            {valueEl}
          </div>
        )
      })}
    </div>
  )
}

// CustomDecodedFields renders a tree decoded by the user-defined custom
// protocol decoder. The shape comes from internal/customdecode.DecodedField
// (name, type, value, hex, enum, sub, error).
export function CustomDecodedFields({ fields, depth = 0 }) {
  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 12 }}>
      {fields.map((f, i) => {
        const nameCls = 'text-purple-400'
        const typeCls = 'text-gray-500'
        if (f.error) {
          return (
            <div key={i}>
              <span className={nameCls}>{f.name}</span>
              <span className={typeCls}> ({f.type}): </span>
              <span className="text-red-400">{f.error}</span>
            </div>
          )
        }
        if (f.sub && f.sub.length) {
          return (
            <div key={i}>
              <span className={nameCls}>{f.name}</span>
              <span className={typeCls}> ({f.type}{f.enum ? ` → ${f.enum}` : ''})</span>
              <CustomDecodedFields fields={f.sub} depth={depth + 1} />
            </div>
          )
        }
        let valueEl
        if (f.hex !== undefined && f.hex !== '') {
          valueEl = <span className="text-yellow-300 break-all">0x{f.hex}</span>
        } else if (f.enum) {
          valueEl = (
            <>
              <span className="text-green-300">{f.enum}</span>
              <span className="text-gray-500"> ({String(f.value)})</span>
            </>
          )
        } else if (typeof f.value === 'string') {
          valueEl = <span className="text-green-300">{JSON.stringify(f.value)}</span>
        } else if (typeof f.value === 'number' || typeof f.value === 'boolean') {
          valueEl = <span className="text-cyan-300">{String(f.value)}</span>
        } else if (f.value === undefined || f.value === null) {
          valueEl = <span className="text-gray-500">∅</span>
        } else {
          valueEl = <span>{String(f.value)}</span>
        }
        return (
          <div key={i}>
            <span className={nameCls}>{f.name}</span>
            <span className={typeCls}> ({f.type}): </span>
            {valueEl}
          </div>
        )
      })}
    </div>
  )
}

export function DecodedLeafValue({ value }) {
  if (typeof value === 'string') return <span className="text-green-300">{JSON.stringify(value)}</span>
  if (typeof value === 'number') return <span className="text-cyan-300">{String(value)}</span>
  if (typeof value === 'boolean') return <span className="text-purple-300">{String(value)}</span>
  if (value === null) return <span className="text-gray-500">null</span>
  return <span>{String(value)}</span>
}

// Read-only tree (no per-field action buttons). The Traffic page uses its
// own action-aware version; SavedFlows just needs the visual structure.
export function DecodedJSONTreeReadOnly({ value, depth = 0 }) {
  const pad = depth === 0 ? 0 : 12
  if (value === null) return <span className="text-gray-500">null</span>
  if (Array.isArray(value)) {
    return (
      <span>
        <span className="text-gray-500">[</span>
        {value.length === 0 ? null : (
          <div style={{ marginLeft: pad }}>
            {value.map((v, i) => (
              <div key={i}>
                <DecodedJSONTreeReadOnly value={v} depth={depth + 1} />
                {i < value.length - 1 ? <span className="text-gray-500">,</span> : null}
              </div>
            ))}
          </div>
        )}
        <span className="text-gray-500">]</span>
      </span>
    )
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value)
    return (
      <span>
        <span className="text-gray-500">{'{'}</span>
        {entries.length === 0 ? null : (
          <div style={{ marginLeft: pad }}>
            {entries.map(([k, v], i) => {
              const isLeaf = v === null || typeof v !== 'object'
              return (
                <div key={k}>
                  <span className="text-cyan-400">"{k}"</span>
                  <span className="text-gray-500">: </span>
                  {isLeaf ? <DecodedLeafValue value={v} /> : <DecodedJSONTreeReadOnly value={v} depth={depth + 1} />}
                  {i < entries.length - 1 ? <span className="text-gray-500">,</span> : null}
                </div>
              )
            })}
          </div>
        )}
        <span className="text-gray-500">{'}'}</span>
      </span>
    )
  }
  return <DecodedLeafValue value={value} />
}

// Parse a server-decoded JSON frame and render it as a tree (or fall back to
// the raw text if it doesn't parse as JSON).
export function DecodedNamedFrameViewReadOnly({ frameJSON }) {
  const parsed = useMemo(() => {
    try {
      const v = JSON.parse(frameJSON)
      return v && typeof v === 'object' ? v : null
    } catch {
      return null
    }
  }, [frameJSON])
  if (parsed) {
    return (
      <div className="text-green-300 whitespace-pre-wrap break-all">
        <DecodedJSONTreeReadOnly value={parsed} />
      </div>
    )
  }
  return (
    <pre className="text-green-300 whitespace-pre-wrap break-all">{frameJSON}</pre>
  )
}
