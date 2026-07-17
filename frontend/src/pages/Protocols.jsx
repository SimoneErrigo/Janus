import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import ErrorBanner from '../components/ErrorBanner'

// Field types are kept in sync with storage.FieldType in the Go backend.
const FIELD_TYPES = [
  { value: 'u8',              label: 'u8 — unsigned 8-bit' },
  { value: 'u16',             label: 'u16 — unsigned 16-bit' },
  { value: 'u32',             label: 'u32 — unsigned 32-bit' },
  { value: 'u64',             label: 'u64 — unsigned 64-bit' },
  { value: 'i8',              label: 'i8 — signed 8-bit' },
  { value: 'i16',             label: 'i16 — signed 16-bit' },
  { value: 'i32',             label: 'i32 — signed 32-bit' },
  { value: 'i64',             label: 'i64 — signed 64-bit' },
  { value: 'f32',             label: 'f32 — float 32-bit' },
  { value: 'f64',             label: 'f64 — double 64-bit' },
  { value: 'bytes_fixed',     label: 'bytes_fixed — N raw bytes' },
  { value: 'string_fixed',    label: 'string_fixed — N bytes as string' },
  { value: 'string_lp_u8',    label: 'string_lp_u8 — u8-prefixed string' },
  { value: 'string_lp_u16',   label: 'string_lp_u16 — u16-prefixed string' },
  { value: 'bytes_lp_u8',     label: 'bytes_lp_u8 — u8-prefixed raw bytes' },
  { value: 'bytes_lp_u16',    label: 'bytes_lp_u16 — u16-prefixed raw bytes' },
  { value: 'remaining_bytes', label: 'remaining_bytes — rest of body' },
  { value: 'dispatch',        label: 'dispatch — payload picked by previous enum field' },
  { value: 'bytes_computed',  label: 'bytes_computed — length = field_a × field_b ÷ N' },
]

const INTEGER_TYPES = new Set(['u8','u16','u32','u64','i8','i16','i32','i64'])
const FIXED_LEN_TYPES = new Set(['bytes_fixed', 'string_fixed'])
const NUMERIC_TYPES = INTEGER_TYPES // alias for clarity in computed-length pickers

const EMPTY_PROTOCOL = {
  name: '', endian: 'little',
  enums: {}, structs: {},
  request_fields: [], response_fields: [],
}

export default function Protocols() {
  const [protocols, setProtocols] = useState([])
  const [editing, setEditing] = useState(null) // protocol object or null
  const [error, setError] = useState('')
  const loadRequestRef = useRef(0)

  const loadProtocols = useCallback(async () => {
    const request = ++loadRequestRef.current
    try {
      const list = await api.listProtocols()
      if (request !== loadRequestRef.current) return
      setProtocols(list || [])
    } catch (err) {
      if (request === loadRequestRef.current) setError(err.message)
    }
  }, [])
  const invalidateLoad = useCallback(() => { loadRequestRef.current++ }, [])

  useEffect(() => {
    const timer = setTimeout(loadProtocols, 0)
    return () => {
      clearTimeout(timer)
      invalidateLoad()
    }
  }, [invalidateLoad, loadProtocols])

  async function handleSave(p) {
    setError('')
    try {
      if (p._isNew) {
        await api.createProtocol(stripInternal(p))
      } else {
        await api.updateProtocol(p.id, stripInternal(p))
      }
      setEditing(null)
      await loadProtocols()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDelete(id) {
    if (!confirm('Delete this protocol? Services bound to it will become unbound.')) return
    try {
      await api.deleteProtocol(id)
      await loadProtocols()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold text-gray-100">Protocols</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Custom binary protocol decoders. Bind a protocol to a service to render packets as a structured tree instead of hex.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setEditing({ ...deepClone(EMPTY_PROTOCOL), _isNew: true, _showImport: true })}
            className="border border-gray-700 hover:border-cyan-500 text-gray-300 hover:text-cyan-300 text-sm px-4 py-2 rounded transition-colors cursor-pointer"
            title="Paste challenge-client Python and let Janus build the enums and structs"
          >
            Import from Python
          </button>
          <button
            onClick={() => setEditing({ ...deepClone(EMPTY_PROTOCOL), _isNew: true })}
            className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded transition-colors cursor-pointer"
          >
            + Add Protocol
          </button>
        </div>
      </div>

      <ErrorBanner error={error} className="mb-4" />

      {editing && (
        <ProtocolEditor
          protocol={editing}
          onSave={handleSave}
          onCancel={() => setEditing(null)}
        />
      )}

      <div className="space-y-3">
        {protocols.map((p) => (
          <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex items-center justify-between">
            <div>
              <div className="font-medium text-gray-100">{p.name}</div>
              <div className="text-xs text-gray-500 mt-0.5">
                <span className="px-1.5 py-0.5 bg-gray-800 rounded text-gray-400">{p.endian || 'little'}-endian</span>
                <span className="ml-2">req: {p.request_fields?.length || 0}</span>
                <span className="ml-2">resp: {p.response_fields?.length || 0}</span>
                <span className="ml-2">structs: {Object.keys(p.structs || {}).length}</span>
                <span className="ml-2">enums: {Object.keys(p.enums || {}).length}</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setEditing(deepClone(p))} className="text-gray-400 hover:text-cyan-400 text-sm px-3 py-1 cursor-pointer">Edit</button>
              <button onClick={() => handleDelete(p.id)} className="text-gray-400 hover:text-red-400 text-sm px-3 py-1 cursor-pointer">Delete</button>
            </div>
          </div>
        ))}
        {protocols.length === 0 && !editing && (
          <p className="text-gray-600 text-center py-8">No protocols defined. Click <em>Add Protocol</em> to create one.</p>
        )}
      </div>
    </div>
  )
}

// ProtocolEditor renders the four-section builder: enums, structs, request
// fields, response fields. State is kept in a single working copy `form`
// that mirrors the wire format the backend expects.
function ProtocolEditor({ protocol, onSave, onCancel }) {
  const [form, setForm] = useState(protocol)
  const [tab, setTab] = useState('request')
  const [showImport, setShowImport] = useState(!!protocol._showImport)

  const enumNames = useMemo(() => Object.keys(form.enums || {}), [form.enums])
  const structNames = useMemo(() => Object.keys(form.structs || {}), [form.structs])
  // Live "what still needs a human" analysis, recomputed as the user edits so
  // items disappear the moment they're resolved.
  const followUps = useMemo(() => computeFollowUps(form), [form])

  function set(k, v) { setForm((f) => ({ ...f, [k]: v })) }

  // Merge an imported draft into the working copy. Imported enum/struct names
  // overwrite same-named entries; endianness and an empty name are adopted from
  // the parsed code since it reflects the real wire format. Auto-wired
  // request/response field lists are adopted only when that direction is still
  // empty, so a re-import never clobbers layout the user has already tweaked.
  function mergeImported(draft) {
    setForm((f) => {
      const next = { ...f }
      next.enums = { ...(f.enums || {}), ...(draft.enums || {}) }
      next.structs = { ...(f.structs || {}), ...(draft.structs || {}) }
      if (draft.endian) next.endian = draft.endian
      if (!f.name && draft.name) next.name = draft.name
      if (draft.request_fields?.length && !f.request_fields?.length) {
        next.request_fields = deepClone(draft.request_fields)
      }
      if (draft.response_fields?.length && !f.response_fields?.length) {
        next.response_fields = deepClone(draft.response_fields)
      }
      return next
    })
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
      <div className="flex justify-end mb-2">
        <button
          onClick={() => setShowImport((v) => !v)}
          className="text-xs text-gray-400 hover:text-cyan-300 cursor-pointer"
        >
          {showImport ? '▾ Hide Python import' : '▸ Import from Python'}
        </button>
      </div>
      {showImport && <ImportPanel onImport={mergeImported} />}

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <Label>Name</Label>
          <input
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="e.g. minecclicker"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div>
          <Label>Endianness</Label>
          <select
            value={form.endian || 'little'}
            onChange={(e) => set('endian', e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
          >
            <option value="little">little</option>
            <option value="big">big</option>
          </select>
        </div>
      </div>

      <div className="flex border-b border-gray-800 mb-4">
        {['request', 'response', 'structs', 'enums'].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px capitalize cursor-pointer transition-colors ${
              tab === t
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {t}
            {t === 'request' && form.request_fields?.length ? ` (${form.request_fields.length})` : ''}
            {t === 'response' && form.response_fields?.length ? ` (${form.response_fields.length})` : ''}
            {t === 'structs' && structNames.length ? ` (${structNames.length})` : ''}
            {t === 'enums' && enumNames.length ? ` (${enumNames.length})` : ''}
          </button>
        ))}
      </div>

      <FollowUps steps={followUps} onGoto={setTab} />

      {tab === 'request' && (
        <FieldListEditor
          fields={form.request_fields || []}
          onChange={(fl) => set('request_fields', fl)}
          enumNames={enumNames}
          allFieldsForDispatch={form.request_fields || []}
        />
      )}
      {tab === 'response' && (
        <>
          {!(form.response_fields || []).length && (
            <p className="text-xs text-gray-500 mb-2 bg-gray-800/40 border border-gray-800 rounded p-2">
              Server replies aren't imported from Python automatically — they're read with
              helper functions and <code className="text-gray-400">if</code> branches Janus can't
              reconstruct. Add the reply fields here (often a status byte followed by a
              {' '}<em>dispatch</em>), or open the <button type="button" onClick={() => setTab('structs')} className="text-cyan-400 hover:underline cursor-pointer">Structs</button> tab and click <span className="text-cyan-400">→ response</span> on a struct to reuse it.
            </p>
          )}
          <FieldListEditor
            fields={form.response_fields || []}
            onChange={(fl) => set('response_fields', fl)}
            enumNames={enumNames}
            allFieldsForDispatch={form.response_fields || []}
          />
        </>
      )}
      {tab === 'structs' && (
        <StructsEditor
          structs={form.structs || {}}
          onChange={(s) => set('structs', s)}
          enumNames={enumNames}
          onUseAsRequest={(fields) => { set('request_fields', deepClone(fields)); setTab('request') }}
          onUseAsResponse={(fields) => { set('response_fields', deepClone(fields)); setTab('response') }}
        />
      )}
      {tab === 'enums' && (
        <EnumsEditor
          enums={form.enums || {}}
          onChange={(e) => set('enums', e)}
        />
      )}

      <div className="flex justify-end gap-2 mt-4 border-t border-gray-800 pt-4">
        <button
          onClick={onCancel}
          className="text-gray-400 hover:text-gray-200 text-sm px-4 py-2 cursor-pointer"
        >
          Cancel
        </button>
        <button
          onClick={() => onSave(form)}
          className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm px-4 py-2 rounded cursor-pointer"
        >
          {form._isNew ? 'Create' : 'Save'}
        </button>
      </div>
    </div>
  )
}

// FieldListEditor edits an ordered list of ProtocolField rows. The same
// component is reused for request/response/struct fields — only the list
// of "previous fields" available for dispatch changes.
function FieldListEditor({ fields, onChange, enumNames, allFieldsForDispatch }) {
  function update(i, patch) {
    onChange(fields.map((f, idx) => (idx === i ? { ...f, ...patch } : f)))
  }
  function remove(i) {
    onChange(fields.filter((_, idx) => idx !== i))
  }
  function move(i, dir) {
    const j = i + dir
    if (j < 0 || j >= fields.length) return
    const out = fields.slice()
    ;[out[i], out[j]] = [out[j], out[i]]
    onChange(out)
  }
  function add() {
    onChange([...(fields || []), { name: `field${fields.length + 1}`, type: 'u8' }])
  }

  return (
    <div className="space-y-2">
      {fields.map((f, i) => {
        // Both dispatch and bytes_computed can only reference fields that
        // come strictly before this one (the decoder reads sequentially).
        const previousFields = (allFieldsForDispatch || fields).slice(0, i)
        const dispatchSources = previousFields.filter((s) => INTEGER_TYPES.has(s.type))
        const numericSources = previousFields.filter((s) => NUMERIC_TYPES.has(s.type))
        return (
          <div key={i} className="grid grid-cols-12 gap-2 bg-gray-800/40 border border-gray-800 rounded p-2">
            <div className="col-span-1 flex items-center justify-center text-xs text-gray-600">#{i + 1}</div>
            <div className="col-span-3">
              <input
                value={f.name}
                onChange={(e) => update(i, { name: e.target.value })}
                placeholder="name"
                className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="col-span-3">
              <select
                value={f.type}
                onChange={(e) => update(i, { type: e.target.value, length: undefined, enum_ref: undefined, dispatch_on: undefined, length_from: undefined, length_mul_from: undefined, length_div: undefined })}
                className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
              >
                {FIELD_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div className="col-span-4">
              {FIXED_LEN_TYPES.has(f.type) && (
                <input
                  type="number"
                  min="1"
                  value={f.length || ''}
                  onChange={(e) => update(i, { length: parseInt(e.target.value, 10) || 0 })}
                  placeholder="length (bytes)"
                  className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
                />
              )}
              {INTEGER_TYPES.has(f.type) && (
                <select
                  value={f.enum_ref || ''}
                  onChange={(e) => update(i, { enum_ref: e.target.value || undefined })}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">— no enum —</option>
                  {enumNames.map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              )}
              {f.type === 'dispatch' && (
                <select
                  value={f.dispatch_on || ''}
                  onChange={(e) => update(i, { dispatch_on: e.target.value || undefined })}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">— pick source field —</option>
                  {dispatchSources.map((s) => (
                    <option key={s.name} value={s.name}>
                      {s.name}{s.enum_ref ? ` (enum: ${s.enum_ref})` : ''}
                    </option>
                  ))}
                </select>
              )}
              {f.type === 'bytes_computed' && (
                <div className="grid grid-cols-3 gap-1">
                  <select
                    value={f.length_from || ''}
                    onChange={(e) => update(i, { length_from: e.target.value || undefined })}
                    className="bg-gray-900 border border-gray-700 rounded px-1 py-1 text-xs text-gray-100 focus:outline-none focus:border-cyan-500"
                    title="Source field for length"
                  >
                    <option value="">— from —</option>
                    {numericSources.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
                  </select>
                  <select
                    value={f.length_mul_from || ''}
                    onChange={(e) => update(i, { length_mul_from: e.target.value || undefined })}
                    className="bg-gray-900 border border-gray-700 rounded px-1 py-1 text-xs text-gray-100 focus:outline-none focus:border-cyan-500"
                    title="Optional multiplier (another previous numeric field)"
                  >
                    <option value="">× 1</option>
                    {numericSources.map((s) => <option key={s.name} value={s.name}>× {s.name}</option>)}
                  </select>
                  <input
                    type="number"
                    min="1"
                    value={f.length_div || ''}
                    onChange={(e) => update(i, { length_div: parseInt(e.target.value, 10) || undefined })}
                    placeholder="÷ N"
                    title="Optional divisor (ceil)"
                    className="bg-gray-900 border border-gray-700 rounded px-1 py-1 text-xs text-gray-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              )}
            </div>
            <div className="col-span-1 flex items-center justify-end gap-1">
              <button onClick={() => move(i, -1)} disabled={i === 0} className="text-gray-500 hover:text-gray-200 disabled:opacity-30 cursor-pointer text-xs px-1">↑</button>
              <button onClick={() => move(i, +1)} disabled={i === fields.length - 1} className="text-gray-500 hover:text-gray-200 disabled:opacity-30 cursor-pointer text-xs px-1">↓</button>
              <button onClick={() => remove(i)} className="text-gray-500 hover:text-red-400 cursor-pointer text-xs px-1">✕</button>
            </div>
          </div>
        )
      })}
      <button
        onClick={add}
        className="w-full bg-gray-800/60 hover:bg-gray-800 border border-dashed border-gray-700 rounded px-3 py-2 text-sm text-gray-400 cursor-pointer"
      >
        + Add field
      </button>
    </div>
  )
}

// StructsEditor manages a map of struct_name -> field list. Structs are
// the dispatch targets: when a protocol's dispatch field resolves an enum
// label, the decoder looks for a struct with the same name as the label.
function StructsEditor({ structs, onChange, enumNames, onUseAsRequest, onUseAsResponse }) {
  const names = Object.keys(structs)
  const [renameDraft, setRenameDraft] = useState({})

  function setStruct(name, fields) {
    onChange({ ...structs, [name]: fields })
  }
  function addStruct() {
    const name = prompt('Struct name (matches an enum label, e.g. LOGIN):')
    if (!name) return
    if (structs[name]) { alert('A struct with that name already exists.'); return }
    onChange({ ...structs, [name]: [] })
  }
  function removeStruct(name) {
    if (!confirm(`Remove struct ${name}?`)) return
    const next = { ...structs }
    delete next[name]
    onChange(next)
  }
  function rename(oldName, newName) {
    if (!newName || newName === oldName) return
    if (structs[newName]) { alert('Name already used.'); return }
    const next = {}
    for (const k of Object.keys(structs)) {
      next[k === oldName ? newName : k] = structs[k]
    }
    onChange(next)
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-500">
        Define reusable groups of fields. A <em>dispatch</em> field looks up a struct whose name matches the resolved enum label of its source field.
      </p>
      {names.map((name) => (
        <div key={name} className="border border-gray-800 rounded p-3">
          <div className="flex items-center gap-2 mb-2">
            <input
              value={renameDraft[name] ?? name}
              onChange={(e) => setRenameDraft((d) => ({ ...d, [name]: e.target.value }))}
              onBlur={() => rename(name, (renameDraft[name] ?? name).trim())}
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 font-mono focus:outline-none focus:border-cyan-500"
            />
            <span className="text-xs text-gray-600">{(structs[name] || []).length} fields</span>
            <div className="flex-1" />
            {onUseAsRequest && (
              <button
                onClick={() => onUseAsRequest(structs[name] || [])}
                title="Copy these fields into the Request layout"
                className="text-gray-500 hover:text-cyan-400 text-xs cursor-pointer"
              >
                → request
              </button>
            )}
            {onUseAsResponse && (
              <button
                onClick={() => onUseAsResponse(structs[name] || [])}
                title="Copy these fields into the Response layout"
                className="text-gray-500 hover:text-cyan-400 text-xs cursor-pointer"
              >
                → response
              </button>
            )}
            <button onClick={() => removeStruct(name)} className="text-gray-500 hover:text-red-400 text-xs cursor-pointer">Remove</button>
          </div>
          <FieldListEditor
            fields={structs[name] || []}
            onChange={(fl) => setStruct(name, fl)}
            enumNames={enumNames}
            allFieldsForDispatch={structs[name] || []}
          />
        </div>
      ))}
      <button
        onClick={addStruct}
        className="w-full bg-gray-800/60 hover:bg-gray-800 border border-dashed border-gray-700 rounded px-3 py-2 text-sm text-gray-400 cursor-pointer"
      >
        + Add struct
      </button>
    </div>
  )
}

// EnumsEditor manages a map of enum_name -> { numeric_value: label }. The
// decoder substitutes the label whenever a numeric field references the
// enum, and dispatch resolves its target struct by the resolved label.
function EnumsEditor({ enums, onChange }) {
  const names = Object.keys(enums)

  function addEnum() {
    const name = prompt('Enum name (e.g. ReqType):')
    if (!name) return
    if (enums[name]) { alert('Already exists.'); return }
    onChange({ ...enums, [name]: {} })
  }
  function removeEnum(name) {
    if (!confirm(`Remove enum ${name}?`)) return
    const next = { ...enums }
    delete next[name]
    onChange(next)
  }
  function addRow(name) {
    const num = prompt('Numeric value:')
    if (num === null || num === '') return
    const label = prompt('Label:')
    if (!label) return
    const next = { ...enums, [name]: { ...enums[name], [num]: label } }
    onChange(next)
  }
  function removeRow(name, key) {
    const tbl = { ...enums[name] }
    delete tbl[key]
    onChange({ ...enums, [name]: tbl })
  }
  function setRow(name, key, label) {
    onChange({ ...enums, [name]: { ...enums[name], [key]: label } })
  }
  function renameKey(name, oldKey, newKey) {
    if (oldKey === newKey || newKey === '' || newKey == null) return
    const tbl = { ...enums[name] }
    tbl[newKey] = tbl[oldKey]
    delete tbl[oldKey]
    onChange({ ...enums, [name]: tbl })
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-500">
        Name → numeric value table. Numeric fields with an <em>enum</em> reference render the label instead of the raw number, and dispatch matches struct names against the same labels.
      </p>
      {names.map((name) => {
        const tbl = enums[name] || {}
        return (
          <div key={name} className="border border-gray-800 rounded p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-sm font-mono text-cyan-400">{name}</span>
              <span className="text-xs text-gray-600">{Object.keys(tbl).length} entries</span>
              <div className="flex-1" />
              <button onClick={() => addRow(name)} className="text-gray-400 hover:text-cyan-400 text-xs cursor-pointer">+ Entry</button>
              <button onClick={() => removeEnum(name)} className="text-gray-500 hover:text-red-400 text-xs cursor-pointer">Remove</button>
            </div>
            <div className="space-y-1">
              {Object.entries(tbl).map(([k, v]) => (
                <div key={k} className="grid grid-cols-12 gap-2 items-center">
                  <input
                    value={k}
                    onBlur={(e) => renameKey(name, k, e.target.value)}
                    onChange={() => {}}
                    defaultValue={k}
                    className="col-span-3 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                  <input
                    value={v}
                    onChange={(e) => setRow(name, k, e.target.value)}
                    className="col-span-8 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-cyan-500"
                  />
                  <button onClick={() => removeRow(name, k)} className="col-span-1 text-gray-500 hover:text-red-400 text-xs cursor-pointer">✕</button>
                </div>
              ))}
              {Object.keys(tbl).length === 0 && (
                <p className="text-xs text-gray-600 italic">No entries yet — click <em>+ Entry</em>.</p>
              )}
            </div>
          </div>
        )
      })}
      <button
        onClick={addEnum}
        className="w-full bg-gray-800/60 hover:bg-gray-800 border border-dashed border-gray-700 rounded px-3 py-2 text-sm text-gray-400 cursor-pointer"
      >
        + Add enum
      </button>
    </div>
  )
}

// ImportPanel lets the user paste challenge-client Python and turns the
// struct.pack/Enum definitions into enums + structs, merged into the editor
// via onImport. It never persists anything itself — the user reviews the
// result in the tabs below and saves through the normal flow.
function ImportPanel({ onImport }) {
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [warnings, setWarnings] = useState([])
  const [summary, setSummary] = useState('')

  async function parse() {
    setError(''); setWarnings([]); setSummary('')
    if (!code.trim()) { setError('Paste some Python first.'); return }
    setBusy(true)
    try {
      const { protocol, warnings } = await api.importProtocol(code)
      onImport(protocol)
      const nEnums = Object.keys(protocol.enums || {}).length
      const nStructs = Object.keys(protocol.structs || {}).length
      const nFields = Object.values(protocol.structs || {}).reduce((a, fl) => a + fl.length, 0)
      const nReq = (protocol.request_fields || []).length
      const wired = nReq ? ` Request auto-wired (${nReq} field${nReq === 1 ? '' : 's'}).` : ''
      setSummary(`Imported ${nEnums} enum${nEnums === 1 ? '' : 's'}, ${nStructs} struct${nStructs === 1 ? '' : 's'} (${nFields} field${nFields === 1 ? '' : 's'}).${wired} Check “Finish manually” below for anything left, then save.`)
      setWarnings(warnings || [])
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-gray-800/40 border border-gray-800 rounded-lg p-3 mb-4">
      <p className="text-xs text-gray-500 mb-2">
        Paste the challenge client's protocol code — a whole class, a single
        {' '}<code className="text-gray-400">Enum</code>, or one packing method is fine (decorators optional).
        Janus builds the enums and structs, maps custom packing logic (bit-packed grids →
        {' '}<code className="text-gray-400">bytes_computed</code>), links <code className="text-gray-400">.value</code> fields to their enum,
        and auto-wires the Request layout when the client prepends a header. Review the tabs and save.
      </p>
      <textarea
        value={code}
        onChange={(e) => setCode(e.target.value)}
        spellCheck={false}
        placeholder={"class ReqType(Enum):\n    SIGNUP = 0\n    LOGIN = 1\n\nclass ReqHdr():\n    @property\n    def bytes(self):\n        return struct.pack('<IBH', self.ts, self.type, self.len)"}
        className="w-full h-48 bg-gray-900 border border-gray-700 rounded px-2 py-2 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500 resize-y"
      />
      <div className="flex items-center gap-2 mt-2">
        <button
          onClick={parse}
          disabled={busy}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded cursor-pointer"
        >
          {busy ? 'Parsing…' : 'Parse & import'}
        </button>
        <button
          onClick={() => { setCode(''); setError(''); setWarnings([]); setSummary('') }}
          className="text-gray-500 hover:text-gray-300 text-xs px-2 py-1.5 cursor-pointer"
        >
          Clear
        </button>
      </div>
      {error && <div className="mt-2 text-xs text-red-400">{error}</div>}
      {summary && <div className="mt-2 text-xs text-green-400">{summary}</div>}
      {warnings.length > 0 && (
        <div className="mt-2">
          <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-1">Parser notes</div>
          <ul className="space-y-0.5">
            {warnings.map((w, i) => (
              <li key={i} className="text-[11px] text-amber-400/90">⚠ {w}</li>
            ))}
          </ul>
          <p className="text-[11px] text-gray-500 mt-1">
            The structural steps (dispatch structs, replies) are also listed under
            {' '}<span className="text-gray-400">“Finish manually”</span> below, which updates as you fix them.
          </p>
        </div>
      )}
    </div>
  )
}

// computeFollowUps inspects the working copy and returns the concrete,
// located steps a human still has to do — the parts the Python importer
// deliberately can't infer. It's recomputed live, so a step vanishes as soon
// as its cause is resolved (e.g. once a dispatch-target struct is created).
function computeFollowUps(form) {
  const steps = []
  const structs = form.structs || {}
  const enums = form.enums || {}
  const structNames = new Set(Object.keys(structs))

  const scopes = [
    ['Request', form.request_fields || [], 'request'],
    ['Response', form.response_fields || [], 'response'],
    ...Object.entries(structs).map(([n, fl]) => [`Struct “${n}”`, fl, 'structs']),
  ]

  for (const [scopeName, fields, tab] of scopes) {
    for (const f of fields) {
      if (f.type !== 'dispatch' || !f.dispatch_on) continue
      const src = fields.find((s) => s.name === f.dispatch_on)
      if (!src) continue
      if (!src.enum_ref) {
        steps.push({
          tab,
          title: `${scopeName}: “${f.dispatch_on}” isn't linked to an enum`,
          detail: `The “${f.name}” dispatch decides the body from “${f.dispatch_on}”, but that field has no enum, so it can only match structs named after raw numbers. Pick an enum for “${f.dispatch_on}” from its dropdown — with several enums imported, Janus can't guess which applies.`,
        })
        continue
      }
      const table = enums[src.enum_ref]
      if (!table) continue
      const missing = [...new Set(Object.values(table))].filter((l) => !structNames.has(l))
      if (missing.length) {
        steps.push({
          tab: 'structs',
          title: `Create body structs for the “${f.name}” dispatch (${src.enum_ref})`,
          detail: `Add a struct named after each ${src.enum_ref} value so bodies decode: ${missing.join(', ')}. Each holds that message's body fields. Which body goes with which value lives in the client's send/recv helpers — not in the packing code — so it can't be filled in automatically. Until then those messages show as raw bytes tagged with the label.`,
        })
      }
    }
  }

  const hasContent = (form.request_fields?.length || Object.keys(structs).length)
  if (hasContent && !(form.response_fields?.length)) {
    steps.push({
      tab: 'response',
      title: 'The Response layout is empty',
      detail: `Server replies aren't imported from Python: they're decoded with helper reads and conditionals that can't be reconstructed mechanically. Build them in the Response tab (often a status byte + a dispatch), or reuse a struct with its “→ response” button.`,
    })
  }

  return steps
}

// FollowUps renders computeFollowUps() as a compact, actionable callout with a
// jump-to-tab link per step. Hidden entirely when nothing is left to do, so a
// fully-wired protocol shows a clean editor.
function FollowUps({ steps, onGoto }) {
  if (!steps || steps.length === 0) return null
  return (
    <div className="mb-4 bg-amber-500/5 border border-amber-500/30 rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-amber-300 text-sm">⚙ Finish manually</span>
        <span className="text-[11px] text-gray-500">
          {steps.length} step{steps.length === 1 ? '' : 's'} the Python import can't infer
        </span>
      </div>
      <ul className="space-y-2">
        {steps.map((s, i) => (
          <li key={i} className="text-xs">
            <div className="flex items-baseline gap-2">
              <span className="text-amber-200 font-medium">{s.title}</span>
              {s.tab && (
                <button
                  type="button"
                  onClick={() => onGoto(s.tab)}
                  className="text-[11px] text-cyan-400 hover:underline cursor-pointer whitespace-nowrap"
                >
                  open {s.tab} →
                </button>
              )}
            </div>
            <p className="text-gray-400 mt-0.5">{s.detail}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}

function Label({ children }) {
  return <label className="block text-xs text-gray-500 mb-1">{children}</label>
}

function deepClone(o) { return JSON.parse(JSON.stringify(o)) }

function stripInternal(o) {
  // Drop any editor-only keys (everything prefixed with "_") before sending
  // to the backend.
  const c = {}
  for (const k of Object.keys(o)) {
    if (!k.startsWith('_')) c[k] = o[k]
  }
  return c
}
