import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import {
  FIELD_GROUPS,
  fieldType,
  opsForType,
  emptyTree,
  emptyPredicate,
  emptyGroup,
  serialize,
  parse,
  listPresets,
  savePreset,
  deletePreset,
	configureFieldSchema,
} from '../utils/filterAst'

// FilterExpression — unified filter/rule expression editor.
//
// Modes:
//   - "builder"   visual, structured editing (default)
//   - "text"      raw textarea for power users
// AST is canonical: builder owns a tree, text editing parses back into a tree
// when switching modes (or shows a banner if the input is too exotic).
//
// Props:
//   value          current expression string (controlled)
//   onChange(str)  fired with serialized expression on edits
//   placeholder    optional placeholder text
//   compact        smaller spacing for tight panels
export default function FilterExpression({ value = '', onChange, placeholder, compact = false, schema = null }) {
  const [mode, setMode] = useState('builder')
  const [tree, setTree] = useState(() => {
    const r = parse(value)
    return r.ok ? r.tree : emptyTree()
  })
  const [text, setText] = useState(value)
  const [parseFail, setParseFail] = useState('') // shown when text->builder fails
  const [validation, setValidation] = useState({ status: 'idle' })
  const [presets, setPresets] = useState(listPresets())
  const [showSave, setShowSave] = useState(false)
  const [presetName, setPresetName] = useState('')

  const lastEmittedRef = useRef(value)
	const fieldGroups = useMemo(() => {
		configureFieldSchema(schema)
		return mergeFieldSchema(schema)
	}, [schema])

  // Sync incoming `value` prop (e.g. preset application from outside).
  // The ref guard makes this idempotent across re-renders.
  useEffect(() => {
    if (value === lastEmittedRef.current) return
    const r = parse(value)
    if (r.ok) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- prop sync, gated by ref equality
      setTree(r.tree)
      setText(value)
      setMode('builder')
      setParseFail('')
    } else {
      setText(value)
      setMode('text')
    }
    lastEmittedRef.current = value
  }, [value])

  function emit(next) {
    lastEmittedRef.current = next
    onChange?.(next)
  }

  function setBuilderTree(next) {
    setTree(next)
    const s = serialize(next)
    setText(s)
    emit(s)
  }

  function commitTextChange(t) {
    setText(t)
    emit(t)
  }

  function switchMode(next) {
    if (next === mode) return
    if (next === 'builder') {
      const r = parse(text)
      if (r.ok) {
        setTree(r.tree)
        setParseFail('')
        setMode('builder')
      } else {
        setParseFail(r.error || 'Expression too complex for the builder')
        // Stay in text but warn.
      }
      return
    }
    // builder -> text: serialize current tree.
    setText(serialize(tree))
    setMode('text')
  }

  // Live syntax validation against the backend (debounced).
  useEffect(() => {
    if (!text.trim()) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- reset to idle on empty
      setValidation({ status: 'idle' })
      return
    }
    setValidation(v => ({ ...v, status: 'pending' }))
    const handle = setTimeout(async () => {
      try {
        const res = await api.validateFilter(text)
        if (res.ok) setValidation({ status: 'ok' })
        else setValidation({ status: 'error', error: res.error, position: res.position })
      } catch (err) {
        setValidation({ status: 'error', error: err.message })
      }
    }, 300)
    return () => clearTimeout(handle)
  }, [text])

  const errorBadge = useMemo(() => {
    if (validation.status === 'pending') return <span className="text-[10px] text-gray-500">checking…</span>
    if (validation.status === 'ok') return <span className="text-[10px] text-emerald-400">✓ valid</span>
    if (validation.status === 'error') return <span className="text-[10px] text-red-400" title={`pos ${validation.position}`}>✗ {validation.error}</span>
    return null
  }, [validation])

  function applyPreset(p) {
    const r = parse(p.expression)
    if (r.ok) {
      setTree(r.tree)
      setText(p.expression)
      emit(p.expression)
      setMode('builder')
      setParseFail('')
    } else {
      setText(p.expression)
      emit(p.expression)
      setMode('text')
    }
  }

  function handleSavePreset() {
    const name = presetName.trim()
    if (!name) return
    setPresets(savePreset(name, text))
    setShowSave(false)
    setPresetName('')
  }

  return (
    <div className={`bg-gray-900 border border-gray-800 rounded ${compact ? 'p-2' : 'p-3'} space-y-2`}>
      {/* header bar: mode tabs + validation + presets + save */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center bg-gray-800 rounded text-xs">
          <button
            onClick={() => switchMode('builder')}
            className={`px-2 py-1 rounded-l cursor-pointer ${mode === 'builder' ? 'bg-cyan-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}>
            Builder
          </button>
          <button
            onClick={() => switchMode('text')}
            className={`px-2 py-1 rounded-r cursor-pointer ${mode === 'text' ? 'bg-cyan-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}>
            Expression
          </button>
        </div>
        <div className="flex-1 min-w-[120px]">{errorBadge}</div>
        {presets.length > 0 && (
          <select
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 cursor-pointer focus:outline-none focus:border-cyan-500"
            onChange={e => {
              const p = presets.find(x => x.name === e.target.value)
              if (p) applyPreset(p)
              e.target.value = ''
            }}
            defaultValue=""
            title="Apply saved preset"
          >
            <option value="" disabled>presets…</option>
            {presets.map(p => <option key={p.name} value={p.name}>{p.name}</option>)}
          </select>
        )}
        <button
          onClick={() => setShowSave(true)}
          className="text-xs px-2 py-1 rounded bg-gray-800 text-gray-300 hover:text-gray-100 cursor-pointer"
          title="Save current expression as a preset"
          disabled={!text.trim()}
        >
          Save…
        </button>
        <button
          onClick={() => {
            const t = emptyTree()
            setTree(t)
            setText('')
            emit('')
            setParseFail('')
          }}
          className="text-xs px-2 py-1 rounded bg-gray-800 text-gray-400 hover:text-red-400 cursor-pointer"
          title="Clear"
        >
          Clear
        </button>
      </div>

      {parseFail && (
        <div className="text-xs text-amber-400 bg-amber-900/20 border border-amber-800/40 rounded px-2 py-1">
          Couldn't switch to builder: {parseFail}. Stayed in expression mode — keep editing as text or simplify the expression.
        </div>
      )}

      {showSave && (
        <div className="flex items-center gap-2 text-xs">
          <input
            value={presetName}
            onChange={e => setPresetName(e.target.value)}
            placeholder="Preset name"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-100 focus:outline-none focus:border-cyan-500"
            autoFocus
          />
          <button onClick={handleSavePreset} className="px-2 py-1 rounded bg-cyan-700 hover:bg-cyan-600 text-white cursor-pointer">Save</button>
          <button onClick={() => { setShowSave(false); setPresetName('') }} className="px-2 py-1 rounded bg-gray-800 text-gray-400 hover:text-gray-200 cursor-pointer">Cancel</button>
          {presets.map(p => (
            <button key={p.name} onClick={() => { setPresets(deletePreset(p.name)) }} className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-500 hover:text-red-400 cursor-pointer" title={`Delete preset "${p.name}"`}>
              ×{p.name}
            </button>
          ))}
        </div>
      )}

      {mode === 'builder' ? (
        <GroupNode node={tree} onChange={setBuilderTree} isRoot fieldGroups={fieldGroups} />
      ) : (
        <TextEditor
          text={text}
          onChange={commitTextChange}
          placeholder={placeholder}
          errorPos={validation.status === 'error' ? validation.position : null}
        />
      )}

      <div className="text-[10px] text-gray-600 font-mono break-all">
        {text || <span className="italic text-gray-700">(empty — matches all)</span>}
      </div>
    </div>
  )
}

// ----- Group node renderer -----

function GroupNode({ node, onChange, isRoot = false, depth = 0, fieldGroups = FIELD_GROUPS }) {
  function update(patch) { onChange({ ...node, ...patch }) }
  function updateChild(idx, child) {
    const next = node.children.slice()
    next[idx] = child
    update({ children: next })
  }
  function deleteChild(idx) {
    const next = node.children.slice()
    next.splice(idx, 1)
    if (next.length === 0) next.push(emptyPredicate())
    update({ children: next })
  }
  function addPredicate() {
    update({ children: [...node.children, emptyPredicate()] })
  }
  function addGroup() {
    update({ children: [...node.children, emptyGroup(node.joiner === 'AND' ? 'OR' : 'AND')] })
  }

  const palette = depth % 2 === 0
    ? 'border-gray-700 bg-gray-900/40'
    : 'border-gray-700 bg-gray-800/40'

  return (
    <div className={`rounded border ${palette} ${isRoot ? 'p-1.5' : 'p-1.5 ml-2'} space-y-1`}>
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-wide">
        <button
          onClick={() => update({ joiner: node.joiner === 'AND' ? 'OR' : 'AND' })}
          className={`px-2 py-0.5 rounded font-bold cursor-pointer ${node.joiner === 'AND' ? 'bg-cyan-900/60 text-cyan-300' : 'bg-purple-900/60 text-purple-300'}`}
          title="Toggle group joiner"
        >
          {node.joiner}
        </button>
        {!isRoot && (
          <button
            onClick={() => update({ not: !node.not })}
            className={`px-1.5 py-0.5 rounded cursor-pointer ${node.not ? 'bg-red-900/60 text-red-300' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}
            title="Negate group"
          >
            NOT
          </button>
        )}
        <span className="text-gray-600">{node.children.length} item{node.children.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="space-y-1">
        {node.children.map((child, idx) => (
          <div key={idx} className="flex items-start gap-1">
            <div className="flex-1">
              {child.kind === 'predicate' ? (
                <PredicateRow
                  node={child}
                  onChange={(c) => updateChild(idx, c)}
				  fieldGroups={fieldGroups}
                />
              ) : (
                <GroupNode node={child} onChange={(c) => updateChild(idx, c)} depth={depth + 1} fieldGroups={fieldGroups} />
              )}
            </div>
            <button
              onClick={() => deleteChild(idx)}
              className="text-gray-600 hover:text-red-400 px-1 cursor-pointer"
              title="Remove"
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-1 pt-1">
        <button
          onClick={addPredicate}
          className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-cyan-300 cursor-pointer"
        >
          + condition
        </button>
        <button
          onClick={addGroup}
          className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-cyan-300 cursor-pointer"
        >
          + group
        </button>
      </div>
    </div>
  )
}

// ----- Predicate row renderer -----

function PredicateRow({ node, onChange, fieldGroups }) {
	const meta = fieldGroups.flatMap((group) => group.fields).find((field) => field.name === node.field)
	const baseType = normalizeSchemaType(meta?.type || fieldType(node.field))
	const t = node.length ? 'int' : baseType
	const ops = useMemo(() => node.length
		? opsForType('int')
		: (meta?.operators?.length ? meta.operators : opsForType(baseType)), [node.length, meta, baseType])
  const isHeader = node.field === 'header'

  function update(patch) {
    const next = { ...node, ...patch }
    // If the field type changed and the current op isn't valid, reset to first valid op.
    if (patch.field !== undefined || patch.length !== undefined) {
	  const nextMeta = fieldGroups.flatMap((group) => group.fields).find((field) => field.name === next.field)
	  const nextBaseType = normalizeSchemaType(nextMeta?.type || fieldType(next.field))
	  const nextType = next.length ? 'int' : nextBaseType
	  const newOps = next.length ? opsForType('int') : (nextMeta?.operators?.length ? nextMeta.operators : opsForType(nextType))
      if (!newOps.includes(next.op)) next.op = newOps[0]
	  if (nextType === 'bool' && (next.value === '' || next.value === undefined)) {
        next.value = true
      }
	  if (nextBaseType !== 'header') next.headerName = ''
    }
    onChange(next)
  }

  return (
    <div className="flex flex-wrap items-center gap-1 bg-gray-800/40 border border-gray-700 rounded px-1.5 py-1">
      <button
        onClick={() => update({ not: !node.not })}
        className={`px-1.5 py-0.5 rounded text-[10px] uppercase cursor-pointer ${node.not ? 'bg-red-900/60 text-red-300' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}
        title="Negate this condition"
      >
        NOT
      </button>

      <select
        value={node.field}
        onChange={e => update({ field: e.target.value })}
        className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100 cursor-pointer focus:outline-none focus:border-cyan-500"
      >
		{fieldGroups.map(g => (
          <optgroup key={g.label} label={g.label}>
            {g.fields.map(f => <option key={f.name} value={f.name} title={f.desc}>{f.name}</option>)}
          </optgroup>
        ))}
      </select>

      {isHeader && (
        <>
          <span className="text-gray-600 text-xs">.</span>
          <input
            value={node.headerName}
            onChange={e => update({ headerName: e.target.value })}
            placeholder="Name (optional)"
            className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100 w-32 focus:outline-none focus:border-cyan-500"
          />
        </>
      )}

      <select
        value={node.op}
        onChange={e => update({ op: e.target.value })}
        className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100 cursor-pointer focus:outline-none focus:border-cyan-500 font-mono"
      >
        {ops.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
	  {(baseType === 'string' || baseType === 'header') && (
		<button type="button" onClick={() => update({ length: !node.length })} className={`px-1.5 py-0.5 rounded text-[10px] cursor-pointer ${node.length ? 'bg-teal-900/60 text-teal-300' : 'bg-gray-800 text-gray-500'}`} title="Compare byte length">len</button>
	  )}

	  {(node.op === 'exists' || node.op === 'missing') ? null : t === 'bool' ? (
        <select
          value={(node.value === true || node.value === 'true') ? 'true' : 'false'}
          onChange={e => update({ value: e.target.value === 'true' })}
          className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100 cursor-pointer focus:outline-none focus:border-cyan-500"
        >
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      ) : (
        <input
          value={node.value ?? ''}
          onChange={e => update({ value: e.target.value })}
          placeholder={node.op === 'in' ? 'a, b, c' : 'value…'}
          className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-100 font-mono flex-1 min-w-[80px] focus:outline-none focus:border-cyan-500"
          spellCheck={false}
        />
      )}
    </div>
  )
}

function normalizeSchemaType(type) {
	if (type === 'headers') return 'header'
	if (type === 'bytes') return 'string'
	return type || 'string'
}

function mergeFieldSchema(schema) {
	if (!schema?.fields?.length) return FIELD_GROUPS
	const backend = new Map(schema.fields.map((field) => [field.name, field]))
	const known = new Set()
	const groups = FIELD_GROUPS.map((group) => ({
		...group,
		fields: group.fields.map((field) => {
			known.add(field.name)
			const live = backend.get(field.name)
			return live ? { ...field, type: normalizeSchemaType(live.type), operators: live.operators || [] } : field
		}),
	}))
	const extra = schema.fields
		.filter((field) => !known.has(field.name))
		.map((field) => ({ name: field.name, type: normalizeSchemaType(field.type), operators: field.operators || [], desc: 'Backend field' }))
	if (extra.length) groups.push({ label: 'Other', fields: extra })
	return groups
}

// ----- Text editor -----

function TextEditor({ text, onChange, placeholder, errorPos }) {
  const ref = useRef(null)
  return (
    <div className="relative">
      <textarea
        ref={ref}
        value={text}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder || 'e.g. body contains "pippo" AND NOT header.User-Agent contains "bot"'}
        rows={3}
        className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-100 focus:outline-none focus:border-cyan-500 resize-y"
        spellCheck={false}
      />
      {errorPos != null && text && (
        <div className="text-[10px] text-red-400 mt-0.5 font-mono">
          ↑ syntax error at byte {errorPos}
        </div>
      )}
    </div>
  )
}
