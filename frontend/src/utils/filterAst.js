// filterAst.js — JS-side parser, serializer, and evaluator for the unified
// Janus filter expression language. Mirrors backend/internal/filter.
//
// The visual builder edits a tree of groups/predicates. We round-trip via:
//   tree  -> serialize()    -> expression string  (sent to backend)
//   text  -> parse(text)    -> tree               (when switching modes)
//   tree  -> evaluate(tree) -> bool               (client-side SSE filter)
//
// The grammar is a strict subset of the backend grammar — we only support the
// shapes the visual builder can produce, so a successful parse always implies
// the result is buildable. Anything more exotic falls back to text mode.

// ----- Field metadata -----

export const FIELD_GROUPS = [
  {
    label: 'Content',
    fields: [
      { name: 'body', type: 'string', desc: 'Decoded body text' },
      { name: 'raw',  type: 'string', desc: 'Raw bytes (use \\xHH escapes)' },
    ],
  },
  {
    label: 'HTTP',
    fields: [
      { name: 'id',        type: 'int',    desc: 'Packet number (the # column)' },
      { name: 'url',       type: 'string', desc: 'Request URL/path' },
	  { name: 'path',      type: 'string', desc: 'URL path without query string' },
      { name: 'method',    type: 'string', desc: 'HTTP method' },
      { name: 'status',    type: 'int',    desc: 'HTTP status code' },
      { name: 'round',     type: 'int',    desc: 'Scoreboard round' },
      { name: 'direction', type: 'string', desc: 'request | response' },
      { name: 'header',    type: 'header', desc: 'Header value (with optional sub-name)' },
    ],
  },
  {
	label: 'Decoded',
	fields: [
	  { name: 'dns.qname', type: 'string', desc: 'DNS question name' },
	  { name: 'dns.qtype', type: 'string', desc: 'DNS question type' },
	  { name: 'resp.command', type: 'string', desc: 'Redis command' },
	  { name: 'mqtt.topic', type: 'string', desc: 'MQTT topic' },
	],
  },
  {
    label: 'Network',
    fields: [
      { name: 'service', type: 'string', desc: 'Service ID' },
      { name: 'proto',   type: 'string', desc: 'http | https | ws | wss | h2 | grpc | tcp' },
      { name: 'src',     type: 'string', desc: 'Source IP (CIDR ok)' },
      { name: 'dst',     type: 'string', desc: 'Destination IP (CIDR ok)' },
      { name: 'peer',    type: 'string', desc: 'Direction-aware peer IP' },
      { name: 'sport',   type: 'int',    desc: 'Source port' },
      { name: 'dport',   type: 'int',    desc: 'Destination port' },
    ],
  },
  {
    label: 'Flags',
    fields: [
      { name: 'flagged',         type: 'bool', desc: 'Packet contains a flag' },
      { name: 'contains_flagid', type: 'bool', desc: 'Packet contains one of our flag IDs' },
      { name: 'dropped',         type: 'bool', desc: 'Packet was dropped by a rule' },
    ],
  },
	{
		label: 'Janus score',
		fields: [
			{ name: 'classification', type: 'string', desc: 'likely_exploit | likely_checker | review | insufficient_data' },
			{ name: 'analyst_label', type: 'string', desc: 'Manual annotation: exploit | checker | normal' },
			{ name: 'attack_score', type: 'int', desc: 'Deterministic exploit evidence (0-100)' },
			{ name: 'normal_score', type: 'int', desc: 'Opening-baseline evidence (0-100)' },
			{ name: 'score_confidence', type: 'int', desc: 'Confidence adjusted by available evidence (0-100)' },
			{ name: 'score_coverage', type: 'int', desc: 'How much evidence was available (0-100)' },
		],
	},
]

const FIELD_INDEX = (() => {
  const m = {}
  for (const g of FIELD_GROUPS) for (const f of g.fields) m[f.name] = f
  return m
})()

export function fieldType(name) { return FIELD_INDEX[name]?.type || 'string' }

export function configureFieldSchema(schema) {
	for (const field of schema?.fields || []) {
		const type = field.type === 'headers' ? 'header' : field.type === 'bytes' ? 'string' : field.type
		FIELD_INDEX[field.name] = { ...(FIELD_INDEX[field.name] || {}), ...field, type }
	}
}

export function opsForType(t) {
  switch (t) {
    case 'string':
    case 'header':
	  return ['contains', 'icontains', '==', '!=', 'matches', 'startswith', 'endswith', 'in', 'exists', 'missing']
    case 'int':
      return ['==', '!=', '>', '<', '>=', '<=', 'in']
    case 'bool':
      return ['==', '!=']
  }
  return ['==']
}

// ----- Tree factory helpers -----

export function emptyTree() {
  return {
    kind: 'group',
    joiner: 'AND',
    not: false,
    children: [emptyPredicate()],
  }
}

export function emptyPredicate() {
  return {
    kind: 'predicate',
    not: false,
    field: 'body',
    headerName: '',
    op: 'contains',
    value: '',
	length: false,
  }
}

export function emptyGroup(joiner = 'AND') {
  return { kind: 'group', joiner, not: false, children: [emptyPredicate()] }
}

// ----- Serialize tree -> expression string -----

export function serialize(node, isRoot = true) {
  if (!node) return ''
  if (node.kind === 'predicate') {
    let s = formatPredicate(node)
    if (!s) return ''
    return node.not ? `NOT ${s}` : s
  }
  // group
  const parts = node.children.map(c => serialize(c, false)).filter(Boolean)
  if (parts.length === 0) return ''
  if (parts.length === 1) {
    const inner = parts[0]
    return node.not ? `NOT (${inner})` : inner
  }
  const joined = parts.join(` ${node.joiner} `)
  if (node.not) return `NOT (${joined})`
  return isRoot ? joined : `(${joined})`
}

function formatPredicate(p) {
	let fld = (p.field === 'header' && p.headerName) ? `header.${p.headerName}` : p.field
	if (p.length) fld += '.length'
	const t = p.length ? 'int' : fieldType(p.field)
	if (p.op === 'exists' || p.op === 'missing') return `${fld} ${p.op}`

  // Bool shortcut: write `flagged` or `NOT flagged` instead of `flagged == true`.
  if (t === 'bool' && p.op === '==') {
    if (p.value === true || p.value === 'true') return fld
    if (p.value === false || p.value === 'false') return `NOT ${fld}`
  }

  if (p.op === 'in') {
    const items = String(p.value || '')
      .split(',').map(s => s.trim()).filter(Boolean)
    if (items.length === 0) return ''
    const rendered = items.map(it => renderListItem(it, t)).join(', ')
    return `${fld} in (${rendered})`
  }

  // Numeric ops — bare value.
  if (t === 'int' && p.op !== 'in') {
    if (p.value === '' || p.value === null || p.value === undefined) return ''
    return `${fld} ${p.op} ${p.value}`
  }
  if (t === 'bool' && (p.op === '==' || p.op === '!=')) {
    return `${fld} ${p.op} ${p.value === true || p.value === 'true' ? 'true' : 'false'}`
  }
  if (p.value === '' || p.value === null || p.value === undefined) return ''
  return `${fld} ${p.op} ${quoteString(p.value)}`
}

function renderListItem(item, t) {
  if (t === 'int') return item
  // IPs / CIDRs: emit as bareword (no quotes) — backend accepts both.
  if (/^[0-9.]+(\/\d{1,2})?$/.test(item)) return item
  return quoteString(item)
}

function quoteString(v) {
  let s = String(v)
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    const cc = s.charCodeAt(i)
    if (c === '\\') out += '\\\\'
    else if (c === '"') out += '\\"'
    else if (c === '\n') out += '\\n'
    else if (c === '\r') out += '\\r'
    else if (c === '\t') out += '\\t'
    else if (cc < 0x20 || cc === 0x7F) out += '\\x' + cc.toString(16).padStart(2, '0').toUpperCase()
    else out += c
  }
  return out + '"'
}

// ----- Parser (text -> tree) -----
//
// We accept any expression the visual builder can produce. Inputs outside
// that subset (deeply-mixed AND/OR at the same level, or unknown fields)
// return { ok: false }. Callers fall back to keeping the user in text mode.

export function parse(src) {
  const trimmed = (src || '').trim()
  if (trimmed === '') return { ok: true, tree: emptyTree() }

  let p
  try {
    p = new Parser(trimmed)
    const tree = p.parseRoot()
    return { ok: true, tree }
  } catch (e) {
    return { ok: false, error: e.message || String(e), position: e.position ?? 0 }
  }
}

class ParseError extends Error {
  constructor(msg, position) { super(msg); this.position = position }
}

class Parser {
  constructor(src) {
    this.toks = tokenize(src)
    this.i = 0
  }
  peek(k = 0) { return this.toks[this.i + k] }
  next() { return this.toks[this.i++] }
  eat(kind, val) {
    const t = this.peek()
    if (t.kind === kind && (val == null || t.val === val)) { this.next(); return true }
    return false
  }
  expect(kind, val) {
    const t = this.peek()
    if (t.kind === kind && (val == null || t.val === val)) return this.next()
    throw new ParseError(`expected ${val || kind}, got "${t.val}"`, t.pos)
  }

  parseRoot() {
    const node = this.parseOr()
    if (this.peek().kind !== 'EOF') {
      const t = this.peek()
      throw new ParseError(`unexpected token "${t.val}"`, t.pos)
    }
    // Ensure root is always a group node so the builder can edit it uniformly.
    if (node.kind === 'predicate') return { kind: 'group', joiner: 'AND', not: false, children: [node] }
    return node
  }

  parseOr() {
    const first = this.parseAnd()
    if (this.peek().kind !== 'OR') return first
    const children = [first]
    while (this.peek().kind === 'OR') {
      this.next()
      children.push(this.parseAnd())
    }
    return { kind: 'group', joiner: 'OR', not: false, children: children.map(unwrapAndIfSolo) }
  }

  parseAnd() {
    const first = this.parseNot()
    if (this.peek().kind !== 'AND') return first
    const children = [first]
    while (this.peek().kind === 'AND') {
      this.next()
      children.push(this.parseNot())
    }
    return { kind: 'group', joiner: 'AND', not: false, children }
  }

  parseNot() {
    if (this.peek().kind === 'NOT') {
      this.next()
      const inner = this.parseNot()
      // Predicate gets its `.not` bumped; group gets a wrapping NOT-flag.
      if (inner.kind === 'predicate') {
        inner.not = !inner.not
        return inner
      }
      inner.not = !inner.not
      return inner
    }
    return this.parseAtom()
  }

  parseAtom() {
    const t = this.peek()
    if (t.kind === 'LP') {
      this.next()
      const inner = this.parseOr()
      this.expect('RP')
      return inner
    }
    if (t.kind === 'BOOL') {
	  // Keep constants in text/server mode. Mapping `true` to `flagged` changed
	  // its meaning and made streamed rows disagree with the REST query.
	  throw new ParseError('standalone boolean expressions require text mode', t.pos)
    }
    if (t.kind === 'IDENT') {
      return this.parsePredicate()
    }
    throw new ParseError(`unexpected "${t.val}"`, t.pos)
  }

  parsePredicate() {
    const fieldTok = this.next()
    let field = fieldTok.val.toLowerCase()
    let headerName = ''
	let length = false
    if (this.peek().kind === 'DOT') {
	  const parts = [field]
	  while (this.peek().kind === 'DOT') {
		this.next()
		const nm = (this.peek().kind === 'IDENT' || this.peek().kind === 'KWOP') ? this.next() : this.expect('IDENT')
		if (['length', 'len', 'size'].includes(nm.val.toLowerCase()) && this.peek().kind !== 'DOT') { length = true; break }
		parts.push(nm.val.toLowerCase())
	  }
	  if ((parts[0] === 'header' || parts[0] === 'headers') && parts.length === 2) { field = 'header'; headerName = parts[1] }
	  else field = parts.join('.')
    }
    field = canonicalField(field)

    // Validate field exists — bail if not (so caller reverts to text mode).
	if (!FIELD_INDEX[field] && !/^(decoded|json|query|form|cookie|dns|resp|mqtt)\./.test(field)) {
      throw new ParseError(`unknown field "${field}"`, fieldTok.pos)
    }

    // Bare bool predicate (`flagged`)
    const upcoming = this.peek()
    if (upcoming.kind === 'AND' || upcoming.kind === 'OR' || upcoming.kind === 'RP' || upcoming.kind === 'EOF') {
	  if (length || fieldType(field) !== 'bool') {
		throw new ParseError(`expected operator after "${field}"`, upcoming.pos)
	  }
      return { kind: 'predicate', not: false, field, headerName, op: '==', value: true }
    }

    // op
    const opTok = this.peek()
    let op
    if (opTok.kind === 'OP') {
      this.next()
      op = opTok.val
    } else if (opTok.kind === 'KWOP') {
      this.next()
      op = opTok.val
    } else {
      throw new ParseError(`expected operator after "${field}"`, opTok.pos)
    }
	if (op === 'exists' || op === 'missing') return { kind: 'predicate', not: false, field, headerName, length, op, value: '' }

    // value
    let value
    if (op === 'in') {
      this.expect('LP')
      const items = []
      while (this.peek().kind !== 'RP') {
        const itemTok = this.next()
        if (itemTok.kind !== 'STRING' && itemTok.kind !== 'NUMBER' && itemTok.kind !== 'IDENT' && itemTok.kind !== 'BOOL') {
          throw new ParseError(`expected list item, got "${itemTok.val}"`, itemTok.pos)
        }
        items.push(itemTok.val)
        if (this.peek().kind === 'COMMA') this.next()
      }
      this.expect('RP')
      value = items.join(', ')
    } else {
      const vTok = this.next()
      if (vTok.kind !== 'STRING' && vTok.kind !== 'NUMBER' && vTok.kind !== 'IDENT' && vTok.kind !== 'BOOL') {
        throw new ParseError(`expected value, got "${vTok.val}"`, vTok.pos)
      }
      value = vTok.kind === 'BOOL' ? (vTok.val === 'true') : vTok.val
    }

	return { kind: 'predicate', not: false, field, headerName, length, op, value }
  }
}

function unwrapAndIfSolo(node) {
  if (node.kind === 'group' && node.joiner === 'AND' && !node.not && node.children.length === 1) {
    return node.children[0]
  }
  return node
}

function canonicalField(name) {
  switch (name) {
    case 'packet_id': case 'pkt': case 'num': case 'no': return 'id'
    case 'headers': return 'header'
    case 'src_ip': return 'src'
    case 'dst_ip': return 'dst'
    case 'peer_ip': return 'peer'
    case 'src_port': return 'sport'
    case 'dst_port': return 'dport'
    case 'protocol': return 'proto'
    case 'service_id': return 'service'
  }
  return name
}

// ----- Tokenizer -----

function tokenize(src) {
  const toks = []
  let i = 0
  const n = src.length
  while (i < n) {
    const c = src[i]
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue }
    if (c === '(') { toks.push({ kind: 'LP', val: '(', pos: i }); i++; continue }
    if (c === ')') { toks.push({ kind: 'RP', val: ')', pos: i }); i++; continue }
    if (c === ',') { toks.push({ kind: 'COMMA', val: ',', pos: i }); i++; continue }
    if (c === '.') { toks.push({ kind: 'DOT', val: '.', pos: i }); i++; continue }
    if (c === '&' && src[i+1] === '&') { toks.push({ kind: 'AND', val: '&&', pos: i }); i += 2; continue }
    if (c === '|' && src[i+1] === '|') { toks.push({ kind: 'OR',  val: '||', pos: i }); i += 2; continue }
    if (c === '!' && src[i+1] !== '=') { toks.push({ kind: 'NOT', val: '!', pos: i }); i++; continue }
    if (c === '~') { toks.push({ kind: 'NOT', val: '~', pos: i }); i++; continue }
    if (c === '=' && src[i+1] === '=') { toks.push({ kind: 'OP', val: '==', pos: i }); i += 2; continue }
    if (c === '!' && src[i+1] === '=') { toks.push({ kind: 'OP', val: '!=', pos: i }); i += 2; continue }
    if (c === '<' && src[i+1] === '=') { toks.push({ kind: 'OP', val: '<=', pos: i }); i += 2; continue }
    if (c === '>' && src[i+1] === '=') { toks.push({ kind: 'OP', val: '>=', pos: i }); i += 2; continue }
    if (c === '<' || c === '>') { toks.push({ kind: 'OP', val: c, pos: i }); i++; continue }
    if (c === '"' || c === "'") {
      const start = i
      let j = i + 1
      let out = ''
      const quote = c
      while (j < n && src[j] !== quote) {
        if (src[j] === '\\' && j + 1 < n) {
          const nx = src[j+1]
          if (nx === 'n') { out += '\n'; j += 2; continue }
          if (nx === 't') { out += '\t'; j += 2; continue }
          if (nx === 'r') { out += '\r'; j += 2; continue }
          if (nx === '\\') { out += '\\'; j += 2; continue }
          if (nx === '"') { out += '"'; j += 2; continue }
          if (nx === "'") { out += "'"; j += 2; continue }
          if (nx === 'x' && j + 3 < n) {
            const hh = src.substr(j+2, 2)
            if (/^[0-9a-fA-F]{2}$/.test(hh)) {
              out += String.fromCharCode(parseInt(hh, 16))
              j += 4
              continue
            }
          }
          out += nx
          j += 2
          continue
        }
        out += src[j]
        j++
      }
      if (j >= n) throw new ParseError('unterminated string', start)
      toks.push({ kind: 'STRING', val: out, pos: start })
      i = j + 1
      continue
    }
    if (c >= '0' && c <= '9') {
      const start = i
      let j = i
      while (j < n && src[j] >= '0' && src[j] <= '9') j++
      let isIPish = false
      while (j < n && (src[j] === '.' || src[j] === '/')) {
        if (j+1 >= n || src[j+1] < '0' || src[j+1] > '9') break
        isIPish = true
        j++
        while (j < n && src[j] >= '0' && src[j] <= '9') j++
      }
      const txt = src.slice(start, j)
      toks.push({ kind: isIPish ? 'IDENT' : 'NUMBER', val: txt, pos: start })
      i = j
      continue
    }
    if (/[A-Za-z_]/.test(c)) {
      const start = i
      let j = i
      while (j < n && /[A-Za-z0-9_/-]/.test(src[j])) j++
      const word = src.slice(start, j)
      const low = word.toLowerCase()
      if (low === 'and') toks.push({ kind: 'AND', val: 'AND', pos: start })
      else if (low === 'or')  toks.push({ kind: 'OR',  val: 'OR',  pos: start })
      else if (low === 'not') toks.push({ kind: 'NOT', val: 'NOT', pos: start })
      else if (low === 'true' || low === 'false') toks.push({ kind: 'BOOL', val: low, pos: start })
      else if (KEYWORD_OPS.has(low)) toks.push({ kind: 'KWOP', val: low, pos: start })
      else toks.push({ kind: 'IDENT', val: word, pos: start })
      i = j
      continue
    }
    throw new ParseError(`unexpected character "${c}"`, i)
  }
  toks.push({ kind: 'EOF', val: '', pos: n })
  return toks
}

const KEYWORD_OPS = new Set(['contains', 'icontains', 'matches', 'startswith', 'endswith', 'in', 'exists', 'missing'])

// ----- Client-side evaluator (used by Traffic SSE filter) -----

// A view object is whatever your packet shape is. The accessor below knows
// about the conventions used in the Traffic page's packet objects.
export function evaluate(tree, packet) {
  if (!tree) return true
  return evalNode(tree, packet)
}

function evalNode(node, p) {
  if (!node) return true
  if (node.kind === 'predicate') {
    const r = evalPredicate(node, p)
    return node.not ? !r : r
  }
  let result
  if (node.children.length === 0) result = true
  else if (node.joiner === 'AND') {
    result = true
    for (const c of node.children) if (!evalNode(c, p)) { result = false; break }
  } else {
    result = false
    for (const c of node.children) if (evalNode(c, p)) { result = true; break }
  }
  return node.not ? !result : result
}

function evalPredicate(pr, p) {
  const t = pr.length ? 'int' : fieldType(pr.field)
	let get = readField(pr, p)
	if (pr.length) get = new TextEncoder().encode(String(get ?? '')).length
	if (pr.op === 'exists') return get !== '' && get != null
	if (pr.op === 'missing') return get === '' || get == null
  if (t === 'bool') {
    const want = pr.value === true || pr.value === 'true'
    return pr.op === '==' ? get === want : get !== want
  }
  if (t === 'int') {
	const got = Number(get)
    const want = parseInt(pr.value, 10)
    if (pr.op === 'in') {
      return splitList(pr.value).map(s => parseInt(s, 10)).includes(got)
    }
    if (pr.op === '==') return got === want
    if (pr.op === '!=') return got !== want
    if (pr.op === '>')  return got >  want
    if (pr.op === '<')  return got <  want
    if (pr.op === '>=') return got >= want
    if (pr.op === '<=') return got <= want
    return false
  }
  // string-shaped
  const txt = String(get ?? '')
  const v = String(pr.value ?? '')
  const isIPField = pr.field === 'src' || pr.field === 'dst' || pr.field === 'peer'

  if (pr.op === 'contains')   return txt.includes(v)
  if (pr.op === 'icontains')  return txt.toLowerCase().includes(v.toLowerCase())
  if (pr.op === '==') {
    if (isIPField && v.includes('/')) return ipv4InCIDR(txt, v)
    return txt === v
  }
  if (pr.op === '!=') {
    if (isIPField && v.includes('/')) return !ipv4InCIDR(txt, v)
    return txt !== v
  }
  if (pr.op === 'startswith') return txt.startsWith(v)
  if (pr.op === 'endswith')   return txt.endsWith(v)
  if (pr.op === 'matches')    {
    try { return new RegExp(v).test(txt) } catch { return false }
  }
  if (pr.op === 'in') {
    const items = splitList(pr.value)
    if (isIPField) {
      return items.some(it => it.includes('/') ? ipv4InCIDR(txt, it) : it === txt)
    }
    return items.includes(txt)
  }
  return false
}

function ipv4ToInt(ip) {
  const parts = String(ip).split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    const x = parseInt(p, 10)
    if (isNaN(x) || x < 0 || x > 255 || String(x) !== p) return null
    n = (n * 256) + x
  }
  return n >>> 0
}

function ipv4InCIDR(ip, cidr) {
  const slash = cidr.indexOf('/')
  if (slash < 0) return ip === cidr
  const base = cidr.slice(0, slash)
  const prefix = parseInt(cidr.slice(slash + 1), 10)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false
  const ipN = ipv4ToInt(ip)
  const baseN = ipv4ToInt(base)
  if (ipN == null || baseN == null) return false
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0
  return (ipN & mask) === (baseN & mask)
}

function splitList(v) {
  return String(v || '').split(',').map(s => s.trim()).filter(Boolean)
}

function readField(pr, p) {
  if (!p) return ''
  switch (pr.field) {
    case 'id':              return p.id ?? 0
    case 'body':            return p.body_string ?? ''
    case 'raw':             return p.body_string ?? ''
    case 'url':             return p.url ?? ''
	case 'path': {
	  try { return decodeURIComponent(new URL(p.url ?? '', 'http://janus.invalid').pathname) } catch { return p.url ?? '' }
	}
    case 'method':          return p.method ?? ''
    case 'status':          return p.status ?? 0
    case 'round':           return p.round ?? p.flagid_round ?? 0
    case 'proto':           return p.protocol ?? ''
    case 'service':         return p.service_id ?? ''
    case 'direction':       return p.direction ?? ''
    case 'src':             return p.src_ip ?? ''
    case 'dst':             return p.dst_ip ?? ''
    case 'peer':            return p.direction === 'response' ? (p.dst_ip ?? '') : (p.src_ip ?? '')
    case 'sport':           return p.src_port ?? 0
    case 'dport':           return p.dst_port ?? 0
    case 'flagged':         return !!p.flagged
    case 'contains_flagid': return !!p.contains_flagid
	case 'dropped':         return !!p.dropped
		case 'classification':   return p.classification ?? ''
		case 'analyst_label':    return p.analyst_label ?? ''
		case 'attack_score':     return p.attack_score ?? 0
		case 'normal_score':     return p.normal_score ?? 0
		case 'score_confidence': return p.score_confidence ?? 0
		case 'score_coverage':   return p.score_coverage ?? 0
    case 'header': {
      const h = p.headers || {}
      if (pr.headerName) {
        const want = pr.headerName.toLowerCase()
        for (const k of Object.keys(h)) if (k.toLowerCase() === want) return h[k]
        return ''
      }
      return Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\n')
    }
	}
	if (pr.field.startsWith('query.')) {
	  try {
		return new URL(p.url ?? '', 'http://janus.invalid').searchParams
		  .getAll(pr.field.slice('query.'.length)).join(',')
	  } catch { return '' }
	}
	if (/^(decoded\.)?(dns|resp|mqtt)\./.test(pr.field)) {
	  const parts = pr.field.replace(/^decoded\./, '').split('.')
	  let value = p.decoded || {}
	  for (const part of parts) value = value?.[part]
	  return value ?? ''
	}
  return ''
}

// ----- Local storage of named presets -----

const PRESET_KEY = 'janus_filter_presets_v1'

export function listPresets() {
  try {
    const raw = localStorage.getItem(PRESET_KEY)
    if (!raw) return []
    const arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr : []
  } catch { return [] }
}

export function savePreset(name, expression) {
  const list = listPresets().filter(p => p.name !== name)
  list.push({ name, expression })
  list.sort((a, b) => a.name.localeCompare(b.name))
  localStorage.setItem(PRESET_KEY, JSON.stringify(list))
  return list
}

export function deletePreset(name) {
  const list = listPresets().filter(p => p.name !== name)
  localStorage.setItem(PRESET_KEY, JSON.stringify(list))
  return list
}
