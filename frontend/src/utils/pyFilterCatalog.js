export const STARTER_CODE = `# Observe first: a string or flow.alert() creates an alert.
def match(flow):
    if flow.method == "POST" and flow.path == "/admin":
        return flow.alert("POST to the admin endpoint")
    return False
`

const FLAG_OUT = `# Count flags in responses and stop suspicious exfiltration.
# connection.flags_out contains flags from earlier forwarded responses;
# flow.flags.count is the current response.
DIRECTION = "response"
MAX_FLAGS_OUT = 2

def match(flow):
    total = flow.connection.flags_out + flow.flags.count
    if flow.flags.count and total > MAX_FLAGS_OUT:
        return flow.close("flag-out limit exceeded (%d)" % total)
    return False
`

const HEADER_LENGTH = `# Block a request when one selected header is too long.
DIRECTION = "request"
HEADER_NAME = "X-Input"
MAX_LENGTH = 256

def match(flow):
    value = flow.header(HEADER_NAME)
    if len(value) > MAX_LENGTH:
        return flow.drop(
            "%s is too long (%d > %d)" % (HEADER_NAME, len(value), MAX_LENGTH)
        )
    return False
`

const REPEATED_REQUEST = `# Block the same complete request repeated consecutively.
# History is bounded and private to this connection.
DIRECTION = "request"
REPETITIONS = 3
MAX_BODY_BYTES = 4096

def signature(message):
    return (message.method, message.url, message.content)

def match(flow):
    recent = flow.requests[-REPETITIONS:]
    if len(recent) < REPETITIONS:
        return False
    if any(not item.body_complete or item.size > MAX_BODY_BYTES for item in recent):
        return False
    if all(signature(item) == signature(recent[0]) for item in recent):
        return flow.drop("identical request repeated %d times" % REPETITIONS)
    return False
`

const TCP_PAYLOAD = `# Block a marker even when TCP splits it across network chunks.
# Only len(BLOCKED_PAYLOAD) - 1 bytes are kept between messages.
DIRECTION = "request"
BLOCKED_PAYLOAD = b"EXPLOIT"
TAIL_KEY = "blocked-payload-tail"

def match(flow):
    if not BLOCKED_PAYLOAD:
        return False

    data = flow.state.get(TAIL_KEY, b"") + flow.content
    if BLOCKED_PAYLOAD in data:
        return flow.close("blocked TCP payload")

    keep = len(BLOCKED_PAYLOAD) - 1
    flow.state[TAIL_KEY] = data[-keep:] if keep else b""
    return False
`

const TOKEN_REPLAY = `# Reject a one-time token reused on the same connection.
import hashlib

DIRECTION = "request"
TOKEN_HEADER = "X-Nonce"
TOKEN_TTL_SECONDS = 120

def match(flow):
    token = flow.header(TOKEN_HEADER)
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode()).digest()
    if flow.state.seen("nonce", token_hash, ttl=TOKEN_TTL_SECONDS):
        return flow.drop("reused one-time token")
    return False
`

const AUTH_SEQUENCE = `# Require a successful HTTP/1 login response before protected requests.
# The state is bounded and belongs only to this connection.
LOGIN_PATH = "/login"
PROTECTED_PATHS = {"/admin", "/export"}
SUCCESS_STATUSES = {200, 204}

def match(flow):
    if flow.is_response and flow.request.path == LOGIN_PATH:
        flow.state["authenticated"] = flow.status in SUCCESS_STATUSES
        return False

    if flow.is_request and flow.path in PROTECTED_PATHS:
        if not flow.state.get("authenticated", False):
            return flow.drop("protected endpoint before successful login")
    return False
`

export const PY_FILTER_TEMPLATES = [
  {
    key: 'flag-out',
    title: 'Flag-out guard',
    description: 'Counts flags sent on a connection and stops exfiltration after a threshold.',
    code: FLAG_OUT,
    mode: 'block',
    difficulty: 'medium',
    directions: ['response'],
    accent: 'rose',
  },
  {
    key: 'header-length',
    title: 'Header length',
    description: 'Blocks a chosen request header when it exceeds a clear character limit.',
    code: HEADER_LENGTH,
    mode: 'block',
    difficulty: 'easy',
    directions: ['request'],
    protocols: ['http', 'https', 'h2', 'h2c'],
    accent: 'amber',
  },
  {
    key: 'repeated-request',
    title: 'Repeated request',
    description: 'Blocks an identical request repeated consecutively on one connection.',
    code: REPEATED_REQUEST,
    mode: 'block',
    difficulty: 'easy',
    directions: ['request'],
    protocols: ['http', 'https', 'h2', 'h2c'],
    accent: 'cyan',
  },
  {
    key: 'tcp-payload',
    title: 'TCP payload marker',
    description: 'Closes TCP when a blocked byte marker appears, even across network chunks.',
    code: TCP_PAYLOAD,
    mode: 'block',
    difficulty: 'easy',
    directions: ['request'],
    protocols: ['tcp', 'tcp-line', 'tls'],
    accent: 'rose',
  },
  {
    key: 'token-replay',
    title: 'One-time token replay',
    description: 'Rejects a nonce reused within a bounded TTL on the same connection.',
    code: TOKEN_REPLAY,
    mode: 'block',
    difficulty: 'medium',
    directions: ['request'],
    protocols: ['http', 'https', 'h2', 'h2c'],
    accent: 'violet',
  },
  {
    key: 'auth-sequence',
    title: 'HTTP/1 authenticated sequence',
    description: 'Correlates login responses and protects later endpoints with a small state machine.',
    code: AUTH_SEQUENCE,
    mode: 'block',
    difficulty: 'hard',
    directions: [],
    protocols: ['http', 'https'],
    accent: 'emerald',
  },
]

export const PY_FILTER_SNIPPETS = [
  { group: 'Actions', label: 'Alert', detail: 'Report only', code: 'return flow.alert("reason")' },
  { group: 'Actions', label: 'Drop message', detail: 'Inline mode', code: 'return flow.drop("reason")' },
  { group: 'Actions', label: 'Close / stop', detail: 'Best effort by protocol', code: 'return flow.close("reason")' },
  { group: 'Actions', label: 'Rewrite', detail: 'Replace current payload', code: 'return flow.rewrite(b"replacement", "reason")' },
  { group: 'Actions', label: 'Rewrite text directly', detail: 'Assign, then keep evaluating', code: 'flow.body = "replacement"' },
  { group: 'Actions', label: 'Rewrite bytes directly', detail: 'Binary-safe assignment', code: 'flow.content = b"replacement"' },
  { group: 'Actions', label: 'Ignore', detail: 'No match', code: 'return False' },
  { group: 'Actions', label: 'Simple match', detail: 'Alert with no reason', code: 'return True' },
  { group: 'Actions', label: 'Reason string', detail: 'Shorthand alert reason', code: 'return "reason"' },
  { group: 'Actions', label: 'Explicit verdict', detail: 'Low-level return form', code: 'return {"match": True, "reason": "reason", "drop": True}' },

  { group: 'Core', label: 'Direction guard', detail: 'Module-level fast scope', code: 'DIRECTION = "request"' },
  { group: 'Core', label: 'Service / protocol / session', detail: 'Canonical identifiers', code: 'flow.service, flow.protocol, flow.session' },
  { group: 'Core', label: 'Direction', detail: 'Value and boolean shortcuts', code: 'flow.direction, flow.is_request, flow.is_response' },
  { group: 'Core', label: 'Endpoints', detail: 'Source and destination tuple', code: 'flow.src, flow.sport, flow.dst, flow.dport' },
  { group: 'Core', label: 'Size / timestamp / round', detail: 'Bytes, Unix time and game round', code: 'flow.size, flow.timestamp, flow.round' },
  { group: 'Core', label: 'Body safety', detail: 'Guard body-based decisions', code: 'flow.body_complete, flow.truncated' },
  { group: 'Core', label: 'Flag booleans', detail: 'Any flag and known Flag ID', code: 'flow.flagged, flow.contains_flagid' },
  { group: 'Core', label: 'Decoded fields', detail: 'Protocol-specific metadata', code: 'flow.decoded' },
  { group: 'Core', label: 'Raw field access', detail: 'Flow remains a dictionary', code: 'flow["field"], flow.get("field", "default")' },

  { group: 'Flags', label: 'Current flag count', detail: 'All detected flags', code: 'flow.flags.count' },
  { group: 'Flags', label: 'Known flag count', detail: 'Known flag IDs only', code: 'flow.flags.known_count' },
  { group: 'Flags', label: 'Matched flag IDs', detail: 'Read-only tuple', code: 'flow.flags.matched_ids' },
  { group: 'Flags', label: 'Flag locations', detail: 'Body, headers, URL', code: 'flow.flags.body_count + flow.flags.header_count + flow.flags.url_count' },
  { group: 'Flags', label: 'Flag mapping', detail: 'Get, keys and items', code: 'flow.flags.get("count"), flow.flags.keys(), flow.flags.items()' },

  { group: 'Connection', label: 'Connection ID', detail: 'Stable lifecycle identifier', code: 'flow.connection.id' },
  { group: 'Connection', label: 'Age / idle', detail: 'Milliseconds', code: 'flow.connection.age_ms, flow.connection.idle_ms' },
  { group: 'Connection', label: 'Messages', detail: 'Total, in and out counters', code: 'flow.connection.messages, flow.connection.messages_in, flow.connection.messages_out' },
  { group: 'Connection', label: 'Bytes', detail: 'In and out counters', code: 'flow.connection.bytes_in, flow.connection.bytes_out' },
  { group: 'Connection', label: 'Request rate', detail: 'Sliding messages per second', code: 'flow.connection.rate_in(seconds=2)' },
  { group: 'Connection', label: 'Response rate', detail: 'Sliding messages per second', code: 'flow.connection.rate_out(seconds=2)' },
  { group: 'Connection', label: 'Flags in', detail: 'Previously forwarded', code: 'flow.connection.flags_in, flow.connection.known_flags_in' },
  { group: 'Connection', label: 'Flags out', detail: 'Previously forwarded', code: 'flow.connection.flags_out, flow.connection.known_flags_out' },
  { group: 'Connection', label: 'Fingerprint', detail: 'Deterministic short hash', code: 'flow.connection.fingerprint()' },
  { group: 'Connection', label: 'Current shape', detail: 'Direction, size, gap, protocol and hint', code: 'flow.connection.current.direction, flow.connection.current.size, flow.connection.current.gap, flow.connection.current.protocol, flow.connection.current.hint' },
  { group: 'Connection', label: 'Recent shapes', detail: 'Bounded metadata, no payload', code: 'flow.connection.recent' },
  { group: 'Connection', label: 'Metrics mapping', detail: 'Get, keys and items', code: 'flow.connection.get("age_ms"), flow.connection.keys(), flow.connection.items()' },

  { group: 'History', label: 'Messages / recent', detail: 'Current message is last', code: 'flow.messages, flow.recent(3)' },
  { group: 'History', label: 'Requests / responses', detail: 'History filtered by direction', code: 'flow.requests, flow.responses' },
  { group: 'History', label: 'Previous sides', detail: 'Previous request and response', code: 'flow.last_request, flow.last_response' },
  { group: 'History', label: 'Correlated sides', detail: 'Current or previous opposite side', code: 'flow.request, flow.response' },

  { group: 'State', label: 'Read / write state', detail: 'Bounded per filter and connection', code: 'flow.state["phase"] = "ready"\nvalue = flow.state.get("phase", "new")' },
  { group: 'State', label: 'Dictionary methods', detail: 'setdefault, update, pop, clear', code: 'flow.state.setdefault("count", 0)\nflow.state.update({"phase": "ready"})\nflow.state.pop("phase", None)\nflow.state.clear()' },
  { group: 'State', label: 'Legacy alias', detail: 'flow.conn is flow.state', code: 'flow.conn["phase"] = "ready"' },
  { group: 'State', label: 'Window counter', detail: 'Bounded weighted counter', code: 'flow.state.count("event", key=flow.src, window=10, amount=1)' },
  { group: 'State', label: 'Seen value', detail: 'TTL membership', code: 'flow.state.seen("token", value, ttl=300)' },
  { group: 'State', label: 'Distinct values', detail: 'Bounded cardinality', code: 'flow.state.distinct("users", user, key=flow.src, window=60)' },
  { group: 'State', label: 'Rolling statistics', detail: 'Returns count, mean, median, MAD, p95, min, max', code: 'stats = flow.state.observe("latency", value, key=flow.path, window=60)\nstats.count, stats.mean, stats.median, stats.mad, stats.p95, stats.min, stats.max' },

  { group: 'Payload', label: 'Text / exact bytes', detail: 'Forgiving text and binary-safe aliases', code: 'flow.body, flow.content, flow.bytes' },
  { group: 'Payload', label: 'JSON body', detail: 'Custom default on parse errors', code: 'flow.json(default={})' },
  { group: 'Payload', label: 'Base64 decode', detail: 'Bytes or None', code: 'util.b64(value)' },
  { group: 'Payload', label: 'Base64 validation', detail: 'Canonical by default', code: 'util.is_base64(value, canonical=True)' },
  { group: 'Payload', label: 'Valid JSON', detail: 'One complete JSON document', code: 'util.valid_json(flow.body)' },
  { group: 'Payload', label: 'Unexpected keys', detail: 'JSON field allowlist', code: 'util.extra_keys(flow.json({}), {"name", "email"})' },
  { group: 'Payload', label: 'Entropy', detail: 'Shannon bits per byte', code: 'util.entropy(flow.content)' },
  { group: 'Payload', label: 'Longest byte run', detail: 'Repeated-byte fingerprint', code: 'util.longest_run(flow.content)' },
  { group: 'Payload', label: 'Repeated block', detail: 'Aligned ECB-like repetition', code: 'util.repeated_block(flow.content, size=16)' },
  { group: 'Payload', label: 'Printable ratio', detail: 'Fraction of printable ASCII', code: 'util.printable_ratio(flow.content)' },
  { group: 'Payload', label: 'Control characters', detail: 'C0 controls or DEL', code: 'util.has_control_chars(value)' },

  { group: 'Files', label: 'File type', detail: 'Magic-byte sniffing', code: 'util.magic(flow.content)' },
  { group: 'Files', label: 'Content-Type check', detail: 'Declared type versus bytes', code: 'util.content_type_ok(flow.header("Content-Type"), flow.content)' },
  { group: 'Files', label: 'Appended data', detail: 'PNG/JPEG trailing bytes', code: 'util.trailing_data(flow.content)' },
  { group: 'Files', label: 'Printable strings', detail: 'ASCII runs', code: 'util.strings(flow.content, min_len=4)' },
  { group: 'Files', label: 'Text layers', detail: 'Bytes, archives, documents and optional QR', code: 'util.text_layers(flow.content, qr=True)' },
  { group: 'Files', label: 'QR decode', detail: 'Decoded strings', code: 'util.qr_decode(flow.content)' },
  { group: 'Files', label: 'Known payload scan', detail: 'Optional categories and QR', code: 'util.find_payload(flow.content, categories=("sqli", "shell"), qr=True)' },
  { group: 'Files', label: 'Custom pattern scan', detail: 'Regexes or substrings', code: 'util.scan(flow.content, [r"pattern"], qr=False)' },
  { group: 'Files', label: 'Inspection report', detail: 'Type, size, layers and first hit', code: 'util.inspect(flow.content, qr=True)' },

  { group: 'HTTP', label: 'Request / response fields', detail: 'Method, URL, path and status', code: 'flow.method, flow.url, flow.path, flow.status' },
  { group: 'HTTP', label: 'Header', detail: 'Case-insensitive and forgiving', code: 'flow.header("Content-Type", "")' },
  { group: 'HTTP', label: 'Header mapping', detail: 'get, membership, keys, items, values', code: 'flow.headers.get("x-token", ""), "x-token" in flow.headers\nflow.headers.keys(), flow.headers.items(), flow.headers.values()' },
  { group: 'HTTP', label: 'Query values', detail: 'First or every repeated value', code: 'flow.query.get("id", ""), flow.query.all("id")' },
  { group: 'HTTP', label: 'Query mapping', detail: 'Membership, keys, items and params alias', code: '"id" in flow.query, flow.query.keys(), flow.query.items(), flow.params["id"]' },
  { group: 'HTTP', label: 'Cookies', detail: 'Forgiving dictionary', code: 'flow.cookies.get("session", "")' },

  { group: 'Paths', label: 'Normalize path', detail: 'Decode and resolve separators', code: 'util.normpath(value, decode=2)' },
  { group: 'Paths', label: 'URI scheme', detail: 'Lowercase scheme or empty', code: 'util.uri_scheme(value)' },
  { group: 'Paths', label: 'Path escape guard', detail: 'Traversal, absolute path, URI or NUL', code: 'util.path_escapes(value)' },

  { group: 'WebSocket', label: 'Message opcode', detail: 'text or binary', code: 'flow.websocket_opcode or flow.header("X-Janus-WebSocket-Opcode")' },
  { group: 'WebSocket', label: 'Message payload', detail: 'Text and exact bytes', code: 'flow.body, flow.content' },

  { group: 'TCP', label: 'Complete lines', detail: 'Reassembled across chunks', code: 'for line in flow.lines:\n        pass' },
  { group: 'TCP', label: 'Named commands', detail: 'Trigger plus named argument lines', code: 'COMMANDS = {b"1": ("login", ("user", "password"))}\nfor command in flow.commands(COMMANDS):\n    command.name, command.user, command.password' },
  { group: 'TCP', label: 'Command fields', detail: 'Args, Flag ID, positional and named access', code: 'command.args, command.flagid\ncommand.arg(0, b""), command.field("user", b"")' },

  { group: 'Debug', label: 'Dry-test console', detail: 'Captured and bounded in test results', code: 'print("value:", value)' },
]
