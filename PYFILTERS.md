# Python filters — reference

A filter defines `match(flow)`. It runs on **every message**: each HTTP
request/response, each TCP chunk, or each complete WebSocket text/binary
message. The same API works across HTTP, TCP, WS, and WSS — a missing field
reads as `""` (never crashes). Module-level state persists across calls (use it
to count / correlate).

New to PyFilters? Start with [PYFILTERS_QUICKSTART.md](PYFILTERS_QUICKSTART.md).
For fuller A/D recipes, use [PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md).

```python
def match(flow):
    ...
    return False
```

## Return values

| return | effect |
|---|---|
| `False` / `None` | no match |
| `True` | match, no reason |
| `"reason"` | match + reason (shown in Alerts) |
| `{"match": True, "reason": "..."}` | same, explicit |
| `{"drop": True}` / `{"block": True}` | drop **this** message in real time (requires the **Blocking** flag). Any truthy `drop` works, so `{"drop": "reason"}` blocks too. |

`match(flow)` runs **once per message on both directions** — branch on
`flow.is_request` / `flow.is_response`, or declare a module-level
`DIRECTION = "request"` (or `"response"`) to have Janus skip the other side.

| filter kind | sees | can drop / rewrite the current message? |
|---|---|---|
| **Blocking** (inline) | TCP/WS/WSS: requests + responses · HTTP: requests | TCP/WS/WSS: both directions · HTTP: requests only |
| **Async** (default) | everything (HTTP + TCP + WS/WSS, both directions) | no — alert only (message already forwarded) |

> Dropping/rewriting a **response** inline is available for **TCP and WebSocket** services today
> (HTTP response bodies are still forwarded before filters run — a response-side
> HTTP filter can only alert).

## Read — HTTP, TCP & WebSocket

| accessor | meaning |
|---|---|
| `flow.service` / `flow.direction` | service id; `"request"` / `"response"` |
| `flow.is_request` / `flow.is_response` | bool |
| `flow.src` / `flow.dst` / `flow.sport` / `flow.dport` | endpoints |
| `flow.body` | body as `str` (settable → rewrite) |
| `flow.content` / `flow.bytes` | body as exact `bytes` (settable → rewrite) |
| `flow.json(default=None)` | parsed JSON body |
| `flow.flagged` / `flow.contains_flagid` | a flag / a known flag-ID appears in this message |
| `flow["x"]`, `flow.get("x")` | raw dict access still works |

## WebSocket messages

Janus invokes `match(flow)` once for each reassembled text or binary message,
not once per frame. `flow.method == "WS"`, `flow.url` is the upgrade URL,
`flow.protocol` is `ws` or `wss`, and
`flow.headers["X-Janus-WebSocket-Opcode"]` is `text` or `binary`. Text is
available through `flow.body`; exact text or binary bytes are available through
`flow.content` / `flow.bytes`.

A Blocking filter can drop or rewrite either direction. Dropping suppresses
only the current message and leaves the WebSocket session alive. Janus preserves
subprotocol negotiation but disables WebSocket extensions so transformed or
compressed payloads cannot bypass filtering. Messages larger than 1 MiB are
dropped before forwarding.

## Read — HTTP only

| accessor | meaning |
|---|---|
| `flow.method` / `flow.url` / `flow.path` | request line parts |
| `flow.status` | response status |
| `flow.headers["Cookie"]` | header, case-insensitive, missing → `""` |
| `flow.header("x", default="")` | same, with default |
| `flow.query["id"]` / `flow.query.all("id")` | query string (forgiving; `.all` → list) |
| `flow.cookies["session"]` | cookie value |

## History / correlation (per service)

| accessor | meaning |
|---|---|
| `flow.messages` / `flow.messages[-1]` | recent messages (current = last) |
| `flow.recent(n=3)` | last `n` messages |
| `flow.requests` / `flow.responses` | recent, filtered by direction |
| `flow.last_request` / `flow.last_response` | most recent of each |
| `flow.request` / `flow.response` | the correlated other side (never `None`) |

History is per service (last 32), mixed across clients. To correlate **per user under SNAT**
(same IP, changing port, maybe no cookie), key your own module-level dict by a **request
field** — a cookie, or the reused **credential** — not by IP.

## TCP streams (a continuous byte flow, not one message per chunk)

| accessor | meaning |
|---|---|
| `flow.conn` | dict persisting for the whole TCP connection — per-connection state, **private to each filter** (same key in two filters won't collide) |
| `for line in flow.lines:` | complete lines, reassembled across chunks (`bytes`) |
| `for cmd in flow.commands(spec):` | parse a line-based CLI into commands |
| `cmd.name` / `cmd.flagid` | command name; flag-ID seen anywhere in it |
| `cmd.user` / `cmd.arg(0)` | an argument by declared name, or positional (`b""` if absent) |

`spec` maps a trigger line to `(name, arg_spec)`, where `arg_spec` is either the
number of argument lines **or a tuple of field names**:

```python
{b"1": ("register", ("user", "pw")),   # named  -> cmd.user, cmd.pw
 b"2": ("login", 2)}                    # count  -> cmd.args[0], cmd.arg(1)
```

Don't unpack `cmd.args` (`user, pw = cmd.args`) when a table mixes commands of
different arities — read by name or with `cmd.arg(i)` instead.

## Rewrite (Blocking filters only)

```python
flow.body = flow.body.replace("foo", "bar")            # HTTP/WS text body (str)
flow.content = flow.content.replace(b"\x00", b"\xff")  # exact bytes (TCP/WS, binary-safe)
```

The rewritten content is forwarded only by an inline **Blocking** filter. For
HTTP that means a request; for TCP and WebSocket it can be a request or a
response. An async filter can return alerts but cannot modify traffic that has
already been forwarded.

## Test a filter before enabling it

The **PyFilters** page can run an unsaved script in isolation. Supply one sample
request/response, load a captured packet, or load a complete reconstructed flow.
For a complete flow, `match()` runs over the packets in order, so module state,
`flow.request`, `flow.response`, `flow.conn`, and `flow.commands()` see the same
sequence they would see live.

Use **Repeat** to replay that sequence in the same script instance. For example,
a counter that alerts on the second login needs a repeat of at least `2`. The
result shows one verdict per packet, including any alert, requested block, and
best-effort rewritten body. A test validates script logic; the live effect still
depends on whether the script is enabled and marked **Blocking**.

## Analysis helpers (`util`)

`util` is injected into every filter — stdlib-only helpers to validate/inspect a
payload and drop immediately. Pass `flow.content` (exact bytes) for binary.

| helper | meaning |
|---|---|
| `util.is_base64(s, canonical=True)` | valid (and by default canonical) base64 |
| `util.b64(s)` | decoded bytes, or `None` |
| `util.valid_json(s)` | one complete, well-formed JSON document |
| `util.extra_keys(obj, allowed)` | dict keys not in `allowed` (mass assignment) |
| `util.entropy(data)` | Shannon entropy (bits/byte) |
| `util.longest_run(data)` / `util.repeated_block(data, size=16)` | uniform run / repeated block (crypto oracles) |
| `util.printable_ratio(data)` / `util.has_control_chars(s)` | printable fraction / any `\r \n \t`/control/DEL |
| `util.magic(data)` | sniffed file type (`png`,`jpg`,`pdf`,`zip`,`svg`,…) or `""` |
| `util.content_type_ok(ct, data)` | declared Content-Type matches the bytes |
| `util.trailing_data(data)` | bytes appended after an image's end (polyglot) |
| `util.qr_decode(data)` | decode a QR code from a PNG/GIF/BMP image → list of strings (all versions 1-40) |
| `util.text_layers(data, qr=False)` | every readable text layer: raw strings + PNG chunks / PDF streams / ZIP entries / QR |
| `util.find_payload(data, categories=None, qr=False)` | first attack signature (sqli/shell/php/xss/xxe/template/traversal) in any layer, else `None` |
| `util.scan(data, patterns, qr=False)` / `util.strings(data)` / `util.inspect(data, qr=False)` | custom regex scan / printable runs / quick report |
| `util.normpath(p)` / `util.uri_scheme(s)` / `util.path_escapes(p)` | path folding / scheme / traversal-or-absolute-or-scheme |

## Examples

**HTTP** — block a login that reuses a registered password with a flag-ID. Correlate by the
credential (SNAT-proof, no cookie/IP needed):

```python
_reg = set()   # persists across calls

def match(flow):
    if flow.method != "POST":
        return False
    pw = (flow.json() or {}).get("password", "")
    if not pw:
        return False
    if flow.path.endswith("/register"):
        _reg.add(pw)
    elif flow.path.endswith("/login") and flow.contains_flagid and pw in _reg:
        return {"drop": True, "reason": "login flag-ID with a registered password"}
    return False
```

**TCP CLI** — same intent, via `flow.commands` + per-connection state and named args:

```python
DIRECTION = "request"
CMDS = {b"1": ("register", ("user", "pw")), b"2": ("login", ("user", "pw"))}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "register":
            flow.conn.setdefault("regs", set()).add(cmd.pw)
        elif cmd.name == "login" and cmd.flagid and cmd.pw in flow.conn.get("regs", set()):
            return {"drop": True, "reason": "login flag-ID with a registered password"}
    return False
```

More recipes — easy to advanced, HTTP, TCP, and WebSocket — are in
[PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md). The deliberately small first
examples are in [PYFILTERS_QUICKSTART.md](PYFILTERS_QUICKSTART.md).
