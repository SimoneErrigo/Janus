# Python filters — reference

A filter defines `match(flow)`. It runs on **every message**: each HTTP request/response,
or each TCP chunk. Same API for HTTP and TCP — a missing field reads as `""` (never
crashes). Module-level state persists across calls (use it to count / correlate).

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
| **Blocking** (inline) | TCP: requests + responses · HTTP: requests | TCP: both directions · HTTP: requests only |
| **Async** (default) | everything (HTTP + TCP, both directions) | no — alert only (message already forwarded) |

> Dropping/rewriting a **response** inline is available for **TCP** services today
> (HTTP response bodies are still forwarded before filters run — a response-side
> HTTP filter can only alert).

## Read — HTTP & TCP

| accessor | meaning |
|---|---|
| `flow.service` / `flow.direction` | service id; `"request"` / `"response"` |
| `flow.is_request` / `flow.is_response` | bool |
| `flow.src` / `flow.dst` / `flow.sport` / `flow.dport` | endpoints |
| `flow.body` | body as `str` (settable → rewrite) |
| `flow.content` | body as exact `bytes` (settable → rewrite) |
| `flow.json(default=None)` | parsed JSON body |
| `flow.flagged` / `flow.contains_flagid` | a flag / a known flag-ID appears in this message |
| `flow["x"]`, `flow.get("x")` | raw dict access still works |

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
flow.body = flow.body.replace("foo", "bar")            # HTTP request body (str)
flow.content = flow.content.replace(b"\x00", b"\xff")  # exact bytes (TCP, binary-safe)
```

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

More recipes — easy to advanced, HTTP and TCP — in
[PYFILTERS_COOKBOOK.md](PYFILTERS_COOKBOOK.md).
